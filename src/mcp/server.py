"""
MCP服务端实现
"""
from fastapi import APIRouter, Header, HTTPException, Request
from typing import Dict, Any
from pydantic import BaseModel
from .tools import get_tool_definitions, get_tool_by_name
from .permissions import MCPPermissionChecker
from ..db.db_operations import QueryProxy
from ..tools.db_metadata_tool import list_tables, table_info
from ..security.interceptor import intercept_sql
from ..security.ip_whitelist import IPWhitelistChecker
from ..security.data_masker import DataMasker
from ..logging.audit_logger import AuditLogger
from ..config import Config
from ..security.secret import decrypt_text
from sqlalchemy import create_engine, Table, MetaData, select
from sqlalchemy.orm import Session
import time


class MCPCallRequest(BaseModel):
    """MCP工具调用请求"""
    tool: str
    arguments: Dict[str, Any]


def build_mcp_router(
    cfg: Config,
    qp: QueryProxy,
    admin_engine,
    audit_logger: AuditLogger,
    ip_checker: IPWhitelistChecker,
    data_masker: DataMasker
):
    """构建MCP路由器"""
    router = APIRouter()
    perm_checker = MCPPermissionChecker(admin_engine)
    
    @router.get("/mcp/tools")
    def list_mcp_tools(x_access_key: str = Header(default="")):
        """列出所有可用的MCP工具"""
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")
        
        # 验证APPKEY有效性
        with Session(admin_engine) as session:
            meta = MetaData()
            keys = Table("access_keys", meta, autoload_with=admin_engine)
            key_row = session.execute(
                select(keys).where(
                    keys.c.ak == x_access_key,
                    keys.c.enabled == True
                )
            ).first()
            
            if not key_row:
                raise HTTPException(status_code=401, detail="无效或已禁用的访问密钥")
        
        return {"tools": get_tool_definitions()}
    
    @router.post("/mcp/call")
    def call_mcp_tool(
        req: MCPCallRequest,
        request: Request,
        x_access_key: str = Header(default="")
    ):
        """调用MCP工具"""
        start_time = time.time()
        client_ip = request.client.host if request.client else None
        
        try:
            if not x_access_key:
                raise HTTPException(status_code=401, detail="缺少访问密钥")
            
            # IP白名单检查
            if client_ip and not ip_checker.check_access(client_ip, x_access_key):
                raise HTTPException(
                    status_code=403,
                    detail=f"IP {client_ip} 不在访问密钥的白名单中"
                )
            
            # 获取工具定义
            tool = get_tool_by_name(req.tool)
            if not tool:
                raise HTTPException(status_code=404, detail=f"工具 {req.tool} 不存在")
            
            # 提取参数
            args = req.arguments
            instance_id = args.get("instance_id")
            database_id = args.get("database_id")
            account_id = args.get("account_id")
            
            if not all([instance_id, database_id, account_id]):
                raise HTTPException(
                    status_code=400,
                    detail="缺少必需参数: instance_id, database_id, account_id"
                )
            
            # 执行工具
            result = _execute_tool(
                tool_name=req.tool,
                args=args,
                access_key=x_access_key,
                instance_id=instance_id,
                database_id=database_id,
                account_id=account_id,
                perm_checker=perm_checker,
                qp=qp,
                cfg=cfg,
                data_masker=data_masker
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 记录审计日志
            audit_logger.log(
                operation=f"mcp_{req.tool}",
                status="success",
                access_key=x_access_key,
                client_ip=client_ip,
                instance_id=instance_id,
                database_id=database_id,
                account_id=account_id,
                sql_text=args.get("sql"),
                duration_ms=duration_ms,
                metadata={"tool": req.tool, "arguments": args}
            )
            
            return {"result": result}
            
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 记录失败日志
            audit_logger.log(
                operation=f"mcp_{req.tool}",
                status="error",
                access_key=x_access_key,
                client_ip=client_ip,
                duration_ms=duration_ms,
                error_message=str(e),
                metadata={"tool": req.tool, "arguments": req.arguments}
            )
            raise
    
    return router


def _execute_tool(
    tool_name: str,
    args: Dict[str, Any],
    access_key: str,
    instance_id: int,
    database_id: int,
    account_id: int,
    perm_checker: MCPPermissionChecker,
    qp: QueryProxy,
    cfg: Config,
    data_masker: DataMasker
) -> Any:
    """执行MCP工具"""
    
    if tool_name == "list_tables":
        # 检查权限
        perm_checker.check_permission(access_key, instance_id, database_id, account_id)
        
        # 获取数据库引擎
        eng, db_name, db_type = _get_engine(cfg, qp, instance_id, database_id, account_id)
        
        # 列出表
        tables = list_tables(eng, db_name, db_type)
        return {"tables": tables}
    
    elif tool_name == "describe_table":
        # 检查权限
        perm_checker.check_permission(access_key, instance_id, database_id, account_id)
        
        table_name = args.get("table")
        if not table_name:
            raise HTTPException(status_code=400, detail="缺少参数: table")
        
        # 获取数据库引擎
        eng, db_name, db_type = _get_engine(cfg, qp, instance_id, database_id, account_id)
        
        # 查询表结构
        info = table_info(eng, db_name, table_name, db_type)
        return {"table": table_name, "columns": info}
    
    elif tool_name == "execute_query":
        # 检查权限
        perm_checker.check_permission(access_key, instance_id, database_id, account_id)
        
        sql = args.get("sql")
        if not sql:
            raise HTTPException(status_code=400, detail="缺少参数: sql")
        
        # SQL安全检查
        sec = intercept_sql(sql, {"key": access_key})
        if not sec["safe"]:
            raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
        
        # 获取数据库引擎
        eng, _, _ = _get_engine(cfg, qp, instance_id, database_id, account_id)
        
        # 执行查询
        rows = qp.run_query(eng, sql)
        
        # 数据脱敏
        masked_rows = data_masker.mask_results(rows)
        
        return {"rows": masked_rows, "count": len(masked_rows)}
    
    elif tool_name == "execute_sql":
        # 判断是否需要DDL权限
        sql = args.get("sql")
        if not sql:
            raise HTTPException(status_code=400, detail="缺少参数: sql")
        
        require_ddl = perm_checker.is_ddl_sql(sql)
        
        # 检查权限（可能需要DDL权限）
        perm_checker.check_permission(
            access_key, instance_id, database_id, account_id,
            require_ddl=require_ddl
        )
        
        # SQL安全检查（DDL也要检查）
        sec = intercept_sql(sql, {"key": access_key})
        if not sec["safe"]:
            raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
        
        # 获取数据库引擎
        eng, _, _ = _get_engine(cfg, qp, instance_id, database_id, account_id)
        
        # 执行SQL
        with eng.connect() as conn:
            result = conn.execute(sql)
            conn.commit()
            
            # 尝试获取结果
            try:
                rows = [dict(r._mapping) for r in result]
                masked_rows = data_masker.mask_results(rows)
                return {"rows": masked_rows, "count": len(masked_rows)}
            except:
                # DDL语句没有结果集
                return {"success": True, "message": "SQL执行成功"}
    
    else:
        raise HTTPException(status_code=404, detail=f"未知工具: {tool_name}")


def _get_engine(cfg: Config, qp: QueryProxy, instance_id: int, database_id: int, account_id: int):
    """获取数据库引擎"""
    from sqlalchemy import Table, MetaData
    
    admin_db_path = cfg.get_admin_db_url()
    admin_engine = create_engine(admin_db_path)
    
    with Session(admin_engine) as session:
        meta = MetaData()
        
        # 获取实例信息
        instances = Table("instances", meta, autoload_with=admin_engine)
        inst = session.execute(
            select(instances).where(instances.c.id == instance_id)
        ).mappings().first()
        
        # 获取数据库信息
        databases = Table("databases", meta, autoload_with=admin_engine)
        db = session.execute(
            select(databases).where(databases.c.id == database_id)
        ).mappings().first()
        
        # 获取账号信息
        accounts = Table("accounts", meta, autoload_with=admin_engine)
        acc = session.execute(
            select(accounts).where(accounts.c.id == account_id)
        ).mappings().first()
        
        if not all([inst, db, acc]):
            raise HTTPException(status_code=404, detail="实例/数据库/账号不存在")
        
        # 解密密码
        pwd = decrypt_text(acc['password_enc'], cfg.security.master_key)
        
        # 获取引擎
        eng = qp.get_engine(
            inst['host'],
            inst['port'],
            acc['username'],
            pwd,
            db['name'],
            inst['db_type']
        )
        
        return eng, db['name'], inst['db_type']
