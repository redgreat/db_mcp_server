"""
MCP服务端实现
"""
from fastapi import APIRouter, Header, HTTPException, Request
from typing import Dict, Any
from pydantic import BaseModel
from .tools import get_tool_definitions, get_tool_by_name
from .permissions import MCPPermissionChecker
from ..db.db_operations import QueryProxy
from ..tools.db_metadata_tool import list_databases, list_tables, list_views, list_procedures, table_info
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
            connection_id = args.get("connection_id")
            
            if connection_id is None:
                raise HTTPException(
                    status_code=400,
                    detail="缺少必需参数: connection_id"
                )
            
            # 执行工具
            result = _execute_tool(
                tool_name=req.tool,
                args=args,
                access_key=x_access_key,
                perm_checker=perm_checker,
                qp=qp,
                cfg=cfg,
                data_masker=data_masker,
                admin_engine=admin_engine
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 记录审计日志
            audit_logger.log(
                operation=f"mcp_{req.tool}",
                status="success",
                access_key=x_access_key,
                client_ip=client_ip,
                connection_id=connection_id,
                sql_text=args.get("sql"),
                duration_ms=duration_ms,
                metadata={"tool": req.tool, "arguments": args}
            )
            
            return {"result": result}
            
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 记录失败日志
            args = req.arguments
            connection_id = args.get("connection_id")
            audit_logger.log(
                operation=f"mcp_{req.tool}",
                status="error",
                access_key=x_access_key,
                client_ip=client_ip,
                connection_id=connection_id,
                sql_text=args.get("sql"),
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
    perm_checker: MCPPermissionChecker,
    qp: QueryProxy,
    cfg: Config,
    data_masker: DataMasker,
    admin_engine: Any
) -> Any:
    """执行MCP工具"""
    
    # 1. 特殊处理 list_connections
    if tool_name == "list_connections":
        search = args.get("search", "")
        with Session(admin_engine) as session:
            meta = MetaData()
            keys = Table("access_keys", meta, autoload_with=admin_engine)
            key_row = session.execute(
                select(keys).where(keys.c.ak == access_key)
            ).mappings().first()
            
            if not key_row:
                raise Exception("访问密钥不存在")
            
            perms = Table("permissions", meta, autoload_with=admin_engine)
            conns = Table("db_connections", meta, autoload_with=admin_engine)
            
            stmt = select(
                conns.c.id, 
                conns.c.conn_name, 
                conns.c.db_type, 
                conns.c.host, 
                conns.c.database
            ).select_from(
                conns.join(perms, conns.c.id == perms.c.connection_id)
            ).where(
                perms.c.key_id == key_row["id"]
            )
            
            if search:
                stmt = stmt.where(conns.c.conn_name.ilike(f"%{search}%"))
                
            conn_rows = session.execute(stmt).mappings().all()
            return {"connections": [dict(r) for r in conn_rows]}

    # 2. 其他工具都需要 connection_id
    connection_id = args.get("connection_id")
    if connection_id is None:
        raise HTTPException(status_code=400, detail="缺少必需参数: connection_id")

    if tool_name == "list_databases":
        perm_checker.check_permission(access_key, connection_id)
        eng, _, db_type = _get_engine(cfg, qp, connection_id)
        databases = list_databases(eng, db_type)
        return {"databases": databases}

    elif tool_name == "list_tables":
        perm_checker.check_permission(access_key, connection_id)
        eng, db_name, db_type = _get_engine(cfg, qp, connection_id)
        database = args.get("database") or db_name
        tables = list_tables(eng, database, db_type)
        return {"database": database, "tables": tables}

    elif tool_name == "list_views":
        perm_checker.check_permission(access_key, connection_id)
        eng, db_name, db_type = _get_engine(cfg, qp, connection_id)
        database = args.get("database") or db_name
        views = list_views(eng, database, db_type)
        return {"database": database, "views": views}

    elif tool_name == "list_procedures":
        perm_checker.check_permission(access_key, connection_id)
        eng, db_name, db_type = _get_engine(cfg, qp, connection_id)
        database = args.get("database") or db_name
        procs = list_procedures(eng, database, db_type)
        return {"database": database, "procedures": procs}
    
    elif tool_name == "describe_table":
        perm_checker.check_permission(access_key, connection_id)
        table_name = args.get("table")
        if not table_name:
            raise HTTPException(status_code=400, detail="缺少参数: table")
        eng, db_name, db_type = _get_engine(cfg, qp, connection_id)
        database = args.get("database") or db_name
        info = table_info(eng, database, table_name, db_type)
        return {"database": database, "table": table_name, "columns": info["columns"]}
    
    elif tool_name == "execute_query":
        perm_checker.check_permission(access_key, connection_id)
        sql = args.get("sql")
        if not sql:
            raise HTTPException(status_code=400, detail="缺少参数: sql")
        sec = intercept_sql(sql, {"key": access_key})
        if not sec["safe"]:
            raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
        eng, _, _ = _get_engine(cfg, qp, connection_id)
        rows = qp.run_query(eng, sql)
        masked_rows = data_masker.mask_results(rows)
        return {"rows": masked_rows, "count": len(masked_rows)}
    
    elif tool_name == "execute_sql":
        sql = args.get("sql")
        if not sql:
            raise HTTPException(status_code=400, detail="缺少参数: sql")
        require_ddl = perm_checker.is_ddl_sql(sql)
        perm_checker.check_permission(access_key, connection_id, require_ddl=require_ddl)
        sec = intercept_sql(sql, {"key": access_key})
        if not sec["safe"]:
            raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
        eng, _, _ = _get_engine(cfg, qp, connection_id)
        from sqlalchemy import text
        with eng.connect() as conn:
            result = conn.execute(text(sql))
            conn.commit()
            try:
                rows = [dict(r._mapping) for r in result]
                masked_rows = data_masker.mask_results(rows)
                return {"rows": masked_rows, "count": len(masked_rows)}
            except:
                return {"success": True, "message": "SQL执行成功"}
    
    else:
        raise HTTPException(status_code=404, detail=f"未知工具: {tool_name}")


def _get_engine(cfg: Config, qp: QueryProxy, connection_id: int):
    """获取数据库引擎"""
    from sqlalchemy import Table, MetaData, create_engine
    
    admin_db_path = cfg.get_admin_db_url()
    admin_engine = create_engine(admin_db_path)
    
    with Session(admin_engine) as session:
        meta = MetaData()
        db_connections = Table("db_connections", meta, autoload_with=admin_engine)
        conn_row = session.execute(
            select(db_connections).where(db_connections.c.id == connection_id)
        ).mappings().first()
        
        if not conn_row:
            raise HTTPException(status_code=404, detail=f"连接 ID {connection_id} 不存在")
        
        # 解密密码
        pwd = decrypt_text(conn_row['password_enc'], cfg.security.master_key)
        
        # 获取引擎
        eng = qp.get_engine(
            conn_row['host'],
            conn_row['port'],
            conn_row['username'],
            pwd,
            conn_row['database'],
            conn_row['db_type']
        )
        
        return eng, conn_row['database'], conn_row['db_type']
