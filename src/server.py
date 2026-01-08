import os
import time
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from typing import Dict, Any, Optional
from .config import Config
from .logging_utils import get_logger
from .admin.web import build_admin_router
from .db.db_operations import QueryProxy
from .security.interceptor import intercept_sql
from .security.secret import decrypt_text
from .logging.audit_logger import AuditLogger
from .security.ip_whitelist import IPWhitelistChecker
from .security.data_masker import DataMasker
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


def create_app() -> FastAPI:
    """创建应用并挂载路由"""
    cfg = Config.load()
    logger = get_logger("server", cfg.logging.dir)
    app = FastAPI()
    
    # 挂载静态文件
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    app.include_router(build_admin_router(cfg))
    qp = QueryProxy()
    
    # 初始化审计日志服务
    admin_db_url = cfg.get_admin_db_url()
    admin_engine = create_engine(admin_db_url, pool_pre_ping=True)
    audit_logger = AuditLogger(admin_engine)
    
    # 初始化IP白名单检查器
    ip_checker = IPWhitelistChecker(admin_engine)
    
    # 初始化数据脱敏器
    data_masker = DataMasker(enabled=True)
    
    # 挂载MCP路由
    from .mcp import build_mcp_router
    mcp_router = build_mcp_router(
        cfg, qp, admin_engine, audit_logger, ip_checker, data_masker
    )
    app.include_router(mcp_router)

    @app.post("/query")
    def query(sql: str, instance_id: int, database_id: int, account_id: int, 
              request: Request, x_access_key: str = Header(default="")):
        """执行查询代理操作"""
        start_time = time.time()
        client_ip = request.client.host if request.client else None
        
        try:
            if not x_access_key:
                raise HTTPException(status_code=401, detail="缺少访问密钥")
            
            # APPKEY级别的IP白名单检查
            if client_ip:
                if not ip_checker.check_access(client_ip, x_access_key):
                    raise HTTPException(
                        status_code=403, 
                        detail=f"IP {client_ip} 不在访问密钥 {x_access_key} 的白名单中，访问被拒绝"
                    )
            
            _check_permission(cfg, x_access_key, instance_id, database_id, account_id)
            
            sec = intercept_sql(sql, {"key": x_access_key})
            if not sec["safe"]:
                raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
            eng, db_name, _ = _resolve_engine(cfg, qp, instance_id, database_id, account_id)
            rows = qp.run_query(eng, sql)
            
            # 数据脱敏
            masked_rows = data_masker.mask_results(rows)
            
            duration_ms = int((time.time() - start_time) * 1000)
            logger.info(f"ak={x_access_key} sql={sql[:128]}")
            
            # 写入审计日志到数据库
            audit_logger.log(
                operation="query",
                status="success",
                access_key=x_access_key,
                client_ip=client_ip,
                instance_id=instance_id,
                database_id=database_id,
                account_id=account_id,
                sql_text=sql,
                rows_affected=len(rows),
                duration_ms=duration_ms
            )
            
            return {"items": masked_rows}
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            # 记录失败的审计日志
            audit_logger.log(
                operation="query",
                status="error",
                access_key=x_access_key,
                client_ip=client_ip,
                instance_id=instance_id,
                database_id=database_id,
                account_id=account_id,
                sql_text=sql,
                duration_ms=duration_ms,
                error_message=str(e)
            )
            raise

    @app.get("/sse/query")
    def sse_query(sql: str, instance_id: int, database_id: int, account_id: int, x_access_key: str = Header(default="")):
        """通过SSE流式返回查询结果"""
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")
        _check_permission(cfg, x_access_key, instance_id, database_id, account_id)
        sec = intercept_sql(sql, {"key": x_access_key})
        if not sec["safe"]:
            raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
        eng, _, _ = _resolve_engine(cfg, qp, instance_id, database_id, account_id)

        def event_stream():
            """生成SSE数据流"""
            try:
                rows = qp.run_query(eng, sql)
                yield f"data: {len(rows)}\n\n"
                for r in rows:
                    yield f"data: {r}\n\n"
            except Exception as e:
                yield f"event: error\ndata: {str(e)}\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    @app.get("/metadata/tables")
    def metadata_tables(instance_id: int, database_id: int, account_id: int, x_access_key: str = Header(default="")):
        """返回数据库表列表"""
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")
        _check_permission(cfg, x_access_key, instance_id, database_id, account_id)
        eng, db_name, db_type = _resolve_engine(cfg, qp, instance_id, database_id, account_id)
        from .tools.db_metadata_tool import list_tables
        return {"items": list_tables(eng, db_name, db_type)}

    @app.get("/metadata/table_info")
    def metadata_table_info(instance_id: int, database_id: int, account_id: int, table: str, x_access_key: str = Header(default="")):
        """返回表结构信息"""
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")
        _check_permission(cfg, x_access_key, instance_id, database_id, account_id)
        eng, db_name, db_type = _resolve_engine(cfg, qp, instance_id, database_id, account_id)
        from .tools.db_metadata_tool import table_info
        return table_info(eng, db_name, table, db_type)

    @app.post("/transaction/begin")
    def txn_begin(instance_id: int, database_id: int, account_id: int, txn_id: str, 
                  timeout: Optional[int] = None, x_access_key: str = Header(default="")):
        """开启事务，支持自定义超时时间
        
        Args:
            timeout: 超时时间（秒），不提供则使用默认值（300秒）
        """
        _check_permission(cfg, x_access_key, instance_id, database_id, account_id)
        eng, _, _ = _resolve_engine(cfg, qp, instance_id, database_id, account_id)
        qp.begin_transaction(eng, txn_id, timeout=timeout)
        logger.info(f"事务开启 txn={txn_id} timeout={timeout or 300}s")
        return {"ok": True, "txn_id": txn_id}

    @app.post("/transactions/commit")
    def txn_commit(txn_id: str):
        """提交事务"""
        qp.commit(txn_id)
        return {"ok": True}

    @app.post("/transactions/rollback")
    def txn_rollback(txn_id: str):
        """回滚事务"""
        qp.rollback(txn_id)
        return {"ok": True}

    @app.get("/transaction/status")
    def txn_status(txn_id: str, x_access_key: str = Header(default="")):
        """查询事务状态（增强版）"""
        return qp.txn_status(txn_id)
    
    @app.get("/transaction/list")
    def txn_list(x_access_key: str = Header(default="")):
        """列出所有活跃事务"""
        return {"transactions": qp.list_transactions()}
    
    @app.post("/transaction/cleanup")
    def txn_cleanup(x_access_key: str = Header(default="")):
        """强制清理过期事务"""
        qp._cleanup_expired_transactions()
        return {"ok": True, "message": "清理完成"}

    return app


def _resolve_engine(cfg: Config, qp: QueryProxy, instance_id: int, database_id: int, account_id: int):
    """解析并返回数据库引擎、库名和类型"""
    from sqlalchemy import Table, MetaData
    meta = MetaData()
    eng_admin = create_engine(f"sqlite:///{cfg.admin_db_path}")
    inst = Table("instances", meta, autoload_with=eng_admin)
    dbs = Table("databases", meta, autoload_with=eng_admin)
    accs = Table("accounts", meta, autoload_with=eng_admin)
    with Session(eng_admin) as s:
        ri = s.execute(select(inst).where(inst.c.id == instance_id)).mappings().first()
        rd = s.execute(select(dbs).where(dbs.c.id == database_id)).mappings().first()
        ra = s.execute(select(accs).where(accs.c.id == account_id)).mappings().first()
        if not ri or not rd or not ra:
            raise HTTPException(status_code=404, detail="实例/库/账号不存在")
        pwd = decrypt_text(ra["password_enc"], cfg.master_key)
        db_type = ri.get("db_type", "mysql")  # 获取数据库类型，默认mysql
        engine = qp.get_engine(ri["host"], int(ri["port"]), ra["username"], pwd, rd["name"], db_type)
        return engine, rd["name"], db_type

def _check_permission(cfg: Config, ak: str, instance_id: int, database_id: int, account_id: int):
    """校验访问密钥权限"""
    from sqlalchemy import Table, MetaData
    meta = MetaData()
    eng_admin = create_engine(f"sqlite:///{cfg.admin_db_path}")
    keys = Table("access_keys", meta, autoload_with=eng_admin)
    perms = Table("permissions", meta, autoload_with=eng_admin)
    with Session(eng_admin) as s:
        k = s.execute(select(keys).where(keys.c.ak == ak, keys.c.enabled == True)).mappings().first()
        if not k:
            raise HTTPException(status_code=403, detail="访问密钥不可用")
        p = s.execute(
            select(perms).where(
                perms.c.key_id == k["id"],
                perms.c.instance_id == instance_id,
                perms.c.database_id == database_id,
                perms.c.account_id == account_id,
            )
        ).mappings().first()
        if not p:
            raise HTTPException(status_code=403, detail="无权访问指定实例/库/账号")

app = create_app()
