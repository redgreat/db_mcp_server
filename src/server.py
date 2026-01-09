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
    
    # 静态文件目录
    static_dir = Path(__file__).resolve().parent / "static"
    
    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        fav_path = static_dir / "favicon.ico"
        if fav_path.exists():
            from fastapi.responses import FileResponse
            return FileResponse(fav_path)
        raise HTTPException(status_code=404)

    if static_dir.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
        logger.info(f"Mounted static directory: {static_dir}")
    else:
        logger.warning(f"Static directory not found: {static_dir}")
    
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
    def query(sql: str, connection_id: int, 
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
            
            _check_permission(cfg, x_access_key, connection_id)
            
            sec = intercept_sql(sql, {"key": x_access_key})
            if not sec["safe"]:
                raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
            eng, db_name, _ = _resolve_engine(cfg, qp, connection_id)
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
                connection_id=connection_id, # 更新审计日志字段
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
                connection_id=connection_id,
                sql_text=sql,
                duration_ms=duration_ms,
                error_message=str(e)
            )
            raise

    @app.get("/sse/query")
    def sse_query(sql: str, connection_id: int, x_access_key: str = Header(default="")):
        """通过SSE流式返回查询结果"""
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")
        _check_permission(cfg, x_access_key, connection_id)
        sec = intercept_sql(sql, {"key": x_access_key})
        if not sec["safe"]:
            raise HTTPException(status_code=400, detail=f"风险SQL 阈值:{sec['risk']}")
        eng, _, _ = _resolve_engine(cfg, qp, connection_id)

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
    def metadata_tables(connection_id: int, x_access_key: str = Header(default="")):
        """返回数据库表列表"""
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")
        _check_permission(cfg, x_access_key, connection_id)
        eng, db_name, db_type = _resolve_engine(cfg, qp, connection_id)
        from .tools.db_metadata_tool import list_tables
        return {"items": list_tables(eng, db_name, db_type)}

    @app.get("/metadata/table_info")
    def metadata_table_info(connection_id: int, table: str, x_access_key: str = Header(default="")):
        """返回表结构信息"""
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")
        _check_permission(cfg, x_access_key, connection_id)
        eng, db_name, db_type = _resolve_engine(cfg, qp, connection_id)
        from .tools.db_metadata_tool import table_info
        return table_info(eng, db_name, table, db_type)

    @app.post("/transaction/begin")
    def txn_begin(connection_id: int, txn_id: str, 
                  timeout: Optional[int] = None, x_access_key: str = Header(default="")):
        """开启事务"""
        _check_permission(cfg, x_access_key, connection_id)
        eng, _, _ = _resolve_engine(cfg, qp, connection_id)
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


def _resolve_engine(cfg: Config, qp: QueryProxy, connection_id: int):
    """解析并返回数据库引擎、库名和类型 (从统一连接表)"""
    from sqlalchemy import Table, MetaData
    meta = MetaData()
    # 使用 PostgreSQL 管理库
    admin_engine = create_engine(cfg.get_admin_db_url(), pool_pre_ping=True)
    conns = Table("db_connections", meta, autoload_with=admin_engine)
    
    with Session(admin_engine) as s:
        r = s.execute(select(conns).where(conns.c.id == connection_id)).mappings().first()
        if not r:
            raise HTTPException(status_code=404, detail="数据库连接记录不存在")
        
        # 解密密码 (使用 master_key)
        pwd = decrypt_text(r["password_enc"], cfg.security.master_key)
        
        engine = qp.get_engine(
            r["host"], 
            int(r["port"]), 
            r["username"], 
            pwd, 
            r["database"], 
            r["db_type"]
        )
        return engine, r["database"], r["db_type"]

def _check_permission(cfg: Config, ak: str, connection_id: int):
    """校验访问密钥对特定连接的权限"""
    from sqlalchemy import Table, MetaData
    meta = MetaData()
    admin_engine = create_engine(cfg.get_admin_db_url(), pool_pre_ping=True)
    keys = Table("access_keys", meta, autoload_with=admin_engine)
    perms = Table("permissions", meta, autoload_with=admin_engine)
    
    with Session(admin_engine) as s:
        k = s.execute(select(keys).where(keys.c.ak == ak, keys.c.enabled == True)).mappings().first()
        if not k:
            raise HTTPException(status_code=403, detail="访问密钥不可用")
        
        p = s.execute(
            select(perms).where(
                perms.c.key_id == k["id"],
                perms.c.connection_id == connection_id
            )
        ).mappings().first()
        
        if not p:
            raise HTTPException(status_code=403, detail="该密钥无权访问此数据库连接")

app = create_app()
