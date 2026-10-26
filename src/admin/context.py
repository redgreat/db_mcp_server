"""管理后台共享上下文：初始化管理库连接、认证服务、日志器等跨路由依赖。

各子路由模块（src/admin/routes/*.py）通过 AdminContext 获取共享资源，
避免在 build_admin_router 中通过闭包传递。
"""
import logging
import secrets
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine, URL
from sqlalchemy.orm import Session

from ..config import Config
from ..db.db_operations import normalize_host_port
from ..logging.system_logger import SystemLogger
from ..logging_utils import get_logger
from ..security.client_ip import get_real_client_ip
from ..security.ip_whitelist import IPWhitelistChecker
from .auth import AuthService
from .models import ensure_schema
from .schema_cache import AdminTables, get_admin_tables


def generate_access_key() -> str:
    """生成随机访问密钥（32 位十六进制）"""
    return secrets.token_hex(16)


def build_database_url(
    db_type: str, host: str, port: int, database: str,
    username: str, password: str,
) -> URL:
    """按数据库类型构建 SQLAlchemy 连接 URL"""
    host, port = normalize_host_port(host, port)
    db_type_lower = (db_type or "").lower()
    if db_type_lower in ("mysql", "mariadb"):
        drivername = "mysql+pymysql"
    elif db_type_lower in ("postgresql", "postgres"):
        drivername = "postgresql+psycopg2"
    elif db_type_lower in ("mssql", "sqlserver"):
        drivername = "mssql+pymssql"
    else:
        raise HTTPException(status_code=400, detail="不支持的数据库类型")

    return URL.create(
        drivername=drivername,
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
    )


def database_connect_args(db_type: str) -> dict:
    """按数据库类型返回连接超时参数"""
    db_type_lower = (db_type or "").lower()
    if db_type_lower in ("mysql", "mariadb"):
        return {"connect_timeout": 5}
    if db_type_lower in ("postgresql", "postgres"):
        return {"connect_timeout": 5}
    if db_type_lower in ("mssql", "sqlserver"):
        return {"login_timeout": 5, "timeout": 5}
    return {}


def test_database_connection(
    db_type: str,
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
) -> None:
    """创建临时 engine 执行 SELECT 1 验证连通性，用完即销毁"""
    host, port = normalize_host_port(host, port)
    test_engine = create_engine(
        build_database_url(db_type, host, port, database, username, password),
        pool_pre_ping=True,
        connect_args=database_connect_args(db_type),
    )
    try:
        with test_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    finally:
        test_engine.dispose()


@dataclass
class AdminContext:
    """管理后台共享资源集合：由 build_admin_router 创建一次后注入各子路由"""

    cfg: Config
    logger: logging.Logger
    engine: Engine
    tbl: AdminTables
    auth_service: AuthService
    ip_checker: IPWhitelistChecker
    system_logger: SystemLogger

    @classmethod
    def create(cls, cfg: Config) -> "AdminContext":
        """初始化管理库、表结构缓存与各共享服务"""
        logger = get_logger("admin", cfg.logging.dir)

        # 使用PostgreSQL作为管理数据库
        admin_db_url = cfg.get_admin_db_url()
        engine = create_engine(admin_db_url, pool_pre_ping=True)
        ensure_schema(engine)
        tbl = get_admin_tables(engine)

        from .llm_active import ensure_single_llm_active
        ensure_single_llm_active(engine)

        # 认证服务
        auth_service = AuthService(
            master_key=cfg.security.master_key,
            jwt_secret=cfg.security.jwt_secret,
            session_timeout=cfg.security.session_timeout
        )

        return cls(
            cfg=cfg,
            logger=logger,
            engine=engine,
            tbl=tbl,
            auth_service=auth_service,
            ip_checker=IPWhitelistChecker(engine),
            system_logger=SystemLogger(engine),
        )

    def fetch_key_descriptions(self, aks) -> dict:
        """批量查询访问密钥的描述，返回 {ak: description}（用于日志列表关联展示）"""
        aks = [a for a in aks if a]
        if not aks:
            return {}
        access_keys = self.tbl["access_keys"]
        with Session(self.engine) as s:
            rows = s.execute(
                select(access_keys.c.ak, access_keys.c.description)
                .where(access_keys.c.ak.in_(aks))
            ).all()
        return {r[0]: (r[1] or "") for r in rows}

    def log_system_op(
        self,
        operation: str,
        resource_type: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        resource_id: Optional[int] = None,
        details: Optional[dict] = None,
        request: Optional[Request] = None,
    ) -> None:
        """记录系统操作日志（自动提取客户端 IP，日志失败不影响主流程）"""
        try:
            ip = get_real_client_ip(request) if request is not None else None
        except Exception:
            ip = None
        try:
            self.system_logger.log(
                operation=operation,
                resource_type=resource_type,
                user_id=user_id,
                username=username,
                resource_id=resource_id,
                details=details,
                client_ip=ip,
            )
        except Exception as e:  # noqa: BLE001
            self.logger.warning("系统操作日志写入失败: %s", e)
