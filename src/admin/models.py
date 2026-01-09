from sqlalchemy import (
    Table, Column, Integer, String, Boolean, ForeignKey, MetaData, 
    Text, DateTime, BigInteger, JSON
)
from sqlalchemy.engine import Engine
from sqlalchemy.sql import func


def ensure_schema(engine: Engine):
    """初始化管理数据库表结构（PostgreSQL）"""
    meta = MetaData()
    
    # 用户表（Web管理端登录）
    admin_users = Table(
        "admin_users", meta,
        Column("id", Integer, primary_key=True),
        Column("username", String(100), nullable=False, unique=True),
        Column("password_hash", String(255), nullable=False),
        Column("email", String(255), nullable=True),
        Column("is_active", Boolean, default=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), onupdate=func.now()),
    )
    
    # 访问密钥表
    access_keys = Table(
        "access_keys", meta,
        Column("id", Integer, primary_key=True),
        Column("ak", String(128), nullable=False, unique=True),
        Column("description", String(255), nullable=True),
        Column("enabled", Boolean, default=True),
        Column("created_by", Integer, ForeignKey("admin_users.id"), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )
    
    # 数据库连接表 (包含实例、库名、账号、加密密码)
    db_connections = Table(
        "db_connections", meta,
        Column("id", Integer, primary_key=True),
        Column("name", String(100), nullable=False, unique=True), # 连接名称
        Column("host", String(255), nullable=False),
        Column("port", Integer, nullable=False),
        Column("db_type", String(20), nullable=False, server_default="mysql"),
        Column("database", String(255), nullable=False), # 数据库名
        Column("username", String(255), nullable=False),
        Column("password_enc", Text, nullable=False),    # 加密存储的密码
        Column("description", String(255), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )
    
    # 权限表 (关联到 db_connections)
    permissions = Table(
        "permissions", meta,
        Column("id", Integer, primary_key=True),
        Column("key_id", Integer, ForeignKey("access_keys.id"), nullable=False),
        Column("connection_id", Integer, ForeignKey("db_connections.id"), nullable=False),
        Column("select_only", Boolean, default=True),
        Column("allow_ddl", Boolean, default=False),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )
    
    # IP白名单表（绑定到access_key）
    whitelist = Table(
        "whitelist", meta,
        Column("id", Integer, primary_key=True),
        Column("key_id", Integer, ForeignKey("access_keys.id"), nullable=False),  # 关联到访问密钥
        Column("cidr", String(64), nullable=False),  # CIDR格式的IP或网段
        Column("description", String(255), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )
    
    # 审计日志表
    audit_logs = Table(
        "audit_logs", meta,
        Column("id", BigInteger, primary_key=True),
        Column("timestamp", DateTime(timezone=True), server_default=func.now(), index=True),
        Column("access_key", String(128), nullable=True, index=True),
        Column("client_ip", String(45), nullable=True),
        Column("connection_id", Integer, ForeignKey("db_connections.id"), nullable=True),
        Column("operation", String(50), nullable=False),  # query/transaction/metadata
        Column("sql_text", Text, nullable=True),
        Column("rows_affected", Integer, nullable=True),
        Column("duration_ms", Integer, nullable=True),
        Column("status", String(20), nullable=False),  # success/error
        Column("error_message", Text, nullable=True),
        Column("metadata", JSON, nullable=True),  # 额外信息
    )
    
    # 系统操作日志表
    system_logs = Table(
        "system_logs", meta,
        Column("id", BigInteger, primary_key=True),
        Column("timestamp", DateTime(timezone=True), server_default=func.now(), index=True),
        Column("user_id", Integer, ForeignKey("admin_users.id"), nullable=True),
        Column("username", String(100), nullable=True),
        Column("operation", String(50), nullable=False, index=True),  # create_key/delete_key等
        Column("resource_type", String(50), nullable=False, index=True),  # access_key/permission/whitelist/connection
        Column("resource_id", Integer, nullable=True),
        Column("details", JSON, nullable=True),  # 操作详情
        Column("client_ip", String(45), nullable=True),
    )
    
    # 会话表（用于JWT认证的可选黑名单）
    sessions = Table(
        "sessions", meta,
        Column("id", Integer, primary_key=True),
        Column("user_id", Integer, ForeignKey("admin_users.id"), nullable=False),
        Column("token_jti", String(255), nullable=False, unique=True, index=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("revoked", Boolean, default=False),
    )
    
    # 创建所有表
    meta.create_all(engine)


def create_default_admin(engine: Engine, master_key: str = None, username: str = "admin", password: str = "admin123"):
    """创建默认管理员账号
    
    Args:
        engine: 数据库引擎
        master_key: 主密钥 (Pepper)
        username: 管理员用户名
        password: 管理员密码
    """
    from sqlalchemy import Table, MetaData, select, insert
    from sqlalchemy.orm import Session
    import bcrypt
    import hmac
    import hashlib
    
    # 如果没传 master_key，尝试从配置加载
    if master_key is None:
        try:
            from ..config import Config
            cfg = Config.load()
            master_key = cfg.security.master_key
        except Exception:
            # 如果加载配置失败，则无法进行加密
            raise ValueError("无法获取 master_key，密码加盐失败")
            
    meta = MetaData()
    admin_users = Table("admin_users", meta, autoload_with=engine)
    
    with Session(engine) as session:
        # 检查是否已存在管理员
        existing = session.execute(
            select(admin_users).where(admin_users.c.username == username)
        ).first()
        
        if not existing:
            # 使用 master_key 处理密码 (Pepper)
            peppered_password = hmac.new(
                master_key.encode('utf-8'),
                password.encode('utf-8'),
                hashlib.sha256
            ).digest()
            
            # 创建默认管理员
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(peppered_password, salt)
            password_hash = hashed.decode('utf-8')
            
            session.execute(
                insert(admin_users).values(
                    username=username,
                    password_hash=password_hash,
                    email=f"{username}@localhost",
                    is_active=True
                )
            )
            session.commit()
            print(f"✅ 创建默认管理员: {username}")
        else:
            print(f"⚠️ 管理员已存在: {username}")
