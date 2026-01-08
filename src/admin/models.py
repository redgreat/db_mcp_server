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
    
    # 实例表
    instances = Table(
        "instances", meta,
        Column("id", Integer, primary_key=True),
        Column("name", String(100), nullable=False, unique=True),
        Column("host", String(255), nullable=False),
        Column("port", Integer, nullable=False),
        Column("db_type", String(20), nullable=False, server_default="mysql"),
        Column("description", String(255), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )
    
    # 数据库表
    databases = Table(
        "databases", meta,
        Column("id", Integer, primary_key=True),
        Column("instance_id", Integer, ForeignKey("instances.id"), nullable=False),
        Column("name", String(255), nullable=False),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )
    
    # 账号表
    accounts = Table(
        "accounts", meta,
        Column("id", Integer, primary_key=True),
        Column("instance_id", Integer, ForeignKey("instances.id"), nullable=False),
        Column("username", String(255), nullable=False),
        Column("password_enc", Text, nullable=False),
        Column("plugin", String(64), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )
    
    # 权限表
    permissions = Table(
        "permissions", meta,
        Column("id", Integer, primary_key=True),
        Column("key_id", Integer, ForeignKey("access_keys.id"), nullable=False),
        Column("instance_id", Integer, ForeignKey("instances.id"), nullable=False),
        Column("database_id", Integer, ForeignKey("databases.id"), nullable=False),
        Column("account_id", Integer, ForeignKey("accounts.id"), nullable=False),
        Column("select_only", Boolean, default=True),
        Column("allow_ddl", Boolean, default=False),  # 是否允许DDL操作
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
    
    # 审计日志表（新增）
    audit_logs = Table(
        "audit_logs", meta,
        Column("id", BigInteger, primary_key=True),
        Column("timestamp", DateTime(timezone=True), server_default=func.now(), index=True),
        Column("access_key", String(128), nullable=True, index=True),
        Column("client_ip", String(45), nullable=True),
        Column("instance_id", Integer, nullable=True),
        Column("database_id", Integer, nullable=True),
        Column("account_id", Integer, nullable=True),
        Column("operation", String(50), nullable=False),  # query/transaction/metadata
        Column("sql_text", Text, nullable=True),
        Column("rows_affected", Integer, nullable=True),
        Column("duration_ms", Integer, nullable=True),
        Column("status", String(20), nullable=False),  # success/error
        Column("error_message", Text, nullable=True),
        Column("metadata", JSON, nullable=True),  # 额外信息
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


def create_default_admin(engine: Engine, username: str = "admin", password: str = "admin123"):
    """创建默认管理员账号
    
    Args:
        engine: 数据库引擎
        username: 管理员用户名
        password: 管理员密码
    """
    from sqlalchemy import Table, MetaData, select, insert
    from sqlalchemy.orm import Session
    from passlib.hash import bcrypt
    
    meta = MetaData()
    admin_users = Table("admin_users", meta, autoload_with=engine)
    
    with Session(engine) as session:
        # 检查是否已存在管理员
        existing = session.execute(
            select(admin_users).where(admin_users.c.username == username)
        ).first()
        
        if not existing:
            # 创建默认管理员
            password_hash = bcrypt.hash(password)
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
