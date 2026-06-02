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
    Table(
        "admin_users", meta,
        Column("id", Integer, primary_key=True, comment="用户ID"),
        Column("username", String(100), nullable=False, unique=True, comment="登录用户名"),
        Column("password_hash", String(255), nullable=False, comment="密码哈希值(bcrypt+pepper)"),
        Column("email", String(255), nullable=True, comment="邮箱地址"),
        Column("role", String(20), nullable=False, server_default="user",
               index=True, comment="用户角色: admin=管理员, user=普通用户"),
        Column("is_active", Boolean, default=True, index=True, comment="账号是否启用"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
        Column("updated_at", DateTime(timezone=True), onupdate=func.now(), comment="最后更新时间"),
    )

    # 访问密钥表
    Table(
        "access_keys", meta,
        Column("id", Integer, primary_key=True, comment="密钥ID"),
        Column("ak", String(128), nullable=False, unique=True, comment="访问密钥(Access Key)"),
        Column("description", String(255), nullable=True, comment="密钥描述"),
        Column("enabled", Boolean, default=True, index=True, comment="是否启用"),
        Column("sql_risk_check_enabled", Boolean, default=True, index=True, comment="是否启用SQL风险监测"),
        Column("created_by", Integer, ForeignKey("admin_users.id"), nullable=True, index=True, comment="创建者用户ID"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
    )

    # 数据库连接表 (包含实例、库名、账号、加密密码)
    Table(
        "db_connections", meta,
        Column("id", Integer, primary_key=True, comment="连接ID"),
        Column("name", String(100), nullable=False, unique=True, comment="连接名称(唯一标识)"),
        Column("host", String(255), nullable=False, comment="数据库主机地址"),
        Column("port", Integer, nullable=False, comment="数据库端口"),
        Column("db_type", String(20), nullable=False, server_default="mysql",
               index=True, comment="数据库类型: mysql/postgresql等"),
        Column("database", String(255), nullable=False, comment="数据库名"),
        Column("username", String(255), nullable=False, comment="数据库用户名"),
        Column("password_enc", Text, nullable=False, comment="加密存储的密码"),
        Column("description", String(255), nullable=True, comment="连接描述"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
    )

    # 权限表 (关联到 db_connections)
    Table(
        "permissions", meta,
        Column("id", Integer, primary_key=True, comment="权限ID"),
        Column("key_id", Integer, ForeignKey("access_keys.id"), nullable=False, index=True, comment="访问密钥ID"),
        Column("connection_id", Integer, ForeignKey("db_connections.id", ondelete="CASCADE"),
               nullable=False, index=True, comment="数据库连接ID"),
        Column("select_only", Boolean, default=True, comment="是否仅查询权限(SELECT)"),
        Column("allow_ddl", Boolean, default=False, comment="是否允许DDL操作(CREATE/DROP/ALTER)"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
    )

    # IP白名单表（绑定到access_key）
    Table(
        "whitelist", meta,
        Column("id", Integer, primary_key=True, comment="白名单ID"),
        Column("key_id", Integer, ForeignKey("access_keys.id"), nullable=False, index=True, comment="访问密钥ID"),
        Column("cidr", String(64), nullable=False, comment="IP地址或CIDR网段"),
        Column("description", String(255), nullable=True, comment="白名单描述"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
    )

    # 审计日志表
    Table(
        "audit_logs", meta,
        Column("id", BigInteger, primary_key=True, comment="日志ID"),
        Column("timestamp", DateTime(timezone=True), server_default=func.now(), index=True, comment="操作时间"),
        Column("access_key", String(128), nullable=True, index=True, comment="访问密钥"),
        Column("client_ip", String(45), nullable=True, index=True, comment="客户端IP地址"),
        Column("connection_id", Integer, ForeignKey("db_connections.id", ondelete="SET NULL"),
               nullable=True, index=True, comment="数据库连接ID"),
        Column("operation", String(50), nullable=False, index=True, comment="操作类型: query/transaction/metadata"),
        Column("sql_text", Text, nullable=True, comment="执行的SQL语句"),
        Column("rows_affected", Integer, nullable=True, comment="影响行数"),
        Column("duration_ms", Integer, nullable=True, comment="执行耗时(毫秒)"),
        Column("status", String(20), nullable=False, index=True, comment="执行状态: success/error"),
        Column("error_message", Text, nullable=True, comment="错误信息"),
        Column("metadata", JSON, nullable=True, comment="额外元数据信息"),
    )

    # 系统操作日志表
    Table(
        "system_logs", meta,
        Column("id", BigInteger, primary_key=True, comment="日志ID"),
        Column("timestamp", DateTime(timezone=True), server_default=func.now(), index=True, comment="操作时间"),
        Column("user_id", Integer, ForeignKey("admin_users.id"), nullable=True, index=True, comment="操作用户ID"),
        Column("username", String(100), nullable=True, comment="操作用户名"),
        Column("operation", String(50), nullable=False, index=True, comment="操作类型: create_key/delete_key/create_user等"),
        Column("resource_type", String(50), nullable=False, index=True,
               comment="资源类型: access_key/permission/whitelist/connection/admin_user"),
        Column("resource_id", Integer, nullable=True, comment="资源ID"),
        Column("details", JSON, nullable=True, comment="操作详情(JSON格式)"),
        Column("client_ip", String(45), nullable=True, comment="客户端IP地址"),
    )

    # 会话表（用于JWT认证的可选黑名单）
    Table(
        "sessions", meta,
        Column("id", Integer, primary_key=True, comment="会话ID"),
        Column("user_id", Integer, ForeignKey("admin_users.id"), nullable=False, index=True, comment="用户ID"),
        Column("token_jti", String(255), nullable=False, unique=True, index=True, comment="JWT Token唯一标识"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
        Column("expires_at", DateTime(timezone=True), nullable=False, index=True, comment="过期时间"),
        Column("revoked", Boolean, default=False, index=True, comment="是否已撤销"),
    )

    # 访问密钥用户关联表（多对多关系）
    Table(
        "access_key_users", meta,
        Column("id", Integer, primary_key=True, comment="关联ID"),
        Column("key_id", Integer, ForeignKey("access_keys.id", ondelete="CASCADE"),
               nullable=False, index=True, comment="访问密钥ID"),
        Column("user_id", Integer, ForeignKey("admin_users.id", ondelete="CASCADE"),
               nullable=False, index=True, comment="用户ID"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="分配时间"),
    )

    # 数据库规则文档表
    Table(
        "db_rules", meta,
        Column("id", Integer, primary_key=True, comment="规则ID"),
        Column("connection_id", Integer, ForeignKey("db_connections.id", ondelete="CASCADE"),
               nullable=False, index=True, comment="数据库连接ID"),
        Column("database", String(255), nullable=False, index=True, comment="数据库名"),
        Column("version", String(50), nullable=True, comment="规则版本"),
        Column("title", String(255), nullable=True, comment="规则标题"),
        Column("rule_md", Text, nullable=False, comment="规则 Markdown 内容"),
        Column("tags", JSON, nullable=True, comment="标签"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
        Column("updated_at", DateTime(timezone=True), onupdate=func.now(), comment="最后更新时间"),
        Column("active", Boolean, server_default="true", index=True, comment="是否生效"),
    )

    # 大模型配置表
    Table(
        "llm_configs", meta,
        Column("id", Integer, primary_key=True, comment="配置ID"),
        Column("provider", String(50), nullable=False, unique=True, comment="提供商: openai/claude/deepseek等"),
        Column("base_url", String(255), nullable=True, comment="API Base URL"),
        Column("api_key_enc", Text, nullable=True, comment="加密存储的API Key"),
        Column("model_name", String(100), nullable=False,
               comment="模型名称(如gpt-4o, claude-3-5-sonnet-20241022, deepseek-coder)"),
        Column("is_active", Boolean, default=False, comment="是否当前激活使用(原则上全局激活一个)"),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), comment="创建时间"),
        Column("updated_at", DateTime(timezone=True), onupdate=func.now(), comment="最后更新时间"),
    )

    # 大模型调用日志（Token 消耗、访问密钥、调用来源）
    Table(
        "llm_call_logs", meta,
        Column("id", BigInteger, primary_key=True, comment="日志ID"),
        Column("timestamp", DateTime(timezone=True), server_default=func.now(), index=True, comment="调用时间"),
        Column("llm_config_id", Integer, ForeignKey("llm_configs.id", ondelete="SET NULL"),
               nullable=True, index=True, comment="当时激活的配置ID"),
        Column("provider", String(50), nullable=False, index=True, comment="提供商"),
        Column("model_name", String(100), nullable=False, comment="模型名称"),
        Column("access_key", String(128), nullable=True, index=True, comment="MCP 访问密钥(若有)"),
        Column("call_source", String(64), nullable=False, server_default="internal",
               index=True, comment="调用来源: mcp / tool / internal"),
        Column("tool_name", String(100), nullable=True, index=True, comment="工具名或 MCP 方法"),
        Column("connection_id", Integer, nullable=True, index=True, comment="关联的数据库连接ID"),
        Column("prompt_tokens", Integer, nullable=False, server_default="0", comment="输入 Token"),
        Column("completion_tokens", Integer, nullable=False, server_default="0", comment="输出 Token"),
        Column("total_tokens", Integer, nullable=False, server_default="0", index=True, comment="总 Token"),
        Column("duration_ms", Integer, nullable=True, comment="调用耗时(毫秒)"),
        Column("status", String(20), nullable=False, index=True, comment="success / error"),
        Column("error_message", Text, nullable=True, comment="失败原因"),
    )

    # 创建所有表
    meta.create_all(engine)

    from sqlalchemy import inspect, text
    insp = inspect(engine)
    cols = {c["name"] for c in insp.get_columns("access_keys")}
    if "sql_risk_check_enabled" not in cols:
        with engine.connect() as conn:
            conn.execute(
                text(
                    "ALTER TABLE access_keys "
                    "ADD COLUMN IF NOT EXISTS sql_risk_check_enabled BOOLEAN DEFAULT TRUE"
                )
            )
            conn.commit()


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
                    role="admin",  # 设置为管理员角色
                    is_active=True
                )
            )
            session.commit()
            print(f"✅ 创建默认管理员: {username}")
        else:
            print(f"⚠️ 管理员已存在: {username}")


def initialize_default_llm_configs(engine: Engine):
    """初始化默认的大模型提供商配置"""
    from sqlalchemy import Table, MetaData, select, insert
    from sqlalchemy.orm import Session

    meta = MetaData()
    llm_configs = Table("llm_configs", meta, autoload_with=engine)

    defaults = [
        {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model_name": "gpt-4o",
            "is_active": False
        },
        {
            "provider": "claude",
            "base_url": "https://api.anthropic.com",
            "model_name": "claude-3-5-sonnet-20241022",
            "is_active": False
        },
        {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com",
            "model_name": "deepseek-coder",
            "is_active": False
        }
    ]

    with Session(engine) as session:
        for default in defaults:
            existing = session.execute(
                select(llm_configs).where(llm_configs.c.provider == default["provider"])
            ).first()

            if not existing:
                session.execute(insert(llm_configs).values(**default))
                print(f"✅ 创建默认 LLM 配置: {default['provider']}")
        session.commit()
