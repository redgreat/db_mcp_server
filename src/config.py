import os
import yaml
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServerConfig:
    """服务器配置"""
    host: str
    port: int


@dataclass
class SecurityConfig:
    """安全配置"""
    master_key: str
    jwt_secret: str
    session_timeout: int


@dataclass
class AdminDatabaseConfig:
    """管理数据库配置（PostgreSQL）"""
    host: str
    port: int
    database: str
    username: str
    password: str
    sslmode: str = "disable"
    timezone: str = "Asia/Shanghai"
    pool_size: int = 10
    max_overflow: int = 20


@dataclass
class DatabaseConfig:
    """数据库连接池配置"""
    pool_enabled: bool
    pool_min_size: int
    pool_max_size: int
    pool_recycle: int
    pool_max_lifetime: int
    connection_timeout: int


@dataclass
class LoggingConfig:
    """日志配置"""
    level: str
    dir: str
    audit_to_database: bool
    audit_to_file: bool


@dataclass
class ObjectStorageConfig:
    provider: str
    endpoint: Optional[str] = None
    bucket: Optional[str] = None
    access_key_id: Optional[str] = None
    access_key_secret: Optional[str] = None
    region: Optional[str] = None
    path_prefix: Optional[str] = None
    public_base_url: Optional[str] = None
    enabled: bool = False


@dataclass
class Config:
    """应用配置"""
    server: ServerConfig
    security: SecurityConfig
    admin_database: AdminDatabaseConfig
    database: DatabaseConfig
    logging: LoggingConfig
    object_storage: Optional[ObjectStorageConfig] = None

    @staticmethod
    def load(config_path: Optional[str] = None) -> "Config":
        """加载配置文件

        Args:
            config_path: 配置文件路径，默认为 config/config.yml

        Returns:
            Config实例
        """
        if config_path is None:
            config_path = os.getenv("CONFIG_PATH", "config/config.yml")

        if not os.path.exists(config_path):
            raise FileNotFoundError(
                f"配置文件不存在: {config_path}\n"
                f"请复制 config/config.yml.example 到 config/config.yml 并修改配置"
            )

        # 从YAML加载
        with open(config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        cfg = Config(
            server=ServerConfig(**data['server']),
            security=SecurityConfig(**data['security']),
            admin_database=AdminDatabaseConfig(**data['admin_database']),
            database=DatabaseConfig(**data['database']),
            logging=LoggingConfig(**data['logging'])
        )
        if 'object_storage' in data and data['object_storage']:
            cfg.object_storage = ObjectStorageConfig(**data['object_storage'])
        return cfg

    def get_admin_db_url(self) -> str:
        """获取管理数据库连接URL"""
        db = self.admin_database
        url = f"postgresql+psycopg2://{db.username}:{db.password}@{db.host}:{db.port}/{db.database}"
        if db.sslmode:
            url += f"?sslmode={db.sslmode}"
        return url
