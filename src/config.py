import os
import yaml
from dataclasses import dataclass
from typing import Optional, Dict, Any
from pathlib import Path


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
class Config:
    """应用配置"""
    server: ServerConfig
    security: SecurityConfig
    admin_database: AdminDatabaseConfig
    database: DatabaseConfig
    logging: LoggingConfig

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
        
        # 支持环境变量覆盖
        data = Config._apply_env_overrides(data)
        
        return Config(
            server=ServerConfig(**data['server']),
            security=SecurityConfig(**data['security']),
            admin_database=AdminDatabaseConfig(**data['admin_database']),
            database=DatabaseConfig(**data['database']),
            logging=LoggingConfig(**data['logging'])
        )
    
    @staticmethod
    def _apply_env_overrides(data: Dict[str, Any]) -> Dict[str, Any]:
        """使用环境变量覆盖配置"""
        # 服务器配置
        if os.getenv("HOST"):
            data['server']['host'] = os.getenv("HOST")
        if os.getenv("PORT"):
            data['server']['port'] = int(os.getenv("PORT"))
        
        # 安全配置
        if os.getenv("MASTER_KEY"):
            data['security']['master_key'] = os.getenv("MASTER_KEY")
        if os.getenv("JWT_SECRET"):
            data['security']['jwt_secret'] = os.getenv("JWT_SECRET")
        
        # 管理数据库配置
        if os.getenv("ADMIN_DB_HOST"):
            data['admin_database']['host'] = os.getenv("ADMIN_DB_HOST")
        if os.getenv("ADMIN_DB_PORT"):
            data['admin_database']['port'] = int(os.getenv("ADMIN_DB_PORT"))
        if os.getenv("ADMIN_DB_NAME"):
            data['admin_database']['database'] = os.getenv("ADMIN_DB_NAME")
        if os.getenv("ADMIN_DB_USER"):
            data['admin_database']['username'] = os.getenv("ADMIN_DB_USER")
        if os.getenv("ADMIN_DB_PASSWORD"):
            data['admin_database']['password'] = os.getenv("ADMIN_DB_PASSWORD")
        
        # 日志配置
        if os.getenv("LOG_DIR"):
            data['logging']['dir'] = os.getenv("LOG_DIR")
        
        return data
    
    def get_admin_db_url(self) -> str:
        """获取管理数据库连接URL"""
        db = self.admin_database
        return f"postgresql+psycopg2://{db.username}:{db.password}@{db.host}:{db.port}/{db.database}"

