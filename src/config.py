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
        
        return Config(
            server=ServerConfig(**data['server']),
            security=SecurityConfig(**data['security']),
            admin_database=AdminDatabaseConfig(**data['admin_database']),
            database=DatabaseConfig(**data['database']),
            logging=LoggingConfig(**data['logging'])
        )

    
    def get_admin_db_url(self) -> str:
        """获取管理数据库连接URL"""
        db = self.admin_database
        return f"postgresql+psycopg2://{db.username}:{db.password}@{db.host}:{db.port}/{db.database}"

