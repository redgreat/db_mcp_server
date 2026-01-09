"""
系统操作日志服务
"""
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Table, MetaData, insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


class SystemLogger:
    """系统操作日志记录器"""
    
    def __init__(self, engine: Engine):
        """
        Args:
            engine: 数据库引擎
        """
        self.engine = engine
        self.meta = MetaData()
        self.system_logs = Table("system_logs", self.meta, autoload_with=engine)
    
    def log(
        self,
        operation: str,
        resource_type: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        resource_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None
    ):
        """记录系统操作日志
        
        Args:
            operation: 操作类型（create_key/delete_key/assign_permission等）
            resource_type: 资源类型（access_key/permission/whitelist/connection）
            user_id: 操作用户ID
            username: 操作用户名
            resource_id: 资源ID
            details: 操作详情（JSON格式）
            client_ip: 客户端IP
        """
        try:
            with Session(self.engine) as session:
                session.execute(
                    insert(self.system_logs).values(
                        timestamp=datetime.utcnow(),
                        user_id=user_id,
                        username=username,
                        operation=operation,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        details=details,
                        client_ip=client_ip
                    )
                )
                session.commit()
        except Exception as e:
            # 系统日志失败不应该影响主业务
            print(f"⚠️ 系统日志写入失败: {e}")
