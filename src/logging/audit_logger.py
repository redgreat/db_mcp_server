"""
审计日志服务
"""
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Table, MetaData, insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


class AuditLogger:
    """审计日志记录器"""
    
    def __init__(self, engine: Engine):
        """
        Args:
            engine: 数据库引擎
        """
        self.engine = engine
        self.meta = MetaData()
        self.audit_logs = Table("audit_logs", self.meta, autoload_with=engine)
    
    def log(
        self,
        operation: str,
        status: str,
        access_key: Optional[str] = None,
        client_ip: Optional[str] = None,
        connection_id: Optional[int] = None,
        sql_text: Optional[str] = None,
        rows_affected: Optional[int] = None,
        duration_ms: Optional[int] = None,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """记录审计日志
        
        Args:
            operation: 操作类型（query/transaction/metadata等）
            status: 状态（success/error）
            access_key: 访问密钥
            client_ip: 客户端IP
            connection_id: 数据库连接ID
            sql_text: SQL语句
            rows_affected: 影响行数
            duration_ms: 执行时长（毫秒）
            error_message: 错误信息
            metadata: 额外元数据
        """
        try:
            with Session(self.engine) as session:
                session.execute(
                    insert(self.audit_logs).values(
                        timestamp=datetime.utcnow(),
                        access_key=access_key,
                        client_ip=client_ip,
                        connection_id=connection_id,
                        operation=operation,
                        sql_text=sql_text[:1000] if sql_text else None,  # 限制长度
                        rows_affected=rows_affected,
                        duration_ms=duration_ms,
                        status=status,
                        error_message=error_message,
                        metadata=metadata
                    )
                )
                session.commit()
        except Exception as e:
            # 审计日志失败不应该影响主业务
            print(f"⚠️ 审计日志写入失败: {e}")
