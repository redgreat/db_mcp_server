"""
MCP权限检查模块
"""
from sqlalchemy import Table, MetaData, select, and_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from fastapi import HTTPException


class MCPPermissionChecker:
    """MCP权限检查器"""
    
    def __init__(self, engine: Engine):
        self.engine = engine
        self.meta = MetaData()
        self.access_keys = Table("access_keys", self.meta, autoload_with=engine)
        self.permissions = Table("permissions", self.meta, autoload_with=engine)
    
    def check_permission(
        self,
        access_key: str,
        instance_id: int,
        database_id: int,
        account_id: int,
        require_ddl: bool = False
    ) -> dict:
        """检查MCP调用权限
        
        Args:
            access_key: 访问密钥
            instance_id: 实例ID
            database_id: 数据库ID
            account_id: 账号ID
            require_ddl: 是否需要DDL权限
            
        Returns:
            权限信息字典
            
        Raises:
            HTTPException: 权限不足
        """
        with Session(self.engine) as session:
            # 查找access_key
            key_row = session.execute(
                select(self.access_keys).where(
                    self.access_keys.c.ak == access_key,
                    self.access_keys.c.enabled == True
                )
            ).mappings().first()
            
            if not key_row:
                raise HTTPException(status_code=401, detail="无效或已禁用的访问密钥")
            
            key_id = key_row['id']
            
            # 查找权限
            perm = session.execute(
                select(self.permissions).where(
                    and_(
                        self.permissions.c.key_id == key_id,
                        self.permissions.c.instance_id == instance_id,
                        self.permissions.c.database_id == database_id,
                        self.permissions.c.account_id == account_id
                    )
                )
            ).mappings().first()
            
            if not perm:
                raise HTTPException(
                    status_code=403,
                    detail=f"访问密钥无权访问实例{instance_id}/数据库{database_id}/账号{account_id}"
                )
            
            # 检查DDL权限
            if require_ddl and not perm['allow_ddl']:
                raise HTTPException(
                    status_code=403,
                    detail="该访问密钥无DDL权限，不能执行CREATE/DROP/ALTER等操作"
                )
            
            return dict(perm)
    
    def is_ddl_sql(self, sql: str) -> bool:
        """判断SQL是否为DDL语句"""
        sql_upper = sql.strip().upper()
        ddl_keywords = ['CREATE', 'DROP', 'ALTER', 'TRUNCATE', 'RENAME']
        
        for keyword in ddl_keywords:
            if sql_upper.startswith(keyword):
                return True
        
        return False
