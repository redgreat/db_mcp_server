"""
APPKEY级别的IP白名单检查模块
"""
import ipaddress
from typing import Optional, List
from sqlalchemy import Table, MetaData, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


class IPWhitelistChecker:
    """IP白名单检查器（APPKEY级别）"""
    
    def __init__(self, engine: Engine):
        """
        Args:
            engine: 管理数据库引擎
        """
        self.engine = engine
        self.meta = MetaData()
        self.whitelist = Table("whitelist", self.meta, autoload_with=engine)
        self.access_keys = Table("access_keys", self.meta, autoload_with=engine)
    
    def check_access(self, client_ip: str, access_key: str) -> bool:
        """检查客户端IP是否在指定APPKEY的白名单中
        
        Args:
            client_ip: 客户端IP地址
            access_key: 访问密钥（APPKEY）
            
        Returns:
            True表示允许访问，False表示拒绝
        """
        if not client_ip or not access_key:
            return False
        
        try:
            client_ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            # 无效的IP地址
            return False
        
        with Session(self.engine) as session:
            # 先查找access_key对应的key_id
            key_row = session.execute(
                select(self.access_keys.c.id).where(
                    self.access_keys.c.ak == access_key
                )
            ).first()
            
            if not key_row:
                # APPKEY不存在
                return False
            
            key_id = key_row[0]
            
            # 查询该APPKEY的白名单规则
            rules = session.execute(
                select(self.whitelist).where(
                    self.whitelist.c.key_id == key_id
                )
            ).mappings().all()
            
            # 如果该APPKEY没有配置白名单，则允许访问
            if not rules:
                return True
            
            # 检查是否匹配任何一条规则
            for rule in rules:
                try:
                    network = ipaddress.ip_network(rule['cidr'], strict=False)
                    if client_ip_obj in network:
                        return True
                except ValueError:
                    # 忽略无效的CIDR
                    continue
            
            # 没有匹配的规则，拒绝访问
            return False
    
    def add_whitelist(
        self,
        key_id: int,
        cidr: str,
        description: Optional[str] = None
    ) -> bool:
        """为指定APPKEY添加白名单规则
        
        Args:
            key_id: 访问密钥ID
            cidr: CIDR格式的IP或网段，如 '192.168.1.0/24' 或 '10.0.0.1'
            description: 描述
            
        Returns:
            True表示添加成功
        """
        try:
            # 验证CIDR格式
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        
        from sqlalchemy import insert
        with Session(self.engine) as session:
            session.execute(
                insert(self.whitelist).values(
                    key_id=key_id,
                    cidr=cidr,
                    description=description
                )
            )
            session.commit()
        return True
    
    def list_whitelist(self, key_id: Optional[int] = None) -> List[dict]:
        """列出白名单规则
        
        Args:
            key_id: 如果指定，只返回该APPKEY的白名单；否则返回所有
        """
        with Session(self.engine) as session:
            query = select(self.whitelist)
            if key_id is not None:
                query = query.where(self.whitelist.c.key_id == key_id)
            
            rows = session.execute(query).mappings().all()
            return [dict(r) for r in rows]
    
    def delete_whitelist(self, whitelist_id: int) -> bool:
        """删除白名单规则"""
        from sqlalchemy import delete
        with Session(self.engine) as session:
            result = session.execute(
                delete(self.whitelist).where(self.whitelist.c.id == whitelist_id)
            )
            session.commit()
            return result.rowcount > 0
    
    def get_whitelist_count(self, key_id: int) -> int:
        """获取指定APPKEY的白名单规则数量"""
        from sqlalchemy import func
        with Session(self.engine) as session:
            count = session.execute(
                select(func.count()).select_from(self.whitelist).where(
                    self.whitelist.c.key_id == key_id
                )
            ).scalar()
            return count or 0
