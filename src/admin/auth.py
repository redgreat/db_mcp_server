"""
认证相关工具
"""
import hmac
import hashlib
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from fastapi import HTTPException, Header


class AuthService:
    """认证服务"""
    
    def __init__(self, master_key: str, jwt_secret: str, session_timeout: int = 3600):
        """
        Args:
            master_key: 主密钥（用于密码Pepper）
            jwt_secret: JWT密钥
            session_timeout: 会话超时时间（秒）
        """
        self.master_key = master_key
        self.jwt_secret = jwt_secret
        self.session_timeout = session_timeout
    
    def _get_peppered_password(self, password: str) -> bytes:
        """使用 master_key 对密码进行 HMAC 处理"""
        return hmac.new(
            self.master_key.encode('utf-8'),
            password.encode('utf-8'),
            hashlib.sha256
        ).digest()
    
    def hash_password(self, password: str) -> str:
        """密码哈希"""
        peppered_password = self._get_peppered_password(password)
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(peppered_password, salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """验证密码"""
        peppered_password = self._get_peppered_password(password)
        return bcrypt.checkpw(peppered_password, password_hash.encode('utf-8'))
    
    def create_token(self, user_id: int, username: str) -> str:
        """创建JWT token
        
        Args:
            user_id: 用户ID
            username: 用户名
            
        Returns:
            JWT token字符串
        """
        now = datetime.utcnow()
        payload = {
            "user_id": user_id,
            "username": username,
            "iat": now,
            "exp": now + timedelta(seconds=self.session_timeout),
            "jti": f"{user_id}_{int(now.timestamp())}"
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """解码JWT token
        
        Args:
            token: JWT token字符串
            
        Returns:
            解码后的payload
            
        Raises:
            HTTPException: token无效或过期
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token已过期")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Token无效")
    
    def get_current_user(self, authorization: str = Header(None)) -> Dict[str, Any]:
        """从请求Header获取当前用户
        
        Args:
            authorization: Authorization header (Bearer token)
            
        Returns:
            用户信息字典
            
        Raises:
            HTTPException: 未认证或token无效
        """
        if not authorization:
            raise HTTPException(status_code=401, detail="未提供认证信息")
        
        # 解析 "Bearer <token>"
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="认证格式错误")
        
        token = parts[1]
        return self.decode_token(token)
