from fastapi import APIRouter, Header, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, select, insert, update, delete
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
import os
from ..config import Config
from ..logging_utils import get_logger
from .models import ensure_schema
from .auth import AuthService
from ..security.secret import encrypt_text
from ..security.ip_whitelist import IPWhitelistChecker


# 请求模型
class LoginRequest(BaseModel):
    username: str
    password: str


class CreateKeyRequest(BaseModel):
    ak: str
    description: str = ""
    enabled: bool = True


def build_admin_router(cfg: Config):
    """创建管理后台路由"""
    router = APIRouter()
    logger = get_logger("admin", cfg.logging.dir)
    
    # 使用PostgreSQL作为管理数据库
    admin_db_url = cfg.get_admin_db_url()
    engine = create_engine(admin_db_url, pool_pre_ping=True)
    ensure_schema(engine)
    
    # 认证服务
    auth_service = AuthService(
        jwt_secret=cfg.security.jwt_secret,
        session_timeout=cfg.security.session_timeout
    )
    
    # IP白名单检查器
    ip_checker = IPWhitelistChecker(engine)
    
    # ==================== 认证相关API ====================
    
    @router.post("/admin/login")
    def login(req: LoginRequest):
        """管理员登录"""
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        admin_users = Table("admin_users", meta, autoload_with=engine)
        
        with Session(engine) as session:
            user = session.execute(
                select(admin_users).where(
                    admin_users.c.username == req.username,
                    admin_users.c.is_active == True
                )
            ).mappings().first()
            
            if not user:
                raise HTTPException(status_code=401, detail="用户名或密码错误")
            
            # 验证密码
            if not auth_service.verify_password(req.password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="用户名或密码错误")
            
            # 生成token
            token = auth_service.create_token(user["id"], user["username"])
            
            logger.info(f"用户登录成功: {req.username}")
            return {
                "token": token,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"]
                }
            }
    
    @router.post("/admin/logout")
    def logout(authorization: str = Header(None)):
        """管理员登出"""
        # 简单实现：客户端删除token即可
        # 如需token黑名单，可在sessions表标记revoked=True
        return {"message": "登出成功"}
    
    @router.get("/admin/me")
    def get_current_user_info(authorization: str = Header(None)):
        """获取当前登录用户信息"""
        user_data = auth_service.get_current_user(authorization)
        return {"user": user_data}
    
    # ==================== 首页 ====================
    
    @router.get("/admin", response_class=HTMLResponse)
    def admin_index():
        """重定向到Web管理界面"""
        static_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'admin.html')
        with open(static_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
        return HTMLResponse(content=html)
    
    # ==================== 访问密钥管理 ====================
    
    @router.get("/admin/keys")
    def list_keys(authorization: str = Header(None)):
        """列出访问密钥（需要登录）"""
        auth_service.get_current_user(authorization)  # 验证登录
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        keys = Table("access_keys", meta, autoload_with=engine)
        with Session(engine) as s:
            rows = s.execute(select(keys)).mappings().all()
        return {"items": [dict(r) for r in rows]}
    
    @router.post("/admin/keys")
    def create_key(req: CreateKeyRequest, authorization: str = Header(None)):
        """创建访问密钥（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        keys = Table("access_keys", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(insert(keys).values(
                ak=req.ak,
                description=req.description,
                enabled=req.enabled,
                created_by=user_data["user_id"]
            ))
            s.commit()
        logger.info(f"创建访问密钥: {req.ak} by {user_data['username']}")
        return {"ok": True}
    
    # ==================== 实例管理 ====================
    
    @router.get("/admin/instances")
    def list_instances(authorization: str = Header(None)):
        """列出实例信息（需要登录）"""
        auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("instances", meta, autoload_with=engine)
        with Session(engine) as s:
            rows = s.execute(select(t)).mappings().all()
        return {"items": [dict(r) for r in rows]}
    
    @router.post("/admin/instances")
    def create_instance(
        name: str,
        host: str,
        port: int,
        db_type: str = "mysql",
        description: str = "",
        authorization: str = Header(None)
    ):
        """创建实例（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("instances", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(insert(t).values(
                name=name,
                host=host,
                port=port,
                db_type=db_type,
                description=description
            ))
            s.commit()
        logger.info(f"创建实例: {name} type:{db_type} by {user_data['username']}")
        return {"ok": True}
    
    # ==================== 数据库管理 ====================
    
    @router.get("/admin/databases")
    def list_databases(authorization: str = Header(None)):
        """列出数据库信息（需要登录）"""
        auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("databases", meta, autoload_with=engine)
        with Session(engine) as s:
            rows = s.execute(select(t)).mappings().all()
        return {"items": [dict(r) for r in rows]}
    
    @router.post("/admin/databases")
    def create_database(
        instance_id: int,
        name: str,
        authorization: str = Header(None)
    ):
        """创建数据库记录（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("databases", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(insert(t).values(instance_id=instance_id, name=name))
            s.commit()
        logger.info(f"创建数据库: {name} on {instance_id} by {user_data['username']}")
        return {"ok": True}
    
    # ==================== 账号管理 ====================
    
    @router.get("/admin/accounts")
    def list_accounts(authorization: str = Header(None)):
        """列出账号信息（需要登录）"""
        auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("accounts", meta, autoload_with=engine)
        with Session(engine) as s:
            rows = s.execute(select(t)).mappings().all()
        masked = []
        for r in rows:
            d = dict(r)
            d["password_enc"] = "***"
            masked.append(d)
        return {"items": masked}
    
    @router.post("/admin/accounts")
    def create_account(
        instance_id: int,
        username: str,
        password: str,
        plugin: str = "",
        authorization: str = Header(None)
    ):
        """创建账号并加密保存密码（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("accounts", meta, autoload_with=engine)
        pwd_enc = encrypt_text(password, cfg.security.master_key)
        with Session(engine) as s:
            s.execute(insert(t).values(
                instance_id=instance_id,
                username=username,
                password_enc=pwd_enc,
                plugin=plugin
            ))
            s.commit()
        logger.info(f"创建账号: {username} on {instance_id} by {user_data['username']}")
        return {"ok": True}
    
    # ==================== 审计日志查询 ====================
    
    @router.get("/admin/audit/logs")
    def query_audit_logs(
        limit: int = 100,
        offset: int = 0,
        access_key: Optional[str] = None,
        operation: Optional[str] = None,
        authorization: str = Header(None)
    ):
        """查询审计日志（需要登录）"""
        auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData, desc
        meta = MetaData()
        logs = Table("audit_logs", meta, autoload_with=engine)
        
        # 构建查询
        query = select(logs).order_by(desc(logs.c.timestamp)).limit(limit).offset(offset)
        
        # 添加过滤条件
        if access_key:
            query = query.where(logs.c.access_key == access_key)
        if operation:
            query = query.where(logs.c.operation == operation)
        
        with Session(engine) as s:
            rows = s.execute(query).mappings().all()
        
        return {"items": [dict(r) for r in rows], "total": len(rows)}
    
    # ==================== 权限管理 ====================
    
    @router.get("/admin/permissions")
    def list_permissions(authorization: str = Header(None)):
        """列出权限配置（需要登录）"""
        auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("permissions", meta, autoload_with=engine)
        with Session(engine) as s:
            rows = s.execute(select(t)).mappings().all()
        return {"items": [dict(r) for r in rows]}
    
    @router.post("/admin/permissions")
    def create_permission(
        key_id: int,
        instance_id: int,
        database_id: int,
        account_id: int,
        select_only: bool = True,
        authorization: str = Header(None)
    ):
        """创建权限（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("permissions", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(insert(t).values(
                key_id=key_id,
                instance_id=instance_id,
                database_id=database_id,
                account_id=account_id,
                select_only=select_only
            ))
            s.commit()
        logger.info(f"创建权限: key={key_id} by {user_data['username']}")
        return {"ok": True}
    
    # ==================== 白名单管理 ====================
    
    @router.get("/admin/whitelist")
    def list_whitelist(
        key_id: Optional[int] = None,
        authorization: str = Header(None)
    ):
        """列出白名单（需要登录）
        
        Args:
            key_id: 访问密钥ID（可选，不指定则返回所有）
        """
        auth_service.get_current_user(authorization)
        rules = ip_checker.list_whitelist(key_id=key_id)
        return {"items": rules}
    
    @router.post("/admin/whitelist")
    def create_whitelist(
        key_id: int,
        cidr: str,
        description: str = "",
        authorization: str = Header(None)
    ):
        """为指定APPKEY添加白名单规则（需要登录）
        
        Args:
            key_id: 访问密钥ID
            cidr: CIDR格式，如 '192.168.1.0/24' 或 '10.0.0.1'
            description: 描述
        """
        user_data = auth_service.get_current_user(authorization)
        
        success = ip_checker.add_whitelist(key_id, cidr, description)
        if not success:
            raise HTTPException(status_code=400, detail="无效的CIDR格式")
        
        logger.info(f"添加白名单: key_id={key_id} CIDR={cidr} by {user_data['username']}")
        return {"ok": True}
    
    @router.delete("/admin/whitelist/{whitelist_id}")
    def delete_whitelist(whitelist_id: int, authorization: str = Header(None)):
        """删除白名单规则（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        success = ip_checker.delete_whitelist(whitelist_id)
        if not success:
            raise HTTPException(status_code=404, detail="白名单规则不存在")
        
        logger.info(f"删除白名单: id={whitelist_id} by {user_data['username']}")
        return {"ok": True}
    
    return router
