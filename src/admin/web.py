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
        master_key=cfg.security.master_key,
        jwt_secret=cfg.security.jwt_secret,
        session_timeout=cfg.security.session_timeout
    )
    
    # IP白名单检查器
    ip_checker = IPWhitelistChecker(engine)
    
    # 初始化数据脱敏器
    # data_masker = DataMasker(enabled=True) # Not defined yet, commenting out for now
    
    # 初始化系统操作日志记录器
    from ..logging.system_logger import SystemLogger
    system_logger = SystemLogger(engine)
    
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
    def list_keys(
        page: int = 1,
        page_size: int = 10,
        authorization: str = Header(None)
    ):
        """列出访问密钥（需要登录，支持分页）"""
        auth_service.get_current_user(authorization)  # 验证登录
        
        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size
        
        from sqlalchemy import Table, MetaData, func
        meta = MetaData()
        keys = Table("access_keys", meta, autoload_with=engine)
        with Session(engine) as s:
            # 获取总数
            total = s.execute(select(func.count()).select_from(keys)).scalar()
            
            # 分页查询
            rows = s.execute(
                select(keys).offset(offset).limit(page_size)
            ).mappings().all()
            
        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size
        }
    
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
        
        # 记录系统日志
        system_logger.log(
            operation="create_key",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={"ak": req.ak, "description": req.description}
        )
        
        logger.info(f"创建访问密钥: {req.ak} by {user_data['username']}")
        return {"ok": True}
    
    @router.patch("/admin/keys/{key_id}/toggle")
    async def toggle_key_status(
        key_id: int,
        request: Request,
        authorization: str = Header(None)
    ):
        """切换访问密钥状态（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        # 从请求体获取 enabled 参数
        body = await request.json()
        enabled = body.get('enabled', True)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        keys = Table("access_keys", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(
                update(keys)
                .where(keys.c.id == key_id)
                .values(enabled=enabled)
            )
            s.commit()
        
        # 记录系统日志
        system_logger.log(
            operation="toggle_key",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=key_id,
            details={"enabled": enabled}
        )
        
        logger.info(f"切换密钥状态: id={key_id} enabled={enabled} by {user_data['username']}")
        return {"ok": True}
    
    @router.delete("/admin/keys/{key_id}")
    def delete_key(key_id: int, authorization: str = Header(None)):
        """删除访问密钥（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        keys = Table("access_keys", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(delete(keys).where(keys.c.id == key_id))
            s.commit()
        
        # 记录系统日志
        system_logger.log(
            operation="delete_key",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=key_id
        )
        
        logger.info(f"删除密钥: id={key_id} by {user_data['username']}")
        return {"ok": True}
    
    # ==================== 数据库连接管理 ====================
    
    @router.get("/admin/connections")
    def list_connections(
        page: int = 1,
        page_size: int = 10,
        authorization: str = Header(None)
    ):
        """列出所有数据库连接（需要登录，支持分页）"""
        auth_service.get_current_user(authorization)
        
        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size
        
        from sqlalchemy import Table, MetaData, func
        meta = MetaData()
        t = Table("db_connections", meta, autoload_with=engine)
        with Session(engine) as s:
            # 获取总数
            total = s.execute(select(func.count()).select_from(t)).scalar()
            
            # 分页查询
            rows = s.execute(
                select(t).offset(offset).limit(page_size)
            ).mappings().all()
            
        # 密码脱敏
        masked = []
        for r in rows:
            d = dict(r)
            d["password_enc"] = "***"
            masked.append(d)
        
        return {
            "items": masked,
            "total": total,
            "page": page,
            "page_size": page_size
        }
    
    @router.post("/admin/connections")
    def create_connection(
        name: str,
        host: str,
        port: int,
        db_type: str,
        database: str,
        username: str,
        password: str,
        description: Optional[str] = "",
        authorization: str = Header(None)
    ):
        """创建数据库连接（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        # 加密密码 (使用 master_key)
        pwd_enc = encrypt_text(password, cfg.security.master_key)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("db_connections", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(insert(t).values(
                name=name,
                host=host,
                port=port,
                db_type=db_type,
                database=database,
                username=username,
                password_enc=pwd_enc,
                description=description
            ))
            s.commit()
        
        # 记录系统日志
        system_logger.log(
            operation="create_connection",
            resource_type="connection",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={"name": name, "host": host, "port": port, "db_type": db_type}
        )
        
        logger.info(f"创建连接: {name} by {user_data['username']}")
        return {"ok": True}

    @router.delete("/admin/connections/{conn_id}")
    def delete_connection(conn_id: int, authorization: str = Header(None)):
        """删除数据库连接（需要登录）"""
        auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("db_connections", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(delete(t).where(t.c.id == conn_id))
            s.commit()
        
        # 记录系统日志
        system_logger.log(
            operation="delete_connection",
            resource_type="connection",
            user_id=auth_service.get_current_user(authorization)["user_id"],
            username=auth_service.get_current_user(authorization)["username"],
            resource_id=conn_id
        )
        
        return {"ok": True}
    
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
        connection_id: int,
        select_only: bool = True,
        allow_ddl: bool = False,
        authorization: str = Header(None)
    ):
        """创建权限（关联到连接 ID）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("permissions", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(insert(t).values(
                key_id=key_id,
                connection_id=connection_id,
                select_only=select_only,
                allow_ddl=allow_ddl
            ))
            s.commit()
        
        # 记录系统日志
        system_logger.log(
            operation="assign_permission",
            resource_type="permission",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={
                "key_id": key_id,
                "connection_id": connection_id,
                "select_only": select_only,
                "allow_ddl": allow_ddl
            }
        )
        
        logger.info(f"创建权限: key={key_id} conn={connection_id} select_only={select_only} allow_ddl={allow_ddl} by {user_data['username']}")
        return {"ok": True}
    
    @router.delete("/admin/permissions/{perm_id}")
    def delete_permission(perm_id: int, authorization: str = Header(None)):
        """删除权限（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        from sqlalchemy import Table, MetaData
        meta = MetaData()
        t = Table("permissions", meta, autoload_with=engine)
        with Session(engine) as s:
            s.execute(delete(t).where(t.c.id == perm_id))
            s.commit()
        
        # 记录系统日志
        system_logger.log(
            operation="delete_permission",
            resource_type="permission",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=perm_id
        )
        
        logger.info(f"删除权限: id={perm_id} by {user_data['username']}")
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
        
        # 记录系统日志
        system_logger.log(
            operation="add_whitelist",
            resource_type="whitelist",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={"key_id": key_id, "cidr": cidr, "description": description}
        )
        
        logger.info(f"添加白名单: key_id={key_id} CIDR={cidr} by {user_data['username']}")
        return {"ok": True}
    
    @router.delete("/admin/whitelist/{whitelist_id}")
    def delete_whitelist(whitelist_id: int, authorization: str = Header(None)):
        """删除白名单规则（需要登录）"""
        user_data = auth_service.get_current_user(authorization)
        
        success = ip_checker.delete_whitelist(whitelist_id)
        if not success:
            raise HTTPException(status_code=404, detail="白名单规则不存在")
        
        # 记录系统日志
        system_logger.log(
            operation="delete_whitelist",
            resource_type="whitelist",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=whitelist_id
        )
        
        logger.info(f"删除白名单: id={whitelist_id} by {user_data['username']}")
        return {"ok": True}
    
    # ==================== 审计日志查询 ====================
    
    @router.get("/admin/audit/logs")
    def list_audit_logs(
        page: int = 1,
        page_size: int = 50,
        access_key: Optional[str] = None,
        operation: Optional[str] = None,
        authorization: str = Header(None)
    ):
        """查询审计日志（需要登录，支持分页）
        
        Args:
            page: 页码（从1开始）
            page_size: 每页记录数（最大1000）
            access_key: 按访问密钥过滤（可选）
            operation: 按操作类型过滤（可选）
        """
        auth_service.get_current_user(authorization)
        
        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size
        
        from sqlalchemy import Table, MetaData, desc, func
        meta = MetaData()
        audit_logs = Table("audit_logs", meta, autoload_with=engine)
        
        with Session(engine) as s:
            # 构建查询
            query = select(audit_logs).order_by(desc(audit_logs.c.timestamp))
            
            # 添加过滤条件
            if access_key:
                query = query.where(audit_logs.c.access_key == access_key)
            if operation:
                query = query.where(audit_logs.c.operation == operation)
            
            # 获取总数
            count_query = select(func.count()).select_from(query.subquery())
            total = s.execute(count_query).scalar()
            
            # 分页查询
            query = query.offset(offset).limit(page_size)
            rows = s.execute(query).mappings().all()
        
        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size
        }
    
    @router.get("/admin/system/logs")
    def list_system_logs(
        page: int = 1,
        page_size: int = 50,
        operation: Optional[str] = None,
        resource_type: Optional[str] = None,
        authorization: str = Header(None)
    ):
        """查询系统操作日志（需要登录，支持分页）
        
        Args:
            page: 页码（从1开始）
            page_size: 每页记录数（最大1000）
            operation: 按操作类型过滤（可选）
            resource_type: 按资源类型过滤（可选）
        """
        auth_service.get_current_user(authorization)
        
        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size
        
        from sqlalchemy import Table, MetaData, desc, func
        meta = MetaData()
        system_logs = Table("system_logs", meta, autoload_with=engine)
        
        with Session(engine) as s:
            # 构建查询
            query = select(system_logs).order_by(desc(system_logs.c.timestamp))
            
            # 添加过滤条件
            if operation:
                query = query.where(system_logs.c.operation == operation)
            if resource_type:
                query = query.where(system_logs.c.resource_type == resource_type)
            
            # 获取总数
            count_query = select(func.count()).select_from(query.subquery())
            total = s.execute(count_query).scalar()
            
            # 分页查询
            query = query.offset(offset).limit(page_size)
            rows = s.execute(query).mappings().all()
        
        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size
        }
    
    return router

