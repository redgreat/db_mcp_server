from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import create_engine, select, insert, update, delete, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel
import os
import secrets
from ..config import Config
from ..logging_utils import get_logger
from .models import ensure_schema
from .auth import AuthService
from ..security.secret import encrypt_text, decrypt_text
from ..security.ip_whitelist import IPWhitelistChecker
from ..timezone_util import serialize_row


# 请求模型
class LoginRequest(BaseModel):
    username: str
    password: str


class CreateKeyRequest(BaseModel):
    ak: Optional[str] = None
    description: str = ""
    enabled: bool = True
    sql_risk_check_enabled: bool = True


class TestConnectionRequest(BaseModel):
    host: str
    port: int
    db_type: str
    database: str
    username: str
    password: Optional[str] = None
    connection_id: Optional[int] = None


class ChangePasswordRequest(BaseModel):
    """修改密码请求"""
    old_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    """创建用户请求"""
    username: str
    password: str
    email: Optional[str] = ""
    role: str = "user"  # admin/user


class UpdateUserRequest(BaseModel):
    """更新用户请求"""
    role: Optional[str] = None
    is_active: Optional[bool] = None


class ResetPasswordRequest(BaseModel):
    """重置用户密码请求"""
    new_password: str


class UpdateLLMConfigRequest(BaseModel):
    """更新大模型配置请求"""
    base_url: str
    api_key: Optional[str] = None
    model_name: str


def build_admin_router(cfg: Config):
    """创建管理后台路由"""
    router = APIRouter()
    logger = get_logger("admin", cfg.logging.dir)

    # 使用PostgreSQL作为管理数据库
    admin_db_url = cfg.get_admin_db_url()
    engine = create_engine(admin_db_url, pool_pre_ping=True)
    ensure_schema(engine)
    from .schema_cache import get_admin_tables
    from .llm_active import ensure_single_llm_active

    tbl = get_admin_tables(engine)
    ensure_single_llm_active(engine)

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

    def _generate_access_key() -> str:
        return secrets.token_hex(16)

    def _build_database_url(db_type: str, host: str, port: int, database: str, username: str, password: str) -> URL:
        db_type_lower = (db_type or "").lower()
        if db_type_lower in ("mysql", "mariadb"):
            drivername = "mysql+pymysql"
        elif db_type_lower in ("postgresql", "postgres"):
            drivername = "postgresql+psycopg2"
        elif db_type_lower in ("mssql", "sqlserver"):
            drivername = "mssql+pymssql"
        else:
            raise HTTPException(status_code=400, detail="不支持的数据库类型")

        return URL.create(
            drivername=drivername,
            username=username,
            password=password,
            host=host,
            port=port,
            database=database,
        )

    def _database_connect_args(db_type: str) -> dict:
        db_type_lower = (db_type or "").lower()
        if db_type_lower in ("mysql", "mariadb"):
            return {"connect_timeout": 5}
        if db_type_lower in ("postgresql", "postgres"):
            return {"connect_timeout": 5}
        if db_type_lower in ("mssql", "sqlserver"):
            return {"login_timeout": 5, "timeout": 5}
        return {}

    def _test_database_connection(
        db_type: str,
        host: str,
        port: int,
        database: str,
        username: str,
        password: str,
    ) -> None:
        test_engine = create_engine(
            _build_database_url(db_type, host, port, database, username, password),
            pool_pre_ping=True,
            connect_args=_database_connect_args(db_type),
        )
        try:
            with test_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        finally:
            test_engine.dispose()

    # ==================== 认证相关API ====================

    @router.post("/admin/login")
    def login(req: LoginRequest):
        """管理员登录"""
        admin_users = tbl["admin_users"]

        with Session(engine) as session:
            user = session.execute(
                select(admin_users).where(
                    admin_users.c.username == req.username,
                    admin_users.c.is_active == True  # noqa: E712
                )
            ).mappings().first()

            if not user:
                raise HTTPException(status_code=401, detail="用户名或密码错误")

            # 验证密码
            if not auth_service.verify_password(req.password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="用户名或密码错误")

            # 生成token（包含角色信息）
            token = auth_service.create_token(
                user["id"],
                user["username"],
                user.get("role", "user")  # 包含角色
            )

            logger.info(f"用户登录成功: {req.username} (role={user.get('role', 'user')})")
            return {
                "token": token,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "role": user.get("role", "user")  # 返回角色信息
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

    @router.post("/admin/change_password")
    def change_password(req: ChangePasswordRequest, authorization: str = Header(None)):
        """修改当前登录管理员密码"""
        user_data = auth_service.get_current_user(authorization)
        user_id = user_data["user_id"]

        admin_users = tbl["admin_users"]

        with Session(engine) as session:
            row = session.execute(
                select(admin_users).where(admin_users.c.id == user_id)
            ).mappings().first()

            if not row:
                raise HTTPException(status_code=404, detail="用户不存在")

            if not auth_service.verify_password(req.old_password, row["password_hash"]):
                raise HTTPException(status_code=400, detail="原密码错误")

            if not req.new_password:
                raise HTTPException(status_code=400, detail="新密码不能为空")

            new_hash = auth_service.hash_password(req.new_password)

            session.execute(
                update(admin_users)
                .where(admin_users.c.id == user_id)
                .values(password_hash=new_hash)
            )
            session.commit()

        return {"ok": True}

    # ==================== 用户管理 ====================

    @router.get("/admin/users")
    def list_users(
        page: int = 1,
        page_size: int = 10,
        authorization: str = Header(None)
    ):
        """列出所有用户（仅管理员）"""
        auth_service.require_admin(authorization)  # 仅管理员可访问

        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import func

        admin_users = tbl["admin_users"]

        with Session(engine) as session:
            total = session.execute(select(func.count()).select_from(admin_users)).scalar()
            rows = session.execute(
                select(admin_users).offset(offset).limit(page_size)
            ).mappings().all()

        users = []
        for r in rows:
            user_dict = serialize_row(r)
            user_dict.pop("password_hash", None)
            users.append(user_dict)

        return {
            "items": users,
            "total": total,
            "page": page,
            "page_size": page_size
        }

    @router.post("/admin/users")
    def create_user(req: CreateUserRequest, authorization: str = Header(None)):
        """创建新用户（仅管理员）"""
        current_user = auth_service.require_admin(authorization)

        # 验证角色值
        if req.role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="角色必须是 admin 或 user")

        admin_users = tbl["admin_users"]

        with Session(engine) as session:
            # 检查用户名是否已存在
            existing = session.execute(
                select(admin_users).where(admin_users.c.username == req.username)
            ).first()

            if existing:
                raise HTTPException(status_code=400, detail="用户名已存在")

            # 创建用户
            password_hash = auth_service.hash_password(req.password)
            result = session.execute(
                insert(admin_users).values(
                    username=req.username,
                    password_hash=password_hash,
                    email=req.email,
                    role=req.role,
                    is_active=True
                )
            )
            session.commit()

            # 获取新创建的用户ID
            new_user_id = result.lastrowid

        # 记录系统日志
        system_logger.log(
            operation="create_user",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=new_user_id,
            details={"username": req.username, "role": req.role, "email": req.email}
        )

        logger.info(f"创建用户: {req.username} (role={req.role}) by {current_user['username']}")
        return {"ok": True, "user_id": new_user_id}

    @router.put("/admin/users/{user_id}")
    def update_user(
        user_id: int,
        req: UpdateUserRequest,
        authorization: str = Header(None)
    ):
        """更新用户信息（仅管理员）"""
        current_user = auth_service.require_admin(authorization)

        # 验证角色值
        if req.role is not None and req.role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="角色必须是 admin 或 user")

        admin_users = tbl["admin_users"]

        with Session(engine) as session:
            # 检查用户是否存在
            existing = session.execute(
                select(admin_users).where(admin_users.c.id == user_id)
            ).first()

            if not existing:
                raise HTTPException(status_code=404, detail="用户不存在")

            # 构建更新字段
            update_values = {}
            if req.role is not None:
                update_values["role"] = req.role
            if req.is_active is not None:
                update_values["is_active"] = req.is_active

            if not update_values:
                raise HTTPException(status_code=400, detail="没有需要更新的字段")

            # 更新用户
            session.execute(
                update(admin_users)
                .where(admin_users.c.id == user_id)
                .values(**update_values)
            )
            session.commit()

        # 记录系统日志
        system_logger.log(
            operation="update_user",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=user_id,
            details=update_values
        )

        logger.info(f"更新用户: id={user_id} {update_values} by {current_user['username']}")
        return {"ok": True}

    @router.delete("/admin/users/{user_id}")
    def delete_user(user_id: int, authorization: str = Header(None)):
        """删除用户（仅管理员）"""
        current_user = auth_service.require_admin(authorization)

        # 不能删除自己
        if user_id == current_user["user_id"]:
            raise HTTPException(status_code=400, detail="不能删除当前登录用户")

        admin_users = tbl["admin_users"]

        with Session(engine) as session:
            # 检查用户是否存在
            existing = session.execute(
                select(admin_users).where(admin_users.c.id == user_id)
            ).mappings().first()

            if not existing:
                raise HTTPException(status_code=404, detail="用户不存在")

            deleted_username = existing["username"]

            # 删除用户
            session.execute(
                delete(admin_users).where(admin_users.c.id == user_id)
            )
            session.commit()

        # 记录系统日志
        system_logger.log(
            operation="delete_user",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=user_id,
            details={"username": deleted_username}
        )

        logger.info(f"删除用户: id={user_id} ({deleted_username}) by {current_user['username']}")
        return {"ok": True}

    @router.post("/admin/users/{user_id}/reset-password")
    def reset_user_password(
        user_id: int,
        req: ResetPasswordRequest,
        authorization: str = Header(None)
    ):
        """重置用户密码（仅管理员）"""
        current_user = auth_service.require_admin(authorization)

        if not req.new_password:
            raise HTTPException(status_code=400, detail="新密码不能为空")

        admin_users = tbl["admin_users"]

        with Session(engine) as session:
            # 检查用户是否存在
            existing = session.execute(
                select(admin_users).where(admin_users.c.id == user_id)
            ).mappings().first()

            if not existing:
                raise HTTPException(status_code=404, detail="用户不存在")

            target_username = existing["username"]

            # 重置密码
            new_hash = auth_service.hash_password(req.new_password)
            session.execute(
                update(admin_users)
                .where(admin_users.c.id == user_id)
                .values(password_hash=new_hash)
            )
            session.commit()

        # 记录系统日志
        system_logger.log(
            operation="reset_password",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=user_id,
            details={"target_username": target_username}
        )

        logger.info(f"重置密码: user_id={user_id} ({target_username}) by {current_user['username']}")
        return {"ok": True}

    # ==================== 大模型配置管理 ====================

    @router.get("/admin/llm_configs")
    def get_llm_configs(authorization: str = Header(None)):
        """获取所有 LLM 配置列表"""
        # 需要管理员权限
        auth_service.require_admin(authorization)

        llm_configs = tbl["llm_configs"]

        with Session(engine) as session:
            rows = session.execute(select(llm_configs).order_by(llm_configs.c.id)).mappings().all()

            items = []
            for r in rows:
                item = serialize_row(r)
                # 不返回真实的 API Key，而是返回是否有设置
                has_key = bool(item.get("api_key_enc"))
                item["has_api_key"] = has_key
                # 删除加密字段避免泄漏
                if "api_key_enc" in item:
                    del item["api_key_enc"]
                items.append(item)

            return {"items": items}

    @router.put("/admin/llm_configs/{config_id}")
    def update_llm_config(config_id: int, req: UpdateLLMConfigRequest, authorization: str = Header(None)):
        """更新指定的 LLM 配置"""
        auth_service.require_admin(authorization)

        llm_configs = tbl["llm_configs"]

        with Session(engine) as session:
            existing = session.execute(select(llm_configs).where(llm_configs.c.id == config_id)).mappings().first()
            if not existing:
                raise HTTPException(status_code=404, detail="配置不存在")

            update_data = {
                "base_url": req.base_url,
                "model_name": req.model_name
            }

            if req.api_key and req.api_key.strip():
                update_data["api_key_enc"] = encrypt_text(req.api_key.strip(), cfg.security.master_key)

            session.execute(
                update(llm_configs)
                .where(llm_configs.c.id == config_id)
                .values(**update_data)
            )
            session.commit()

        from ..ai.service import reset_llm_client
        reset_llm_client()

        return {"ok": True, "message": "配置已更新"}

    @router.post("/admin/llm_configs/{config_id}/activate")
    def activate_llm_config(config_id: int, authorization: str = Header(None)):
        """激活指定的 LLM 配置"""
        auth_service.require_admin(authorization)

        llm_configs = tbl["llm_configs"]

        with Session(engine) as session:
            existing = session.execute(select(llm_configs).where(llm_configs.c.id == config_id)).mappings().first()
            if not existing:
                raise HTTPException(status_code=404, detail="配置不存在")
            if not existing.get("api_key_enc"):
                raise HTTPException(status_code=400, detail="请先配置 API Key 后再激活")

            session.execute(update(llm_configs).values(is_active=False))
            # 激活指定的配置
            session.execute(update(llm_configs).where(llm_configs.c.id == config_id).values(is_active=True))
            session.commit()

        ensure_single_llm_active(engine)
        from ..ai.service import reset_llm_client
        reset_llm_client()

        return {"ok": True, "message": f"已激活配置: {existing['provider']}"}

    @router.get("/admin/llm_call_logs")
    def list_llm_call_logs(
        page: int = 1,
        page_size: int = 10,
        access_key: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        authorization: str = Header(None),
    ):
        """大模型调用明细（管理员看全部，普通用户只看自己有权密钥的日志）"""
        current_user = auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        offset = (page - 1) * page_size

        from sqlalchemy import desc, func
        from datetime import datetime

        logs = tbl["llm_call_logs"]
        with Session(engine) as s:
            allowed_aks = None
            if user_role != "admin":
                allowed_aks = s.execute(
                    select(tbl["access_keys"].c.ak)
                    .join(tbl["access_key_users"], tbl["access_keys"].c.id == tbl["access_key_users"].c.key_id)
                    .where(tbl["access_key_users"].c.user_id == user_id)
                ).scalars().all()

            q = select(logs)
            count_stmt = select(func.count()).select_from(logs)

            if user_role != "admin":
                if allowed_aks:
                    q = q.where(logs.c.access_key.in_(allowed_aks))
                    count_stmt = count_stmt.where(logs.c.access_key.in_(allowed_aks))
                else:
                    q = q.where(logs.c.id == -1)
                    count_stmt = count_stmt.where(logs.c.id == -1)

            if access_key:
                q = q.where(logs.c.access_key.ilike(f"%{access_key}%"))
                count_stmt = count_stmt.where(logs.c.access_key.ilike(f"%{access_key}%"))
            if date_from:
                try:
                    dt = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
                    q = q.where(logs.c.timestamp >= dt)
                    count_stmt = count_stmt.where(logs.c.timestamp >= dt)
                except ValueError:
                    pass
            if date_to:
                try:
                    dt = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
                    q = q.where(logs.c.timestamp <= dt)
                    count_stmt = count_stmt.where(logs.c.timestamp <= dt)
                except ValueError:
                    pass

            total = s.execute(count_stmt).scalar() or 0
            rows = s.execute(
                q.order_by(desc(logs.c.timestamp)).offset(offset).limit(page_size)
            ).mappings().all()

        return {
            "items": [serialize_row(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    @router.get("/admin/llm_call_logs/daily")
    def list_llm_call_logs_daily(
        days: int = 14,
        authorization: str = Header(None),
    ):
        """按日汇总 Token 消耗（管理员看全部，普通用户只看自己有权密钥）"""
        current_user = auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        days = min(max(1, days), 90)

        from sqlalchemy import func, cast, Date
        from datetime import timedelta
        from ..timezone_util import now_app

        logs = tbl["llm_call_logs"]
        since = now_app() - timedelta(days=days)

        with Session(engine) as s:
            allowed_aks = None
            if user_role != "admin":
                allowed_aks = s.execute(
                    select(tbl["access_keys"].c.ak)
                    .join(tbl["access_key_users"], tbl["access_keys"].c.id == tbl["access_key_users"].c.key_id)
                    .where(tbl["access_key_users"].c.user_id == user_id)
                ).scalars().all()

            day_col = cast(func.date_trunc("day", logs.c.timestamp), Date).label("day")
            stmt = (
                select(
                    day_col,
                    logs.c.access_key,
                    logs.c.provider,
                    logs.c.model_name,
                    func.count().label("call_count"),
                    func.coalesce(func.sum(logs.c.prompt_tokens), 0).label("prompt_tokens"),
                    func.coalesce(func.sum(logs.c.completion_tokens), 0).label("completion_tokens"),
                    func.coalesce(func.sum(logs.c.total_tokens), 0).label("total_tokens"),
                )
                .where(logs.c.timestamp >= since)
            )

            if user_role != "admin":
                if allowed_aks:
                    stmt = stmt.where(logs.c.access_key.in_(allowed_aks))
                else:
                    stmt = stmt.where(logs.c.id == -1)

            stmt = stmt.group_by(day_col, logs.c.access_key, logs.c.provider, logs.c.model_name)
            stmt = stmt.order_by(day_col.desc(), func.sum(logs.c.total_tokens).desc())

            rows = s.execute(stmt).mappings().all()

        items = []
        for r in rows:
            item = serialize_row(r)
            if item.get("day"):
                item["day"] = str(item["day"])[:10]
            items.append(item)

        return {"items": items, "days": days}

    # ==================== 首页 ====================

    @router.get("/admin")
    @router.get("/admin/")
    def admin_index():
        """兼容书签 /admin：Svelte 应用路由在 /connections 等路径，不能在同一 URL 下挂载 index（会触发客户端 Not found）。"""
        static_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'index.html')
        if os.path.exists(static_path):
            return RedirectResponse(url="/connections", status_code=302)
        return HTMLResponse(
            content="<p>Frontend not built. Run: cd frontend && npm run build</p>",
            status_code=503,
        )

    # ==================== 访问密钥管理 ====================

    @router.get("/admin/keys")
    def list_keys(
        page: int = 1,
        page_size: int = 10,
        authorization: str = Header(None)
    ):
        """列出访问密钥（需要登录，支持分页，基于用户角色筛选）"""
        current_user = auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import func

        keys = tbl["access_keys"]
        key_users = tbl["access_key_users"]

        with Session(engine) as s:
            if user_role == "admin":
                # 管理员：查看所有密钥
                total = s.execute(select(func.count()).select_from(keys)).scalar()
                rows = s.execute(
                    select(keys).offset(offset).limit(page_size)
                ).mappings().all()
            else:
                # 普通用户：只查看分配给自己的密钥
                total = s.execute(
                    select(func.count())
                    .select_from(keys.join(key_users, keys.c.id == key_users.c.key_id))
                    .where(key_users.c.user_id == user_id)
                ).scalar()
                rows = s.execute(
                    select(keys)
                    .join(key_users, keys.c.id == key_users.c.key_id)
                    .where(key_users.c.user_id == user_id)
                    .offset(offset)
                    .limit(page_size)
                ).mappings().all()

        return {
            "items": [serialize_row(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size
        }

    @router.post("/admin/keys")
    def create_key(req: CreateKeyRequest, authorization: str = Header(None)):
        """创建访问密钥（仅管理员）"""
        user_data = auth_service.require_admin(authorization)

        keys = tbl["access_keys"]
        with Session(engine) as s:
            ak = (req.ak or "").strip()
            if not ak:
                for _ in range(5):
                    candidate = _generate_access_key()
                    exists = s.execute(select(keys.c.id).where(keys.c.ak == candidate)).first()
                    if not exists:
                        ak = candidate
                        break
                if not ak:
                    raise HTTPException(status_code=500, detail="生成访问密钥失败，请重试")

            s.execute(insert(keys).values(
                ak=ak,
                description=req.description,
                enabled=req.enabled,
                sql_risk_check_enabled=req.sql_risk_check_enabled,
                created_by=user_data["user_id"]
            ))
            s.commit()

        # 记录系统日志
        system_logger.log(
            operation="create_key",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={"ak": ak, "description": req.description}
        )

        logger.info(f"创建访问密钥: {ak} by {user_data['username']}")
        return {"ok": True, "ak": ak}

    @router.patch("/admin/keys/{key_id}/sql_risk_check")
    async def update_key_sql_risk_check(
        key_id: int,
        request: Request,
        authorization: str = Header(None)
    ):
        """更新访问密钥的SQL风险监测开关（仅管理员）"""
        user_data = auth_service.require_admin(authorization)
        body = await request.json()
        enabled = bool(body.get("sql_risk_check_enabled", True))
        keys = tbl["access_keys"]
        with Session(engine) as s:
            s.execute(
                update(keys)
                .where(keys.c.id == key_id)
                .values(sql_risk_check_enabled=enabled)
            )
            s.commit()
        system_logger.log(
            operation="toggle_sql_risk_check",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=key_id,
            details={"sql_risk_check_enabled": enabled}
        )
        return {"ok": True}

    @router.patch("/admin/keys/{key_id}/toggle")
    async def toggle_key_status(
        key_id: int,
        request: Request,
        authorization: str = Header(None)
    ):
        """切换访问密钥状态（仅管理员）"""
        user_data = auth_service.require_admin(authorization)

        # 从请求体获取 enabled 参数
        body = await request.json()
        enabled = body.get('enabled', True)

        keys = tbl["access_keys"]
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
        """删除访问密钥（仅管理员）"""
        user_data = auth_service.require_admin(authorization)

        keys = tbl["access_keys"]
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

    # ==================== 密钥用户管理 ====================

    @router.get("/admin/keys/{key_id}/users")
    def list_key_users(key_id: int, authorization: str = Header(None)):
        """获取密钥已分配的用户列表（仅管理员）"""
        auth_service.require_admin(authorization)

        key_users = tbl["access_key_users"]
        admin_users = tbl["admin_users"]

        with Session(engine) as s:
            # JOIN 查询获取用户详细信息
            query = (
                select(
                    admin_users.c.id,
                    admin_users.c.username,
                    admin_users.c.email,
                    admin_users.c.role,
                    key_users.c.created_at.label("assigned_at")
                )
                .join(key_users, admin_users.c.id == key_users.c.user_id)
                .where(key_users.c.key_id == key_id)
            )
            rows = s.execute(query).mappings().all()

        return {"users": [serialize_row(r) for r in rows]}

    @router.post("/admin/keys/{key_id}/users")
    async def assign_users_to_key(
        key_id: int,
        request: Request,
        authorization: str = Header(None)
    ):
        """为密钥分配用户（仅管理员）"""
        current_user = auth_service.require_admin(authorization)

        key_users = tbl["access_key_users"]

        # 从请求体获取用户ID列表
        body = await request.json()
        user_ids = body if isinstance(body, list) else body.get("user_ids", [])

        with Session(engine) as s:
            # 批量插入（忽略已存在的记录）
            for user_id in user_ids:
                try:
                    s.execute(insert(key_users).values(
                        key_id=key_id,
                        user_id=user_id
                    ))
                except Exception:
                    # 忽略重复插入错误
                    pass
            s.commit()

        # 记录系统日志
        system_logger.log(
            operation="assign_key_users",
            resource_type="access_key",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=key_id,
            details={"user_ids": user_ids}
        )

        logger.info(f"为密钥 {key_id} 分配用户: {user_ids} by {current_user['username']}")
        return {"ok": True}

    @router.delete("/admin/keys/{key_id}/users/{user_id}")
    def remove_user_from_key(
        key_id: int,
        user_id: int,
        authorization: str = Header(None)
    ):
        """取消密钥对某用户的分配（仅管理员）"""
        current_user = auth_service.require_admin(authorization)

        key_users = tbl["access_key_users"]

        with Session(engine) as s:
            s.execute(
                delete(key_users).where(
                    key_users.c.key_id == key_id,
                    key_users.c.user_id == user_id
                )
            )
            s.commit()

        # 记录系统日志
        system_logger.log(
            operation="remove_key_user",
            resource_type="access_key",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=key_id,
            details={"removed_user_id": user_id}
        )

        logger.info(f"取消密钥 {key_id} 对用户 {user_id} 的分配 by {current_user['username']}")
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

        from sqlalchemy import func

        t = tbl["db_connections"]
        list_cols = (
            t.c.id,
            t.c.name,
            t.c.host,
            t.c.port,
            t.c.db_type,
            t.c.database,
            t.c.username,
            t.c.description,
            t.c.created_at,
        )
        with Session(engine) as s:
            total = s.execute(select(func.count()).select_from(t)).scalar()
            rows = s.execute(
                select(*list_cols).offset(offset).limit(page_size)
            ).mappings().all()

        masked = [serialize_row(r) for r in rows]

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
        """创建数据库连接（仅管理员）"""
        user_data = auth_service.require_admin(authorization)

        # 加密密码 (使用 master_key)
        pwd_enc = encrypt_text(password, cfg.security.master_key)

        t = tbl["db_connections"]
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

    @router.post("/admin/connections/test")
    def test_connection(req: TestConnectionRequest, authorization: str = Header(None)):
        """测试数据库连接有效性（仅管理员）"""
        auth_service.require_admin(authorization)

        password = req.password or ""
        if not password and req.connection_id is not None:
            t = tbl["db_connections"]
            with Session(engine) as s:
                row = s.execute(select(t).where(t.c.id == req.connection_id)).mappings().first()
                if not row:
                    raise HTTPException(status_code=404, detail="连接不存在")
                password = decrypt_text(row["password_enc"], cfg.security.master_key)

        if not password:
            raise HTTPException(status_code=400, detail="请先填写数据库密码后再测试连接")

        try:
            _test_database_connection(
                db_type=req.db_type,
                host=req.host,
                port=req.port,
                database=req.database,
                username=req.username,
                password=password,
            )
        except HTTPException:
            raise
        except SQLAlchemyError as exc:
            logger.warning(
                "测试数据库连接失败: type=%s host=%s port=%s database=%s user=%s error=%s",
                req.db_type,
                req.host,
                req.port,
                req.database,
                req.username,
                exc,
            )
            raise HTTPException(status_code=400, detail=f"连接失败: {exc}") from exc
        except Exception as exc:
            logger.warning(
                "测试数据库连接异常: type=%s host=%s port=%s database=%s user=%s error=%s",
                req.db_type,
                req.host,
                req.port,
                req.database,
                req.username,
                exc,
            )
            raise HTTPException(status_code=400, detail=f"连接失败: {exc}") from exc

        return {"ok": True, "message": "连接测试成功"}

    @router.put("/admin/connections/{conn_id}")
    def update_connection(
        conn_id: int,
        name: str,
        host: str,
        port: int,
        db_type: str,
        database: str,
        username: str,
        password: Optional[str] = None,
        description: Optional[str] = "",
        authorization: str = Header(None)
    ):
        """更新数据库连接（仅管理员）；password 不传或为空则保留原密码"""
        user_data = auth_service.require_admin(authorization)

        t = tbl["db_connections"]
        with Session(engine) as s:
            row = s.execute(select(t).where(t.c.id == conn_id)).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="连接不存在")

            vals = {
                "name": name,
                "host": host,
                "port": port,
                "db_type": db_type,
                "database": database,
                "username": username,
                "description": description or "",
            }
            if password:
                vals["password_enc"] = encrypt_text(password, cfg.security.master_key)

            s.execute(update(t).where(t.c.id == conn_id).values(**vals))
            s.commit()

        system_logger.log(
            operation="update_connection",
            resource_type="connection",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=conn_id,
            details={"name": name, "host": host, "port": port, "db_type": db_type},
        )

        logger.info(f"更新连接 id={conn_id}: {name} by {user_data['username']}")
        return {"ok": True}

    @router.get("/admin/connections/{conn_id}/delete-preview")
    def delete_connection_preview(conn_id: int, authorization: str = Header(None)):
        """删除前预览：统计将影响的关联数据（仅管理员）"""
        auth_service.require_admin(authorization)

        from sqlalchemy import func, inspect as sa_inspect

        conns = tbl["db_connections"]
        with Session(engine) as s:
            row = s.execute(select(conns).where(conns.c.id == conn_id)).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="连接不存在")

            permissions = tbl["permissions"]
            perm_count = s.execute(
                select(func.count())
                .select_from(permissions)
                .where(permissions.c.connection_id == conn_id)
            ).scalar() or 0

            rule_count = 0
            if "db_rules" in sa_inspect(engine).get_table_names():
                db_rules = tbl["db_rules"]
                rule_count = s.execute(
                    select(func.count())
                    .select_from(db_rules)
                    .where(db_rules.c.connection_id == conn_id)
                ).scalar() or 0

            audit_logs = tbl["audit_logs"]
            audit_count = s.execute(
                select(func.count())
                .select_from(audit_logs)
                .where(audit_logs.c.connection_id == conn_id)
            ).scalar() or 0

        return {
            "connection": {
                "id": row["id"],
                "name": row["name"],
                "host": row["host"],
                "port": row["port"],
                "db_type": row["db_type"],
                "database": row["database"],
                "username": row["username"],
            },
            "permission_count": int(perm_count),
            "db_rule_count": int(rule_count),
            "audit_log_count": int(audit_count),
        }

    @router.delete("/admin/connections/{conn_id}")
    def delete_connection(conn_id: int, authorization: str = Header(None)):
        """删除数据库连接（仅管理员）；先解除/删除关联的权限、规则与审计引用"""
        user_data = auth_service.require_admin(authorization)

        from sqlalchemy.exc import IntegrityError

        conns = tbl["db_connections"]
        with Session(engine) as s:
            row = s.execute(select(conns).where(conns.c.id == conn_id)).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="连接不存在")

            permissions = tbl["permissions"]
            s.execute(delete(permissions).where(permissions.c.connection_id == conn_id))

            from sqlalchemy import inspect as sa_inspect
            if "db_rules" in sa_inspect(engine).get_table_names():
                db_rules = tbl["db_rules"]
                s.execute(delete(db_rules).where(db_rules.c.connection_id == conn_id))

            audit_logs = tbl["audit_logs"]
            s.execute(
                update(audit_logs)
                .where(audit_logs.c.connection_id == conn_id)
                .values(connection_id=None)
            )

            try:
                s.execute(delete(conns).where(conns.c.id == conn_id))
                s.commit()
            except IntegrityError as exc:
                s.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="无法删除连接：仍存在未清理的关联数据，请稍后重试或联系管理员",
                ) from exc

        system_logger.log(
            operation="delete_connection",
            resource_type="connection",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=conn_id,
        )

        logger.info(f"删除连接 id={conn_id} by {user_data['username']}")
        return {"ok": True}

    # ==================== 权限管理 ====================

    @router.get("/admin/permissions")
    def list_permissions(authorization: str = Header(None)):
        """列出权限配置（需要登录，基于用户角色筛选）"""
        current_user = auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        permissions = tbl["permissions"]

        with Session(engine) as s:
            if user_role == "admin":
                # 管理员：返回所有权限
                rows = s.execute(select(permissions)).mappings().all()
            else:
                # 普通用户：只返回自己有权访问的密钥的权限
                key_users = tbl["access_key_users"]
                query = (
                    select(permissions)
                    .join(key_users, permissions.c.key_id == key_users.c.key_id)
                    .where(key_users.c.user_id == user_id)
                )
                rows = s.execute(query).mappings().all()

        return {"items": [serialize_row(r) for r in rows]}

    @router.post("/admin/permissions")
    def create_permission(
        key_id: int,
        connection_id: int,
        select_only: bool = True,
        allow_ddl: bool = False,
        authorization: str = Header(None)
    ):
        """创建权限（仅管理员）"""
        user_data = auth_service.require_admin(authorization)

        t = tbl["permissions"]
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

        logger.info(
            f"创建权限: key={key_id} conn={connection_id} "
            f"select_only={select_only} allow_ddl={allow_ddl} by {user_data['username']}"
        )
        return {"ok": True}

    @router.delete("/admin/permissions/{perm_id}")
    def delete_permission(perm_id: int, authorization: str = Header(None)):
        """删除权限（仅管理员）"""
        user_data = auth_service.require_admin(authorization)

        t = tbl["permissions"]
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
        """列出白名单（需要登录，基于用户角色筛选）

        Args:
            key_id: 访问密钥ID（可选，不指定则返回所有）
        """
        current_user = auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        if user_role == "admin":
            # 管理员：返回所有白名单或指定key_id的白名单
            rules = ip_checker.list_whitelist(key_id=key_id)
        else:
            # 普通用户：只返回自己有权访问的密钥的白名单
            whitelist = tbl["whitelist"]
            key_users = tbl["access_key_users"]

            with Session(engine) as s:
                query = (
                    select(whitelist)
                    .join(key_users, whitelist.c.key_id == key_users.c.key_id)
                    .where(key_users.c.user_id == user_id)
                )

                # 如果指定了key_id，添加过滤条件
                if key_id is not None:
                    query = query.where(whitelist.c.key_id == key_id)

                rows = s.execute(query).mappings().all()
                rules = [serialize_row(r) for r in rows]

        return {"items": rules}

    @router.post("/admin/whitelist")
    def create_whitelist(
        key_id: int,
        cidr: str,
        description: str = "",
        authorization: str = Header(None)
    ):
        """为指定APPKEY添加白名单规则（仅管理员）

        Args:
            key_id: 访问密钥ID
            cidr: CIDR格式，如 '192.168.1.0/24' 或 '10.0.0.1'
            description: 描述
        """
        user_data = auth_service.require_admin(authorization)

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
        """删除白名单规则（仅管理员）"""
        user_data = auth_service.require_admin(authorization)

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
        """查询审计日志（管理员看全部，普通用户只看自己有权密钥的日志）"""
        current_user = auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import desc, func

        audit_logs = tbl["audit_logs"]

        with Session(engine) as s:
            # 普通用户：只看分配给自己密钥的日志
            allowed_aks = None
            if user_role != "admin":
                allowed_aks = s.execute(
                    select(tbl["access_keys"].c.ak)
                    .join(tbl["access_key_users"], tbl["access_keys"].c.id == tbl["access_key_users"].c.key_id)
                    .where(tbl["access_key_users"].c.user_id == user_id)
                ).scalars().all()

            query = select(audit_logs).order_by(desc(audit_logs.c.timestamp))
            count_stmt = select(func.count()).select_from(audit_logs)

            if user_role != "admin":
                if allowed_aks:
                    query = query.where(audit_logs.c.access_key.in_(allowed_aks))
                    count_stmt = count_stmt.where(audit_logs.c.access_key.in_(allowed_aks))
                else:
                    query = query.where(audit_logs.c.id == -1)
                    count_stmt = count_stmt.where(audit_logs.c.id == -1)

            if access_key:
                query = query.where(audit_logs.c.access_key == access_key)
                count_stmt = count_stmt.where(audit_logs.c.access_key == access_key)
            if operation:
                query = query.where(audit_logs.c.operation == operation)
                count_stmt = count_stmt.where(audit_logs.c.operation == operation)

            total = s.execute(count_stmt).scalar()
            rows = s.execute(query.offset(offset).limit(page_size)).mappings().all()

        return {
            "items": [serialize_row(r) for r in rows],
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
        """查询系统操作日志（仅管理员，支持分页）

        Args:
            page: 页码（从1开始）
            page_size: 每页记录数（最大1000）
            operation: 按操作类型过滤（可选）
            resource_type: 按资源类型过滤（可选）
        """
        auth_service.require_admin(authorization)  # 仅管理员可访问

        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import desc, func

        system_logs = tbl["system_logs"]

        with Session(engine) as s:
            query = select(system_logs).order_by(desc(system_logs.c.timestamp))

            # 添加过滤条件
            if operation:
                query = query.where(system_logs.c.operation == operation)
            if resource_type:
                query = query.where(system_logs.c.resource_type == resource_type)

            count_stmt = select(func.count()).select_from(system_logs)
            if operation:
                count_stmt = count_stmt.where(system_logs.c.operation == operation)
            if resource_type:
                count_stmt = count_stmt.where(system_logs.c.resource_type == resource_type)
            total = s.execute(count_stmt).scalar()

            rows = s.execute(query.offset(offset).limit(page_size)).mappings().all()

        return {
            "items": [serialize_row(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size
        }

    return router
