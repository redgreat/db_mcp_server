"""用户管理接口：用户 CRUD 与重置密码（仅管理员）"""
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from ...timezone_util import serialize_row
from ..context import AdminContext
from ..schemas import CreateUserRequest, ResetPasswordRequest, UpdateUserRequest


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/users")
    def list_users(
        page: int = 1,
        page_size: int = 10,
        search: Optional[str] = None,
        authorization: str = Header(None)
    ):
        """列出所有用户（仅管理员），支持按用户名/邮箱模糊搜索"""
        ctx.auth_service.require_admin(authorization)  # 仅管理员可访问

        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import func, or_

        admin_users = ctx.tbl["admin_users"]
        keyword = (search or "").strip()
        cond = None
        if keyword:
            cond = or_(
                admin_users.c.username.ilike(f"%{keyword}%"),
                admin_users.c.email.ilike(f"%{keyword}%")
            )

        with Session(ctx.engine) as session:
            count_stmt = select(func.count()).select_from(admin_users)
            query = select(admin_users)
            if cond is not None:
                count_stmt = count_stmt.where(cond)
                query = query.where(cond)
            total = session.execute(count_stmt).scalar()
            rows = session.execute(
                query.order_by(admin_users.c.id).offset(offset).limit(page_size)
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
        current_user = ctx.auth_service.require_admin(authorization)

        # 验证角色值
        if req.role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="角色必须是 admin 或 user")

        admin_users = ctx.tbl["admin_users"]

        with Session(ctx.engine) as session:
            # 检查用户名是否已存在
            existing = session.execute(
                select(admin_users).where(admin_users.c.username == req.username)
            ).first()

            if existing:
                raise HTTPException(status_code=400, detail="用户名已存在")

            # 创建用户
            password_hash = ctx.auth_service.hash_password(req.password)
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
        ctx.system_logger.log(
            operation="create_user",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=new_user_id,
            details={"username": req.username, "role": req.role, "email": req.email}
        )

        ctx.logger.info(f"创建用户: {req.username} (role={req.role}) by {current_user['username']}")
        return {"ok": True, "user_id": new_user_id}

    @router.put("/admin/users/{user_id}")
    def update_user(
        user_id: int,
        req: UpdateUserRequest,
        authorization: str = Header(None)
    ):
        """更新用户信息（仅管理员）"""
        current_user = ctx.auth_service.require_admin(authorization)

        # 验证角色值
        if req.role is not None and req.role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="角色必须是 admin 或 user")

        admin_users = ctx.tbl["admin_users"]

        with Session(ctx.engine) as session:
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
        ctx.system_logger.log(
            operation="update_user",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=user_id,
            details=update_values
        )

        ctx.logger.info(f"更新用户: id={user_id} {update_values} by {current_user['username']}")
        return {"ok": True}

    @router.delete("/admin/users/{user_id}")
    def delete_user(user_id: int, authorization: str = Header(None)):
        """删除用户（仅管理员）"""
        current_user = ctx.auth_service.require_admin(authorization)

        # 不能删除自己
        if user_id == current_user["user_id"]:
            raise HTTPException(status_code=400, detail="不能删除当前登录用户")

        admin_users = ctx.tbl["admin_users"]

        with Session(ctx.engine) as session:
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
        ctx.system_logger.log(
            operation="delete_user",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=user_id,
            details={"username": deleted_username}
        )

        ctx.logger.info(f"删除用户: id={user_id} ({deleted_username}) by {current_user['username']}")
        return {"ok": True}

    @router.post("/admin/users/{user_id}/reset-password")
    def reset_user_password(
        user_id: int,
        req: ResetPasswordRequest,
        authorization: str = Header(None)
    ):
        """重置用户密码（仅管理员）"""
        current_user = ctx.auth_service.require_admin(authorization)

        if not req.new_password:
            raise HTTPException(status_code=400, detail="新密码不能为空")

        admin_users = ctx.tbl["admin_users"]

        with Session(ctx.engine) as session:
            # 检查用户是否存在
            existing = session.execute(
                select(admin_users).where(admin_users.c.id == user_id)
            ).mappings().first()

            if not existing:
                raise HTTPException(status_code=404, detail="用户不存在")

            target_username = existing["username"]

            # 重置密码
            new_hash = ctx.auth_service.hash_password(req.new_password)
            session.execute(
                update(admin_users)
                .where(admin_users.c.id == user_id)
                .values(password_hash=new_hash)
            )
            session.commit()

        # 记录系统日志
        ctx.system_logger.log(
            operation="reset_password",
            resource_type="admin_user",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=user_id,
            details={"target_username": target_username}
        )

        ctx.logger.info(f"重置密码: user_id={user_id} ({target_username}) by {current_user['username']}")
        return {"ok": True}

    return router
