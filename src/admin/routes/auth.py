"""认证相关接口：登录 / 登出 / 当前用户 / 修改密码"""
from fastapi import APIRouter, Header, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..context import AdminContext
from ..schemas import ChangePasswordRequest, LoginRequest


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.post("/admin/login")
    def login(req: LoginRequest, request: Request):
        """管理员登录"""
        admin_users = ctx.tbl["admin_users"]

        with Session(ctx.engine) as session:
            user = session.execute(
                select(admin_users).where(
                    admin_users.c.username == req.username,
                    admin_users.c.is_active == True  # noqa: E712
                )
            ).mappings().first()

            if not user:
                # 记录登录失败（原因与密码错误保持一致，避免暴露用户名是否存在）
                ctx.log_system_op(
                    "login", "auth",
                    username=req.username,
                    details={"result": "failed", "reason": "用户名或密码错误"},
                    request=request,
                )
                raise HTTPException(status_code=401, detail="用户名或密码错误")

            # 验证密码
            if not ctx.auth_service.verify_password(req.password, user["password_hash"]):
                ctx.log_system_op(
                    "login", "auth",
                    username=req.username,
                    details={"result": "failed", "reason": "用户名或密码错误"},
                    request=request,
                )
                raise HTTPException(status_code=401, detail="用户名或密码错误")

            # 生成token（包含角色信息）
            token = ctx.auth_service.create_token(
                user["id"],
                user["username"],
                user.get("role", "user")  # 包含角色
            )

            # 记录登录成功
            ctx.log_system_op(
                "login", "auth",
                user_id=user["id"],
                username=user["username"],
                details={"result": "success", "role": user.get("role", "user")},
                request=request,
            )

            ctx.logger.info(f"用户登录成功: {req.username} (role={user.get('role', 'user')})")
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
    def logout(request: Request, authorization: str = Header(None)):
        """管理员登出"""
        # 简单实现：客户端删除token即可
        # 如需token黑名单，可在sessions表标记revoked=True
        user_data = None
        try:
            if authorization:
                user_data = ctx.auth_service.get_current_user(authorization)
        except Exception:  # noqa: BLE001
            user_data = None

        ctx.log_system_op(
            "logout", "auth",
            user_id=user_data.get("user_id") if user_data else None,
            username=user_data.get("username") if user_data else None,
            details={"result": "success"},
            request=request,
        )
        return {"message": "登出成功"}

    @router.get("/admin/me")
    def get_current_user_info(authorization: str = Header(None)):
        """获取当前登录用户信息"""
        user_data = ctx.auth_service.get_current_user(authorization)
        return {"user": user_data}

    @router.post("/admin/change_password")
    def change_password(request: Request, req: ChangePasswordRequest, authorization: str = Header(None)):
        """修改当前登录管理员密码"""
        user_data = ctx.auth_service.get_current_user(authorization)
        user_id = user_data["user_id"]
        username = user_data.get("username")

        admin_users = ctx.tbl["admin_users"]

        with Session(ctx.engine) as session:
            row = session.execute(
                select(admin_users).where(admin_users.c.id == user_id)
            ).mappings().first()

            if not row:
                raise HTTPException(status_code=404, detail="用户不存在")

            if not ctx.auth_service.verify_password(req.old_password, row["password_hash"]):
                ctx.log_system_op(
                    "change_password", "auth",
                    user_id=user_id, username=username,
                    details={"result": "failed", "reason": "原密码错误"},
                    request=request,
                )
                raise HTTPException(status_code=400, detail="原密码错误")

            if not req.new_password:
                raise HTTPException(status_code=400, detail="新密码不能为空")

            new_hash = ctx.auth_service.hash_password(req.new_password)

            session.execute(
                update(admin_users)
                .where(admin_users.c.id == user_id)
                .values(password_hash=new_hash)
            )
            session.commit()

        ctx.log_system_op(
            "change_password", "auth",
            user_id=user_id, username=username,
            details={"result": "success"},
            request=request,
        )
        return {"ok": True}

    return router
