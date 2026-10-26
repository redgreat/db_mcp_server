"""密钥 × 连接 权限授权接口"""
from fastapi import APIRouter, Header
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from ...timezone_util import serialize_row
from ..context import AdminContext


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/permissions")
    def list_permissions(authorization: str = Header(None)):
        """列出权限配置（需要登录，基于用户角色筛选）"""
        current_user = ctx.auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        permissions = ctx.tbl["permissions"]

        with Session(ctx.engine) as s:
            if user_role == "admin":
                # 管理员：返回所有权限
                rows = s.execute(select(permissions)).mappings().all()
            else:
                # 普通用户：只返回自己有权访问的密钥的权限
                key_users = ctx.tbl["access_key_users"]
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
        user_data = ctx.auth_service.require_admin(authorization)

        t = ctx.tbl["permissions"]
        with Session(ctx.engine) as s:
            s.execute(insert(t).values(
                key_id=key_id,
                connection_id=connection_id,
                select_only=select_only,
                allow_ddl=allow_ddl
            ))
            s.commit()

        # 记录系统日志
        ctx.system_logger.log(
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

        ctx.logger.info(
            f"创建权限: key={key_id} conn={connection_id} "
            f"select_only={select_only} allow_ddl={allow_ddl} by {user_data['username']}"
        )
        return {"ok": True}

    @router.delete("/admin/permissions/{perm_id}")
    def delete_permission(perm_id: int, authorization: str = Header(None)):
        """删除权限（仅管理员）"""
        user_data = ctx.auth_service.require_admin(authorization)

        t = ctx.tbl["permissions"]
        with Session(ctx.engine) as s:
            s.execute(delete(t).where(t.c.id == perm_id))
            s.commit()

        # 记录系统日志
        ctx.system_logger.log(
            operation="delete_permission",
            resource_type="permission",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=perm_id
        )

        ctx.logger.info(f"删除权限: id={perm_id} by {user_data['username']}")
        return {"ok": True}

    return router
