"""IP 白名单管理接口"""
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...timezone_util import serialize_row
from ..context import AdminContext


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/whitelist")
    def list_whitelist(
        key_id: Optional[int] = None,
        authorization: str = Header(None)
    ):
        """列出白名单（需要登录，基于用户角色筛选）

        Args:
            key_id: 访问密钥ID（可选，不指定则返回所有）
        """
        current_user = ctx.auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        if user_role == "admin":
            # 管理员：返回所有白名单或指定key_id的白名单
            rules = ctx.ip_checker.list_whitelist(key_id=key_id)
        else:
            # 普通用户：只返回自己有权访问的密钥的白名单
            whitelist = ctx.tbl["whitelist"]
            key_users = ctx.tbl["access_key_users"]

            with Session(ctx.engine) as s:
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
        user_data = ctx.auth_service.require_admin(authorization)

        success = ctx.ip_checker.add_whitelist(key_id, cidr, description)
        if not success:
            raise HTTPException(status_code=400, detail="无效的CIDR格式")

        # 记录系统日志
        ctx.system_logger.log(
            operation="add_whitelist",
            resource_type="whitelist",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={"key_id": key_id, "cidr": cidr, "description": description}
        )

        ctx.logger.info(f"添加白名单: key_id={key_id} CIDR={cidr} by {user_data['username']}")
        return {"ok": True}

    @router.delete("/admin/whitelist/{whitelist_id}")
    def delete_whitelist(whitelist_id: int, authorization: str = Header(None)):
        """删除白名单规则（仅管理员）"""
        user_data = ctx.auth_service.require_admin(authorization)

        success = ctx.ip_checker.delete_whitelist(whitelist_id)
        if not success:
            raise HTTPException(status_code=404, detail="白名单规则不存在")

        # 记录系统日志
        ctx.system_logger.log(
            operation="delete_whitelist",
            resource_type="whitelist",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=whitelist_id
        )

        ctx.logger.info(f"删除白名单: id={whitelist_id} by {user_data['username']}")
        return {"ok": True}

    return router
