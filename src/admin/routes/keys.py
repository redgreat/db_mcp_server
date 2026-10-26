"""访问密钥与密钥-用户分配接口"""
from fastapi import APIRouter, Header, HTTPException, Request
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from ...timezone_util import serialize_row
from ..context import AdminContext, generate_access_key
from ..schemas import CreateKeyRequest


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/keys")
    def list_keys(
        page: int = 1,
        page_size: int = 10,
        authorization: str = Header(None)
    ):
        """列出访问密钥（需要登录，支持分页，基于用户角色筛选）"""
        current_user = ctx.auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import func

        keys = ctx.tbl["access_keys"]
        key_users = ctx.tbl["access_key_users"]

        with Session(ctx.engine) as s:
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
        user_data = ctx.auth_service.require_admin(authorization)

        keys = ctx.tbl["access_keys"]
        with Session(ctx.engine) as s:
            ak = (req.ak or "").strip()
            if not ak:
                for _ in range(5):
                    candidate = generate_access_key()
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
        ctx.system_logger.log(
            operation="create_key",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={"ak": ak, "description": req.description}
        )

        ctx.logger.info(f"创建访问密钥: {ak} by {user_data['username']}")
        return {"ok": True, "ak": ak}

    @router.patch("/admin/keys/{key_id}/description")
    async def update_key_description(
        key_id: int,
        request: Request,
        authorization: str = Header(None)
    ):
        """更新访问密钥描述"""
        user_data = ctx.auth_service.require_admin(authorization)
        body = await request.json()
        description = str(body.get("description", "") or "")
        keys = ctx.tbl["access_keys"]
        with Session(ctx.engine) as s:
            s.execute(
                update(keys)
                .where(keys.c.id == key_id)
                .values(description=description)
            )
            s.commit()
        ctx.system_logger.log(
            operation="update_key_description",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=key_id,
            details={"description": description}
        )
        ctx.logger.info(f"更新密钥描述: id={key_id} by {user_data['username']}")
        return {"ok": True}

    @router.patch("/admin/keys/{key_id}/sql_risk_check")
    async def update_key_sql_risk_check(
        key_id: int,
        request: Request,
        authorization: str = Header(None)
    ):
        """更新访问密钥的SQL风险监测开关（仅管理员）"""
        user_data = ctx.auth_service.require_admin(authorization)
        body = await request.json()
        enabled = bool(body.get("sql_risk_check_enabled", True))
        keys = ctx.tbl["access_keys"]
        with Session(ctx.engine) as s:
            s.execute(
                update(keys)
                .where(keys.c.id == key_id)
                .values(sql_risk_check_enabled=enabled)
            )
            s.commit()
        ctx.system_logger.log(
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
        user_data = ctx.auth_service.require_admin(authorization)

        # 从请求体获取 enabled 参数
        body = await request.json()
        enabled = body.get('enabled', True)

        keys = ctx.tbl["access_keys"]
        with Session(ctx.engine) as s:
            s.execute(
                update(keys)
                .where(keys.c.id == key_id)
                .values(enabled=enabled)
            )
            s.commit()

        # 记录系统日志
        ctx.system_logger.log(
            operation="toggle_key",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=key_id,
            details={"enabled": enabled}
        )

        ctx.logger.info(f"切换密钥状态: id={key_id} enabled={enabled} by {user_data['username']}")
        return {"ok": True}

    @router.delete("/admin/keys/{key_id}")
    def delete_key(key_id: int, authorization: str = Header(None)):
        """删除访问密钥（仅管理员）"""
        user_data = ctx.auth_service.require_admin(authorization)

        keys = ctx.tbl["access_keys"]
        with Session(ctx.engine) as s:
            s.execute(delete(keys).where(keys.c.id == key_id))
            s.commit()

        # 记录系统日志
        ctx.system_logger.log(
            operation="delete_key",
            resource_type="access_key",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=key_id
        )

        ctx.logger.info(f"删除密钥: id={key_id} by {user_data['username']}")
        return {"ok": True}

    # ==================== 密钥用户管理 ====================

    @router.get("/admin/keys/{key_id}/users")
    def list_key_users(key_id: int, authorization: str = Header(None)):
        """获取密钥已分配的用户列表（仅管理员）"""
        ctx.auth_service.require_admin(authorization)

        key_users = ctx.tbl["access_key_users"]
        admin_users = ctx.tbl["admin_users"]

        with Session(ctx.engine) as s:
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
        current_user = ctx.auth_service.require_admin(authorization)

        key_users = ctx.tbl["access_key_users"]

        # 从请求体获取用户ID列表
        body = await request.json()
        user_ids = body if isinstance(body, list) else body.get("user_ids", [])

        with Session(ctx.engine) as s:
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
        ctx.system_logger.log(
            operation="assign_key_users",
            resource_type="access_key",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=key_id,
            details={"user_ids": user_ids}
        )

        ctx.logger.info(f"为密钥 {key_id} 分配用户: {user_ids} by {current_user['username']}")
        return {"ok": True}

    @router.delete("/admin/keys/{key_id}/users/{user_id}")
    def remove_user_from_key(
        key_id: int,
        user_id: int,
        authorization: str = Header(None)
    ):
        """取消密钥对某用户的分配（仅管理员）"""
        current_user = ctx.auth_service.require_admin(authorization)

        key_users = ctx.tbl["access_key_users"]

        with Session(ctx.engine) as s:
            s.execute(
                delete(key_users).where(
                    key_users.c.key_id == key_id,
                    key_users.c.user_id == user_id
                )
            )
            s.commit()

        # 记录系统日志
        ctx.system_logger.log(
            operation="remove_key_user",
            resource_type="access_key",
            user_id=current_user["user_id"],
            username=current_user["username"],
            resource_id=key_id,
            details={"removed_user_id": user_id}
        )

        ctx.logger.info(f"取消密钥 {key_id} 对用户 {user_id} 的分配 by {current_user['username']}")
        return {"ok": True}

    return router
