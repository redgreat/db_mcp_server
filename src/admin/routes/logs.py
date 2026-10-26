"""日志查询接口：数据库操作审计日志 + 系统操作日志"""
from typing import Optional

from fastapi import APIRouter, Header
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...timezone_util import serialize_row
from ..context import AdminContext


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/audit/logs")
    def list_audit_logs(
        page: int = 1,
        page_size: int = 50,
        access_key: Optional[str] = None,
        operation: Optional[str] = None,
        min_duration_ms: Optional[int] = None,
        authorization: str = Header(None)
    ):
        """查询审计日志（管理员看全部，普通用户只看自己有权密钥的日志）"""
        current_user = ctx.auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import desc, func

        audit_logs = ctx.tbl["audit_logs"]

        with Session(ctx.engine) as s:
            # 普通用户：只看分配给自己密钥的日志
            allowed_aks = None
            if user_role != "admin":
                allowed_aks = s.execute(
                    select(ctx.tbl["access_keys"].c.ak)
                    .join(ctx.tbl["access_key_users"], ctx.tbl["access_keys"].c.id == ctx.tbl["access_key_users"].c.key_id)
                    .where(ctx.tbl["access_key_users"].c.user_id == user_id)
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
            if min_duration_ms is not None and min_duration_ms >= 0:
                query = query.where(audit_logs.c.duration_ms >= min_duration_ms)
                count_stmt = count_stmt.where(audit_logs.c.duration_ms >= min_duration_ms)

            total = s.execute(count_stmt).scalar()
            rows = s.execute(query.offset(offset).limit(page_size)).mappings().all()

        # 关联访问密钥描述（实时关联：修改密钥描述后历史日志同步生效）
        desc_map = ctx.fetch_key_descriptions(r["access_key"] for r in rows)
        items = []
        for r in rows:
            item = serialize_row(r)
            item["access_key_description"] = desc_map.get(r["access_key"]) or None
            items.append(item)

        return {
            "items": items,
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
        ctx.auth_service.require_admin(authorization)  # 仅管理员可访问

        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import desc, func

        system_logs = ctx.tbl["system_logs"]

        with Session(ctx.engine) as s:
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
