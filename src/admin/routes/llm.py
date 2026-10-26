"""大模型配置与调用日志接口"""
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ...security.secret import encrypt_text
from ...timezone_util import serialize_row
from ..context import AdminContext
from ..schemas import UpdateLLMConfigRequest


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/llm_configs")
    def get_llm_configs(authorization: str = Header(None)):
        """获取所有 LLM 配置列表"""
        # 需要管理员权限
        ctx.auth_service.require_admin(authorization)

        llm_configs = ctx.tbl["llm_configs"]

        with Session(ctx.engine) as session:
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
    def update_llm_config(request: Request, config_id: int, req: UpdateLLMConfigRequest, authorization: str = Header(None)):
        """更新指定的 LLM 配置"""
        user = ctx.auth_service.require_admin(authorization)

        llm_configs = ctx.tbl["llm_configs"]

        with Session(ctx.engine) as session:
            existing = session.execute(select(llm_configs).where(llm_configs.c.id == config_id)).mappings().first()
            if not existing:
                raise HTTPException(status_code=404, detail="配置不存在")

            update_data = {
                "base_url": req.base_url,
                "model_name": req.model_name
            }

            if req.api_key and req.api_key.strip():
                update_data["api_key_enc"] = encrypt_text(req.api_key.strip(), ctx.cfg.security.master_key)

            session.execute(
                update(llm_configs)
                .where(llm_configs.c.id == config_id)
                .values(**update_data)
            )
            session.commit()

        from ...ai.service import reset_llm_client
        reset_llm_client()

        # 记录系统操作日志（不记录密钥明文）
        ctx.log_system_op(
            "update_llm_config", "llm_config",
            user_id=user.get("user_id"), username=user.get("username"),
            resource_id=config_id,
            details={
                "base_url": req.base_url,
                "model_name": req.model_name,
                "has_api_key": bool(req.api_key and req.api_key.strip()),
            },
            request=request,
        )

        return {"ok": True, "message": "配置已更新"}

    @router.post("/admin/llm_configs/{config_id}/activate")
    def activate_llm_config(request: Request, config_id: int, authorization: str = Header(None)):
        """激活指定的 LLM 配置"""
        user = ctx.auth_service.require_admin(authorization)

        llm_configs = ctx.tbl["llm_configs"]

        with Session(ctx.engine) as session:
            existing = session.execute(select(llm_configs).where(llm_configs.c.id == config_id)).mappings().first()
            if not existing:
                raise HTTPException(status_code=404, detail="配置不存在")
            if not existing.get("api_key_enc"):
                raise HTTPException(status_code=400, detail="请先配置 API Key 后再激活")

            session.execute(update(llm_configs).values(is_active=False))
            # 激活指定的配置
            session.execute(update(llm_configs).where(llm_configs.c.id == config_id).values(is_active=True))
            session.commit()

        from ..llm_active import ensure_single_llm_active
        ensure_single_llm_active(ctx.engine)
        from ...ai.service import reset_llm_client
        reset_llm_client()

        # 记录系统操作日志
        ctx.log_system_op(
            "activate_llm_config", "llm_config",
            user_id=user.get("user_id"), username=user.get("username"),
            resource_id=config_id,
            details={"provider": existing.get("provider"), "model_name": existing.get("model_name")},
            request=request,
        )

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
        current_user = ctx.auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        offset = (page - 1) * page_size

        from sqlalchemy import desc, func
        from datetime import datetime

        logs = ctx.tbl["llm_call_logs"]
        with Session(ctx.engine) as s:
            allowed_aks = None
            if user_role != "admin":
                allowed_aks = s.execute(
                    select(ctx.tbl["access_keys"].c.ak)
                    .join(ctx.tbl["access_key_users"], ctx.tbl["access_keys"].c.id == ctx.tbl["access_key_users"].c.key_id)
                    .where(ctx.tbl["access_key_users"].c.user_id == user_id)
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
            "page_size": page_size,
        }

    @router.get("/admin/llm_call_logs/daily")
    def list_llm_call_logs_daily(
        days: int = 14,
        authorization: str = Header(None),
    ):
        """按日汇总 Token 消耗（管理员看全部，普通用户只看自己有权密钥）"""
        current_user = ctx.auth_service.get_current_user(authorization)
        user_id = current_user["user_id"]
        user_role = current_user.get("role", "user")

        days = min(max(1, days), 90)

        from sqlalchemy import func, cast, Date
        from datetime import timedelta
        from ...timezone_util import now_app

        logs = ctx.tbl["llm_call_logs"]
        since = now_app() - timedelta(days=days)

        with Session(ctx.engine) as s:
            allowed_aks = None
            if user_role != "admin":
                allowed_aks = s.execute(
                    select(ctx.tbl["access_keys"].c.ak)
                    .join(ctx.tbl["access_key_users"], ctx.tbl["access_keys"].c.id == ctx.tbl["access_key_users"].c.key_id)
                    .where(ctx.tbl["access_key_users"].c.user_id == user_id)
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

    return router
