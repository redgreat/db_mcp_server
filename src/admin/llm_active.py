"""保证全局仅有一个大模型配置处于激活状态。"""
from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


def ensure_single_llm_active(engine: Engine) -> None:
    from .schema_cache import get_admin_tables

    llm_configs = get_admin_tables(engine)["llm_configs"]
    with Session(engine) as session:
        rows = session.execute(
            select(llm_configs.c.id).where(llm_configs.c.is_active == True)  # noqa: E712
        ).all()
        if len(rows) <= 1:
            return
        keep_id = min(r[0] for r in rows)
        session.execute(update(llm_configs).values(is_active=False))
        session.execute(
            update(llm_configs).where(llm_configs.c.id == keep_id).values(is_active=True)
        )
        session.commit()
