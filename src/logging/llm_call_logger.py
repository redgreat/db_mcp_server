"""大模型调用日志（Token 消耗、访问密钥、调用来源）。"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy import insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ..timezone_util import now_app

logger = logging.getLogger(__name__)

_instance: Optional["LlmCallLogger"] = None


class LlmCallLogger:
    def __init__(self, engine: Engine):
        self.engine = engine
        from ..admin.schema_cache import get_admin_tables

        self._tbl = get_admin_tables(engine)

    def log_call(
        self,
        *,
        provider: str,
        model_name: str,
        llm_config_id: Optional[int],
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        status: str,
        duration_ms: Optional[int] = None,
        access_key: Optional[str] = None,
        call_source: Optional[str] = None,
        tool_name: Optional[str] = None,
        connection_id: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> None:
        try:
            logs = self._tbl["llm_call_logs"]
            with Session(self.engine) as session:
                session.execute(
                    insert(logs).values(
                        timestamp=now_app(),
                        llm_config_id=llm_config_id,
                        provider=provider,
                        model_name=model_name,
                        access_key=(access_key[:128] if access_key else None),
                        call_source=(call_source or "internal")[:64],
                        tool_name=(tool_name[:100] if tool_name else None),
                        connection_id=connection_id,
                        prompt_tokens=prompt_tokens or 0,
                        completion_tokens=completion_tokens or 0,
                        total_tokens=total_tokens or 0,
                        duration_ms=duration_ms,
                        status=status,
                        error_message=(error_message[:2000] if error_message else None),
                    )
                )
                session.commit()
        except Exception as e:
            logger.warning("大模型调用日志写入失败: %s", e)


def get_llm_call_logger(engine: Optional[Engine] = None) -> LlmCallLogger:
    global _instance
    if _instance is None:
        if engine is None:
            from sqlalchemy import create_engine
            from ..config import Config

            cfg = Config.load()
            engine = create_engine(cfg.get_admin_db_url(), pool_pre_ping=True)
        _instance = LlmCallLogger(engine)
    return _instance
