"""大模型调用日志上下文（MCP 等入口可注入 access_key / tool_name）。"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, Optional

_llm_ctx: ContextVar[Dict[str, Any]] = ContextVar("llm_log_ctx", default={})


def get_llm_log_context() -> Dict[str, Any]:
    return dict(_llm_ctx.get())


@contextmanager
def llm_log_context(
    *,
    access_key: Optional[str] = None,
    call_source: Optional[str] = None,
    tool_name: Optional[str] = None,
    connection_id: Optional[int] = None,
) -> Iterator[None]:
    prev = _llm_ctx.get()
    merged = {**prev}
    if access_key is not None:
        merged["access_key"] = access_key
    if call_source is not None:
        merged["call_source"] = call_source
    if tool_name is not None:
        merged["tool_name"] = tool_name
    if connection_id is not None:
        merged["connection_id"] = connection_id
    token = _llm_ctx.set(merged)
    try:
        yield
    finally:
        _llm_ctx.reset(token)
