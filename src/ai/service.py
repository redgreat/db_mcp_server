"""
项目内统一大模型调用入口。

用法:
    from src.ai.service import is_llm_enabled, llm_ask, llm_ask_json

    if is_llm_enabled():
        text = llm_ask(system_prompt, user_prompt)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional, TypeVar

from .llm_client import LLMClient

logger = logging.getLogger(__name__)

_client: Optional[LLMClient] = None
T = TypeVar("T")


def reset_llm_client() -> None:
    """配置变更后清除缓存（激活新模型后调用）。"""
    global _client
    _client = None


def get_llm_client() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client


def is_llm_enabled() -> bool:
    return get_llm_client().is_enabled()


def get_active_llm_info() -> Optional[Dict[str, Any]]:
    """返回当前激活模型信息（不含密钥）。"""
    c = get_llm_client()
    if not c.is_enabled() or not c.active_config:
        return None
    cfg = c.active_config
    return {
        "provider": cfg.get("provider"),
        "model_name": cfg.get("model_name"),
        "base_url": cfg.get("base_url"),
    }


def llm_ask(
    system_prompt: str,
    user_prompt: str,
    *,
    temperature: float = 0.2,
    tool_name: Optional[str] = None,
    call_source: Optional[str] = None,
) -> str:
    """
    调用当前激活的大模型，返回文本内容。
    未配置时抛出异常，由调用方捕获或先用 is_llm_enabled() 判断。
    """
    client = get_llm_client()
    if not client.is_enabled():
        raise RuntimeError("大模型未启用：请在管理后台「大模型配置」中激活并填写 API Key")

    # temperature 暂由 LLMClient 内部固定；后续可扩展
    result = llm_ask_with_usage(system_prompt, user_prompt, tool_name=tool_name, call_source=call_source)
    return result.get("content") or ""


def llm_ask_with_usage(
    system_prompt: str,
    user_prompt: str,
    *,
    tool_name: Optional[str] = None,
    call_source: Optional[str] = None,
) -> Dict[str, Any]:
    """返回 { content, usage }。"""
    import time

    from ..logging.llm_call_logger import get_llm_call_logger
    from .context import get_llm_log_context

    client = get_llm_client()
    if not client.is_enabled():
        raise RuntimeError("大模型未启用")

    ctx = get_llm_log_context()
    access_key = ctx.get("access_key")
    connection_id = ctx.get("connection_id")
    src = call_source or ctx.get("call_source") or ("tool" if tool_name else "internal")
    tname = tool_name or ctx.get("tool_name")
    cfg = client.active_config or {}
    provider = cfg.get("provider", "")
    model = cfg.get("model_name", "")
    config_id = cfg.get("id")

    started = time.time()
    try:
        result = client.ask(system_prompt, user_prompt)
        usage = result.get("usage") or {}
        get_llm_call_logger().log_call(
            provider=provider,
            model_name=model,
            llm_config_id=config_id,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            total_tokens=int(usage.get("total_tokens") or 0),
            duration_ms=int((time.time() - started) * 1000),
            status="success",
            access_key=access_key,
            call_source=src,
            tool_name=tname,
            connection_id=connection_id,
        )
        return result
    except Exception as e:
        get_llm_call_logger().log_call(
            provider=provider,
            model_name=model,
            llm_config_id=config_id,
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            duration_ms=int((time.time() - started) * 1000),
            status="error",
            access_key=access_key,
            call_source=src,
            tool_name=tname,
            connection_id=connection_id,
            error_message=str(e),
        )
        raise


def _extract_json_text(raw: str) -> str:
    text = (raw or "").strip()
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.I)
    if m:
        return m.group(1).strip()
    return text


def llm_ask_json(
    system_prompt: str,
    user_prompt: str,
    *,
    default: Optional[T] = None,
) -> Any:
    """要求模型返回 JSON，解析失败时返回 default。"""
    sys = (
        system_prompt.rstrip()
        + "\n\n请仅输出合法 JSON，不要 Markdown 代码块外的说明文字。"
    )
    try:
        raw = llm_ask(sys, user_prompt)
        return json.loads(_extract_json_text(raw))
    except Exception as e:
        logger.warning("llm_ask_json 解析失败: %s", e)
        if default is not None:
            return default
        raise


def llm_disabled_message() -> str:
    return "⚠️ AI 未启用：请在管理后台「大模型配置」中激活提供商并填写 API Key。"
