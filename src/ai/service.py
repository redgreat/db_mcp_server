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
) -> str:
    """
    调用当前激活的大模型，返回文本内容。
    未配置时抛出异常，由调用方捕获或先用 is_llm_enabled() 判断。
    """
    client = get_llm_client()
    if not client.is_enabled():
        raise RuntimeError("大模型未启用：请在管理后台「大模型配置」中激活并填写 API Key")

    # temperature 暂由 LLMClient 内部固定；后续可扩展
    result = client.ask(system_prompt, user_prompt)
    return result.get("content") or ""


def llm_ask_with_usage(system_prompt: str, user_prompt: str) -> Dict[str, Any]:
    """返回 { content, usage }。"""
    client = get_llm_client()
    if not client.is_enabled():
        raise RuntimeError("大模型未启用")
    return client.ask(system_prompt, user_prompt)


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
