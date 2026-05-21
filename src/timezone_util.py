"""应用统一使用东八区（Asia/Shanghai）时间。"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

try:
    from zoneinfo import ZoneInfo

    APP_TZ = ZoneInfo("Asia/Shanghai")
except Exception:
    # Windows 等环境未安装 tzdata 时使用固定 UTC+8
    APP_TZ = timezone(timedelta(hours=8), name="Asia/Shanghai")

UTC = timezone.utc


def now_app() -> datetime:
    """当前时间（带 Asia/Shanghai 时区）。"""
    return datetime.now(APP_TZ)


def assume_utc_if_naive(dt: datetime) -> datetime:
    """历史数据可能为 naive UTC，补齐为 aware UTC。"""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def to_app_timezone(dt: datetime) -> datetime:
    """将任意 aware/naive 时间转为东八区。"""
    return assume_utc_if_naive(dt).astimezone(APP_TZ)


def to_api_iso(dt: Optional[datetime]) -> Optional[str]:
    """API 返回用 ISO 8601 字符串（东八区，含偏移）。"""
    if dt is None:
        return None
    return to_app_timezone(dt).isoformat()


def log_record_time(secs: float) -> time.struct_time:
    """logging.Formatter 用：将 epoch 秒格式化为东八区本地时间。"""
    return to_app_timezone(datetime.fromtimestamp(secs, tz=UTC)).timetuple()


def serialize_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """将 ORM/表行转为 dict，并把 datetime 字段格式化为东八区 ISO。"""
    out: dict[str, Any] = {}
    for k, v in row.items():
        if isinstance(v, datetime):
            out[k] = to_api_iso(v)
        else:
            out[k] = v
    return out
