from typing import Dict, Any, Optional, List
from sqlalchemy.engine import Engine
from sqlalchemy import text


def run_select(eng: Engine, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """执行只读查询并返回结果"""
    with eng.connect() as conn:
        rs = conn.execute(text(sql), params or {})
        return [dict(r._mapping) for r in rs]

