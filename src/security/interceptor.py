from typing import Dict, Any
from .sql_analyzer import is_safe_sql, risk_score


def intercept_sql(sql: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    """拦截与分析SQL安全"""
    safe = is_safe_sql(sql)
    score = risk_score(sql)
    return {"safe": safe, "risk": score}

