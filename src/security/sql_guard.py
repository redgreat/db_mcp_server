"""SQL permission classification helpers."""
import re
from typing import Iterable


DDL_KEYWORDS = {"CREATE", "DROP", "ALTER", "TRUNCATE", "RENAME"}
READ_ONLY_KEYWORDS = {
    "SELECT",
    "SHOW",
    "DESCRIBE",
    "DESC",
    "EXPLAIN",
    "WITH",
    "VALUES",
    "TABLE",
}
WRITE_KEYWORDS = {
    "INSERT",
    "UPDATE",
    "DELETE",
    "REPLACE",
    "MERGE",
    "UPSERT",
    "CALL",
    "EXEC",
    "EXECUTE",
    "USE",
    "SET",
    "GRANT",
    "REVOKE",
    "LOCK",
    "UNLOCK",
    "ANALYZE",
    "OPTIMIZE",
    "REPAIR",
    "VACUUM",
}

_SQL_LINE_COMMENT_RE = re.compile(r"--[^\n\r]*(?:[\n\r]|$)|#[^\n\r]*(?:[\n\r]|$)")
_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_FIRST_KEYWORD_RE = re.compile(r"^[\s;(]*([A-Z_]+)", re.IGNORECASE)


def strip_sql_comments(sql: str) -> str:
    """Remove SQL comments before keyword classification."""
    without_block = _SQL_BLOCK_COMMENT_RE.sub(" ", sql or "")
    return _SQL_LINE_COMMENT_RE.sub(" ", without_block).strip()


def split_sql_statements(sql: str) -> list[str]:
    """Split SQL on semicolons outside quoted strings."""
    cleaned = strip_sql_comments(sql)
    statements: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(cleaned):
        ch = cleaned[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                next_ch = cleaned[i + 1] if i + 1 < len(cleaned) else ""
                # SQL escapes a quote by doubling it, e.g. 'it''s'.
                if next_ch == quote:
                    buf.append(next_ch)
                    i += 1
                else:
                    quote = None
        else:
            if ch in ("'", '"', "`"):
                quote = ch
                buf.append(ch)
            elif ch == ";":
                stmt = "".join(buf).strip()
                if stmt:
                    statements.append(stmt)
                buf = []
            else:
                buf.append(ch)
        i += 1

    stmt = "".join(buf).strip()
    if stmt:
        statements.append(stmt)
    return statements


def first_sql_keyword(statement: str) -> str:
    """Return the first keyword in a SQL statement."""
    match = _FIRST_KEYWORD_RE.match(statement or "")
    return match.group(1).upper() if match else ""


def sql_keywords(sql: str) -> list[str]:
    """Return first keywords for all non-empty statements."""
    return [first_sql_keyword(stmt) for stmt in split_sql_statements(sql) if first_sql_keyword(stmt)]


def is_read_only_sql(sql: str) -> bool:
    """Return True only when every statement is classified as read-only."""
    keywords = sql_keywords(sql)
    return bool(keywords) and all(keyword in READ_ONLY_KEYWORDS for keyword in keywords)


def is_ddl_sql(sql: str) -> bool:
    """Return True if any statement is DDL."""
    return any(keyword in DDL_KEYWORDS for keyword in sql_keywords(sql))


def ensure_sql_allowed(
    sql: str,
    *,
    select_only: bool = True,
    allow_ddl: bool = False,
    read_only_error: str = "该连接仅允许 SELECT 查询，不允许执行修改操作",
    ddl_error: str = "该连接不允许执行 DDL 操作（CREATE/DROP/ALTER等）",
) -> None:
    """Raise PermissionError when SQL violates connection permission flags."""
    keywords = sql_keywords(sql)
    if not keywords:
        raise PermissionError("SQL 不能为空")

    ddl = any(keyword in DDL_KEYWORDS for keyword in keywords)
    read_only = all(keyword in READ_ONLY_KEYWORDS for keyword in keywords)

    if select_only and not read_only:
        raise PermissionError(read_only_error)

    if ddl and not allow_ddl:
        raise PermissionError(ddl_error)


def ensure_read_only_sql(sql: str, *, error: str = "该工具仅允许执行 SELECT/SHOW/DESCRIBE/EXPLAIN 等只读语句") -> None:
    """Raise PermissionError if SQL is not strictly read-only."""
    keywords = sql_keywords(sql)
    if not keywords:
        raise PermissionError("SQL 不能为空")
    if not all(keyword in READ_ONLY_KEYWORDS for keyword in keywords):
        raise PermissionError(error)
