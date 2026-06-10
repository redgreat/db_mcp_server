import pytest

from src.security.sql_guard import ensure_read_only_sql, ensure_sql_allowed, is_ddl_sql, is_read_only_sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM users",
        " show tables",
        "/* comment */ EXPLAIN SELECT * FROM users",
        "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent",
        "SELECT ';' AS semi; SHOW TABLES",
    ],
)
def test_read_only_sql_allowed(sql):
    assert is_read_only_sql(sql)
    ensure_read_only_sql(sql)
    ensure_sql_allowed(sql, select_only=True, allow_ddl=False)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE users SET name = 'x' WHERE id = 1",
        "DELETE FROM users WHERE id = 1",
        "INSERT INTO users(id) VALUES (1)",
        "SELECT * FROM users; DELETE FROM users WHERE id = 1",
        "/* hidden */ UPDATE users SET name = 'x'",
    ],
)
def test_select_only_blocks_dml(sql):
    assert not is_read_only_sql(sql)
    with pytest.raises(PermissionError):
        ensure_read_only_sql(sql)
    with pytest.raises(PermissionError):
        ensure_sql_allowed(sql, select_only=True, allow_ddl=True)


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE users_bak AS SELECT * FROM users",
        "ALTER TABLE users ADD COLUMN age INT",
        "DROP TABLE users",
        "TRUNCATE TABLE users",
    ],
)
def test_ddl_requires_allow_ddl(sql):
    assert is_ddl_sql(sql)
    with pytest.raises(PermissionError):
        ensure_sql_allowed(sql, select_only=False, allow_ddl=False)
    ensure_sql_allowed(sql, select_only=False, allow_ddl=True)


def test_write_allowed_when_not_select_only_and_not_ddl():
    ensure_sql_allowed("UPDATE users SET name = 'x' WHERE id = 1", select_only=False, allow_ddl=False)
