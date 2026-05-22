"""管理库表结构缓存，避免每次 API 请求 autoload_with 反射（约 2–5s）。"""
from __future__ import annotations

from sqlalchemy import MetaData, Table
from sqlalchemy.engine import Engine

# 管理库全部业务表
ADMIN_TABLE_NAMES = (
    "admin_users",
    "access_keys",
    "access_key_users",
    "db_connections",
    "permissions",
    "whitelist",
    "audit_logs",
    "system_logs",
    "sessions",
    "db_rules",
    "llm_configs",
)


class AdminTables:
    def __init__(self, engine: Engine):
        self.engine = engine
        self.meta = MetaData()
        self._cache: dict[str, Table] = {}

    def __getitem__(self, name: str) -> Table:
        if name not in self._cache:
            self._cache[name] = Table(name, self.meta, autoload_with=self.engine)
        return self._cache[name]

    def preload_all(self) -> None:
        for name in ADMIN_TABLE_NAMES:
            self[name]


_instances: dict[int, AdminTables] = {}


def get_admin_tables(engine: Engine) -> AdminTables:
    key = id(engine)
    if key not in _instances:
        inst = AdminTables(engine)
        inst.preload_all()
        _instances[key] = inst
    return _instances[key]
