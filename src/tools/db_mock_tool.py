from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any, Optional
import random
import string
import json
from datetime import datetime, timedelta


def get_table_constraints(eng: Engine, database: str, table: str, db_type: str = "mysql") -> Dict[str, Any]:
    """获取表的字段、约束等完整信息用于数据生成"""
    if db_type.lower() == "postgresql":
        schema = "public" if database == "public" else database
        col_sql = """
            SELECT c.column_name, c.data_type, c.character_maximum_length,
                   c.numeric_precision, c.numeric_scale, c.is_nullable,
                   c.column_default,
                   CASE WHEN pk.column_name IS NOT NULL THEN 'PRI' ELSE '' END AS column_key
            FROM information_schema.columns c
            LEFT JOIN (
                SELECT ku.column_name FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage ku
                    ON tc.constraint_name = ku.constraint_name AND tc.table_schema = ku.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                    AND tc.table_name = :tb AND tc.table_schema = :schema
            ) pk ON c.column_name = pk.column_name
            WHERE c.table_name = :tb AND c.table_schema = :schema
            ORDER BY c.ordinal_position
        """
        fk_sql = """
            SELECT kcu.column_name AS from_column, ccu.table_name AS to_table,
                   ccu.column_name AS to_column
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage ccu
                ON tc.constraint_name = ccu.constraint_name AND tc.table_schema = ccu.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
                AND tc.table_name = :tb AND tc.table_schema = :schema
        """
        uniq_sql = """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'UNIQUE'
                AND tc.table_name = :tb AND tc.table_schema = :schema
        """
        with eng.connect() as conn:
            cols = conn.execute(text(col_sql), {"tb": table, "schema": schema}).mappings().all()
            fks = conn.execute(text(fk_sql), {"tb": table, "schema": schema}).mappings().all()
            uniqs = conn.execute(text(uniq_sql), {"tb": table, "schema": schema}).mappings().all()
    else:
        col_sql = """
            SELECT COLUMN_NAME AS column_name, DATA_TYPE AS data_type,
                   CHARACTER_MAXIMUM_LENGTH AS character_maximum_length,
                   NUMERIC_PRECISION AS numeric_precision, NUMERIC_SCALE AS numeric_scale,
                   IS_NULLABLE AS is_nullable, COLUMN_DEFAULT AS column_default,
                   COLUMN_KEY AS column_key, EXTRA AS extra
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :tb
            ORDER BY ORDINAL_POSITION
        """
        fk_sql = """
            SELECT COLUMN_NAME AS from_column, REFERENCED_TABLE_NAME AS to_table,
                   REFERENCED_COLUMN_NAME AS to_column
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :tb AND REFERENCED_TABLE_NAME IS NOT NULL
        """
        uniq_sql = """
            SELECT COLUMN_NAME AS column_name
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :tb AND NON_UNIQUE = 0
                AND INDEX_NAME != 'PRIMARY'
        """
        with eng.connect() as conn:
            cols = conn.execute(text(col_sql), {"db": database, "tb": table}).mappings().all()
            fks = conn.execute(text(fk_sql), {"db": database, "tb": table}).mappings().all()
            uniqs = conn.execute(text(uniq_sql), {"db": database, "tb": table}).mappings().all()

    fk_map = {fk["from_column"]: {"table": fk["to_table"], "column": fk["to_column"]} for fk in fks}
    unique_cols = {u["column_name"] for u in uniqs}

    return {
        "columns": [dict(c) for c in cols],
        "foreign_keys": fk_map,
        "unique_columns": unique_cols
    }


def _get_fk_values(eng: Engine, ref_table: str, ref_column: str, count: int) -> List:
    """获取外键引用表的可用值"""
    with eng.connect() as conn:
        rows = conn.execute(
            text(f"SELECT {ref_column} FROM {ref_table} ORDER BY RANDOM() LIMIT :cnt"),
            {"cnt": count * 2}
        ).all()
        if not rows:
            rows = conn.execute(
                text(f"SELECT {ref_column} FROM {ref_table} LIMIT :cnt"),
                {"cnt": count * 2}
            ).all()
    return [r[0] for r in rows] if rows else []


def _generate_value(col: Dict, idx: int, fk_values: Optional[List] = None) -> str:
    """根据字段类型生成测试数据值"""
    dtype = col["data_type"].lower()
    cname = col["column_name"].lower()

    if fk_values:
        val = fk_values[idx % len(fk_values)] if fk_values else 1
        if isinstance(val, str):
            return f"'{val}'"
        return str(val)

    is_auto = col.get("extra", "")
    if "auto_increment" in str(is_auto).lower():
        return None
    if col.get("column_default") and "nextval" in str(col.get("column_default", "")).lower():
        return None

    if dtype in ("int", "integer", "bigint", "smallint", "tinyint", "mediumint"):
        if "phone" in cname or "mobile" in cname:
            return f"'1{random.randint(3000000000, 9999999999)}'"
        if "age" in cname:
            return str(random.randint(18, 65))
        if "status" in cname or "state" in cname:
            return str(random.choice([0, 1]))
        if "type" in cname:
            return str(random.randint(1, 5))
        return str(random.randint(1, 10000))

    elif dtype in ("decimal", "numeric", "float", "double", "real"):
        precision = int(col.get("numeric_precision") or 10)
        scale = int(col.get("numeric_scale") or 2)
        max_val = 10 ** (precision - scale) - 1
        val = round(random.uniform(0, min(max_val, 99999)), scale)
        return str(val)

    elif dtype in ("varchar", "char", "character varying", "text", "longtext", "mediumtext", "tinytext"):
        max_len = int(col.get("character_maximum_length") or 50)
        max_len = min(max_len, 50)
        if "email" in cname:
            user = ''.join(random.choices(string.ascii_lowercase, k=6))
            return f"'{user}@test.com'"
        if "name" in cname or "title" in cname:
            return f"'测试{idx + 1}'"
        if "url" in cname or "link" in cname:
            return f"'https://example.com/{idx}'"
        if "ip" in cname or "address" in cname and "email" not in cname:
            return f"'192.168.{random.randint(1, 254)}.{random.randint(1, 254)}'"
        gen_len = min(max_len, 10)
        val = ''.join(random.choices(string.ascii_letters + string.digits, k=gen_len))
        return f"'{val}'"

    elif dtype in ("date",):
        base = datetime(2024, 1, 1)
        d = base + timedelta(days=random.randint(0, 365))
        return f"'{d.strftime('%Y-%m-%d')}'"

    elif dtype in ("datetime", "timestamp", "timestamp without time zone", "timestamp with time zone"):
        base = datetime(2024, 1, 1)
        d = base + timedelta(days=random.randint(0, 365), hours=random.randint(0, 23),
                             minutes=random.randint(0, 59))
        return f"'{d.strftime('%Y-%m-%d %H:%M:%S')}'"

    elif dtype in ("time", "time without time zone"):
        return f"'{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}'"

    elif dtype in ("boolean", "bool", "bit"):
        return random.choice(["TRUE", "FALSE"])

    elif dtype in ("json", "jsonb"):
        obj = {"key": f"value_{idx}"}
        return f"'{json.dumps(obj, ensure_ascii=False)}'"

    elif dtype in ("uuid",):
        import uuid
        return f"'{uuid.uuid4()}'"

    else:
        return f"'test_{idx}'"


def generate_mock_data(eng: Engine, database: str, table: str,
                       db_type: str = "mysql", count: int = 10) -> Dict[str, Any]:
    """生成测试数据 INSERT 语句"""
    count = min(count, 100)
    constraints = get_table_constraints(eng, database, table, db_type)
    columns = constraints["columns"]
    fk_map = constraints["foreign_keys"]

    fk_values_cache = {}
    for col_name, ref in fk_map.items():
        try:
            fk_values_cache[col_name] = _get_fk_values(eng, ref["table"], ref["column"], count)
        except Exception:
            fk_values_cache[col_name] = []

    insert_columns = []
    for col in columns:
        val = _generate_value(col, 0, fk_values_cache.get(col["column_name"]))
        if val is not None:
            insert_columns.append(col)

    col_names = [c["column_name"] for c in insert_columns]
    inserts = []

    for i in range(count):
        values = []
        for col in insert_columns:
            fk_vals = fk_values_cache.get(col["column_name"])
            val = _generate_value(col, i, fk_vals)
            if val is None:
                val = "NULL"
            values.append(val)
        inserts.append(
            f"INSERT INTO {table} ({', '.join(col_names)}) VALUES ({', '.join(values)});"
        )

    return {
        "table": table,
        "database": database,
        "row_count": count,
        "column_count": len(col_names),
        "columns": col_names,
        "inserts": "\n".join(inserts),
        "foreign_key_refs": {k: v for k, v in fk_map.items()},
        "notes": [
            "已自动跳过自增主键字段",
            "外键字段已引用目标表的真实数据" if fk_map else "无外键约束",
            "请在执行前确认数据符合业务逻辑"
        ]
    }
