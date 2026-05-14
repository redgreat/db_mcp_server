from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import Dict, Any


def get_schema_detail(eng: Engine, database: str, db_type: str = "mysql") -> Dict[str, Any]:
    """获取数据库完整 Schema 信息（表+字段+索引+外键）"""
    tables = {}

    if db_type.lower() == "postgresql":
        schema = "public" if database == "public" else database

        col_sql = """
            SELECT c.table_name, c.column_name, c.data_type,
                   c.character_maximum_length, c.numeric_precision, c.numeric_scale,
                   c.is_nullable, c.column_default,
                   COALESCE(pgd.description, '') AS column_comment
            FROM information_schema.columns c
            LEFT JOIN pg_catalog.pg_statio_all_tables st
                ON st.schemaname = c.table_schema AND st.relname = c.table_name
            LEFT JOIN pg_catalog.pg_description pgd
                ON pgd.objoid = st.relid AND pgd.objsubid = c.ordinal_position
            WHERE c.table_schema = :schema
            ORDER BY c.table_name, c.ordinal_position
        """
        idx_sql = """
            SELECT tablename AS table_name, indexname AS index_name, indexdef AS index_def
            FROM pg_indexes WHERE schemaname = :schema
        """
        fk_sql = """
            SELECT tc.table_name AS from_table, kcu.column_name AS from_column,
                   ccu.table_name AS to_table, ccu.column_name AS to_column,
                   tc.constraint_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage ccu
                ON tc.constraint_name = ccu.constraint_name AND tc.table_schema = ccu.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = :schema
        """

        with eng.connect() as conn:
            cols = conn.execute(text(col_sql), {"schema": schema}).mappings().all()
            idxs = conn.execute(text(idx_sql), {"schema": schema}).mappings().all()
            fks = conn.execute(text(fk_sql), {"schema": schema}).mappings().all()
    else:
        col_sql = """
            SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name,
                   DATA_TYPE AS data_type, CHARACTER_MAXIMUM_LENGTH AS character_maximum_length,
                   NUMERIC_PRECISION AS numeric_precision, NUMERIC_SCALE AS numeric_scale,
                   IS_NULLABLE AS is_nullable, COLUMN_DEFAULT AS column_default,
                   COALESCE(COLUMN_COMMENT, '') AS column_comment
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = :db ORDER BY TABLE_NAME, ORDINAL_POSITION
        """
        idx_sql = """
            SELECT TABLE_NAME AS table_name, INDEX_NAME AS index_name,
                   COLUMN_NAME AS column_name, NON_UNIQUE AS non_unique,
                   INDEX_TYPE AS index_type, SEQ_IN_INDEX AS seq
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = :db ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
        """
        fk_sql = """
            SELECT TABLE_NAME AS from_table, COLUMN_NAME AS from_column,
                   REFERENCED_TABLE_NAME AS to_table, REFERENCED_COLUMN_NAME AS to_column,
                   CONSTRAINT_NAME AS constraint_name
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = :db AND REFERENCED_TABLE_NAME IS NOT NULL
        """

        with eng.connect() as conn:
            cols = conn.execute(text(col_sql), {"db": database}).mappings().all()
            idxs = conn.execute(text(idx_sql), {"db": database}).mappings().all()
            fks = conn.execute(text(fk_sql), {"db": database}).mappings().all()

    for c in cols:
        tname = c["table_name"]
        if tname not in tables:
            tables[tname] = {"columns": [], "indexes": {}, "foreign_keys": []}
        tables[tname]["columns"].append({
            "name": c["column_name"],
            "type": c["data_type"],
            "max_length": c.get("character_maximum_length"),
            "precision": c.get("numeric_precision"),
            "scale": c.get("numeric_scale"),
            "nullable": c["is_nullable"],
            "default": str(c["column_default"]) if c.get("column_default") else None,
            "comment": c.get("column_comment", "")
        })

    for idx in idxs:
        tname = idx["table_name"]
        if tname not in tables:
            continue
        iname = idx["index_name"]
        if db_type.lower() == "postgresql":
            tables[tname]["indexes"][iname] = {"definition": idx["index_def"]}
        else:
            if iname not in tables[tname]["indexes"]:
                tables[tname]["indexes"][iname] = {
                    "columns": [], "unique": not idx["non_unique"], "type": idx["index_type"]
                }
            tables[tname]["indexes"][iname]["columns"].append(idx["column_name"])

    for fk in fks:
        tname = fk["from_table"]
        if tname in tables:
            tables[tname]["foreign_keys"].append(dict(fk))

    return tables


def compare_schemas(
    eng_source: Engine, db_source: str, db_type_source: str,
    eng_target: Engine, db_target: str, db_type_target: str
) -> Dict[str, Any]:
    """对比两个数据库的 Schema 差异"""
    src = get_schema_detail(eng_source, db_source, db_type_source)
    tgt = get_schema_detail(eng_target, db_target, db_type_target)

    src_tables = set(src.keys())
    tgt_tables = set(tgt.keys())

    result = {
        "source": {"database": db_source, "db_type": db_type_source, "table_count": len(src_tables)},
        "target": {"database": db_target, "db_type": db_type_target, "table_count": len(tgt_tables)},
        "only_in_source": sorted(src_tables - tgt_tables),
        "only_in_target": sorted(tgt_tables - src_tables),
        "column_diffs": [],
        "index_diffs": []
    }

    common = src_tables & tgt_tables
    for tname in sorted(common):
        src_cols = {c["name"]: c for c in src[tname]["columns"]}
        tgt_cols = {c["name"]: c for c in tgt[tname]["columns"]}

        s_names = set(src_cols.keys())
        t_names = set(tgt_cols.keys())

        for col in sorted(s_names - t_names):
            result["column_diffs"].append({
                "table": tname, "column": col, "diff": "only_in_source",
                "source": src_cols[col]
            })
        for col in sorted(t_names - s_names):
            result["column_diffs"].append({
                "table": tname, "column": col, "diff": "only_in_target",
                "target": tgt_cols[col]
            })
        for col in sorted(s_names & t_names):
            sc, tc = src_cols[col], tgt_cols[col]
            diffs = {}
            if sc["type"] != tc["type"]:
                diffs["type"] = {"source": sc["type"], "target": tc["type"]}
            if sc["nullable"] != tc["nullable"]:
                diffs["nullable"] = {"source": sc["nullable"], "target": tc["nullable"]}
            if sc.get("max_length") != tc.get("max_length"):
                diffs["max_length"] = {"source": sc.get("max_length"), "target": tc.get("max_length")}
            if diffs:
                result["column_diffs"].append({
                    "table": tname, "column": col, "diff": "modified", "details": diffs
                })

        s_idx = set(src[tname]["indexes"].keys())
        t_idx = set(tgt[tname]["indexes"].keys())
        for idx in sorted(s_idx - t_idx):
            result["index_diffs"].append({"table": tname, "index": idx, "diff": "only_in_source"})
        for idx in sorted(t_idx - s_idx):
            result["index_diffs"].append({"table": tname, "index": idx, "diff": "only_in_target"})

    return result


def generate_sync_ddl(comparison: Dict[str, Any], target_db_type: str = "mysql") -> str:
    """根据对比结果生成同步 DDL"""
    ddl = []
    db_type = target_db_type.lower()

    for tname in comparison.get("only_in_source", []):
        ddl.append(f"-- 表 {tname} 仅存在于源库，需在目标库创建")
        ddl.append(f"-- 请从源库导出 CREATE TABLE {tname} 语句并在目标库执行")
        ddl.append("")

    for diff in comparison.get("column_diffs", []):
        tname = diff["table"]
        col = diff["column"]
        if diff["diff"] == "only_in_source":
            sc = diff["source"]
            col_type = sc["type"]
            if sc.get("max_length"):
                col_type += f"({sc['max_length']})"
            elif sc.get("precision"):
                col_type += f"({sc['precision']}"
                if sc.get("scale"):
                    col_type += f",{sc['scale']}"
                col_type += ")"
            nullable = "" if sc["nullable"] == "YES" else " NOT NULL"
            default = f" DEFAULT {sc['default']}" if sc.get("default") else ""
            ddl.append(f"ALTER TABLE {tname} ADD COLUMN {col} {col_type}{nullable}{default};")
            if sc.get("comment") and db_type == "postgresql":
                ddl.append(f"COMMENT ON COLUMN {tname}.{col} IS '{sc['comment']}';")
        elif diff["diff"] == "modified":
            details = diff.get("details", {})
            parts = []
            if "type" in details:
                parts.append(f"类型: {details['type']['source']} → {details['type']['target']}")
            if "nullable" in details:
                parts.append(f"可空: {details['nullable']['source']} → {details['nullable']['target']}")
            if "max_length" in details:
                parts.append(f"长度: {details['max_length']['source']} → {details['max_length']['target']}")
            ddl.append(f"-- {tname}.{col} 差异: {', '.join(parts)}")
            if "type" in details or "max_length" in details:
                new_type = details.get("type", {}).get("source", "")
                if new_type:
                    if db_type == "postgresql":
                        ddl.append(f"ALTER TABLE {tname} ALTER COLUMN {col} TYPE {new_type};")
                    else:
                        ddl.append(f"ALTER TABLE {tname} MODIFY COLUMN {col} {new_type};")

    for tname in comparison.get("only_in_target", []):
        ddl.append(f"-- 表 {tname} 仅存在于目标库（源库中不存在），如需删除:")
        ddl.append(f"-- DROP TABLE IF EXISTS {tname};")
        ddl.append("")

    return "\n".join(ddl) if ddl else "-- 两个数据库 Schema 完全一致，无需同步"
