from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any, Optional
import re


def get_foreign_keys(eng: Engine, database: str, db_type: str = "mysql") -> List[Dict[str, str]]:
    """获取所有外键关系"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                tc.table_name AS from_table,
                kcu.column_name AS from_column,
                ccu.table_name AS to_table,
                ccu.column_name AS to_column,
                tc.constraint_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage ccu
                ON tc.constraint_name = ccu.constraint_name AND tc.table_schema = ccu.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = :schema
            ORDER BY tc.table_name
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    else:
        sql = """
            SELECT
                TABLE_NAME AS from_table,
                COLUMN_NAME AS from_column,
                REFERENCED_TABLE_NAME AS to_table,
                REFERENCED_COLUMN_NAME AS to_column,
                CONSTRAINT_NAME AS constraint_name
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = :db AND REFERENCED_TABLE_NAME IS NOT NULL
            ORDER BY TABLE_NAME
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    return [dict(r) for r in rows]


def get_table_columns_for_er(eng: Engine, database: str, db_type: str = "mysql") -> Dict[str, List[Dict[str, str]]]:
    """获取所有表的字段精简信息（用于 ER 图）"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                c.table_name,
                c.column_name,
                c.data_type,
                CASE WHEN pk.column_name IS NOT NULL THEN 'PK' ELSE '' END AS key_type,
                COALESCE(pgd.description, '') AS column_comment
            FROM information_schema.columns c
            LEFT JOIN pg_catalog.pg_statio_all_tables st
                ON st.schemaname = c.table_schema AND st.relname = c.table_name
            LEFT JOIN pg_catalog.pg_description pgd
                ON pgd.objoid = st.relid AND pgd.objsubid = c.ordinal_position
            LEFT JOIN (
                SELECT ku.table_name, ku.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage ku
                    ON tc.constraint_name = ku.constraint_name AND tc.table_schema = ku.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = :schema
            ) pk ON c.table_name = pk.table_name AND c.column_name = pk.column_name
            WHERE c.table_schema = :schema
            ORDER BY c.table_name, c.ordinal_position
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    else:
        sql = """
            SELECT
                c.TABLE_NAME AS table_name,
                c.COLUMN_NAME AS column_name,
                c.DATA_TYPE AS data_type,
                CASE WHEN c.COLUMN_KEY = 'PRI' THEN 'PK' ELSE '' END AS key_type,
                COALESCE(c.COLUMN_COMMENT, '') AS column_comment
            FROM information_schema.COLUMNS c
            WHERE c.TABLE_SCHEMA = :db
            ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    result = {}
    for r in rows:
        tname = r["table_name"]
        if tname not in result:
            result[tname] = []
        result[tname].append({
            "column_name": r["column_name"],
            "data_type": r["data_type"],
            "key_type": r["key_type"],
            "comment": r["column_comment"]
        })
    return result


def analyze_implicit_relationships(table_columns: Dict[str, List[Dict]], existing_fks: List[Dict]) -> List[Dict[str, str]]:
    """分析命名约定推断隐含关系（如 user_id → users）"""
    all_tables = set(table_columns.keys())
    existing_pairs = {(fk["from_table"], fk["from_column"]) for fk in existing_fks}
    implicit = []

    for table, cols in table_columns.items():
        for col in cols:
            cname = col["column_name"]
            if (table, cname) in existing_pairs:
                continue
            if not cname.endswith("_id"):
                continue
            ref_base = cname[:-3]
            candidates = [ref_base, ref_base + "s", ref_base + "es"]
            for candidate in candidates:
                if candidate in all_tables and candidate != table:
                    implicit.append({
                        "from_table": table,
                        "from_column": cname,
                        "to_table": candidate,
                        "to_column": "id",
                        "inferred": True
                    })
                    break

    return implicit


def generate_er_mermaid(eng: Engine, database: str, db_type: str = "mysql",
                        include_columns: bool = True,
                        include_implicit: bool = True) -> Dict[str, Any]:
    """生成 Mermaid erDiagram 代码"""
    table_columns = get_table_columns_for_er(eng, database, db_type)
    fks = get_foreign_keys(eng, database, db_type)
    implicit_rels = []
    if include_implicit:
        implicit_rels = analyze_implicit_relationships(table_columns, fks)

    lines = ["erDiagram"]

    def safe_name(name: str) -> str:
        return re.sub(r'[^a-zA-Z0-9_]', '_', name)

    if include_columns:
        for tname, cols in table_columns.items():
            sname = safe_name(tname)
            lines.append(f"    {sname} {{")
            for col in cols:
                dtype = re.sub(r'[^a-zA-Z0-9]', '_', col["data_type"])
                pk_mark = "PK" if col["key_type"] == "PK" else ""
                comment = col["comment"][:30].replace('"', "'") if col["comment"] else ""
                if pk_mark and comment:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark} "{comment}"')
                elif pk_mark:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark}')
                elif comment:
                    lines.append(f'        {dtype} {col["column_name"]} "{comment}"')
                else:
                    lines.append(f'        {dtype} {col["column_name"]}')
            lines.append("    }")

    for fk in fks:
        from_t = safe_name(fk["from_table"])
        to_t = safe_name(fk["to_table"])
        label = fk.get("constraint_name", f'{fk["from_column"]}')
        lines.append(f'    {to_t} ||--o{{ {from_t} : "{label}"')

    for rel in implicit_rels:
        from_t = safe_name(rel["from_table"])
        to_t = safe_name(rel["to_table"])
        lines.append(f'    {to_t} ||--o{{ {from_t} : "{rel["from_column"]}(推断)"')

    mermaid_code = "\n".join(lines)

    return {
        "mermaid": mermaid_code,
        "table_count": len(table_columns),
        "explicit_relationships": len(fks),
        "implicit_relationships": len(implicit_rels),
        "tables": list(table_columns.keys())
    }


def generate_er_text_description(eng: Engine, database: str, db_type: str = "mysql",
                                  include_implicit: bool = True) -> str:
    """生成实体关系的文字描述"""
    table_columns = get_table_columns_for_er(eng, database, db_type)
    fks = get_foreign_keys(eng, database, db_type)

    lines = [f"# 数据库 {database} 实体关系描述\n"]
    lines.append(f"共 {len(table_columns)} 张表，{len(fks)} 个显式外键关系。\n")

    lines.append("## 实体列表\n")
    for tname, cols in table_columns.items():
        pk_cols = [c["column_name"] for c in cols if c["key_type"] == "PK"]
        pk_str = f" (主键: {', '.join(pk_cols)})" if pk_cols else ""
        lines.append(f"- **{tname}**{pk_str}: {len(cols)} 个字段")

    if fks:
        lines.append("\n## 显式外键关系\n")
        for fk in fks:
            lines.append(
                f"- {fk['from_table']}.{fk['from_column']} → "
                f"{fk['to_table']}.{fk['to_column']} "
                f"({fk.get('constraint_name', '')})"
            )

    if include_implicit:
        implicit = analyze_implicit_relationships(table_columns, fks)
        if implicit:
            lines.append("\n## 推断的隐含关系\n")
            lines.append("> 以下关系基于字段命名约定（如 xxx_id → xxx/xxxs 表）推断，请确认是否正确。\n")
            for rel in implicit:
                lines.append(
                    f"- {rel['from_table']}.{rel['from_column']} → "
                    f"{rel['to_table']}.{rel['to_column']} (推断)"
                )

    return "\n".join(lines)
