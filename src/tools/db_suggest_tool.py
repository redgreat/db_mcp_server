from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any


def get_table_full_info(eng: Engine, database: str, table: str, db_type: str = "mysql") -> Dict[str, Any]:
    """获取表的完整信息（字段、索引、外键、触发器）"""
    from .db_doc_tool import get_table_columns_detail, get_table_indexes
    from .db_er_tool import get_foreign_keys
    from .db_dataflow_tool import get_triggers

    columns = get_table_columns_detail(eng, database, table, db_type)
    indexes = get_table_indexes(eng, database, table, db_type)

    all_fks = get_foreign_keys(eng, database, db_type)
    table_fks = [fk for fk in all_fks if fk["from_table"] == table]
    ref_fks = [fk for fk in all_fks if fk["to_table"] == table]

    all_triggers = get_triggers(eng, database, db_type)
    table_triggers = [t for t in all_triggers if t["table_name"] == table]

    return {
        "table": table,
        "database": database,
        "columns": columns,
        "indexes": indexes,
        "foreign_keys": table_fks,
        "referenced_by": ref_fks,
        "triggers": table_triggers
    }


def get_dependent_views(eng: Engine, database: str, table: str, db_type: str = "mysql") -> List[Dict[str, str]]:
    """查找依赖此表的视图"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT DISTINCT v.viewname AS view_name, v.definition AS view_definition
            FROM pg_views v
            WHERE v.schemaname = :schema
              AND v.definition ILIKE :pattern
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema, "pattern": f"%{table}%"}).mappings().all()
    else:
        sql = """
            SELECT TABLE_NAME AS view_name, VIEW_DEFINITION AS view_definition
            FROM information_schema.VIEWS
            WHERE TABLE_SCHEMA = :db
              AND VIEW_DEFINITION LIKE :pattern
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database, "pattern": f"%{table}%"}).mappings().all()

    return [dict(r) for r in rows]


def get_dependent_procedures(eng: Engine, database: str, table: str, db_type: str = "mysql") -> List[Dict[str, str]]:
    """查找引用此表的存储过程"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT p.proname AS proc_name,
                   pg_get_functiondef(p.oid) AS proc_definition
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = :schema
              AND pg_get_functiondef(p.oid) ILIKE :pattern
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema, "pattern": f"%{table}%"}).mappings().all()
    else:
        sql = """
            SELECT ROUTINE_NAME AS proc_name,
                   ROUTINE_DEFINITION AS proc_definition
            FROM information_schema.ROUTINES
            WHERE ROUTINE_SCHEMA = :db
              AND ROUTINE_DEFINITION LIKE :pattern
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database, "pattern": f"%{table}%"}).mappings().all()

    return [dict(r) for r in rows]


def generate_alter_ddl(table: str, columns_to_add: List[Dict[str, str]], db_type: str = "mysql") -> str:
    """根据需要生成 ALTER TABLE DDL

    columns_to_add 格式:
    [{"name": "col_name", "type": "VARCHAR(100)", "nullable": "YES", "default": "NULL", "comment": "备注"}]
    """
    ddl_lines = []

    for col in columns_to_add:
        name = col["name"]
        col_type = col["type"]
        nullable = "NULL" if col.get("nullable", "YES").upper() == "YES" else "NOT NULL"
        default = f"DEFAULT {col['default']}" if col.get("default") else ""
        comment = col.get("comment", "")

        if db_type.lower() == "postgresql":
            parts = [f"ALTER TABLE {table} ADD COLUMN {name} {col_type}"]
            if nullable == "NOT NULL":
                parts.append(nullable)
            if default:
                parts.append(default)
            ddl_lines.append(" ".join(parts) + ";")
            if comment:
                ddl_lines.append(f"COMMENT ON COLUMN {table}.{name} IS '{comment}';")
        else:
            parts = [f"ALTER TABLE {table} ADD COLUMN {name} {col_type}"]
            if nullable == "NOT NULL":
                parts.append(nullable)
            if default:
                parts.append(default)
            if comment:
                parts.append(f"COMMENT '{comment}'")
            ddl_lines.append(" ".join(parts) + ";")

    return "\n".join(ddl_lines)


def analyze_impact(eng: Engine, database: str, table: str,
                   columns_to_add: List[Dict[str, str]],
                   db_type: str = "mysql") -> Dict[str, Any]:
    """分析字段添加对关联对象的影响"""
    dep_views = get_dependent_views(eng, database, table, db_type)
    dep_procs = get_dependent_procedures(eng, database, table, db_type)

    ddl = generate_alter_ddl(table, columns_to_add, db_type)

    impact = {
        "ddl": ddl,
        "column_count": len(columns_to_add),
        "dependent_views": [],
        "dependent_procedures": [],
        "suggestions": []
    }

    for v in dep_views:
        impact["dependent_views"].append({
            "name": v["view_name"],
            "may_need_update": True,
            "reason": f"视图 {v['view_name']} 引用了表 {table}，添加字段后可能需要修改视图定义以包含新字段"
        })

    for p in dep_procs:
        impact["dependent_procedures"].append({
            "name": p["proc_name"],
            "may_need_update": True,
            "reason": f"存储过程 {p['proc_name']} 引用了表 {table}，如果过程中使用了 SELECT * 或 INSERT 不带字段列表，则需要调整"
        })

    if dep_views:
        impact["suggestions"].append(
            f"建议检查 {len(dep_views)} 个相关视图，确认是否需要更新以包含新字段"
        )
    if dep_procs:
        impact["suggestions"].append(
            f"建议检查 {len(dep_procs)} 个相关存储过程，确认 INSERT/SELECT 语句是否需要调整"
        )

    for col in columns_to_add:
        if col.get("nullable", "YES").upper() == "NO" and not col.get("default"):
            impact["suggestions"].append(
                f"字段 {col['name']} 设置为 NOT NULL 但未指定默认值，"
                f"如果表中已有数据，ALTER 可能失败。建议添加 DEFAULT 值或先回填数据"
            )

    return impact


def suggest_columns(eng: Engine, database: str, table: str, db_type: str = "mysql") -> Dict[str, Any]:
    """智能字段添加建议：基于表名和现有字段，使用大模型推荐合适的扩展字段"""
    import json

    # 1. 获取表当前所有信息
    info = get_table_full_info(eng, database, table, db_type)

    result = {
        "table": table,
        "existing_columns": [c["column_name"] for c in info["columns"]],
        "ai_suggestions": "",
        "ai_usage": None
    }

    try:
        from ..ai.llm_client import LLMClient
        llm = LLMClient()
    except Exception:
        llm = None

    if llm and llm.is_enabled():
        system_prompt = (
            "你是一个业务架构师和数据库建模专家。用户将提供一个数据库表的名字及它现有的字段列表。\n"
            "请根据表名推断该表的业务场景（例如用户表、订单表、商品表等），并推荐 3-5 个适合加入该表的常用业务字段。\n"
            "请直接返回 Markdown 格式，包含字段名、建议类型、长度以及推荐理由。\n"
            "切勿闲聊。"
        )

        user_prompt = f"表名: {table}\n现有字段:\n```json\n{json.dumps(info['columns'], ensure_ascii=False, indent=2)}\n```"

        try:
            ai_result = llm.ask(system_prompt, user_prompt)
            result["ai_suggestions"] = ai_result["content"]
            result["ai_usage"] = ai_result["usage"]
        except Exception as e:
            result["ai_suggestions"] = f"AI 调用失败：{e}"
    else:
        result["ai_suggestions"] = "⚠️ AI 智能分析未启用，请在系统后台配置大模型。"

    return result
