from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any
import re


def get_explain_plan(eng: Engine, sql: str, db_type: str = "mysql") -> Dict[str, Any]:
    """获取 SQL 执行计划"""
    if db_type.lower() == "postgresql":
        explain_sql = f"EXPLAIN (ANALYZE false, COSTS true, FORMAT JSON) {sql}"
    else:
        explain_sql = f"EXPLAIN FORMAT=JSON {sql}"

    with eng.connect() as conn:
        try:
            rows = conn.execute(text(explain_sql)).all()
            if db_type.lower() == "postgresql":
                import json
                plan = rows[0][0] if rows else []
                return {"format": "json", "plan": plan}
            else:
                raw = rows[0][0] if rows else "{}"
                import json
                plan = json.loads(raw)
                return {"format": "json", "plan": plan}
        except Exception:
            try:
                rows = conn.execute(text(f"EXPLAIN {sql}")).all()
                lines = [str(r[0]) if len(r) == 1 else str(r) for r in rows]
                return {"format": "text", "plan": "\n".join(lines)}
            except Exception as e2:
                return {"format": "error", "error": str(e2)}


def extract_tables_from_sql(sql: str) -> List[str]:
    """从 SQL 中提取涉及的表名"""
    sql_clean = re.sub(r'--.*$', '', sql, flags=re.MULTILINE)
    sql_clean = re.sub(r'/\*.*?\*/', '', sql_clean, flags=re.DOTALL)

    tables = set()
    patterns = [
        r'(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+`?(\w+)`?',
        r'(?:from|join|into|update|table)\s+`?(\w+)`?',
    ]
    for p in patterns:
        for m in re.finditer(p, sql_clean, re.IGNORECASE):
            name = m.group(1).lower()
            if name not in ('select', 'where', 'set', 'values', 'and', 'or', 'not',
                            'null', 'true', 'false', 'as', 'on', 'in', 'exists'):
                tables.add(m.group(1))
    return sorted(tables)


def get_table_indexes_for_analysis(eng: Engine, database: str, table: str, db_type: str = "mysql") -> List[Dict]:
    """获取指定表的索引信息"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT indexname AS index_name, indexdef AS index_def
            FROM pg_indexes
            WHERE schemaname = :schema AND tablename = :tb
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema, "tb": table}).mappings().all()
            return [dict(r) for r in rows]
    else:
        sql = """
            SELECT INDEX_NAME AS index_name, COLUMN_NAME AS column_name,
                   NON_UNIQUE AS non_unique, SEQ_IN_INDEX AS seq, INDEX_TYPE AS index_type
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :tb
            ORDER BY INDEX_NAME, SEQ_IN_INDEX
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database, "tb": table}).mappings().all()
            return [dict(r) for r in rows]


def _analyze_plan_issues(plan: Any, db_type: str) -> List[Dict[str, str]]:
    """分析执行计划中的问题"""
    issues = []

    plan_str = str(plan).lower()

    if "full scan" in plan_str or "seq scan" in plan_str or '"all"' in plan_str:
        issues.append({
            "type": "full_table_scan",
            "severity": "high",
            "message": "检测到全表扫描，建议为 WHERE 条件字段添加索引"
        })

    if "filesort" in plan_str:
        issues.append({
            "type": "filesort",
            "severity": "medium",
            "message": "检测到文件排序（filesort），建议为 ORDER BY 字段添加索引"
        })

    if "temporary" in plan_str or "using temporary" in plan_str:
        issues.append({
            "type": "temp_table",
            "severity": "medium",
            "message": "检测到使用临时表，建议优化 GROUP BY / DISTINCT 操作"
        })

    if "nested loop" in plan_str and "rows" in plan_str:
        issues.append({
            "type": "nested_loop",
            "severity": "low",
            "message": "检测到嵌套循环连接，数据量大时建议使用 Hash Join"
        })

    return issues


def _generate_index_suggestions(sql: str, tables: List[str],
                                existing_indexes: Dict[str, List],
                                plan_issues: List) -> List[Dict[str, str]]:
    """生成索引建议"""
    suggestions = []

    where_cols = re.findall(
        r'WHERE\s+.*?(\w+)\s*(?:=|>|<|>=|<=|!=|<>|LIKE|IN|BETWEEN)',
        sql, re.IGNORECASE | re.DOTALL
    )
    order_cols = re.findall(
        r'ORDER\s+BY\s+([\w\s,]+?)(?:\s+ASC|\s+DESC|\s+LIMIT|\s*$|\s*\))',
        sql, re.IGNORECASE
    )
    _group_cols = re.findall(  # noqa: F841
        r'GROUP\s+BY\s+([\w\s,]+?)(?:\s+HAVING|\s+ORDER|\s+LIMIT|\s*$|\s*\))',
        sql, re.IGNORECASE
    )

    all_indexed_cols = set()
    for tbl, idxs in existing_indexes.items():
        for idx in idxs:
            col = idx.get("column_name", "")
            if col:
                all_indexed_cols.add(f"{tbl}.{col}".lower())
            idx_def = idx.get("index_def", "")
            if idx_def:
                for m in re.finditer(r'(\w+)', idx_def.split('(')[-1] if '(' in idx_def else ""):
                    all_indexed_cols.add(f"{tbl}.{m.group(1)}".lower())

    for col in where_cols:
        found = any(col.lower() in ic for ic in all_indexed_cols)
        if not found:
            suggestions.append({
                "type": "index",
                "column": col,
                "message": f"WHERE 条件中的 {col} 字段缺少索引，建议创建"
            })

    for oc_str in order_cols:
        cols = [c.strip() for c in oc_str.split(',')]
        for col in cols:
            col_name = col.split()[0]
            found = any(col_name.lower() in ic for ic in all_indexed_cols)
            if not found:
                suggestions.append({
                    "type": "index",
                    "column": col_name,
                    "message": f"ORDER BY 字段 {col_name} 缺少索引，排序可能导致 filesort"
                })

    return suggestions


def _generate_rewrite_suggestions(sql: str) -> List[Dict[str, str]]:
    """生成 SQL 改写建议"""
    suggestions = []
    sql_upper = sql.upper().strip()

    if re.search(r'SELECT\s+\*', sql_upper):
        suggestions.append({
            "type": "rewrite",
            "message": "避免使用 SELECT *，建议明确指定需要的字段以减少网络传输和内存占用"
        })

    if re.search(r'LIKE\s+[\'"]%', sql):
        suggestions.append({
            "type": "rewrite",
            "message": "LIKE '%xxx' 前缀通配符无法使用索引，建议改用全文索引或调整匹配方式"
        })

    if re.search(r'OR\s+', sql_upper) and 'WHERE' in sql_upper:
        suggestions.append({
            "type": "rewrite",
            "message": "WHERE 子句中使用 OR 可能导致索引失效，建议考虑改写为 UNION ALL"
        })

    if re.search(r'NOT\s+IN\s*\(', sql_upper):
        suggestions.append({
            "type": "rewrite",
            "message": "NOT IN 子查询在数据量大时性能差，建议改写为 NOT EXISTS 或 LEFT JOIN ... IS NULL"
        })

    if re.search(r'(?:FUNCTION|CONVERT|CAST|DATE_FORMAT|YEAR|MONTH)\s*\(', sql_upper):
        if 'WHERE' in sql_upper:
            suggestions.append({
                "type": "rewrite",
                "message": "WHERE 条件中对字段使用函数会导致索引失效，建议将函数应用于值而非字段"
            })

    if not re.search(r'LIMIT\s+\d+', sql_upper) and sql_upper.startswith('SELECT'):
        suggestions.append({
            "type": "rewrite",
            "message": "查询未使用 LIMIT 限制返回行数，大表查询建议添加 LIMIT"
        })

    if re.search(r'OFFSET\s+\d{4,}', sql_upper):
        suggestions.append({
            "type": "rewrite",
            "message": "使用了大 OFFSET 值进行分页，建议改用基于游标 (WHERE id > ?) 的分页方式"
        })

    return suggestions


def analyze_sql(eng: Engine, database: str, sql: str, db_type: str = "mysql") -> Dict[str, Any]:
    """SQL 综合审查"""
    result = {
        "original_sql": sql,
        "tables_involved": [],
        "explain_plan": {},
        "plan_issues": [],
        "index_suggestions": [],
        "rewrite_suggestions": []
    }

    tables = extract_tables_from_sql(sql)
    result["tables_involved"] = tables

    result["explain_plan"] = get_explain_plan(eng, sql, db_type)

    if result["explain_plan"].get("format") != "error":
        result["plan_issues"] = _analyze_plan_issues(result["explain_plan"].get("plan"), db_type)

    existing_indexes = {}
    for tbl in tables:
        try:
            existing_indexes[tbl] = get_table_indexes_for_analysis(eng, database, tbl, db_type)
        except Exception:
            existing_indexes[tbl] = []

    result["index_suggestions"] = _generate_index_suggestions(
        sql, tables, existing_indexes, result["plan_issues"]
    )
    result["rewrite_suggestions"] = _generate_rewrite_suggestions(sql)

    try:
        from ..ai.llm_client import LLMClient
        llm = LLMClient()
    except Exception:
        llm = None

    if llm and llm.is_enabled():
        system_prompt = (
            "你是一个顶级的数据库性能优化专家。请根据用户提供的 SQL 语句、"
            "涉及表的现有索引结构以及 EXPLAIN 执行计划，诊断潜在的性能瓶颈。\n"
            "你需要提供：\n"
            "1. 最专业的索引创建建议（请提供标准 SQL DDL 语句）。\n"
            "2. SQL 语句的高效改写建议（并解释为什么）。\n"
            "请直接输出 Markdown 格式的分析报告，无需多余闲聊。"
        )

        user_prompt = f"### SQL 语句\n```sql\n{sql}\n```\n\n### 涉及表的现有索引\n"
        for tbl, idxs in existing_indexes.items():
            user_prompt += f"**表 {tbl}**:\n```json\n{idxs}\n```\n"

        user_prompt += f"\n### EXPLAIN 执行计划\n```json\n{result['explain_plan']}\n```\n"

        try:
            ai_result = llm.ask(system_prompt, user_prompt)
            result["ai_assessment"] = ai_result["content"]
            result["ai_usage"] = ai_result["usage"]
            result["overall_assessment"] = "🌟 [AI 智能审查开启] 已由大模型深度分析，请参阅 ai_assessment。"
        except Exception as e:
            result["ai_assessment"] = f"AI 调用失败：{e}"
            result["overall_assessment"] = "⚠️ AI 分析失败，已降级回基础规则分析。"
    else:
        # 如果没有配置 AI，使用原有的统计逻辑
        all_issues = result["plan_issues"] + result["index_suggestions"] + result["rewrite_suggestions"]
        if not all_issues:
            result["overall_assessment"] = "SQL 质量良好，未发现明显性能问题"
        else:
            high = sum(1 for i in all_issues if i.get("severity") == "high")
            medium = sum(1 for i in all_issues if i.get("severity") == "medium")
            result["overall_assessment"] = (
                f"发现 {len(all_issues)} 个潜在问题"
                f"（高风险 {high} 个，中风险 {medium} 个），请参考建议优化"
            )

    return result
