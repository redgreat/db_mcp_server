from typing import Dict, Any, List, Optional
from sqlalchemy.engine import Engine
import os
import time

def _header(title: str) -> str:
    return f"# {title}\n"

def _sec(title: str) -> str:
    return f"## {title}\n"

def _bullet(items: List[str]) -> str:
    return "\n".join(f"- {x}" for x in items) + "\n"

def generate_db_rule_markdown(eng: Engine, database: str, db_type: str = "mysql") -> str:
    """生成数据库规则文档 Markdown"""
    from .db_doc_tool import get_all_tables_with_comments, get_table_columns_detail
    from .db_er_tool import get_foreign_keys, analyze_implicit_relationships, get_table_columns_for_er
    from .db_dataflow_tool import analyze_data_flow
    lines: List[str] = []
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lines.append(_header(f"{database} 数据库规则 (RULE.md)"))
    lines.append(f"- 生成时间: {ts}")
    lines.append(f"- 数据库类型: {db_type}")
    lines.append("")
    lines.append(_sec("实体与字段"))
    tables = get_all_tables_with_comments(eng, database, db_type)
    for t in tables:
        tname = t["table_name"]
        tcomment = t.get("table_comment") or ""
        lines.append(f"### {tname}")
        if tcomment:
            lines.append(f"> {tcomment}")
        cols = get_table_columns_detail(eng, database, tname, db_type)
        lines.append("| 字段名 | 类型 | 长度/精度 | 可空 | 默认值 | 键 | 备注 |")
        lines.append("|--------|------|-----------|------|--------|-----|------|")
        for c in cols:
            length = ""
            if c.get("character_maximum_length"):
                length = str(c["character_maximum_length"])
            elif c.get("numeric_precision"):
                length = str(c["numeric_precision"])
                if c.get("numeric_scale"):
                    length += f",{c['numeric_scale']}"
            lines.append(
                f"| {c['column_name']} | {c['data_type']} | {length} "
                f"| {c['is_nullable']} | {c.get('column_default', '') or ''} "
                f"| {c.get('column_key', '')} | {c.get('column_comment', '')} |"
            )
        lines.append("")
    lines.append(_sec("关系与连接建议"))
    table_columns = get_table_columns_for_er(eng, database, db_type)
    fks = get_foreign_keys(eng, database, db_type)
    implicit = analyze_implicit_relationships(table_columns, fks)
    if fks:
        lines.append("**显式外键**")
        for fk in fks:
            lines.append(f"- {fk['from_table']}.{fk['from_column']} → {fk['to_table']}.{fk['to_column']} ({fk.get('constraint_name', '')})")
        lines.append("")
    if implicit:
        lines.append("**推断关系**")
        for rel in implicit:
            lines.append(f"- {rel['from_table']}.{rel['from_column']} → {rel['to_table']}.{rel['to_column']} (推断)")
        lines.append("")
    lines.append(_sec("数据流梳理"))
    flow = analyze_data_flow(eng, database, db_type)
    lines.append(f"- 数据表: {len(flow['tables'])} 张")
    lines.append(f"- 视图: {len(flow['views'])} 个")
    lines.append(f"- 存储过程: {len(flow['procedures'])} 个")
    lines.append(f"- 触发器: {len(flow['triggers'])} 个")
    lines.append(f"- 数据流: {len(flow['flows'])} 条")
    lines.append("")
    lines.append(_sec("报表建模建议"))
    lines.append(_bullet([
        "优先使用显式外键与主键进行连接",
        "跨表取名统一使用表别名与全限定字段",
        "大表查询增加时间/组织维度过滤",
        "使用聚合时明确分组字段，避免隐式扩行",
    ]))
    lines.append(_sec("安全与脱敏"))
    lines.append(_bullet([
        "所有规则仅用于 SELECT 读取，不允许 DDL/DML",
        "敏感字段建议在服务端统一脱敏",
    ]))
    return "\n".join(lines)

def save_rule_to_project(content: str, database: str, base_dir: Optional[str] = None) -> str:
    """保存 RULE.md 到项目目录"""
    base = base_dir or os.getcwd()
    dest_dir = os.path.join(base, "rules", database)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, "RULE.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.abspath(path)

def save_rule_to_admin_db(admin_engine, connection_id: int, database: str, title: Optional[str], content: str, version: Optional[str] = None, tags: Optional[dict] = None) -> int:
    """保存 RULE.md 到管理数据库"""
    from sqlalchemy import Table, MetaData, select, insert, update
    from sqlalchemy.orm import Session
    meta = MetaData()
    db_rules = Table("db_rules", meta, autoload_with=admin_engine)
    with Session(admin_engine) as s:
        existing = s.execute(
            select(db_rules.c.id).where(db_rules.c.connection_id == connection_id, db_rules.c.database == database, db_rules.c.active == True)
        ).first()
        now_title = title or f"{database} 规则"
        if existing:
            rid = existing[0]
            s.execute(
                update(db_rules).where(db_rules.c.id == rid).values(
                    title=now_title,
                    version=version,
                    rule_md=content,
                    tags=tags or {},
                )
            )
            s.commit()
            return rid
        else:
            res = s.execute(
                insert(db_rules).values(
                    connection_id=connection_id,
                    database=database,
                    title=now_title,
                    version=version,
                    rule_md=content,
                    tags=tags or {},
                    active=True,
                )
            )
            s.commit()
            try:
                return int(res.inserted_primary_key[0])
            except Exception:
                return 0

def generate_and_save_rule(
    eng: Engine,
    admin_engine,
    database: str,
    db_type: str,
    connection_id: int,
    save_to_project: bool = True,
    save_to_admin: bool = True,
    project_base: Optional[str] = None,
    title: Optional[str] = None,
    version: Optional[str] = None,
    tags: Optional[dict] = None
) -> Dict[str, Any]:
    """生成并保存 RULE.md，返回保存结果信息"""
    content = generate_db_rule_markdown(eng, database, db_type)
    saved_path = None
    rule_id = None
    if save_to_project:
        saved_path = save_rule_to_project(content, database, base_dir=project_base)
    if save_to_admin:
        rule_id = save_rule_to_admin_db(admin_engine, connection_id, database, title, content, version, tags)
    return {
        "database": database,
        "saved_path": saved_path,
        "rule_id": rule_id,
        "length": len(content)
    }
