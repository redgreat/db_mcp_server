from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any
import re
import time
import base64
import logging


def get_triggers(eng: Engine, database: str, db_type: str = "mysql") -> List[Dict[str, Any]]:
    """获取数据库触发器"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                t.tgname AS trigger_name,
                c.relname AS table_name,
                CASE t.tgtype & 2 WHEN 2 THEN 'BEFORE' ELSE 'AFTER' END AS timing,
                CASE
                    WHEN t.tgtype & 4 = 4 THEN 'INSERT'
                    WHEN t.tgtype & 8 = 8 THEN 'DELETE'
                    WHEN t.tgtype & 16 = 16 THEN 'UPDATE'
                    ELSE 'OTHER'
                END AS event,
                p.proname AS function_name
            FROM pg_trigger t
            JOIN pg_class c ON t.tgrelid = c.oid
            JOIN pg_namespace n ON c.relnamespace = n.oid
            JOIN pg_proc p ON t.tgfoid = p.oid
            WHERE NOT t.tgisinternal AND n.nspname = :schema
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    else:
        sql = """
            SELECT
                TRIGGER_NAME AS trigger_name,
                EVENT_OBJECT_TABLE AS table_name,
                ACTION_TIMING AS timing,
                EVENT_MANIPULATION AS event,
                ACTION_STATEMENT AS action_statement
            FROM information_schema.TRIGGERS
            WHERE TRIGGER_SCHEMA = :db
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    return [dict(r) for r in rows]


def get_view_definitions(eng: Engine, database: str, db_type: str = "mysql") -> List[Dict[str, str]]:
    """获取视图定义源码"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT viewname AS view_name,
                   definition AS view_definition
            FROM pg_views
            WHERE schemaname = :schema
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    else:
        sql = """
            SELECT TABLE_NAME AS view_name,
                   VIEW_DEFINITION AS view_definition
            FROM information_schema.VIEWS
            WHERE TABLE_SCHEMA = :db
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    return [dict(r) for r in rows]


def get_procedure_definitions(eng: Engine, database: str, db_type: str = "mysql") -> List[Dict[str, str]]:
    """获取存储过程源码"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT p.proname AS proc_name,
                   pg_get_functiondef(p.oid) AS proc_definition
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = :schema
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    else:
        sql = """
            SELECT ROUTINE_NAME AS proc_name,
                   ROUTINE_DEFINITION AS proc_definition
            FROM information_schema.ROUTINES
            WHERE ROUTINE_SCHEMA = :db
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    return [dict(r) for r in rows]


def _extract_table_refs(sql_text: str, all_tables: set) -> List[str]:
    """从 SQL 文本中提取引用的表名"""
    if not sql_text:
        return []
    refs = set()
    sql_upper = sql_text.upper()
    for table in all_tables:
        pattern = r'\b' + re.escape(table.upper()) + r'\b'
        if re.search(pattern, sql_upper):
            refs.add(table)
    return list(refs)


def analyze_data_flow(eng: Engine, database: str, db_type: str = "mysql") -> Dict[str, Any]:
    """分析数据流向"""
    from .db_metadata_tool import list_tables
    from .db_er_tool import get_foreign_keys

    tables = list_tables(eng, database, db_type)
    table_set = set(tables)
    fks = get_foreign_keys(eng, database, db_type)
    triggers = get_triggers(eng, database, db_type)
    views = get_view_definitions(eng, database, db_type)
    procs = get_procedure_definitions(eng, database, db_type)

    flows = []

    for fk in fks:
        flows.append({
            "type": "foreign_key",
            "from": fk["to_table"],
            "to": fk["from_table"],
            "label": f"FK: {fk['from_column']} → {fk['to_column']}",
            "direction": "reference"
        })

    for trigger in triggers:
        flows.append({
            "type": "trigger",
            "from": trigger["table_name"],
            "to": f"trigger:{trigger['trigger_name']}",
            "label": f"{trigger['timing']} {trigger['event']}",
            "direction": "process"
        })

    for view in views:
        source_tables = _extract_table_refs(view.get("view_definition", ""), table_set)
        for src in source_tables:
            flows.append({
                "type": "view",
                "from": src,
                "to": f"view:{view['view_name']}",
                "label": "数据来源",
                "direction": "transform"
            })

    for proc in procs:
        ref_tables = _extract_table_refs(proc.get("proc_definition", ""), table_set)
        for ref in ref_tables:
            flows.append({
                "type": "procedure",
                "from": ref,
                "to": f"proc:{proc['proc_name']}",
                "label": "数据处理",
                "direction": "process"
            })

    return {
        "tables": tables,
        "triggers": [t["trigger_name"] for t in triggers],
        "views": [v["view_name"] for v in views],
        "procedures": [p["proc_name"] for p in procs],
        "flows": flows
    }


def generate_dataflow_mermaid(eng: Engine, database: str, db_type: str = "mysql") -> Dict[str, Any]:
    """生成 Mermaid 数据流图"""
    analysis = analyze_data_flow(eng, database, db_type)

    def safe(name: str) -> str:
        return re.sub(r'[^a-zA-Z0-9_]', '_', name)

    lines = ["graph LR"]

    for table in analysis["tables"]:
        lines.append(f'    {safe(table)}[("{table}")]')

    for view in analysis["views"]:
        lines.append(f'    view_{safe(view)}{{"{view}"}}')

    for proc in analysis["procedures"]:
        lines.append(f'    proc_{safe(proc)}(("{proc}"))')

    for trigger in analysis["triggers"]:
        lines.append(f'    trigger_{safe(trigger)}>{safe(trigger)}]')

    added = set()
    for flow in analysis["flows"]:
        from_node = safe(flow["from"])
        to_node = safe(flow["to"])

        if flow["to"].startswith("view:"):
            to_node = "view_" + safe(flow["to"].split(":", 1)[1])
        elif flow["to"].startswith("proc:"):
            to_node = "proc_" + safe(flow["to"].split(":", 1)[1])
        elif flow["to"].startswith("trigger:"):
            to_node = "trigger_" + safe(flow["to"].split(":", 1)[1])

        edge_key = f"{from_node}->{to_node}"
        if edge_key in added:
            continue
        added.add(edge_key)

        label = flow["label"][:20]
        lines.append(f'    {from_node} -->|"{label}"| {to_node}')

    mermaid_code = "\n".join(lines)

    return {
        "mermaid": mermaid_code,
        "table_count": len(analysis["tables"]),
        "view_count": len(analysis["views"]),
        "procedure_count": len(analysis["procedures"]),
        "trigger_count": len(analysis["triggers"]),
        "flow_count": len(analysis["flows"])
    }


def generate_dataflow_description(eng: Engine, database: str, db_type: str = "mysql") -> str:
    """生成数据流文字描述"""
    analysis = analyze_data_flow(eng, database, db_type)

    lines = [f"# 数据库 {database} 数据流分析\n"]
    lines.append(f"## 概要\n")
    lines.append(f"- 数据表: {len(analysis['tables'])} 张")
    lines.append(f"- 视图: {len(analysis['views'])} 个")
    lines.append(f"- 存储过程: {len(analysis['procedures'])} 个")
    lines.append(f"- 触发器: {len(analysis['triggers'])} 个")
    lines.append(f"- 数据流: {len(analysis['flows'])} 条\n")

    fk_flows = [f for f in analysis["flows"] if f["type"] == "foreign_key"]
    if fk_flows:
        lines.append("## 外键引用关系\n")
        for f in fk_flows:
            lines.append(f"- {f['from']} → {f['to']}: {f['label']}")
        lines.append("")

    view_flows = [f for f in analysis["flows"] if f["type"] == "view"]
    if view_flows:
        lines.append("## 视图数据来源\n")
        by_view = {}
        for f in view_flows:
            vname = f["to"].split(":", 1)[1] if ":" in f["to"] else f["to"]
            if vname not in by_view:
                by_view[vname] = []
            by_view[vname].append(f["from"])
        for vname, sources in by_view.items():
            lines.append(f"- **{vname}** ← {', '.join(sources)}")
        lines.append("")

    trigger_flows = [f for f in analysis["flows"] if f["type"] == "trigger"]
    if trigger_flows:
        lines.append("## 触发器处理\n")
        for f in trigger_flows:
            tname = f["to"].split(":", 1)[1] if ":" in f["to"] else f["to"]
            lines.append(f"- {f['from']} → **{tname}** ({f['label']})")
        lines.append("")

    proc_flows = [f for f in analysis["flows"] if f["type"] == "procedure"]
    if proc_flows:
        lines.append("## 存储过程数据处理\n")
        by_proc = {}
        for f in proc_flows:
            pname = f["to"].split(":", 1)[1] if ":" in f["to"] else f["to"]
            if pname not in by_proc:
                by_proc[pname] = []
            by_proc[pname].append(f["from"])
        for pname, tables in by_proc.items():
            lines.append(f"- **{pname}**: 涉及表 {', '.join(tables)}")
        lines.append("")

    return "\n".join(lines)


def export_dataflow_report_pdf(eng: Engine, database: str, db_type: str = "mysql") -> Dict[str, Any]:
    """生成 PDF 格式的数据流报告，返回 base64 编码的 PDF 内容"""
    from fpdf import FPDF
    from .db_doc_tool import _find_cjk_font
    
    logger = logging.getLogger(__name__)
    
    # 生成内容
    mermaid_data = generate_dataflow_mermaid(eng, database, db_type)
    text_desc = generate_dataflow_description(eng, database, db_type)
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"db_dataflow_{database}_{timestamp}.pdf"

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # 查找并注册中文字体
    has_cjk_font = False
    font_path = _find_cjk_font()
    if font_path:
        try:
            pdf.add_font("CJK", "", font_path, uni=True)
            pdf.add_font("CJKb", "", font_path, uni=True)
            has_cjk_font = True
        except Exception as e:
            logger.warning(f"加载中文字体失败: {e}")

    if not has_cjk_font:
        raise RuntimeError("未找到可用的中文字体，无法生成 PDF。")

    pdf.add_page()
    
    def set_font(style="", size=10):
        if "B" in style.upper():
            pdf.set_font("CJKb", "", size + 1)
        else:
            pdf.set_font("CJK", "", size)

    # 绘制标题和说明
    set_font("B", 18)
    pdf.cell(0, 12, f"数据库数据流报告 — {database}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # 绘制文字描述部分
    for line in text_desc.split("\n"):
        stripped = line.strip()
        if stripped.startswith("# "):
            continue
        elif stripped.startswith("## "):
            set_font("B", 14)
            pdf.ln(5)
            pdf.cell(0, 10, stripped[3:], new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith("- "):
            set_font("", 9)
            pdf.cell(0, 6, f"  {stripped}", new_x="LMARGIN", new_y="NEXT")
        elif stripped:
            set_font("", 9)
            pdf.multi_cell(0, 6, stripped)
            pdf.ln(2)

    # 绘制 Mermaid 源码部分
    pdf.add_page()
    set_font("B", 14)
    pdf.cell(0, 10, "Mermaid 数据流图源码 (可在支持 Mermaid 的编辑器中渲染)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    
    pdf.set_fill_color(240, 240, 240)
    set_font("", 8)
    pdf.multi_cell(0, 5, mermaid_data["mermaid"], border=1, fill=True)

    pdf_bytes = pdf.output()
    pdf_base64 = base64.b64encode(pdf_bytes).decode("ascii")

    return {
        "filename": filename,
        "size_bytes": len(pdf_bytes),
        "mermaid_code": mermaid_data["mermaid"],
        "pdf_base64": pdf_base64
    }
