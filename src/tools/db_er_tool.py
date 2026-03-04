from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any, Optional
import re
import time
import base64
import logging


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
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                c.table_name,
                c.column_name,
                c.data_type,
                c.character_maximum_length,
                c.numeric_precision,
                c.numeric_scale,
                c.is_nullable,
                c.column_default,
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
                c.CHARACTER_MAXIMUM_LENGTH AS character_maximum_length,
                c.NUMERIC_PRECISION AS numeric_precision,
                c.NUMERIC_SCALE AS numeric_scale,
                c.IS_NULLABLE AS is_nullable,
                c.COLUMN_DEFAULT AS column_default,
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
        # 计算长度
        length = ""
        if r.get("character_maximum_length"):
            length = str(r["character_maximum_length"])
        elif r.get("numeric_precision"):
            length = str(r["numeric_precision"])
            if r.get("numeric_scale"):
                length += f",{r['numeric_scale']}"
        result[tname].append({
            "column_name": r["column_name"],
            "data_type": r["data_type"],
            "key_type": r["key_type"],
            "comment": r["column_comment"],
            "length": length,
            "nullable": r.get("is_nullable"),
            "default": r.get("column_default")
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
                meta = []
                if col.get("length"):
                    meta.append(f"len:{col['length']}")
                if col.get("nullable"):
                    meta.append("NULL" if str(col["nullable"]).upper() in ("YES", "TRUE") else "NN")
                if col.get("default"):
                    dval = str(col["default"]).replace('"', "'")
                    meta.append(f"def:{dval}")
                comment_parts = []
                if col.get("comment"):
                    comment_parts.append(col["comment"][:50].replace('"', "'"))
                if meta:
                    comment_parts.append(" ".join(meta))
                if pk_mark and comment_parts:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark} "{ " | ".join(comment_parts) }"')
                elif pk_mark:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark}')
                elif comment_parts:
                    lines.append(f'        {dtype} {col["column_name"]} "{ " | ".join(comment_parts) }"')
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

def generate_er_mermaid_parts(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
    include_columns: bool = True,
    include_implicit: bool = True,
    max_tables_per_part: int = 150,
    max_chars: int = 500000
) -> List[str]:
    """生成按片段划分的 Mermaid erDiagram 代码
    
    Args:
        eng: 数据库引擎
        database: 库名
        db_type: 数据库类型
        include_columns: 是否包含字段
        include_implicit: 是否包含推断关系
        max_tables_per_part: 单片段最大表数量
        max_chars: 单片段最大字符数
        
    Returns:
        Mermaid 文本片段列表
    """
    table_columns = get_table_columns_for_er(eng, database, db_type)
    fks = get_foreign_keys(eng, database, db_type)
    implicit_rels = analyze_implicit_relationships(table_columns, fks) if include_implicit else []
    
    def safe_name(name: str) -> str:
        import re as _re
        return _re.sub(r'[^a-zA-Z0-9_]', '_', name)
    
    # 预先构建每个表的块内容
    table_blocks: List[str] = []
    for tname, cols in table_columns.items():
        sname = safe_name(tname)
        lines = [f"    {sname} {{"]
        if include_columns:
            for col in cols:
                dtype = re.sub(r'[^a-zA-Z0-9]', '_', col["data_type"])
                pk_mark = "PK" if col["key_type"] == "PK" else ""
                meta = []
                if col.get("length"):
                    meta.append(f"len:{col['length']}")
                if col.get("nullable"):
                    meta.append("NULL" if str(col["nullable"]).upper() in ("YES", "TRUE") else "NN")
                if col.get("default"):
                    dval = str(col["default"]).replace('"', "'")
                    meta.append(f"def:{dval}")
                comment_parts = []
                if col.get("comment"):
                    comment_parts.append(col["comment"][:50].replace('"', "'"))
                if meta:
                    comment_parts.append(" ".join(meta))
                if pk_mark and comment_parts:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark} "{ " | ".join(comment_parts) }"')
                elif pk_mark:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark}')
                elif comment_parts:
                    lines.append(f'        {dtype} {col["column_name"]} "{ " | ".join(comment_parts) }"')
                else:
                    lines.append(f'        {dtype} {col["column_name"]}')
        lines.append("    }")
        table_blocks.append("\n".join(lines))
    
    # 外键关系块
    fk_blocks: List[str] = []
    for fk in fks:
        from_t = safe_name(fk["from_table"])
        to_t = safe_name(fk["to_table"])
        label = fk.get("constraint_name", f'{fk["from_column"]}')
        fk_blocks.append(f'    {to_t} ||--o{{ {from_t} : "{label}"')
    
    # 推断关系块
    implicit_blocks: List[str] = []
    for rel in implicit_rels:
        from_t = safe_name(rel["from_table"])
        to_t = safe_name(rel["to_table"])
        implicit_blocks.append(f'    {to_t} ||--o{{ {from_t} : "{rel["from_column"]}(推断)"')
    
    # 组装分片
    parts: List[str] = []
    current_lines: List[str] = ["erDiagram"]
    current_tables = 0
    
    for block in table_blocks:
        next_len = sum(len(l) for l in current_lines) + len(block)
        if (max_tables_per_part and current_tables >= max_tables_per_part) or next_len > max_chars:
            parts.append("\n".join(current_lines))
            current_lines = ["erDiagram"]
            current_tables = 0
        current_lines.append(block)
        current_tables += 1
    
    # 尝试添加外键与隐含关系
    rel_blocks = fk_blocks + implicit_blocks
    for block in rel_blocks:
        next_len = sum(len(l) for l in current_lines) + len(block)
        if next_len > max_chars:
            parts.append("\n".join(current_lines))
            current_lines = ["erDiagram"]
        current_lines.append(block)
    
    if current_lines:
        parts.append("\n".join(current_lines))
    
    return parts

def save_er_mermaid_split(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
    save_dir: str = ".",
    filename_prefix: Optional[str] = None,
    include_columns: bool = True,
    include_implicit: bool = True,
    max_tables_per_part: int = 150,
    max_chars: int = 500000
) -> List[str]:
    """生成并保存分片 Mermaid 文档
    
    Args:
        eng: 数据库引擎
        database: 库名
        db_type: 数据库类型
        save_dir: 保存目录
        filename_prefix: 文件名前缀
        include_columns: 是否包含字段
        include_implicit: 是否包含推断关系
        max_tables_per_part: 单片段最大表数量
        max_chars: 单片段最大字符数
        
    Returns:
        保存的文件路径列表
    """
    import os
    parts = generate_er_mermaid_parts(
        eng, database, db_type, include_columns, include_implicit, max_tables_per_part, max_chars
    )
    if not os.path.isdir(save_dir):
        os.makedirs(save_dir, exist_ok=True)
    if not filename_prefix:
        filename_prefix = f"db_er_{database}"
    saved = []
    for i, content in enumerate(parts, 1):
        path = os.path.join(save_dir, f"{filename_prefix}_part_{i}.md")
        md = f"```mermaid\n{content}\n```"
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        saved.append(path)
    return saved

def export_er_report_pdf(eng: Engine, database: str, db_type: str = "mysql",
                         include_columns: bool = True,
                         include_implicit: bool = True,
                         save_path: Optional[str] = None) -> Dict[str, Any]:
    """生成 PDF 格式的 ER 图报告，返回 base64 编码的 PDF 内容"""
    from fpdf import FPDF
    from .db_doc_tool import _find_cjk_font
    import os
    
    logger = logging.getLogger(__name__)
    
    # 生成内容
    mermaid_data = generate_er_mermaid(eng, database, db_type, include_columns, include_implicit)
    text_desc = generate_er_text_description(eng, database, db_type, include_implicit)
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"db_er_{database}_{timestamp}.pdf"

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
    pdf.cell(0, 12, f"数据库 ER 关系报告 — {database}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # 绘制文字描述部分
    for line in text_desc.split("\n"):
        stripped = line.strip()
        if stripped.startswith("# "):
            continue # 已经画过大标题了
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
    pdf.cell(0, 10, "Mermaid ER 图源码 (可在支持 Mermaid 的编辑器中渲染)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    
    pdf.set_fill_color(240, 240, 240)
    set_font("", 8)
    # 使用 multi_cell 绘制代码块，虽然不能直接画图，但提供了可保存的代码
    pdf.multi_cell(0, 5, mermaid_data["mermaid"], border=1, fill=True)

    pdf_bytes = pdf.output()
    
    saved_to = None
    if save_path:
        # 确保目录存在
        save_dir = os.path.dirname(os.path.abspath(save_path))
        if save_dir and not os.path.exists(save_dir):
            os.makedirs(save_dir, exist_ok=True)
        with open(save_path, 'wb') as f:
            f.write(pdf_bytes)
        saved_to = os.path.abspath(save_path)
        logger.info(f"ER 图报告已保存到本地: {saved_to}")

    pdf_base64 = base64.b64encode(pdf_bytes).decode("ascii")

    return {
        "filename": filename,
        "size_bytes": len(pdf_bytes),
        "mermaid_code": mermaid_data["mermaid"],
        "pdf_base64": pdf_base64,
        "saved_to": saved_to
    }
