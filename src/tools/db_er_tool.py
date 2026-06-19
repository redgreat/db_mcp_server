from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any, Optional
import re
import time
import logging

logger = logging.getLogger(__name__)


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


def analyze_implicit_relationships(
    table_columns: Dict[str, List[Dict]], existing_fks: List[Dict]
) -> List[Dict[str, str]]:
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
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark} "{" | ".join(comment_parts)}"')
                elif pk_mark:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark}')
                elif comment_parts:
                    lines.append(f'        {dtype} {col["column_name"]} "{" | ".join(comment_parts)}"')
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
                                 include_implicit: bool = True,
                                 for_pdf: bool = False) -> str:
    """生成实体关系的文字描述（按业务域与表备注归纳，非简单表清单）。"""
    from .er_entity_catalog import build_entity_catalog, format_entity_catalog_markdown

    catalog = build_entity_catalog(eng, database, db_type)
    text = format_entity_catalog_markdown(catalog, for_pdf=for_pdf)

    if not for_pdf:
        from .er_entity_catalog import llm_er_business_insights

        insights = llm_er_business_insights(catalog)
        if insights:
            text = f"## AI 业务模型解读\n\n{insights}\n\n" + text

    if include_implicit and not for_pdf:
        table_columns = get_table_columns_for_er(eng, database, db_type)
        fks = get_foreign_keys(eng, database, db_type)
        implicit = analyze_implicit_relationships(table_columns, fks)
        if implicit:
            text += "\n\n## 推断的隐含关系\n"
            text += "> 基于字段命名（如 xxx_id → xxx 表）推断，请人工确认。\n"
            for rel in implicit[:80]:
                text += (
                    f"\n- {rel['from_table']}.{rel['from_column']} → "
                    f"{rel['to_table']}.{rel['to_column']} (推断)"
                )
            if len(implicit) > 80:
                text += f"\n- … 另有 {len(implicit) - 80} 条推断关系\n"

    return text


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
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark} "{" | ".join(comment_parts)}"')
                elif pk_mark:
                    lines.append(f'        {dtype} {col["column_name"]} {pk_mark}')
                elif comment_parts:
                    lines.append(f'        {dtype} {col["column_name"]} "{" | ".join(comment_parts)}"')
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
        next_len = sum(len(ln) for ln in current_lines) + len(block)
        if (max_tables_per_part and current_tables >= max_tables_per_part) or next_len > max_chars:
            parts.append("\n".join(current_lines))
            current_lines = ["erDiagram"]
            current_tables = 0
        current_lines.append(block)
        current_tables += 1

    # 尝试添加外键与隐含关系
    rel_blocks = fk_blocks + implicit_blocks
    for block in rel_blocks:
        next_len = sum(len(ln) for ln in current_lines) + len(block)
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


def _render_er_images(
    eng: Engine,
    database: str,
    db_type: str,
    tmp_dir: str,
    include_implicit: bool,
) -> list[str]:
    """可选使用 mmdc 渲染 ER 图，返回图片路径列表。

    默认不再依赖 SchemaCrawler/tbls。那两条路径体积大、部署复杂，且对本项目
    的业务域分片和隐含关系推断帮助有限；Mermaid 源码本身就是稳定可消费的交付物。
    """
    from .mermaid_render import mmdc_available, render_mermaid_parts_to_pngs
    from .er_entity_catalog import generate_mermaid_parts_by_domain

    if mmdc_available():
        diagram_parts = generate_mermaid_parts_by_domain(
            eng, database, db_type,
            include_implicit=include_implicit,
            max_tables_per_part=35,
        )
        image_paths = render_mermaid_parts_to_pngs(diagram_parts, tmp_dir, prefix="er")
        if image_paths:
            logger.info("ER 图使用 mmdc 渲染成功")
        return image_paths

    logger.info("未安装 mmdc，PDF 将只包含 ER 摘要与 Mermaid 源码预览")
    return []


def export_er_report_pdf(eng: Engine, database: str, db_type: str = "mysql",
                         include_columns: bool = True,
                         include_implicit: bool = True,
                         save_path: Optional[str] = None) -> Dict[str, Any]:
    """生成 PDF 格式的 ER 图报告（中文摘要 + 可选 Mermaid 图片渲染）。"""
    import os
    import tempfile
    from fpdf import FPDF
    from pathlib import Path

    from .pdf_cjk import (
        register_cjk_fonts,
        safe_multi_cell,
        place_image_fit_page,
        write_er_pdf_summary,
    )
    from .er_entity_catalog import build_entity_catalog

    logger = logging.getLogger(__name__)

    catalog = build_entity_catalog(eng, database, db_type)
    mermaid_data = generate_er_mermaid(eng, database, db_type, include_columns, include_implicit)
    mermaid_preview = mermaid_data["mermaid"][:5000]
    text_desc = generate_er_text_description(eng, database, db_type, include_implicit, for_pdf=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"db_er_{database}_{timestamp}.pdf"

    if save_path:
        save_path = os.path.abspath(save_path)
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        filename = os.path.basename(save_path)
    else:
        downloads_dir = Path(__file__).resolve().parent.parent.parent / "data" / "downloads"
        downloads_dir.mkdir(parents=True, exist_ok=True)
        save_path = str(downloads_dir / filename)

    image_paths: list[str] = []
    with tempfile.TemporaryDirectory(prefix="er_img_") as tmp:
        image_paths = _render_er_images(eng, database, db_type, tmp, include_implicit)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=14)
        pdf.set_margins(14, 14, 14)
        font_used = register_cjk_fonts(pdf)
        logger.info("ER PDF 使用字体: %s", font_used)
        pdf.add_page()

        safe_multi_cell(
            pdf,
            f"数据库 ER 关系报告 — {database}",
            bold=True,
            size=18,
            h=9,
        )
        pdf.ln(4)

        write_er_pdf_summary(pdf, catalog)

        if image_paths:
            pdf.add_page()
            safe_multi_cell(
                pdf,
                f"ER 关系图（共 {len(image_paths)} 张）",
                bold=True,
                size=14,
            )
            pdf.ln(2)
            for i, img in enumerate(image_paths, 1):
                place_image_fit_page(
                    pdf,
                    img,
                    caption=f"分片 {i} / {len(image_paths)}",
                )
        else:
            pdf.add_page()
            safe_multi_cell(
                pdf,
                "未生成 ER 图片：当前运行环境未安装 mmdc，或 Mermaid 渲染失败。"
                "下方保留 Mermaid 源码预览；完整源码请使用 format=markdown 导出。",
                bold=True,
                size=12,
            )
            pdf.ln(3)
            safe_multi_cell(pdf, mermaid_preview, size=7, h=4)

        pdf_bytes = pdf.output()
        if isinstance(pdf_bytes, str):
            pdf_bytes = pdf_bytes.encode("latin-1")

    with open(save_path, 'wb') as f:
        f.write(pdf_bytes)
    saved_to = os.path.abspath(save_path)
    logger.info(f"ER PDF 已保存到本地: {saved_to}")

    download_url = f"/downloads/{filename}"

    mermaid_src = mermaid_data["mermaid"]
    mermaid_preview = mermaid_src[:2000] + "\n... (为节省空间已截断)" if len(mermaid_src) > 2000 else mermaid_src
    return {
        "success": True,
        "format": "pdf",
        "filename": filename,
        "size_bytes": len(pdf_bytes),
        "file_path": saved_to,
        "download_url": download_url,
        "mermaid_preview": mermaid_preview,
        "table_count": mermaid_data.get("table_count"),
    }
