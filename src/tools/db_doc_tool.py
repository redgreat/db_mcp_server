from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any, Optional
import json
import os
import time


def get_db_summary(eng: Engine, database: str, db_type: str = "mysql") -> Dict[str, Any]:
    """获取数据库概要信息"""
    summary = {"database": database, "db_type": db_type}

    if db_type.lower() == "postgresql":
        with eng.connect() as conn:
            row = conn.execute(text("SELECT version()")).scalar()
            summary["version"] = row

            row = conn.execute(text("""
                SELECT pg_size_pretty(pg_database_size(:db))
            """), {"db": database}).scalar()
            summary["size"] = row

            row = conn.execute(text("""
                SELECT datcollate, datctype
                FROM pg_database WHERE datname = :db
            """), {"db": database}).mappings().first()
            if row:
                summary["collation"] = row["datcollate"]
                summary["ctype"] = row["datctype"]
    elif db_type.lower() in ("sqlserver", "mssql"):
        with eng.connect() as conn:
            row = conn.execute(text("SELECT @@VERSION")).scalar()
            summary["version"] = row
            
            row = conn.execute(text("""
                SELECT collation_name 
                FROM sys.databases WHERE name = :db
            """), {"db": database}).mappings().first()
            if row:
                summary["collation"] = row["collation_name"]
    else:
        with eng.connect() as conn:
            row = conn.execute(text("SELECT version()")).scalar()
            summary["version"] = row

            row = conn.execute(text("""
                SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME
                FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = :db
            """), {"db": database}).mappings().first()
            if row:
                summary["charset"] = row["DEFAULT_CHARACTER_SET_NAME"]
                summary["collation"] = row["DEFAULT_COLLATION_NAME"]

            row = conn.execute(text("""
                SELECT ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS size_mb
                FROM information_schema.TABLES WHERE TABLE_SCHEMA = :db
            """), {"db": database}).scalar()
            summary["size_mb"] = float(row) if row else 0

    return summary


def get_all_tables_with_comments(eng: Engine, database: str, db_type: str = "mysql") -> List[Dict[str, str]]:
    """获取所有表名及表备注"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT c.relname AS table_name,
                   COALESCE(d.description, '') AS table_comment
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_catalog.pg_description d ON d.objoid = c.oid AND d.objsubid = 0
            WHERE c.relkind = 'r' AND n.nspname = :schema
            ORDER BY c.relname
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    elif db_type.lower() in ("sqlserver", "mssql"):
        sql = """
            SELECT 
                t.name AS table_name,
                ISNULL(ep.value, '') AS table_comment
            FROM sys.tables t
            LEFT JOIN sys.extended_properties ep 
                ON ep.major_id = t.object_id AND ep.minor_id = 0 AND ep.name = 'MS_Description'
            ORDER BY t.name
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql)).mappings().all()
    else:
        sql = """
            SELECT TABLE_NAME AS table_name,
                   COALESCE(TABLE_COMMENT, '') AS table_comment
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = :db AND TABLE_TYPE = 'BASE TABLE'
            ORDER BY TABLE_NAME
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    return [dict(r) for r in rows]


def get_table_columns_detail(eng: Engine, database: str, table: str, db_type: str = "mysql") -> List[Dict[str, Any]]:
    """获取单表的字段详细信息"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                c.column_name,
                c.data_type,
                c.character_maximum_length,
                c.numeric_precision,
                c.numeric_scale,
                c.is_nullable,
                c.column_default,
                COALESCE(pgd.description, '') AS column_comment,
                CASE WHEN pk.column_name IS NOT NULL THEN 'PRI' ELSE '' END AS column_key
            FROM information_schema.columns c
            LEFT JOIN pg_catalog.pg_statio_all_tables st
                ON st.schemaname = c.table_schema AND st.relname = c.table_name
            LEFT JOIN pg_catalog.pg_description pgd
                ON pgd.objoid = st.relid AND pgd.objsubid = c.ordinal_position
            LEFT JOIN (
                SELECT ku.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage ku
                    ON tc.constraint_name = ku.constraint_name AND tc.table_schema = ku.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                    AND tc.table_name = :tb AND tc.table_schema = :schema
            ) pk ON c.column_name = pk.column_name
            WHERE c.table_name = :tb AND c.table_schema = :schema
            ORDER BY c.ordinal_position
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"tb": table, "schema": schema}).mappings().all()
    elif db_type.lower() in ("sqlserver", "mssql"):
        sql = """
            SELECT 
                c.COLUMN_NAME AS column_name,
                c.DATA_TYPE AS data_type,
                c.CHARACTER_MAXIMUM_LENGTH AS character_maximum_length,
                c.NUMERIC_PRECISION AS numeric_precision,
                c.NUMERIC_SCALE AS numeric_scale,
                c.IS_NULLABLE AS is_nullable,
                c.COLUMN_DEFAULT AS column_default,
                ISNULL(ep.value, '') AS column_comment,
                CASE WHEN pk.COLUMN_NAME IS NOT NULL THEN 'PRI' ELSE '' END AS column_key
            FROM INFORMATION_SCHEMA.COLUMNS c
            LEFT JOIN sys.tables t ON t.name = c.TABLE_NAME
            LEFT JOIN sys.columns sc ON sc.object_id = t.object_id AND sc.name = c.COLUMN_NAME
            LEFT JOIN sys.extended_properties ep ON ep.major_id = t.object_id AND ep.minor_id = sc.column_id AND ep.name = 'MS_Description'
            LEFT JOIN (
                SELECT kcu.COLUMN_NAME
                FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
                JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu 
                    ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME AND tc.TABLE_SCHEMA = kcu.TABLE_SCHEMA
                WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY' 
                    AND tc.TABLE_NAME = :tb AND tc.TABLE_CATALOG = :db
            ) pk ON c.COLUMN_NAME = pk.COLUMN_NAME
            WHERE c.TABLE_NAME = :tb AND c.TABLE_CATALOG = :db
            ORDER BY c.ORDINAL_POSITION
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"tb": table, "db": database}).mappings().all()
    else:
        sql = """
            SELECT
                COLUMN_NAME AS column_name,
                DATA_TYPE AS data_type,
                CHARACTER_MAXIMUM_LENGTH AS character_maximum_length,
                NUMERIC_PRECISION AS numeric_precision,
                NUMERIC_SCALE AS numeric_scale,
                IS_NULLABLE AS is_nullable,
                COLUMN_DEFAULT AS column_default,
                COALESCE(COLUMN_COMMENT, '') AS column_comment,
                COLUMN_KEY AS column_key
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :tb
            ORDER BY ORDINAL_POSITION
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database, "tb": table}).mappings().all()

    return [dict(r) for r in rows]


def get_table_indexes(eng: Engine, database: str, table: str, db_type: str = "mysql") -> List[Dict[str, Any]]:
    """获取表的索引信息"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT indexname AS index_name,
                   indexdef AS index_definition
            FROM pg_indexes
            WHERE schemaname = :schema AND tablename = :tb
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema, "tb": table}).mappings().all()
    elif db_type.lower() in ("sqlserver", "mssql"):
        sql = """
            SELECT 
                i.name AS index_name,
                c.name AS column_name,
                CASE WHEN i.is_unique = 1 THEN 0 ELSE 1 END AS non_unique,
                i.type_desc AS index_type
            FROM sys.indexes i
            JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
            JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
            JOIN sys.tables t ON i.object_id = t.object_id
            WHERE t.name = :tb AND i.type > 0
            ORDER BY i.name, ic.key_ordinal
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"tb": table}).mappings().all()
    else:
        sql = """
            SELECT INDEX_NAME AS index_name,
                   COLUMN_NAME AS column_name,
                   NON_UNIQUE AS non_unique,
                   INDEX_TYPE AS index_type
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :tb
            ORDER BY INDEX_NAME, SEQ_IN_INDEX
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database, "tb": table}).mappings().all()

    return [dict(r) for r in rows]

def get_table_foreign_keys(eng: Engine, database: str, table: str, db_type: str = "mysql") -> List[Dict[str, Any]]:
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                tc.constraint_name AS constraint_name,
                kcu.column_name AS column_name,
                ccu.table_name AS referenced_table,
                ccu.column_name AS referenced_column
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
              ON tc.constraint_name = kcu.constraint_name
             AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage AS ccu
              ON ccu.constraint_name = tc.constraint_name
             AND ccu.table_schema = tc.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_name = :tb
              AND tc.table_schema = :schema
            ORDER BY kcu.column_name
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"tb": table, "schema": schema}).mappings().all()
    elif db_type.lower() in ("sqlserver", "mssql"):
        sql = """
            SELECT
                fk.name AS constraint_name,
                c1.name AS column_name,
                t2.name AS referenced_table,
                c2.name AS referenced_column
            FROM sys.foreign_keys fk
            JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
            JOIN sys.tables t1 ON fkc.parent_object_id = t1.object_id
            JOIN sys.columns c1 ON fkc.parent_object_id = c1.object_id AND fkc.parent_column_id = c1.column_id
            JOIN sys.tables t2 ON fkc.referenced_object_id = t2.object_id
            JOIN sys.columns c2 ON fkc.referenced_object_id = c2.object_id AND fkc.referenced_column_id = c2.column_id
            WHERE t1.name = :tb
            ORDER BY c1.name
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"tb": table}).mappings().all()
    else:
        sql = """
            SELECT
                CONSTRAINT_NAME AS constraint_name,
                COLUMN_NAME AS column_name,
                REFERENCED_TABLE_NAME AS referenced_table,
                REFERENCED_COLUMN_NAME AS referenced_column
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = :db
              AND TABLE_NAME = :tb
              AND REFERENCED_TABLE_NAME IS NOT NULL
            ORDER BY COLUMN_NAME
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database, "tb": table}).mappings().all()
    return [dict(r) for r in rows]


def generate_db_doc_markdown(eng: Engine, database: str, db_type: str = "mysql") -> str:
    """生成 Markdown 格式的数据库说明文档"""
    lines = []
    summary = get_db_summary(eng, database, db_type)

    lines.append(f"# 数据库说明文档 — {database}\n")
    lines.append("## 数据库概要\n")
    lines.append(f"| 属性 | 值 |")
    lines.append(f"|------|------|")
    for k, v in summary.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    tables = get_all_tables_with_comments(eng, database, db_type)
    lines.append("## 表汇总\n")
    lines.append("| 序号 | 表名 | 备注 |")
    lines.append("|------|------|------|")
    for i, t in enumerate(tables, 1):
        lines.append(f"| {i} | {t['table_name']} | {t['table_comment']} |")
    lines.append("")

    for t in tables:
        tname = t["table_name"]
        tcomment = t["table_comment"]
        lines.append(f"## {tname}")
        if tcomment:
            lines.append(f"\n> {tcomment}\n")
        else:
            lines.append("")

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

        indexes = get_table_indexes(eng, database, tname, db_type)
        if indexes:
            lines.append(f"**索引:**\n")
            if db_type.lower() == "postgresql":
                for idx in indexes:
                    lines.append(f"- `{idx['index_name']}`: {idx['index_definition']}")
            else:
                idx_map = {}
                for idx in indexes:
                    name = idx["index_name"]
                    if name not in idx_map:
                        idx_map[name] = {
                            "columns": [],
                            "unique": not idx["non_unique"],
                            "type": idx["index_type"]
                        }
                    idx_map[name]["columns"].append(idx["column_name"])
                for name, info in idx_map.items():
                    uq = "UNIQUE " if info["unique"] else ""
                    cols = ", ".join(info["columns"])
                    lines.append(f"- `{name}`: {uq}{info['type']} ({cols})")
            lines.append("")
        
        fks = get_table_foreign_keys(eng, database, tname, db_type)
        if fks:
            lines.append(f"**外键:**\n")
            for fk in fks:
                lines.append(
                    f"- `{fk['constraint_name']}`: {tname}.{fk['column_name']} → "
                    f"{fk['referenced_table']}.{fk['referenced_column']}"
                )
            lines.append("")

    return "\n".join(lines)


def _find_cjk_font() -> Optional[str]:
    """搜索系统中可用的中文字体文件，返回字体文件路径"""
    import platform
    import logging

    logger = logging.getLogger(__name__)

    # 按优先级排列的中文字体文件
    cjk_font_names = [
        "simhei.ttf",           # 黑体
        "simsun.ttc",           # 宋体
        "msyh.ttc",             # 微软雅黑
        "msyh.ttf",             # 微软雅黑 (ttf版)
        "msyhbd.ttc",           # 微软雅黑粗体
        "NotoSansCJKsc-Regular.ttf",   # Noto Sans CJK
        "NotoSansSC-Regular.ttf",      # Noto Sans SC
        "wqy-microhei.ttc",            # 文泉驿微米黑
        "wqy-zenhei.ttc",              # 文泉驿正黑
        "DroidSansFallbackFull.ttf",   # Droid Sans Fallback
    ]

    # 系统字体目录
    system = platform.system()
    font_dirs = []

    if system == "Windows":
        windir = os.environ.get("WINDIR", r"C:\Windows")
        font_dirs.append(os.path.join(windir, "Fonts"))
        # 用户字体目录
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            font_dirs.append(os.path.join(local_app, "Microsoft", "Windows", "Fonts"))
    elif system == "Darwin":
        font_dirs.extend([
            "/System/Library/Fonts",
            "/Library/Fonts",
            os.path.expanduser("~/Library/Fonts"),
        ])
    else:
        font_dirs.extend([
            "/usr/share/fonts",
            "/usr/local/share/fonts",
            "/usr/share/fonts/truetype",
            "/usr/share/fonts/opentype",
            os.path.expanduser("~/.local/share/fonts"),
            os.path.expanduser("~/.fonts"),
        ])

    # 项目内置字体目录优先
    project_font_dir = os.path.join(os.path.dirname(__file__), "..", "static", "fonts")
    if os.path.isdir(project_font_dir):
        font_dirs.insert(0, project_font_dir)

    for font_dir in font_dirs:
        if not os.path.isdir(font_dir):
            continue
        # 先精确匹配优先列表
        for font_name in cjk_font_names:
            font_path = os.path.join(font_dir, font_name)
            if os.path.isfile(font_path):
                logger.info(f"找到中文字体: {font_path}")
                return font_path
        # 递归搜索（针对 Linux 字体子目录结构）
        if system not in ("Windows", "Darwin"):
            for root, _dirs, files in os.walk(font_dir):
                for font_name in cjk_font_names:
                    if font_name in files:
                        font_path = os.path.join(root, font_name)
                        logger.info(f"找到中文字体: {font_path}")
                        return font_path

    logger.warning("未找到系统中文字体，PDF 可能无法显示中文")
    return None


def export_db_doc_pdf(eng: Engine, database: str, db_type: str = "mysql", save_path: Optional[str] = None) -> Dict[str, Any]:
    """生成 PDF 格式的数据库说明文档，返回 base64 编码的 PDF 内容"""
    from fpdf import FPDF
    import base64
    import logging

    logger = logging.getLogger(__name__)

    md_content = generate_db_doc_markdown(eng, database, db_type)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"db_doc_{database}_{timestamp}.pdf"
    
    # 获取通用的下载目录
    import os
    from pathlib import Path
    downloads_dir = Path(__file__).resolve().parent.parent.parent / "data" / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    save_path = str(downloads_dir / filename)

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
            logger.info(f"已加载中文字体: {font_path}")
        except Exception as e:
            logger.warning(f"加载中文字体失败: {e}，将尝试回退方案")
            has_cjk_font = False

    if not has_cjk_font:
        raise RuntimeError(
            "未找到可用的中文字体，无法生成包含中文的 PDF。"
            "请安装中文字体（如 SimHei、SimSun、微软雅黑）或将 .ttf 字体文件放入 src/static/fonts/ 目录。"
        )

    pdf.add_page()

    def set_font(style="", size=10):
        """设置字体，CJK 字体用 CJKb 模拟粗体"""
        if "B" in style.upper():
            pdf.set_font("CJKb", "", size + 1)
        else:
            pdf.set_font("CJK", "", size)

    for line in md_content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("# "):
            set_font("B", 18)
            pdf.cell(0, 12, stripped[2:], new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith("## "):
            set_font("B", 14)
            pdf.cell(0, 10, stripped[3:], new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith("|") and stripped.endswith("|"):
            if "---" in stripped:
                continue
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            set_font("", 8)
            col_width = (pdf.w - 20) / max(len(cells), 1)
            for cell in cells:
                pdf.cell(col_width, 6, cell[:30], border=1)
            pdf.ln()
        elif stripped.startswith("> "):
            set_font("", 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 7, stripped[2:], new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
        elif stripped.startswith("- "):
            set_font("", 9)
            pdf.cell(0, 6, f"  {stripped[2:]}", new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith("**") and stripped.endswith("**"):
            set_font("B", 10)
            pdf.cell(0, 8, stripped.strip("*"), new_x="LMARGIN", new_y="NEXT")
        elif stripped:
            set_font("", 9)
            pdf.cell(0, 6, stripped, new_x="LMARGIN", new_y="NEXT")

    pdf_bytes = pdf.output()
    
    with open(save_path, 'wb') as f:
        f.write(pdf_bytes)
    saved_to = os.path.abspath(save_path)
    logger.info(f"PDF 已保存到本地: {saved_to}")

    download_url = f"/downloads/{filename}"

    return {
        "success": True,
        "message": f"数据库说明文档生成成功，共包含 {len(get_all_tables_with_comments(eng, database, db_type))} 张表。",
        "file_path": saved_to,
        "download_url": download_url,
        "markdown_preview": md_content[:2000] + "\n... (为节省空间已截断)" if len(md_content) > 2000 else md_content
    }

def generate_db_doc_markdown_parts(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
    max_chars: int = 500000,
    max_tables_per_part: Optional[int] = None
) -> List[str]:
    """生成按片段划分的 Markdown 文档
    
    Args:
        eng: 数据库引擎
        database: 库名
        db_type: 数据库类型
        max_chars: 单片段最大字符数
        max_tables_per_part: 单片段最大表数量
        
    Returns:
        Markdown 文本片段列表
    """
    summary = get_db_summary(eng, database, db_type)
    tables = get_all_tables_with_comments(eng, database, db_type)
    
    header_lines = []
    header_lines.append(f"# 数据库说明文档 — {database}\n")
    header_lines.append("## 数据库概要\n")
    header_lines.append("| 属性 | 值 |")
    header_lines.append("|------|------|")
    for k, v in summary.items():
        header_lines.append(f"| {k} | {v} |")
    header_lines.append("")
    
    list_lines = []
    list_lines.append("## 表汇总\n")
    list_lines.append("| 序号 | 表名 | 备注 |")
    list_lines.append("|------|------|------|")
    for i, t in enumerate(tables, 1):
        list_lines.append(f"| {i} | {t['table_name']} | {t['table_comment']} |")
    list_lines.append("")
    
    def table_block(tname: str, tcomment: str) -> str:
        lines = []
        lines.append(f"## {tname}")
        if tcomment:
            lines.append(f"\n> {tcomment}\n")
        else:
            lines.append("")
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
        idxs = get_table_indexes(eng, database, tname, db_type)
        if idxs:
            lines.append("**索引:**\n")
            if db_type.lower() == "postgresql":
                for idx in idxs:
                    lines.append(f"- `{idx['index_name']}`: {idx['index_definition']}")
            else:
                idx_map: Dict[str, Dict[str, Any]] = {}
                for idx in idxs:
                    name = idx["index_name"]
                    if name not in idx_map:
                        idx_map[name] = {
                            "columns": [],
                            "unique": not idx["non_unique"],
                            "type": idx["index_type"]
                        }
                    idx_map[name]["columns"].append(idx["column_name"])
                for name, info in idx_map.items():
                    uq = "UNIQUE " if info["unique"] else ""
                    cols_join = ", ".join(info["columns"])
                    lines.append(f"- `{name}`: {uq}{info['type']} ({cols_join})")
            lines.append("")
        fks = get_table_foreign_keys(eng, database, tname, db_type)
        if fks:
            lines.append("**外键:**\n")
            for fk in fks:
                lines.append(
                    f"- `{fk['constraint_name']}`: {tname}.{fk['column_name']} → "
                    f"{fk['referenced_table']}.{fk['referenced_column']}"
                )
            lines.append("")
        return "\n".join(lines)
    
    parts: List[str] = []
    current_lines: List[str] = []
    current_tables = 0
    
    # 首片段加入概要与表汇总
    current_lines.extend(header_lines)
    current_lines.extend(list_lines)
    
    for t in tables:
        block = table_block(t["table_name"], t["table_comment"])
        # 预检查是否需要切片
        next_len = sum(len(l) for l in current_lines) + len(block)
        hit_chars = next_len > max_chars
        hit_tables = max_tables_per_part is not None and current_tables >= max_tables_per_part
        if hit_chars or hit_tables:
            parts.append("\n".join(current_lines))
            current_lines = []
            current_tables = 0
            # 非首片段标题
            current_lines.append(f"# 数据库说明文档 — {database}（分片）\n")
        current_lines.append(block)
        current_tables += 1
    
    if current_lines:
        parts.append("\n".join(current_lines))
    
    return parts

def save_db_doc_markdown_split(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
    save_dir: str = ".",
    filename_prefix: Optional[str] = None,
    max_chars: int = 500000,
    max_tables_per_part: Optional[int] = None
) -> List[str]:
    """生成并保存分片 Markdown 文档
    
    Args:
        eng: 数据库引擎
        database: 库名
        db_type: 数据库类型
        save_dir: 保存目录
        filename_prefix: 文件名前缀
        max_chars: 单片段最大字符数
        max_tables_per_part: 单片段最大表数量
        
    Returns:
        保存的文件路径列表
    """
    import os
    parts = generate_db_doc_markdown_parts(
        eng, database, db_type, max_chars=max_chars, max_tables_per_part=max_tables_per_part
    )
    if not os.path.isdir(save_dir):
        os.makedirs(save_dir, exist_ok=True)
    if not filename_prefix:
        filename_prefix = f"db_doc_{database}"
    saved = []
    for i, content in enumerate(parts, 1):
        path = os.path.join(save_dir, f"{filename_prefix}_part_{i}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        saved.append(path)
    return saved
