import os
import sys
from typing import List
from sqlalchemy import create_engine, Table, MetaData, select

# 允许从项目根目录导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import Config
from sqlalchemy.engine import URL
from src.security.secret import decrypt_text
from src.tools.db_doc_tool import (
    generate_db_doc_markdown,
    save_db_doc_markdown_split,
)
from src.tools.db_er_tool import (
    generate_er_text_description,
    save_er_mermaid_split,
)


def _get_target_connection(cfg: Config, database_name: str) -> dict:
    """获取指定数据库的连接记录"""
    # 使用 URL.create 避免编码问题
    adb = cfg.admin_database
    admin_url = URL.create(
        "postgresql+psycopg2",
        username=adb.username,
        password=adb.password,
        host=adb.host,
        port=adb.port,
        database=adb.database,
    )
    admin_engine = create_engine(admin_url, pool_pre_ping=True)
    meta = MetaData()
    conns = Table("db_connections", meta, autoload_with=admin_engine)
    with admin_engine.connect() as conn:
        row = conn.execute(
            select(conns).where(conns.c.database == database_name)
        ).mappings().first()
    if not row:
        raise RuntimeError(f"未找到数据库 '{database_name}' 的连接记录")
    return dict(row)


def _make_engine(conn_row: dict, master_key: str):
    """构造数据源引擎"""
    pwd = decrypt_text(conn_row["password_enc"], master_key)
    db_type = (conn_row["db_type"] or "mysql").lower()
    if db_type == "postgresql":
        uri = f"postgresql+psycopg2://{conn_row['username']}:{pwd}@{conn_row['host']}:{int(conn_row['port'])}/{conn_row['database']}"
    else:
        uri = f"mysql+pymysql://{conn_row['username']}:{pwd}@{conn_row['host']}:{int(conn_row['port'])}/{conn_row['database']}"
    return create_engine(uri, pool_pre_ping=True), db_type


def _write_index_md(path: str, title: str, summary_lines: List[str], parts: List[str]):
    """写入索引型 MD 文件"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = []
    lines.append(f"# {title}")
    lines.append("")
    for ln in summary_lines:
        lines.append(ln)
    lines.append("")
    lines.append("## 分片文件")
    for i, p in enumerate(parts, 1):
        rel = os.path.relpath(p, os.path.dirname(path)).replace("\\", "/")
        lines.append(f"- 第 {i} 片: {rel}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    """生成 whcenter 的数据字典与 ER 图（分片保存并覆盖索引文件）"""
    cfg = Config.load()
    database_name = "whcenter"
    save_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "doc")
    os.makedirs(save_dir, exist_ok=True)

    # 1. 获取连接并构造引擎
    conn_row = _get_target_connection(cfg, database_name)
    eng, db_type = _make_engine(conn_row, cfg.security.master_key)

    # 2. 数据字典分片保存
    doc_parts = save_db_doc_markdown_split(
        eng,
        database_name,
        db_type,
        save_dir=save_dir,
        filename_prefix=f"{database_name}_doc",
        max_chars=400_000,
        max_tables_per_part=120,
    )

    # 覆盖索引文件（简要说明 + 分片列表）
    md_full_summary = generate_db_doc_markdown(eng, database_name, db_type).split("\n")[:40]
    _write_index_md(
        os.path.join(save_dir, f"{database_name}_数据字典.md"),
        f"{database_name} 数据库说明文档（索引）",
        md_full_summary,
        doc_parts,
    )

    # 3. ER 图分片保存（Mermaid）
    er_parts = save_er_mermaid_split(
        eng,
        database_name,
        db_type,
        save_dir=save_dir,
        filename_prefix=f"{database_name}_er",
        include_columns=True,
        include_implicit=True,
        max_tables_per_part=120,
        max_chars=400_000,
    )

    # 覆盖 ER 图索引文件（文字描述 + 分片列表）
    er_text = generate_er_text_description(eng, database_name, db_type, include_implicit=True).split("\n")[:80]
    _write_index_md(
        os.path.join(save_dir, f"{database_name}_ER图.md"),
        f"{database_name} ER 图（索引）",
        er_text,
        er_parts,
    )

    print("✅ 生成完成")
    print(f"数据字典分片: {len(doc_parts)} 个")
    print(f"ER 图分片: {len(er_parts)} 个")
    print(f"索引文件:")
    print(f"  - {os.path.join(save_dir, f'{database_name}_数据字典.md')}")
    print(f"  - {os.path.join(save_dir, f'{database_name}_ER图.md')}")


if __name__ == "__main__":
    main()
