"""数据库 DDL 导出工具。

封装 export_db_schema.py 的核心逻辑，从 SQLAlchemy Engine 直连数据库
导出完整 DDL（表、视图、存储过程、触发器、索引等），
无需 mysqldump / pg_dump 外部命令。
"""
from __future__ import annotations

import logging
import time
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from sqlalchemy import text, MetaData, inspect, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.schema import CreateTable, CreateIndex

logger = logging.getLogger(__name__)


def export_mysql_ddl(eng: Engine, database: str) -> str:
    """导出 MySQL 数据库的完整 DDL（表、视图、存储过程/函数、触发器、事件）。"""
    parts: List[str] = []
    parts.append(f"-- MySQL DDL 导出 — {database}\n")
    parts.append("-- 由 db_ddl_tool.py 生成\n")
    parts.append("SET NAMES utf8mb4;\n\n")

    with eng.connect() as conn:
        tables = conn.execute(text(
            "SELECT TABLE_NAME FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA=:db AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME"
        ), {"db": database}).scalars().all()

        for t in tables:
            try:
                row = conn.execute(text(f"SHOW CREATE TABLE `{database}`.`{t}`")).first()
                if row:
                    ddl = row[1] if len(row) > 1 else str(row)
                    parts.append(f"DROP TABLE IF EXISTS `{t}`;\n{ddl};\n\n")
            except Exception as exc:
                parts.append(f"-- 跳过表 `{t}`: {exc}\n\n")

        views = conn.execute(text(
            "SELECT TABLE_NAME FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA=:db AND TABLE_TYPE='VIEW' ORDER BY TABLE_NAME"
        ), {"db": database}).scalars().all()

        for v in views:
            try:
                row = conn.execute(text(f"SHOW CREATE VIEW `{database}`.`{v}`")).first()
                if row:
                    ddl = row[1] if len(row) > 1 else str(row)
                    parts.append(f"DROP VIEW IF EXISTS `{v}`;\n{ddl};\n\n")
            except Exception as exc:
                parts.append(f"-- 跳过视图 `{v}`: {exc}\n\n")

        routines = conn.execute(text(
            "SELECT ROUTINE_NAME, ROUTINE_TYPE FROM information_schema.ROUTINES "
            "WHERE ROUTINE_SCHEMA=:db ORDER BY ROUTINE_TYPE, ROUTINE_NAME"
        ), {"db": database}).all()

        for rname, rtype in routines:
            try:
                kind = rtype.upper()
                row = conn.execute(text(f"SHOW CREATE {kind} `{database}`.`{rname}`")).first()
                if row:
                    ddl = row[2] if len(row) > 2 else (row[1] if len(row) > 1 else str(row))
                    delimiter = "$$"
                    parts.append(
                        f"-- {kind}: `{rname}`\n"
                        f"DELIMITER {delimiter}\n"
                        f"DROP {kind} IF EXISTS `{rname}`{delimiter}\n"
                        f"{ddl}{delimiter}\n"
                        f"DELIMITER ;\n\n"
                    )
            except Exception as exc:
                parts.append(f"-- 跳过例程 `{rname}`: {exc}\n\n")

        triggers = conn.execute(text(
            "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS "
            "WHERE TRIGGER_SCHEMA=:db ORDER BY TRIGGER_NAME"
        ), {"db": database}).scalars().all()

        for tr in triggers:
            try:
                row = conn.execute(text(f"SHOW CREATE TRIGGER `{database}`.`{tr}`")).first()
                if row:
                    ddl = row[2] if len(row) > 2 else (row[1] if len(row) > 1 else str(row))
                    parts.append(f"DROP TRIGGER IF EXISTS `{tr}`;\n{ddl};\n\n")
            except Exception as exc:
                parts.append(f"-- 跳过触发器 `{tr}`: {exc}\n\n")

    return "".join(parts)


def export_postgresql_ddl(eng: Engine, database: str, schema: str = "public") -> str:
    """导出 PostgreSQL schema 的完整 DDL（表、索引、视图、函数、触发器）。"""
    import warnings
    from sqlalchemy.sql import sqltypes
    from sqlalchemy.types import UserDefinedType

    parts: List[str] = []
    parts.append(f"-- PostgreSQL DDL 导出 — {database}.{schema}\n")
    parts.append("-- 由 db_ddl_tool.py 生成\n")
    parts.append("SET client_encoding = 'UTF8';\n\n")

    insp = inspect(eng)
    table_names = list(insp.get_table_names(schema=schema))
    view_names = list(insp.get_view_names(schema=schema) or [])

    metadata = MetaData()
    if table_names:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            metadata.reflect(bind=eng, schema=schema, only=table_names, resolve_fks=True)

    parts.append(f"-- ========== 表 ==========\n\n")
    for table in metadata.sorted_tables:
        try:
            ddl = str(CreateTable(table).compile(dialect=eng.dialect)).rstrip() + ";\n\n"
            parts.append(ddl)
        except Exception as exc:
            parts.append(f"-- 跳过表 {table.name}: {exc}\n\n")

    parts.append(f"-- ========== 索引 ==========\n\n")
    for table in metadata.sorted_tables:
        for idx in sorted(table.indexes, key=lambda i: (i.name or "")):
            try:
                ddl = str(CreateIndex(idx).compile(dialect=eng.dialect)).rstrip() + ";\n\n"
                parts.append(ddl)
            except Exception:
                continue

    parts.append(f"-- ========== 视图 ==========\n\n")
    for v in sorted(view_names):
        try:
            defn = insp.get_view_definition(v, schema=schema)
            if defn:
                qsch = schema.replace('"', '""')
                qv = v.replace('"', '""')
                parts.append(
                    f'DROP VIEW IF EXISTS "{qsch}"."{qv}" CASCADE;\n'
                    f'CREATE OR REPLACE VIEW "{qsch}"."{qv}" AS {defn};\n\n'
                )
        except Exception:
            continue

    with eng.connect() as conn:
        funcs = conn.execute(text(
            "SELECT p.oid, p.prokind::text FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid "
            "WHERE n.nspname = :schema AND p.prokind IN ('f', 'p') ORDER BY p.oid"
        ), {"schema": schema}).all()

        parts.append(f"-- ========== 函数与存储过程 ==========\n\n")
        for oid, prokind in funcs:
            try:
                sig = conn.execute(text("SELECT CAST(:oid AS regprocedure)::text"), {"oid": oid}).scalar()
                ddl = conn.execute(text("SELECT pg_get_functiondef(CAST(:oid AS oid))"), {"oid": oid}).scalar()
                kind_cn = "存储过程" if prokind == "p" else "函数"
                stmt = ddl.strip()
                if not stmt.endswith(";"):
                    stmt += ";"
                parts.append(f"-- {kind_cn}: {sig}\n{stmt}\n\n")
            except Exception as exc:
                conn.rollback()
                parts.append(f"-- 跳过 oid={oid}: {exc}\n\n")

        triggers = conn.execute(text(
            "SELECT c.relname, t.tgname, t.oid FROM pg_catalog.pg_trigger t "
            "JOIN pg_catalog.pg_class c ON t.tgrelid = c.oid "
            "JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid "
            "WHERE n.nspname = :schema AND NOT t.tgisinternal ORDER BY c.relname, t.tgname"
        ), {"schema": schema}).all()

        parts.append(f"-- ========== 触发器 ==========\n\n")
        for tbl_name, trig_name, t_oid in triggers:
            try:
                ddl = conn.execute(
                    text("SELECT pg_get_triggerdef(CAST(:oid AS oid), true)"),
                    {"oid": t_oid},
                ).scalar()
                if ddl:
                    stmt = ddl.strip()
                    if not stmt.endswith(";"):
                        stmt += ";"
                    parts.append(f"-- 触发器: {tbl_name}.{trig_name}\n{stmt}\n\n")
            except Exception as exc:
                conn.rollback()
                parts.append(f"-- 跳过触发器 {tbl_name}.{trig_name}: {exc}\n\n")

    return "".join(parts)


def export_ddl(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
    schema: Optional[str] = None,
) -> str:
    """导出数据库完整 DDL。"""
    if db_type.lower() == "postgresql":
        return export_postgresql_ddl(eng, database, schema or "public")
    else:
        return export_mysql_ddl(eng, database)


def export_ddl_to_file(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
    schema: Optional[str] = None,
    save_path: Optional[str] = None,
) -> Dict[str, Any]:
    """导出 DDL 并保存为 SQL 文件。"""
    ddl_content = export_ddl(eng, database, db_type, schema)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"ddl_{database}_{timestamp}.sql"

    downloads_dir = Path(__file__).resolve().parent.parent.parent / "data" / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    save_path = save_path or str(downloads_dir / filename)

    with open(save_path, "w", encoding="utf-8") as f:
        f.write(ddl_content)

    saved_to = os.path.abspath(save_path)
    logger.info(f"DDL 已保存到本地: {saved_to}")

    download_url = f"/downloads/{filename}"
    ddl_preview = ddl_content[:2000] + "\n... (为节省空间已截断)" if len(ddl_content) > 2000 else ddl_content

    return {
        "success": True,
        "format": "sql",
        "file_path": saved_to,
        "download_url": download_url,
        "ddl_preview": ddl_preview,
        "size_bytes": len(ddl_content.encode("utf-8")),
    }