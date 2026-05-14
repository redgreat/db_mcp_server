from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import Dict, Any
from datetime import datetime


def backup_table(eng: Engine, database: str, table: str,
                 db_type: str = "mysql", suffix: str = None) -> Dict[str, Any]:
    """通过 CREATE TABLE AS SELECT 方式快速备份指定表"""
    if not suffix:
        suffix = datetime.now().strftime("%Y%m%d_%H%M%S")

    backup_name = f"{table}_bak_{suffix}"

    with eng.connect() as conn:
        if db_type.lower() == "postgresql":
            check_sql = """
                SELECT COUNT(*) AS cnt FROM information_schema.tables
                WHERE table_schema = :schema AND table_name = :tb
            """
            schema = "public" if database == "public" else database
            row = conn.execute(text(check_sql), {"schema": schema, "tb": backup_name}).mappings().first()
        elif db_type.lower() in ("sqlserver", "mssql"):
            check_sql = """
                SELECT COUNT(*) AS cnt FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_CATALOG = :db AND TABLE_NAME = :tb
            """
            row = conn.execute(text(check_sql), {"db": database, "tb": backup_name}).mappings().first()
        else:
            check_sql = """
                SELECT COUNT(*) AS cnt FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :tb
            """
            row = conn.execute(text(check_sql), {"db": database, "tb": backup_name}).mappings().first()

        if row and int(row["cnt"]) > 0:
            return {
                "success": False,
                "error": f"备份表 {backup_name} 已存在，请更换后缀或删除已有备份",
                "backup_table": backup_name
            }

        if db_type.lower() == "postgresql":
            src_count = conn.execute(text(f'SELECT COUNT(*) AS cnt FROM "{table}"')).mappings().first()
            create_sql = f'CREATE TABLE "{backup_name}" AS SELECT * FROM "{table}"'
        elif db_type.lower() in ("sqlserver", "mssql"):
            src_count = conn.execute(text(f"SELECT COUNT(*) AS cnt FROM [{table}]")).mappings().first()
            create_sql = f"SELECT * INTO [{backup_name}] FROM [{table}]"
        else:
            src_count = conn.execute(text(f"SELECT COUNT(*) AS cnt FROM `{table}`")).mappings().first()
            create_sql = f"CREATE TABLE `{backup_name}` AS SELECT * FROM `{table}`"

        source_rows = int(src_count["cnt"]) if src_count else 0

        conn.execute(text(create_sql))
        conn.commit()

        if db_type.lower() == "postgresql":
            bak_count = conn.execute(text(f'SELECT COUNT(*) AS cnt FROM "{backup_name}"')).mappings().first()
        elif db_type.lower() in ("sqlserver", "mssql"):
            bak_count = conn.execute(text(f"SELECT COUNT(*) AS cnt FROM [{backup_name}]")).mappings().first()
        else:
            bak_count = conn.execute(text(f"SELECT COUNT(*) AS cnt FROM `{backup_name}`")).mappings().first()

        backup_rows = int(bak_count["cnt"]) if bak_count else 0

    return {
        "success": True,
        "source_table": table,
        "backup_table": backup_name,
        "database": database,
        "source_rows": source_rows,
        "backup_rows": backup_rows,
        "ddl": create_sql,
        "notes": [
            "备份表不包含原表的索引、外键、触发器等约束",
            "如需完整结构备份请使用 mysqldump / pg_dump",
            f"还原方式: INSERT INTO {table} SELECT * FROM {backup_name}",
            f"清理方式: DROP TABLE {backup_name}"
        ]
    }
