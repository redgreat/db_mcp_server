from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any


def list_databases(eng: Engine, db_type: str = "mysql") -> List[str]:
    """列出服务器上的所有数据库
    
    Args:
        eng: 数据库引擎
        db_type: 数据库类型 ('mysql' 或 'postgresql')
    
    Returns:
        数据库名称列表
    """
    if db_type.lower() == "postgresql":
        sql = "SELECT datname FROM pg_database WHERE datistemplate = false"
    else:
        sql = "SHOW DATABASES"
        
    with eng.connect() as conn:
        rows = conn.execute(text(sql)).all()
    return [r[0] for r in rows]


def list_tables(eng: Engine, database: str, db_type: str = "mysql") -> List[str]:
    """列出数据库中的所有表
    
    Args:
        eng: 数据库引擎
        database: 数据库名称
        db_type: 数据库类型 ('mysql' 或 'postgresql')
    
    Returns:
        表名列表
    """
    if db_type.lower() == "postgresql":
        # PostgreSQL使用不同的系统表
        sql = """
            SELECT tablename 
            FROM pg_catalog.pg_tables 
            WHERE schemaname = :schema
        """
        # PostgreSQL中，默认schema是public
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).all()
    else:
        # MySQL使用information_schema
        sql = "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=:db AND TABLE_TYPE='BASE TABLE'"
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).all()
    return [r[0] for r in rows]


def list_views(eng: Engine, database: str, db_type: str = "mysql") -> List[str]:
    """列出数据库中的所有视图
    
    Args:
        eng: 数据库引擎
        database: 数据库名称
        db_type: 数据库类型 ('mysql' 或 'postgresql')
    
    Returns:
        视图名列表
    """
    if db_type.lower() == "postgresql":
        sql = "SELECT viewname FROM pg_catalog.pg_views WHERE schemaname = :schema"
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).all()
    else:
        sql = "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=:db AND TABLE_TYPE='VIEW'"
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).all()
    return [r[0] for r in rows]


def list_procedures(eng: Engine, database: str, db_type: str = "mysql") -> List[str]:
    """列出数据库中的所有存储过程
    
    Args:
        eng: 数据库引擎
        database: 数据库名称
        db_type: 数据库类型 ('mysql' 或 'postgresql')
    
    Returns:
        存储过程名列表
    """
    if db_type.lower() == "postgresql":
        sql = """
            SELECT p.proname
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = :schema
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).all()
    else:
        sql = "SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=:db AND ROUTINE_TYPE='PROCEDURE'"
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).all()
    return [r[0] for r in rows]


def table_info(eng: Engine, database: str, table: str, db_type: str = "mysql") -> Dict[str, Any]:
    """查询表字段与主键信息
    
    Args:
        eng: 数据库引擎
        database: 数据库名称
        table: 表名
        db_type: 数据库类型 ('mysql' 或 'postgresql')
    
    Returns:
        包含列信息的字典
    """
    if db_type.lower() == "postgresql":
        # PostgreSQL查询列信息
        cols_sql = """
        SELECT 
            column_name as "COLUMN_NAME",
            data_type as "DATA_TYPE",
            is_nullable as "IS_NULLABLE",
            CASE 
                WHEN pk.column_name IS NOT NULL THEN 'PRI'
                ELSE ''
            END as "COLUMN_KEY"
        FROM information_schema.columns c
        LEFT JOIN (
            SELECT ku.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage ku
                ON tc.constraint_name = ku.constraint_name
                AND tc.table_schema = ku.table_schema
            WHERE tc.constraint_type = 'PRIMARY KEY'
                AND tc.table_name = :tb
                AND tc.table_schema = :schema
        ) pk ON c.column_name = pk.column_name
        WHERE c.table_name = :tb
            AND c.table_schema = :schema
        ORDER BY c.ordinal_position
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            cols = conn.execute(text(cols_sql), {"tb": table, "schema": schema}).mappings().all()
    else:
        # MySQL查询列信息
        cols_sql = """
        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=:db AND TABLE_NAME=:tb
        """
        with eng.connect() as conn:
            cols = conn.execute(text(cols_sql), {"db": database, "tb": table}).mappings().all()
    return {"columns": [dict(c) for c in cols]}
