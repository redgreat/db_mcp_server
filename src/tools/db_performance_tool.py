from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import List, Dict, Any


def get_connection_stats(eng: Engine, db_type: str = "mysql") -> Dict[str, Any]:
    """获取当前连接数统计"""
    if db_type.lower() == "postgresql":
        with eng.connect() as conn:
            row = conn.execute(text("""
                SELECT
                    (SELECT count(*) FROM pg_stat_activity) AS total_connections,
                    (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') AS active,
                    (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle') AS idle,
                    (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction') AS idle_in_transaction,
                    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') AS max_connections
            """)).mappings().first()
            return dict(row)
    else:
        with eng.connect() as conn:
            row = conn.execute(text("""
                SELECT
                    (SELECT COUNT(*) FROM information_schema.PROCESSLIST) AS total_connections,
                    (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND != 'Sleep') AS active,
                    (SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND = 'Sleep') AS idle,
                    (SELECT @@max_connections) AS max_connections
            """)).mappings().first()
            return dict(row)


def get_slow_queries(eng: Engine, db_type: str = "mysql", limit: int = 20) -> List[Dict[str, Any]]:
    """获取慢 SQL 列表"""
    if db_type.lower() == "postgresql":
        with eng.connect() as conn:
            try:
                rows = conn.execute(text("""
                    SELECT
                        query,
                        calls,
                        ROUND(total_exec_time::numeric, 2) AS total_time_ms,
                        ROUND(mean_exec_time::numeric, 2) AS avg_time_ms,
                        ROUND(max_exec_time::numeric, 2) AS max_time_ms,
                        rows
                    FROM pg_stat_statements
                    ORDER BY mean_exec_time DESC
                    LIMIT :lmt
                """), {"lmt": limit}).mappings().all()
                return [dict(r) for r in rows]
            except Exception:
                rows = conn.execute(text("""
                    SELECT
                        query,
                        state,
                        EXTRACT(EPOCH FROM (now() - query_start))::numeric(10,2) AS running_seconds,
                        wait_event_type,
                        wait_event
                    FROM pg_stat_activity
                    WHERE state = 'active' AND query NOT LIKE '%pg_stat_activity%'
                    ORDER BY query_start ASC
                    LIMIT :lmt
                """), {"lmt": limit}).mappings().all()
                return [dict(r) for r in rows]
    else:
        with eng.connect() as conn:
            try:
                rows = conn.execute(text("""
                    SELECT
                        DIGEST_TEXT AS query,
                        COUNT_STAR AS calls,
                        ROUND(SUM_TIMER_WAIT / 1000000000, 2) AS total_time_ms,
                        ROUND(AVG_TIMER_WAIT / 1000000000, 2) AS avg_time_ms,
                        ROUND(MAX_TIMER_WAIT / 1000000000, 2) AS max_time_ms,
                        SUM_ROWS_EXAMINED AS rows_examined,
                        SUM_ROWS_SENT AS rows_sent
                    FROM performance_schema.events_statements_summary_by_digest
                    WHERE DIGEST_TEXT IS NOT NULL
                    ORDER BY AVG_TIMER_WAIT DESC
                    LIMIT :lmt
                """), {"lmt": limit}).mappings().all()
                return [dict(r) for r in rows]
            except Exception:
                rows = conn.execute(text("""
                    SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE,
                           LEFT(INFO, 500) AS query
                    FROM information_schema.PROCESSLIST
                    WHERE COMMAND != 'Sleep' AND INFO IS NOT NULL
                    ORDER BY TIME DESC
                    LIMIT :lmt
                """), {"lmt": limit}).mappings().all()
                return [dict(r) for r in rows]


def get_lock_info(eng: Engine, db_type: str = "mysql") -> List[Dict[str, Any]]:
    """获取锁等待信息"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                blocked.pid AS blocked_pid,
                blocked.query AS blocked_query,
                blocking.pid AS blocking_pid,
                blocking.query AS blocking_query,
                blocked.wait_event_type,
                blocked.wait_event
            FROM pg_stat_activity blocked
            JOIN pg_locks bl ON bl.pid = blocked.pid
            JOIN pg_locks kl ON kl.locktype = bl.locktype
                AND kl.database IS NOT DISTINCT FROM bl.database
                AND kl.relation IS NOT DISTINCT FROM bl.relation
                AND kl.page IS NOT DISTINCT FROM bl.page
                AND kl.tuple IS NOT DISTINCT FROM bl.tuple
                AND kl.transactionid IS NOT DISTINCT FROM bl.transactionid
                AND kl.classid IS NOT DISTINCT FROM bl.classid
                AND kl.objid IS NOT DISTINCT FROM bl.objid
                AND kl.objsubid IS NOT DISTINCT FROM bl.objsubid
                AND kl.pid != bl.pid
                AND NOT bl.granted
            JOIN pg_stat_activity blocking ON kl.pid = blocking.pid
            LIMIT 50
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql)).mappings().all()
    else:
        sql = """
            SELECT
                r.trx_id AS waiting_trx_id,
                r.trx_mysql_thread_id AS waiting_pid,
                r.trx_query AS waiting_query,
                b.trx_id AS blocking_trx_id,
                b.trx_mysql_thread_id AS blocking_pid,
                b.trx_query AS blocking_query
            FROM information_schema.INNODB_LOCK_WAITS w
            JOIN information_schema.INNODB_TRX r ON w.requesting_trx_id = r.trx_id
            JOIN information_schema.INNODB_TRX b ON w.blocking_trx_id = b.trx_id
            LIMIT 50
        """
        with eng.connect() as conn:
            try:
                rows = conn.execute(text(sql)).mappings().all()
            except Exception:
                rows = conn.execute(text("""
                    SELECT
                        r.trx_id AS waiting_trx_id,
                        r.trx_mysql_thread_id AS waiting_pid,
                        r.trx_query AS waiting_query
                    FROM information_schema.INNODB_TRX r
                    WHERE r.trx_state = 'LOCK WAIT'
                    LIMIT 50
                """)).mappings().all()

    return [dict(r) for r in rows]


def get_table_stats(eng: Engine, database: str, db_type: str = "mysql") -> List[Dict[str, Any]]:
    """获取表统计信息（大小、行数、碎片率）"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                relname AS table_name,
                pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
                pg_size_pretty(pg_relation_size(c.oid)) AS data_size,
                pg_size_pretty(pg_indexes_size(c.oid)) AS index_size,
                n_live_tup AS row_count,
                n_dead_tup AS dead_rows,
                CASE WHEN n_live_tup > 0
                    THEN ROUND(n_dead_tup * 100.0 / n_live_tup, 2)
                    ELSE 0
                END AS dead_row_ratio
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
            WHERE c.relkind = 'r' AND n.nspname = :schema
            ORDER BY pg_total_relation_size(c.oid) DESC
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    else:
        sql = """
            SELECT
                TABLE_NAME AS table_name,
                CONCAT(ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2), ' MB') AS total_size,
                CONCAT(ROUND(DATA_LENGTH / 1024 / 1024, 2), ' MB') AS data_size,
                CONCAT(ROUND(INDEX_LENGTH / 1024 / 1024, 2), ' MB') AS index_size,
                TABLE_ROWS AS row_count,
                CONCAT(ROUND(DATA_FREE / 1024 / 1024, 2), ' MB') AS fragmented_space,
                CASE WHEN DATA_LENGTH > 0
                    THEN ROUND(DATA_FREE * 100.0 / DATA_LENGTH, 2)
                    ELSE 0
                END AS fragmentation_ratio
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = :db AND TABLE_TYPE = 'BASE TABLE'
            ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    return [dict(r) for r in rows]


def get_index_usage(eng: Engine, database: str, db_type: str = "mysql") -> List[Dict[str, Any]]:
    """获取索引使用情况"""
    if db_type.lower() == "postgresql":
        sql = """
            SELECT
                schemaname AS schema_name,
                relname AS table_name,
                indexrelname AS index_name,
                idx_scan AS scans,
                idx_tup_read AS tuples_read,
                idx_tup_fetch AS tuples_fetched,
                pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
            FROM pg_stat_user_indexes
            WHERE schemaname = :schema
            ORDER BY idx_scan ASC
        """
        schema = "public" if database == "public" else database
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"schema": schema}).mappings().all()
    else:
        sql = """
            SELECT
                TABLE_NAME AS table_name,
                INDEX_NAME AS index_name,
                SEQ_IN_INDEX AS seq,
                COLUMN_NAME AS column_name,
                CARDINALITY AS cardinality,
                INDEX_TYPE AS index_type,
                NON_UNIQUE AS non_unique
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = :db
            ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
        """
        with eng.connect() as conn:
            rows = conn.execute(text(sql), {"db": database}).mappings().all()

    return [dict(r) for r in rows]


def generate_performance_report(eng: Engine, database: str, db_type: str = "mysql") -> Dict[str, Any]:
    """生成综合性能报告"""
    conn_stats = get_connection_stats(eng, db_type)
    slow_queries = get_slow_queries(eng, db_type, limit=10)
    lock_info = get_lock_info(eng, db_type)
    table_stats = get_table_stats(eng, database, db_type)
    index_usage = get_index_usage(eng, database, db_type)

    suggestions = []

    max_conn = int(conn_stats.get("max_connections", 100))
    total_conn = int(conn_stats.get("total_connections", 0))
    if max_conn > 0 and total_conn / max_conn > 0.8:
        suggestions.append({
            "type": "connection",
            "severity": "high",
            "message": (
                f"连接数使用率已达 {total_conn}/{max_conn} "
                f"({round(total_conn / max_conn * 100)}%)，建议增加 max_connections 或优化连接池"
            ),
        })

    if lock_info:
        suggestions.append({
            "type": "lock",
            "severity": "high",
            "message": f"当前存在 {len(lock_info)} 个锁等待，请检查是否有长事务阻塞"
        })

    if db_type.lower() == "postgresql":
        for t in table_stats:
            dead_ratio = float(t.get("dead_row_ratio", 0))
            if dead_ratio > 20:
                suggestions.append({
                    "type": "vacuum",
                    "severity": "medium",
                    "message": f"表 {t['table_name']} 死⾏比例达 {dead_ratio}%，建议执行 VACUUM ANALYZE"
                })
    else:
        for t in table_stats:
            frag_ratio = float(t.get("fragmentation_ratio", 0))
            if frag_ratio > 20:
                suggestions.append({
                    "type": "fragmentation",
                    "severity": "medium",
                    "message": f"表 {t['table_name']} 碎片率达 {frag_ratio}%，建议执行 OPTIMIZE TABLE"
                })

    if db_type.lower() == "postgresql":
        unused_indexes = [i for i in index_usage if int(i.get("scans", 0)) == 0]
        if unused_indexes:
            for idx in unused_indexes[:5]:
                suggestions.append({
                    "type": "index",
                    "severity": "low",
                    "message": (
                        f"索引 {idx['index_name']}（表 {idx['table_name']}）"
                        f"从未被使用，大小 {idx.get('index_size', 'N/A')}，可考虑删除"
                    )
                })

    for sq in slow_queries[:3]:
        query = str(sq.get("query", ""))[:200]
        avg_ms = sq.get("avg_time_ms", 0)
        if avg_ms and float(avg_ms) > 1000:
            suggestions.append({
                "type": "slow_query",
                "severity": "medium",
                "message": f"慢 SQL（平均 {avg_ms}ms）: {query}..."
            })

    result = {
        "connection_stats": conn_stats,
        "slow_queries": slow_queries,
        "lock_info": lock_info,
        "table_stats": table_stats[:20],
        "index_usage_summary": {
            "total_indexes": len(index_usage),
            "unused_indexes": (
                len([i for i in index_usage if int(i.get("scans", 0)) == 0])
                if db_type.lower() == "postgresql" else None
            )
        },
        "suggestions": suggestions,
        "ai_analysis": "",
        "ai_usage": None
    }

    from ..ai.service import is_llm_enabled, llm_ask_with_usage, llm_disabled_message

    if is_llm_enabled():
        import json

        system_prompt = (
            "你是一个极其资深的 DBA（数据库管理员）。用户会提供一组从数据库中抓取的性能数据，"
            "包括当前连接数、Top 慢查询记录、活跃锁等待链、表碎片/死行率情况等。\n"
            "请你综合这些数据，出具一份清晰、具有高度实操性的《数据库性能诊断与调优报告》。\n"
            "请直接以 Markdown 输出，无需多余寒暄。"
        )
        user_prompt = "性能采集数据如下：\n"
        user_prompt += f"连接状态：{json.dumps(conn_stats, ensure_ascii=False)}\n"
        user_prompt += f"锁等待：{json.dumps(lock_info, ensure_ascii=False)}\n"
        user_prompt += f"慢查询 Top5：{json.dumps(slow_queries[:5], ensure_ascii=False)}\n"
        user_prompt += f"部分表统计：{json.dumps(table_stats[:5], ensure_ascii=False)}\n"
        try:
            ai_result = llm_ask_with_usage(
                system_prompt, user_prompt, tool_name="analyze_db_performance"
            )
            result["ai_analysis"] = ai_result["content"]
            result["ai_usage"] = ai_result["usage"]
        except Exception as e:
            result["ai_analysis"] = f"AI 调用失败：{e}"
    else:
        result["ai_analysis"] = llm_disabled_message()

    return result
