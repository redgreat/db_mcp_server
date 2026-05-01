from sqlalchemy import text
from sqlalchemy.engine import Engine
from typing import Dict, Any


def get_mysql_variables(eng: Engine) -> Dict[str, str]:
    """获取 MySQL 关键配置参数"""
    important_vars = [
        'innodb_buffer_pool_size', 'innodb_buffer_pool_instances',
        'innodb_log_file_size', 'innodb_log_buffer_size',
        'innodb_flush_log_at_trx_commit', 'innodb_flush_method',
        'innodb_io_capacity', 'innodb_io_capacity_max',
        'innodb_read_io_threads', 'innodb_write_io_threads',
        'innodb_file_per_table', 'innodb_open_files',
        'innodb_lock_wait_timeout', 'innodb_thread_concurrency',
        'max_connections', 'max_connect_errors',
        'thread_cache_size', 'table_open_cache', 'table_definition_cache',
        'sort_buffer_size', 'join_buffer_size', 'read_buffer_size',
        'read_rnd_buffer_size', 'tmp_table_size', 'max_heap_table_size',
        'key_buffer_size', 'query_cache_type', 'query_cache_size',
        'slow_query_log', 'long_query_time', 'log_queries_not_using_indexes',
        'binlog_format', 'sync_binlog', 'expire_logs_days',
        'max_allowed_packet', 'interactive_timeout', 'wait_timeout',
        'net_read_timeout', 'net_write_timeout',
        'character_set_server', 'collation_server',
        'lower_case_table_names', 'sql_mode'
    ]
    result = {}
    with eng.connect() as conn:
        for var in important_vars:
            try:
                row = conn.execute(text(f"SHOW VARIABLES LIKE '{var}'")).first()
                if row:
                    result[row[0]] = row[1]
            except Exception:
                pass
    return result


def get_mysql_status(eng: Engine) -> Dict[str, str]:
    """获取 MySQL 运行状态"""
    important_status = [
        'Uptime', 'Threads_connected', 'Threads_running', 'Threads_created',
        'Max_used_connections',
        'Innodb_buffer_pool_read_requests', 'Innodb_buffer_pool_reads',
        'Innodb_buffer_pool_pages_total', 'Innodb_buffer_pool_pages_free',
        'Innodb_buffer_pool_pages_dirty',
        'Innodb_rows_read', 'Innodb_rows_inserted', 'Innodb_rows_updated', 'Innodb_rows_deleted',
        'Innodb_log_waits',
        'Connections', 'Aborted_connects', 'Aborted_clients',
        'Slow_queries', 'Questions', 'Com_select', 'Com_insert', 'Com_update', 'Com_delete',
        'Sort_merge_passes', 'Sort_scan',
        'Table_locks_waited', 'Table_locks_immediate',
        'Created_tmp_tables', 'Created_tmp_disk_tables',
        'Open_tables', 'Opened_tables',
        'Select_full_join', 'Select_scan',
        'Key_reads', 'Key_read_requests'
    ]
    result = {}
    with eng.connect() as conn:
        for var in important_status:
            try:
                row = conn.execute(text(f"SHOW GLOBAL STATUS LIKE '{var}'")).first()
                if row:
                    result[row[0]] = row[1]
            except Exception:
                pass
    return result


def get_pg_settings(eng: Engine) -> Dict[str, Dict[str, str]]:
    """获取 PostgreSQL 关键配置参数"""
    important_settings = [
        'shared_buffers', 'effective_cache_size', 'work_mem', 'maintenance_work_mem',
        'wal_buffers', 'checkpoint_completion_target', 'checkpoint_timeout',
        'max_wal_size', 'min_wal_size',
        'max_connections', 'max_worker_processes', 'max_parallel_workers_per_gather',
        'max_parallel_workers', 'max_parallel_maintenance_workers',
        'random_page_cost', 'effective_io_concurrency', 'seq_page_cost',
        'default_statistics_target', 'from_collapse_limit', 'join_collapse_limit',
        'temp_buffers', 'huge_pages',
        'autovacuum', 'autovacuum_max_workers', 'autovacuum_vacuum_cost_delay',
        'autovacuum_vacuum_scale_factor', 'autovacuum_analyze_scale_factor',
        'log_min_duration_statement', 'log_checkpoints', 'log_lock_waits',
        'log_temp_files', 'log_statement',
        'wal_level', 'synchronous_commit', 'fsync',
        'shared_preload_libraries',
        'listen_addresses', 'port',
        'timezone', 'lc_messages'
    ]
    sql = """
        SELECT name, setting, unit, category, short_desc,
               boot_val, reset_val, source
        FROM pg_settings WHERE name = ANY(:names)
    """
    with eng.connect() as conn:
        rows = conn.execute(text(sql), {"names": important_settings}).mappings().all()
    return {r["name"]: dict(r) for r in rows}


def get_pg_stat_summary(eng: Engine) -> Dict[str, Any]:
    """获取 PostgreSQL 运行统计摘要"""
    result = {}
    with eng.connect() as conn:
        try:
            row = conn.execute(text("""
                SELECT
                    sum(numbackends) AS total_backends,
                    sum(xact_commit) AS total_commits,
                    sum(xact_rollback) AS total_rollbacks,
                    sum(blks_read) AS total_blks_read,
                    sum(blks_hit) AS total_blks_hit,
                    sum(tup_returned) AS tup_returned,
                    sum(tup_fetched) AS tup_fetched,
                    sum(tup_inserted) AS tup_inserted,
                    sum(tup_updated) AS tup_updated,
                    sum(tup_deleted) AS tup_deleted,
                    sum(conflicts) AS conflicts,
                    sum(temp_files) AS temp_files,
                    sum(temp_bytes) AS temp_bytes,
                    sum(deadlocks) AS deadlocks
                FROM pg_stat_database
            """)).mappings().first()
            result["database_stats"] = {k: int(v) if v else 0 for k, v in dict(row).items()}
        except Exception:
            pass

        try:
            row = conn.execute(text("""
                SELECT
                    CASE WHEN (blks_hit + blks_read) > 0
                        THEN ROUND(blks_hit * 100.0 / (blks_hit + blks_read), 2)
                        ELSE 100
                    END AS cache_hit_ratio
                FROM (
                    SELECT sum(blks_hit) AS blks_hit, sum(blks_read) AS blks_read
                    FROM pg_stat_database
                ) t
            """)).mappings().first()
            result["cache_hit_ratio"] = float(row["cache_hit_ratio"])
        except Exception:
            pass

    return result


def _parse_size_to_bytes(size_str: str) -> int:
    """将大小字符串转成字节数"""
    size_str = str(size_str).strip()
    multipliers = {'kb': 1024, 'mb': 1024**2, 'gb': 1024**3, 'tb': 1024**4,
                   'k': 1024, 'm': 1024**2, 'g': 1024**3, 't': 1024**4}
    for suffix, mult in multipliers.items():
        if size_str.lower().endswith(suffix):
            try:
                return int(float(size_str[:-len(suffix)].strip()) * mult)
            except ValueError:
                return 0
    try:
        return int(size_str)
    except ValueError:
        return 0


def _format_bytes(b: int) -> str:
    """字节数转可读格式"""
    if b >= 1024**3:
        return f"{b / 1024**3:.1f}GB"
    elif b >= 1024**2:
        return f"{b / 1024**2:.0f}MB"
    elif b >= 1024:
        return f"{b / 1024:.0f}KB"
    return f"{b}B"


def analyze_mysql_config(eng: Engine) -> Dict[str, Any]:
    """分析 MySQL 配置并给出调优建议"""
    variables = get_mysql_variables(eng)
    status = get_mysql_status(eng)
    suggestions = []

    total_mem_sql = "SELECT @@innodb_buffer_pool_size AS bp_size"
    with eng.connect() as conn:
        try:
            row = conn.execute(text(total_mem_sql)).mappings().first()
            bp_size = int(row["bp_size"]) if row else 0
        except Exception:
            bp_size = _parse_size_to_bytes(variables.get("innodb_buffer_pool_size", "0"))

    bp_reads = int(status.get("Innodb_buffer_pool_read_requests", 0))
    bp_disk = int(status.get("Innodb_buffer_pool_reads", 0))
    if bp_reads > 0:
        hit_ratio = round((bp_reads - bp_disk) / bp_reads * 100, 2)
        if hit_ratio < 99:
            suggestions.append({
                "parameter": "innodb_buffer_pool_size",
                "current": _format_bytes(bp_size),
                "severity": "high",
                "message": (
                    f"Buffer Pool 命中率仅 {hit_ratio}%，"
                    f"建议增大 innodb_buffer_pool_size"
                    f"（当前 {_format_bytes(bp_size)}），推荐为物理内存的 60-80%"
                )
            })

    max_conn = int(variables.get("max_connections", 151))
    max_used = int(status.get("Max_used_connections", 0))
    if max_used > 0 and max_used / max_conn > 0.8:
        suggestions.append({
            "parameter": "max_connections",
            "current": str(max_conn),
            "recommended": str(max(max_conn, int(max_used * 1.5))),
            "severity": "high",
            "message": f"历史最大连接数 {max_used}/{max_conn} 使用率超 80%，建议增大 max_connections"
        })

    flush_commit = variables.get("innodb_flush_log_at_trx_commit", "1")
    sync_binlog = variables.get("sync_binlog", "1")
    if flush_commit == "1" and sync_binlog == "1":
        suggestions.append({
            "parameter": "innodb_flush_log_at_trx_commit / sync_binlog",
            "current": f"flush={flush_commit}, sync={sync_binlog}",
            "severity": "info",
            "message": "当前为最高数据安全配置（双1），如对性能有较高要求且可接受少量数据丢失，可考虑 flush=2, sync=0"
        })

    tmp_tables = int(status.get("Created_tmp_tables", 0))
    tmp_disk = int(status.get("Created_tmp_disk_tables", 0))
    if tmp_tables > 0 and tmp_disk / tmp_tables > 0.25:
        tmp_size = variables.get("tmp_table_size", "16M")
        suggestions.append({
            "parameter": "tmp_table_size / max_heap_table_size",
            "current": tmp_size,
            "severity": "medium",
            "message": f"磁盘临时表比率 {round(tmp_disk / tmp_tables * 100)}%，建议增大 tmp_table_size 和 max_heap_table_size"
        })

    thread_cache = int(variables.get("thread_cache_size", 0))
    threads_created = int(status.get("Threads_created", 0))
    connections = int(status.get("Connections", 1))
    if connections > 0 and threads_created / connections > 0.01:
        suggestions.append({
            "parameter": "thread_cache_size",
            "current": str(thread_cache),
            "recommended": str(max(thread_cache, 32)),
            "severity": "low",
            "message": "线程创建比率偏高，建议增大 thread_cache_size 以减少线程创建开销"
        })

    slow_queries = int(status.get("Slow_queries", 0))
    questions = int(status.get("Questions", 1))
    if questions > 0 and slow_queries / questions > 0.001:
        long_qt = variables.get("long_query_time", "10")
        suggestions.append({
            "parameter": "long_query_time",
            "current": long_qt,
            "severity": "medium",
            "message": f"慢查询占比 {round(slow_queries / questions * 100, 3)}%，当前阈值 {long_qt}s，建议配合分析慢查询日志"
        })

    log_idx = variables.get("log_queries_not_using_indexes", "OFF")
    if log_idx.upper() == "OFF":
        suggestions.append({
            "parameter": "log_queries_not_using_indexes",
            "current": "OFF",
            "recommended": "ON",
            "severity": "low",
            "message": "建议开启 log_queries_not_using_indexes 以记录未使用索引的查询"
        })

    table_open = int(status.get("Opened_tables", 0))
    table_cache = int(variables.get("table_open_cache", 400))
    uptime = int(status.get("Uptime", 1))
    if uptime > 0 and table_open / uptime > 1:
        suggestions.append({
            "parameter": "table_open_cache",
            "current": str(table_cache),
            "recommended": str(max(table_cache, table_cache * 2)),
            "severity": "low",
            "message": f"表打开频率偏高 ({round(table_open / uptime, 1)}/s)，建议增大 table_open_cache"
        })

    return {
        "db_type": "mysql",
        "current_config": variables,
        "runtime_status": status,
        "suggestions": suggestions,
        "summary": f"共分析 {len(variables)} 个配置参数，发现 {len(suggestions)} 条调优建议"
    }


def analyze_pg_config(eng: Engine) -> Dict[str, Any]:
    """分析 PostgreSQL 配置并给出调优建议"""
    settings = get_pg_settings(eng)
    stat_summary = get_pg_stat_summary(eng)
    suggestions = []

    shared_buf = settings.get("shared_buffers", {})
    if shared_buf:
        buf_bytes = _parse_size_to_bytes(
            f"{shared_buf.get('setting', '0')}{shared_buf.get('unit', 'B') or 'B'}"
        )
        if buf_bytes < 256 * 1024 * 1024:
            suggestions.append({
                "parameter": "shared_buffers",
                "current": f"{shared_buf.get('setting')} {shared_buf.get('unit', '')}",
                "severity": "high",
                "message": f"shared_buffers 仅 {_format_bytes(buf_bytes)}，建议设为物理内存的 25%（至少 256MB）"
            })

    cache_hit = stat_summary.get("cache_hit_ratio", 100)
    if cache_hit < 99:
        suggestions.append({
            "parameter": "shared_buffers / effective_cache_size",
            "current": f"命中率 {cache_hit}%",
            "severity": "high",
            "message": f"缓存命中率 {cache_hit}%，建议增大 shared_buffers 和 effective_cache_size"
        })

    work_mem = settings.get("work_mem", {})
    if work_mem:
        wm_bytes = _parse_size_to_bytes(
            f"{work_mem.get('setting', '0')}{work_mem.get('unit', 'B') or 'B'}"
        )
        if wm_bytes < 4 * 1024 * 1024:
            suggestions.append({
                "parameter": "work_mem",
                "current": f"{work_mem.get('setting')} {work_mem.get('unit', '')}",
                "recommended": "8MB-64MB",
                "severity": "medium",
                "message": "work_mem 偏小，复杂排序/哈希操作可能溢出到磁盘。建议适当增大（注意每连接独立分配）"
            })

    maint_mem = settings.get("maintenance_work_mem", {})
    if maint_mem:
        mm_bytes = _parse_size_to_bytes(
            f"{maint_mem.get('setting', '0')}{maint_mem.get('unit', 'B') or 'B'}"
        )
        if mm_bytes < 64 * 1024 * 1024:
            suggestions.append({
                "parameter": "maintenance_work_mem",
                "current": f"{maint_mem.get('setting')} {maint_mem.get('unit', '')}",
                "recommended": "256MB-1GB",
                "severity": "low",
                "message": "maintenance_work_mem 偏小，会影响 VACUUM / CREATE INDEX 性能"
            })

    rpc = settings.get("random_page_cost", {})
    if rpc and float(rpc.get("setting", 4)) >= 4:
        suggestions.append({
            "parameter": "random_page_cost",
            "current": rpc.get("setting"),
            "recommended": "1.1 (SSD) / 2.0 (HDD)",
            "severity": "medium",
            "message": "random_page_cost=4 是 HDD 默认值，如使用 SSD 建议降低到 1.1，以让优化器更多选择索引扫描"
        })

    eio = settings.get("effective_io_concurrency", {})
    if eio and int(eio.get("setting", 1)) <= 1:
        suggestions.append({
            "parameter": "effective_io_concurrency",
            "current": eio.get("setting"),
            "recommended": "200 (SSD)",
            "severity": "low",
            "message": "effective_io_concurrency 偏低，SSD 建议设为 200"
        })

    max_parallel = settings.get("max_parallel_workers_per_gather", {})
    if max_parallel and int(max_parallel.get("setting", 0)) == 0:
        suggestions.append({
            "parameter": "max_parallel_workers_per_gather",
            "current": "0",
            "recommended": "2-4",
            "severity": "medium",
            "message": "并行查询未启用，建议设置 max_parallel_workers_per_gather=2-4 以利用多核 CPU"
        })

    autovac = settings.get("autovacuum", {})
    if autovac and autovac.get("setting") == "off":
        suggestions.append({
            "parameter": "autovacuum",
            "current": "off",
            "recommended": "on",
            "severity": "high",
            "message": "autovacuum 已关闭！这会导致表膨胀和事务 ID 回卷，强烈建议开启"
        })

    db_stats = stat_summary.get("database_stats", {})
    deadlocks = db_stats.get("deadlocks", 0)
    if deadlocks > 0:
        suggestions.append({
            "parameter": "deadlock_timeout",
            "current": f"累计 {deadlocks} 次死锁",
            "severity": "medium",
            "message": f"检测到 {deadlocks} 次死锁，建议检查应用的锁使用模式并开启 log_lock_waits"
        })

    temp_files = db_stats.get("temp_files", 0)
    if temp_files > 100:
        suggestions.append({
            "parameter": "work_mem",
            "current": f"累计 {temp_files} 个临时文件",
            "severity": "medium",
            "message": f"产生了 {temp_files} 个临时文件，说明 work_mem 不足，建议增大"
        })

    log_duration = settings.get("log_min_duration_statement", {})
    if log_duration and int(log_duration.get("setting", -1)) == -1:
        suggestions.append({
            "parameter": "log_min_duration_statement",
            "current": "-1 (disabled)",
            "recommended": "1000 (1s)",
            "severity": "low",
            "message": "慢查询日志未开启，建议设置 log_min_duration_statement=1000 以记录超过 1 秒的查询"
        })

    config_dict = {}
    for name, s in settings.items():
        config_dict[name] = {
            "value": s.get("setting", ""),
            "unit": s.get("unit", ""),
            "source": s.get("source", ""),
            "description": s.get("short_desc", "")
        }

    return {
        "db_type": "postgresql",
        "current_config": config_dict,
        "runtime_stats": stat_summary,
        "suggestions": suggestions,
        "summary": f"共分析 {len(settings)} 个配置参数，发现 {len(suggestions)} 条调优建议"
    }


def analyze_db_config(eng: Engine, db_type: str = "mysql") -> Dict[str, Any]:
    """统一入口：分析数据库配置参数并给出调优建议"""
    if db_type.lower() == "postgresql":
        result = analyze_pg_config(eng)
    else:
        result = analyze_mysql_config(eng)

    result["ai_analysis"] = ""
    result["ai_usage"] = None

    try:
        from ..ai.llm_client import LLMClient
        llm = LLMClient()
    except Exception:
        llm = None

    if llm and llm.is_enabled():
        system_prompt = (
            f"你是一个极其资深的 {db_type} 数据库管理员。用户会提供一组从数据库中抓取的配置参数和运行状态指标。\n"
            "请你综合这些数据，寻找配置中存在的不合理项，并出具一份清晰、具有高度实操性的《数据库参数配置调优建议报告》。\n"
            "请直接以 Markdown 输出，无需多余寒暄。"
        )

        import json

        # 裁剪下长内容防止过长
        config_data = result.get("current_config", {})
        status_data = result.get("runtime_status", result.get("runtime_stats", {}))

        user_prompt = "配置与状态数据如下：\n"
        user_prompt += f"当前配置：{json.dumps(config_data, ensure_ascii=False)[:3000]}\n...\n"
        user_prompt += f"运行状态：{json.dumps(status_data, ensure_ascii=False)[:3000]}\n...\n"

        try:
            ai_result = llm.ask(system_prompt, user_prompt)
            result["ai_analysis"] = ai_result["content"]
            result["ai_usage"] = ai_result["usage"]
        except Exception as e:
            result["ai_analysis"] = f"AI 调用失败：{e}"
    else:
        result["ai_analysis"] = "⚠️ AI 智能分析未启用，请在系统后台配置大模型。"

    return result
