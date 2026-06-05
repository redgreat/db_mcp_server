"""封装 SchemaCrawler CLI，将数据库 schema 渲染为高质量 ER 图（SVG/PNG）。

依赖：
  - Java Runtime (JRE 17+)
  - SchemaCrawler JAR（schemacrawler-16.x.x-distribution.jar）
  - Graphviz（dot 命令，用于 SVG/PNG 输出）

使用方式：
  Python 通过 subprocess 调用 SchemaCrawler CLI，传入 JDBC 连接参数，
  输出 SVG/PNG 文件路径，供 PDF 嵌入或独立下载。
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

_SC_HOME = os.environ.get(
    "SCHEMACRAWLER_HOME",
    str(Path(__file__).resolve().parent.parent.parent / "opt" / "schemacrawler"),
)
_SC_JAR_PATTERN = "schemacrawler-distribution-*.jar"
_SC_LIB_DIR = os.path.join(_SC_HOME, "lib")
_SC_CONFIG_TEMPLATE = """\
schemacrawler.schema=\
  {schema}
schemacrawler.table_filters.include=\
  .*
schemacrawler.table_filters.exclude=\
  ^(?:(?:BIN\\$).*)$
schemacrawler.column_filters.include=\
  .*
schemacrawler.column_filters.exclude=\
  ^$
"""


def schemacrawler_available() -> bool:
    if not shutil.which("java"):
        return False
    home = Path(_SC_HOME)
    if not home.is_dir():
        return False
    jars = list(home.glob(_SC_JAR_PATTERN))
    if not jars:
        jars = list(home.rglob("schemacrawler-*.jar"))
    return len(jars) > 0


def _find_sc_jar() -> str:
    home = Path(_SC_HOME)
    jars = sorted(home.glob(_SC_JAR_PATTERN))
    if not jars:
        jars = sorted(home.rglob("schemacrawler-*.jar"))
    if not jars:
        raise FileNotFoundError(f"未找到 SchemaCrawler JAR: {_SC_HOME}")
    return str(jars[-1])


def _build_classpath() -> str:
    entries: List[str] = []
    entries.append(_find_sc_jar())
    lib_dir = Path(_SC_LIB_DIR)
    if lib_dir.is_dir():
        for jar in sorted(lib_dir.glob("*.jar")):
            entries.append(str(jar))
    return os.pathsep.join(entries)


def _jdbc_url(db_type: str, host: str, port: int, database: str) -> str:
    if db_type.lower() in ("mysql", "mariadb"):
        return f"jdbc:mysql://{host}:{port}/{database}?useSSL=false&allowPublicKeyRetrieval=true&characterEncoding=utf8mb4"
    elif db_type.lower() == "postgresql":
        return f"jdbc:postgresql://{host}:{port}/{database}?currentSchema=public"
    elif db_type.lower() in ("sqlserver", "mssql"):
        return f"jdbc:sqlserver://{host}:{port};databaseName={database};encrypt=false;trustServerCertificate=true"
    else:
        raise ValueError(f"SchemaCrawler 不支持的数据库类型: {db_type}")


def _jdbc_driver_class(db_type: str) -> str:
    if db_type.lower() in ("mysql", "mariadb"):
        return "com.mysql.cj.jdbc.Driver"
    elif db_type.lower() == "postgresql":
        return "org.postgresql.Driver"
    elif db_type.lower() in ("sqlserver", "mssql"):
        return "com.microsoft.sqlserver.jdbc.SQLServerDriver"
    else:
        raise ValueError(f"SchemaCrawler 不支持的数据库类型: {db_type}")


def render_er_diagram(
    db_type: str,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
    output_path: str,
    *,
    output_format: str = "svg",
    schema: Optional[str] = None,
    title: Optional[str] = None,
    timeout_sec: int = 300,
    show_columns: bool = True,
    max_tables: Optional[int] = None,
) -> Dict[str, Any]:
    """调用 SchemaCrawler 生成 ER 图。

    Args:
        db_type: 数据库类型 (mysql/postgresql/sqlserver)
        host: 主机
        port: 端口
        database: 库名
        user: 用户名
        password: 密码
        output_path: 输出文件路径（svg/png/pdf）
        output_format: 输出格式 svg/png/pdf
        schema: PostgreSQL schema（默认 public）
        title: 图标题
        timeout_sec: 超时秒数
        show_columns: 是否显示列详情
        max_tables: 限制表数量（调试用）

    Returns:
        {"success": bool, "file_path": str, "format": str, "error": str|None}
    """
    if not schemacrawler_available():
        return {"success": False, "file_path": None, "format": output_format, "error": "SchemaCrawler 不可用"}

    jdbc_url = _jdbc_url(db_type, host, port, database)
    driver_class = _jdbc_driver_class(db_type)
    classpath = _build_classpath()

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".properties", delete=False, encoding="utf-8") as cfg_f:
        schema_name = schema or ("public" if db_type.lower() == "postgresql" else database)
        cfg_f.write(_SC_CONFIG_TEMPLATE.format(schema=schema_name))
        if title:
            cfg_f.write(f"schemacrawler.title={title}\n")
        cfg_path = cfg_f.name

    try:
        cmd = [
            "java",
            "-classpath", classpath,
            "schemacrawler.Main",
            "-url", jdbc_url,
            "-user", user,
            "-password", password,
            "-driver", driver_class,
            "-command", "schema",
            "-outputformat", output_format,
            "-outputfile", str(out),
            "-configfile", cfg_path,
        ]

        if not show_columns:
            cmd.extend(["-infolevel", "minimum"])

        if max_tables:
            cmd.extend(["-table_filters.include", f".{{0,{max_tables}}}"])

        env = os.environ.copy()
        env.setdefault("LANG", "zh_CN.UTF-8")
        env.setdefault("LC_ALL", "zh_CN.UTF-8")

        logger.info("SchemaCrawler 命令: %s", " ".join(cmd[:8]) + " ...")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )

        if proc.returncode != 0:
            error_msg = f"SchemaCrawler 失败 (rc={proc.returncode}): {(proc.stderr or '')[:2000]}"
            logger.error(error_msg)
            return {"success": False, "file_path": None, "format": output_format, "error": error_msg}

        if not out.is_file() or out.stat().st_size < 100:
            error_msg = f"SchemaCrawler 未生成有效输出: {out}"
            logger.error(error_msg)
            return {"success": False, "file_path": None, "format": output_format, "error": error_msg}

        logger.info("SchemaCrawler 已生成: %s (%s bytes)", out, out.stat().st_size)
        return {"success": True, "file_path": str(out), "format": output_format, "error": None}

    except subprocess.TimeoutExpired:
        error_msg = f"SchemaCrawler 超时 ({timeout_sec}s)"
        logger.error(error_msg)
        return {"success": False, "file_path": None, "format": output_format, "error": error_msg}
    except Exception as e:
        error_msg = f"SchemaCrawler 异常: {e}"
        logger.error(error_msg)
        return {"success": False, "file_path": None, "format": output_format, "error": error_msg}
    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def render_er_diagram_from_engine(
    eng: Any,
    database: str,
    db_type: str,
    output_path: str,
    *,
    output_format: str = "svg",
    schema: Optional[str] = None,
    title: Optional[str] = None,
    timeout_sec: int = 300,
    show_columns: bool = True,
) -> Dict[str, Any]:
    """从 SQLAlchemy Engine 提取连接参数，调用 SchemaCrawler 生成 ER 图。"""
    url = eng.url
    host = url.host or "127.0.0.1"
    port = url.port or (3306 if db_type.lower() == "mysql" else 5432)
    user = url.username or "root"
    password = url.password or ""

    return render_er_diagram(
        db_type=db_type,
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        output_path=output_path,
        output_format=output_format,
        schema=schema,
        title=title or f"ER Diagram - {database}",
        timeout_sec=timeout_sec,
        show_columns=show_columns,
    )


def render_er_parts_to_svgs(
    eng: Any,
    database: str,
    db_type: str,
    work_dir: str,
    *,
    prefix: str = "er_sc",
    output_format: str = "svg",
    schema: Optional[str] = None,
    max_tables_per_part: int = 50,
) -> List[str]:
    """按表数量分片渲染 ER 图，返回成功生成的文件路径列表。"""
    from .db_metadata_tool import list_tables

    tables = list_tables(eng, database, db_type)
    if not tables:
        return []

    saved: List[str] = []
    for i in range(0, len(tables), max_tables_per_part):
        part_tables = tables[i:i + max_tables_per_part]
        part_idx = i // max_tables_per_part + 1
        output_file = os.path.join(work_dir, f"{prefix}_part_{part_idx}.{output_format}")

        result = render_er_diagram_from_engine(
            eng, database, db_type, output_file,
            output_format=output_format,
            schema=schema,
            title=f"ER Diagram - {database} (Part {part_idx})",
        )
        if result["success"]:
            saved.append(result["file_path"])

    return saved