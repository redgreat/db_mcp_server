"""封装 tbls CLI，生成数据库 ER 图、数据流图和文档。

依赖：
  - Go Runtime（编译 tbls）或 tbls 二进制
  - Graphviz（dot 命令，用于 SVG/PNG 输出）

tbls 功能：
  - doc: 生成数据库文档（Markdown）
  - svg: 生成 ER 关系图 SVG
  - png: 生成 ER 关系图 PNG
  - dot: 生成 Graphviz DOT 源码
  - diff: 对比两个数据库 schema 差异

使用方式：
  Python 通过 subprocess 调用 tbls CLI，传入数据库 URL，
  输出 SVG/PNG/Markdown 文件路径。
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def tbls_available() -> bool:
    return shutil.which("tbls") is not None


def _db_url(db_type: str, host: str, port: int, database: str, user: str, password: str) -> str:
    if db_type.lower() in ("mysql", "mariadb"):
        return f"mysql://{user}:{password}@{host}:{port}/{database}"
    elif db_type.lower() == "postgresql":
        return f"postgres://{user}:{password}@{host}:{port}/{database}?sslmode=disable"
    elif db_type.lower() in ("sqlserver", "mssql"):
        return f"mssql://{user}:{password}@{host}:{port}/{database}"
    else:
        raise ValueError(f"tbls 不支持的数据库类型: {db_type}")


def _extract_connection_params(eng: Any) -> Dict[str, Any]:
    url = eng.url
    return {
        "host": url.host or "127.0.0.1",
        "port": url.port,
        "user": url.username or "",
        "password": url.password or "",
    }


def render_er_svg(
    db_type: str,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
    output_path: str,
    *,
    schema: Optional[str] = None,
    timeout_sec: int = 300,
    exclude_tables: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """调用 tbls doc 生成 ER 图 SVG。

    Args:
        db_type: 数据库类型
        host: 主机
        port: 端口
        database: 库名
        user: 用户名
        password: 密码
        output_path: 输出 SVG 文件路径
        schema: PostgreSQL schema
        timeout_sec: 超时秒数
        exclude_tables: 排除的表名列表

    Returns:
        {"success": bool, "file_path": str|None, "error": str|None}
    """
    if not tbls_available():
        return {"success": False, "file_path": None, "error": "tbls 不可用"}

    db_url = _db_url(db_type, host, port, database, user, password)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="tbls_") as tmp_dir:
        config_path = os.path.join(tmp_dir, ".tbls.yml")
        config_content = f"DSN: \"{db_url}\"\n"
        if schema and db_type.lower() == "postgresql":
            config_content += f"schema: \"{schema}\"\n"
        if exclude_tables:
            patterns = ", ".join(f'"{t}"' for t in exclude_tables)
            config_content += f"exclude:\n  - tables:\n      - {patterns}\n"

        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config_content)

        try:
            cmd = [
                "tbls", "doc",
                "--config", config_path,
                "-t", tmp_dir,
                "--format", "svg",
            ]

            env = os.environ.copy()
            env.setdefault("LANG", "zh_CN.UTF-8")

            logger.info("tbls doc 命令: %s", " ".join(cmd[:6]) + " ...")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                env=env,
            )

            if proc.returncode != 0:
                error_msg = f"tbls doc 失败 (rc={proc.returncode}): {(proc.stderr or '')[:2000]}"
                logger.error(error_msg)
                return {"success": False, "file_path": None, "error": error_msg}

            svg_src = os.path.join(tmp_dir, "schema.svg")
            if os.path.isfile(svg_src):
                shutil.copy2(svg_src, str(out))
                logger.info("tbls 已生成 ER SVG: %s (%s bytes)", out, out.stat().st_size)
                return {"success": True, "file_path": str(out), "error": None}

            dot_src = os.path.join(tmp_dir, "schema.dot")
            if os.path.isfile(dot_src) and shutil.which("dot"):
                dot_out = str(out).replace(".svg", ".png") if str(out).endswith(".svg") else str(out)
                dot_cmd = ["dot", "-Tpng", "-o", dot_out, dot_src]
                subprocess.run(dot_cmd, capture_output=True, timeout=60)
                if os.path.isfile(dot_out):
                    logger.info("tbls+dot 已生成 ER PNG: %s", dot_out)
                    return {"success": True, "file_path": dot_out, "error": None}

            error_msg = f"tbls doc 未生成 SVG: {tmp_dir}"
            logger.error(error_msg)
            return {"success": False, "file_path": None, "error": error_msg}

        except subprocess.TimeoutExpired:
            error_msg = f"tbls doc 超时 ({timeout_sec}s)"
            logger.error(error_msg)
            return {"success": False, "file_path": None, "error": error_msg}
        except Exception as e:
            error_msg = f"tbls doc 异常: {e}"
            logger.error(error_msg)
            return {"success": False, "file_path": None, "error": error_msg}


def render_er_svg_from_engine(
    eng: Any,
    database: str,
    db_type: str,
    output_path: str,
    *,
    schema: Optional[str] = None,
    timeout_sec: int = 300,
) -> Dict[str, Any]:
    """从 SQLAlchemy Engine 提取连接参数，调用 tbls 生成 ER 图 SVG。"""
    params = _extract_connection_params(eng)
    default_port = 3306 if db_type.lower() == "mysql" else 5432
    return render_er_svg(
        db_type=db_type,
        host=params["host"],
        port=params["port"] or default_port,
        database=database,
        user=params["user"],
        password=params["password"],
        output_path=output_path,
        schema=schema,
        timeout_sec=timeout_sec,
    )


def generate_tbls_markdown_doc(
    db_type: str,
    host: str,
    port: int,
    database: str,
    user: str,
    password: str,
    output_dir: str,
    *,
    schema: Optional[str] = None,
    timeout_sec: int = 300,
) -> Dict[str, Any]:
    """调用 tbls doc 生成 Markdown 格式的数据库文档。

    Returns:
        {"success": bool, "output_dir": str, "error": str|None}
    """
    if not tbls_available():
        return {"success": False, "output_dir": None, "error": "tbls 不可用"}

    db_url = _db_url(db_type, host, port, database, user, password)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    config_path = os.path.join(str(out_dir), ".tbls.yml")
    config_content = f"DSN: \"{db_url}\"\n"
    if schema and db_type.lower() == "postgresql":
        config_content += f"schema: \"{schema}\"\n"

    with open(config_path, "w", encoding="utf-8") as f:
        f.write(config_content)

    try:
        cmd = [
            "tbls", "doc",
            "--config", config_path,
            "-t", str(out_dir),
            "--format", "md",
        ]

        env = os.environ.copy()
        env.setdefault("LANG", "zh_CN.UTF-8")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )

        if proc.returncode != 0:
            error_msg = f"tbls doc md 失败 (rc={proc.returncode}): {(proc.stderr or '')[:2000]}"
            logger.error(error_msg)
            return {"success": False, "output_dir": None, "error": error_msg}

        return {"success": True, "output_dir": str(out_dir), "error": None}

    except subprocess.TimeoutExpired:
        return {"success": False, "output_dir": None, "error": f"tbls doc 超时 ({timeout_sec}s)"}
    except Exception as e:
        return {"success": False, "output_dir": None, "error": f"tbls doc 异常: {e}"}


def diff_schemas(
    db_type: str,
    source_host: str, source_port: int, source_database: str, source_user: str, source_password: str,
    target_host: str, target_port: int, target_database: str, target_user: str, target_password: str,
    *,
    timeout_sec: int = 300,
) -> Dict[str, Any]:
    """调用 tbls diff 对比两个数据库 schema 差异。

    Returns:
        {"success": bool, "diff": str, "error": str|None}
    """
    if not tbls_available():
        return {"success": False, "diff": "", "error": "tbls 不可用"}

    source_url = _db_url(db_type, source_host, source_port, source_database, source_user, source_password)
    target_url = _db_url(db_type, target_host, target_port, target_database, target_user, target_password)

    try:
        cmd = ["tbls", "diff", source_url, target_url, "--format", "text"]

        env = os.environ.copy()
        env.setdefault("LANG", "zh_CN.UTF-8")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )

        diff_text = (proc.stdout or "") + (proc.stderr or "")

        if proc.returncode == 0:
            return {"success": True, "diff": diff_text, "error": None}
        else:
            return {"success": True, "diff": diff_text, "error": f"tbls diff rc={proc.returncode}"}

    except subprocess.TimeoutExpired:
        return {"success": False, "diff": "", "error": f"tbls diff 超时 ({timeout_sec}s)"}
    except Exception as e:
        return {"success": False, "diff": "", "error": f"tbls diff 异常: {e}"}