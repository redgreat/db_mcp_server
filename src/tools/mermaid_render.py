"""将 Mermaid 源码渲染为 PNG（依赖 mermaid-cli / mmdc）。"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

# Docker 内非 root 用户跑 Chromium 需关闭沙箱（写死在代码里，无需单独配置文件）
_PUPPETEER_CONFIG_JSON = {
    "args": [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--font-render-hinting=none",
    ],
}

# Mermaid 主题：指定 CJK 字体族，避免 Chromium 回退字体导致中文叠字
_MERMAID_THEME_JSON = {
    "theme": "default",
    "themeVariables": {
        "fontFamily": (
            "Noto Sans CJK SC, Noto Sans SC, WenQuanYi Micro Hei, "
            "sans-serif"
        ),
        "fontSize": "14px",
    },
}


def mmdc_available() -> bool:
    return shutil.which("mmdc") is not None


def render_mermaid_to_png(
    mermaid_source: str,
    output_png: str,
    *,
    timeout_sec: int = 180,
    width: int = 2400,
    scale: float = 1.5,
) -> bool:
    """
    调用 mmdc 将 Mermaid 渲染为 PNG。
    需安装: npm i -g @mermaid-js/mermaid-cli，且系统有 Chromium。
    """
    if not mmdc_available():
        logger.warning("未找到 mmdc，跳过 Mermaid 图片渲染")
        return False

    out = Path(output_png)
    out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".mmd", delete=False, encoding="utf-8"
    ) as f:
        f.write(mermaid_source)
        mmd_path = f.name

    puppeteer_cfg = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(_PUPPETEER_CONFIG_JSON, puppeteer_cfg, ensure_ascii=False)
    puppeteer_cfg.flush()
    puppeteer_path = puppeteer_cfg.name
    puppeteer_cfg.close()

    mermaid_cfg = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(_MERMAID_THEME_JSON, mermaid_cfg, ensure_ascii=False)
    mermaid_cfg.flush()
    mermaid_cfg_path = mermaid_cfg.name
    mermaid_cfg.close()

    try:
        cmd = [
            "mmdc",
            "-i",
            mmd_path,
            "-o",
            str(out),
            "-b",
            "white",
            "-w",
            str(width),
            "-s",
            str(scale),
            "-p",
            puppeteer_path,
            "-c",
            mermaid_cfg_path,
        ]
        env = os.environ.copy()
        env.setdefault("LANG", "zh_CN.UTF-8")
        env.setdefault("LC_ALL", "zh_CN.UTF-8")
        # Docker / Linux 下指定 Chromium 可执行文件（若存在）
        for chrome in (
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
        ):
            if os.path.isfile(chrome):
                env["PUPPETEER_EXECUTABLE_PATH"] = chrome
                break

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )
        if proc.returncode != 0:
            logger.error(
                "mmdc 失败: rc=%s stdout=%s stderr=%s",
                proc.returncode,
                (proc.stdout or "")[:400],
                (proc.stderr or "")[:1200],
            )
            return False
        if not out.is_file() or out.stat().st_size < 100:
            logger.error("mmdc 未生成有效 PNG: %s", out)
            return False
        logger.info("Mermaid 已渲染: %s (%s bytes)", out, out.stat().st_size)
        return True
    except subprocess.TimeoutExpired:
        logger.error("mmdc 超时 (%ss)", timeout_sec)
        return False
    except Exception as e:
        logger.error("mmdc 异常: %s", e)
        return False
    finally:
        for p in (mmd_path, puppeteer_path, mermaid_cfg_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def render_mermaid_parts_to_pngs(
    parts: List[str],
    work_dir: str,
    *,
    prefix: str = "er_part",
) -> List[str]:
    """分片渲染，返回成功生成的 PNG 路径列表。"""
    saved: List[str] = []
    for i, src in enumerate(parts, 1):
        png = os.path.join(work_dir, f"{prefix}_{i}.png")
        if render_mermaid_to_png(src, png):
            saved.append(png)
    return saved
