"""FPDF2 中文字体注册（避免 .ttc 未指定 face 导致乱码）。"""
from __future__ import annotations

import logging
import os
from typing import Optional

from fpdf import FPDF

from .db_doc_tool import _find_cjk_font

logger = logging.getLogger(__name__)

FONT_REGULAR = "AppCJK"
FONT_BOLD = "AppCJK-Bold"


def register_cjk_fonts(pdf: FPDF) -> str:
    """注册可用的中文 TrueType/OpenType 字体，返回字体路径。"""
    font_path = _find_cjk_font()
    if not font_path:
        raise RuntimeError(
            "未找到可用的中文字体（需 .ttf/.otf）。"
            "请将 NotoSansSC-Regular.ttf 放入 src/static/fonts/，"
            "或在镜像中安装 fonts-noto-cjk 并确保存在 .ttf 文件。"
        )

    ext = font_path.lower()
    kwargs: dict = {}
    if ext.endswith(".ttc") or ext.endswith(".otc"):
        # fpdf2 2.8+：TTC 必须指定字形索引，否则易出现乱码
        kwargs["collection_font_number"] = 0
        logger.info("使用 TTC/OTC 字体 collection_font_number=0: %s", font_path)

    try:
        pdf.add_font(FONT_REGULAR, "", font_path, **kwargs)
        pdf.add_font(FONT_BOLD, "", font_path, **kwargs)
    except Exception as e:
        raise RuntimeError(f"加载中文字体失败: {font_path}: {e}") from e

    logger.info("PDF 已加载中文字体: %s", font_path)
    return font_path


def set_cjk_font(pdf: FPDF, style: str = "", size: int = 10) -> None:
    """设置正文字体；粗体使用同一字族（无独立粗体文件时）。"""
    name = FONT_BOLD if style.upper() == "B" else FONT_REGULAR
    pdf.set_font(name, size=size)


def write_markdownish_lines(pdf: FPDF, text: str, body_size: int = 9) -> None:
    """将 Markdown 风格文本写入 PDF。"""
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            pdf.ln(2)
            continue
        if stripped.startswith("# "):
            continue
        if stripped.startswith("## "):
            set_cjk_font(pdf, "B", 14)
            pdf.ln(4)
            pdf.multi_cell(0, 8, stripped[3:])
            pdf.ln(2)
        elif stripped.startswith("- "):
            set_cjk_font(pdf, size=body_size)
            pdf.multi_cell(0, 6, f"  • {stripped[2:]}")
        elif stripped.startswith("> "):
            set_cjk_font(pdf, size=body_size - 1)
            pdf.multi_cell(0, 6, stripped)
        else:
            set_cjk_font(pdf, size=body_size)
            pdf.multi_cell(0, 6, stripped)
            pdf.ln(1)
