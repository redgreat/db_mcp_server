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


def text_width(pdf: FPDF) -> float:
    """可用文本宽度（避免 w=0 在部分状态下触发 fpdf2 宽度错误）。"""
    w = pdf.w - pdf.l_margin - pdf.r_margin
    return max(w, 20.0)


def ensure_vertical_space(pdf: FPDF, needed_mm: float = 15) -> None:
    """当前页剩余高度不足时换页。"""
    if pdf.get_y() + needed_mm > pdf.h - pdf.b_margin:
        pdf.add_page()


def safe_multi_cell(pdf: FPDF, text: str, h: float = 6, style: str = "", size: int = 9) -> None:
    if not text:
        return
    ensure_vertical_space(pdf, needed_mm=h * 2)
    set_cjk_font(pdf, style, size)
    pdf.multi_cell(text_width(pdf), h, text)


def _png_pixel_size(path: str) -> tuple[int, int]:
    with open(path, "rb") as f:
        sig = f.read(24)
    if len(sig) < 24 or sig[:8] != b"\x89PNG\r\n\x1a\n":
        return 800, 600
    w_px = int.from_bytes(sig[16:20], "big")
    h_px = int.from_bytes(sig[20:24], "big")
    return max(w_px, 1), max(h_px, 1)


def place_image_fit_page(pdf: FPDF, image_path: str) -> None:
    """新页放置图片，按页宽缩放，过高则压缩到可打印高度。"""
    pdf.add_page()
    ew = text_width(pdf)
    max_h = pdf.h - pdf.t_margin - pdf.b_margin - 15
    w_px, h_px = _png_pixel_size(image_path)
    h_mm = ew * h_px / w_px
    w_mm = ew
    if h_mm > max_h:
        h_mm = max_h
        w_mm = h_mm * w_px / h_px
    pdf.image(image_path, w=w_mm, h=h_mm)
    pdf.ln(4)


def write_markdownish_lines(pdf: FPDF, text: str, body_size: int = 9) -> None:
    """将 Markdown 风格文本写入 PDF。"""
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            pdf.ln(2)
            continue
        if stripped.startswith("# "):
            continue
        if stripped.startswith("### "):
            set_cjk_font(pdf, "B", 12)
            ensure_vertical_space(pdf, 10)
            pdf.ln(2)
            safe_multi_cell(pdf, stripped[4:], h=7, style="B", size=12)
            pdf.ln(1)
        elif stripped.startswith("## "):
            set_cjk_font(pdf, "B", 14)
            ensure_vertical_space(pdf, 12)
            pdf.ln(2)
            safe_multi_cell(pdf, stripped[3:], h=8, style="B", size=14)
            pdf.ln(2)
        elif stripped.startswith("- "):
            prefix = "    " if line.startswith("  ") else "  "
            safe_multi_cell(pdf, f"{prefix}• {stripped[2:]}", h=6, size=body_size - (1 if line.startswith("  ") else 0))
        elif stripped.startswith("> "):
            safe_multi_cell(pdf, stripped, h=6, size=max(body_size - 1, 8))
        elif stripped.startswith("|"):
            continue
        else:
            safe_multi_cell(pdf, stripped, h=6, size=body_size)
            pdf.ln(1)
