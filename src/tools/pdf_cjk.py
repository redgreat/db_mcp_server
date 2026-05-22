"""FPDF2 中文字体与排版（避免 TTC 错索引、multi_cell 坐标错乱导致叠字）。"""
from __future__ import annotations

import logging
import os
import re
from typing import Optional

from fpdf import FPDF

from .db_doc_tool import _find_cjk_font

logger = logging.getLogger(__name__)

FONT_FAMILY = "NotoSC"


def _strip_md(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    return text.strip()


def _ttc_collection_index(font_path: str) -> int:
    """TTC 内嵌字体索引：Noto Sans CJK 简体一般为 2，文泉驿等为 0。"""
    base = os.path.basename(font_path).lower()
    if "notosanscjk" in base or "noto sans cjk" in base.replace("_", " "):
        return 2
    return 0


def register_cjk_fonts(pdf: FPDF) -> str:
    """注册中文字体（镜像内为 apt 提供的 NotoSansCJK / 文泉驿 TTC）。"""
    font_path = _find_cjk_font()
    if not font_path:
        raise RuntimeError(
            "未找到可用的中文字体。请确认镜像已安装 fonts-noto-cjk 且 "
            "src/static/fonts/ 下存在 NotoSansCJK-Regular.ttc"
        )

    lower = font_path.lower()
    kwargs: dict = {}
    if lower.endswith(".ttc") or lower.endswith(".otc"):
        idx = _ttc_collection_index(font_path)
        kwargs["collection_font_number"] = idx
        logger.info("TTC 字体 collection_font_number=%s: %s", idx, font_path)

    try:
        pdf.add_font(FONT_FAMILY, style="", fname=font_path, **kwargs)
        # fpdf2 将 family 截断为 6 字符；set_font(..., "B") 会查找 notoscB，须单独注册
        pdf.add_font(FONT_FAMILY, style="B", fname=font_path, **kwargs)
    except TypeError:
        pdf.add_font(FONT_FAMILY, "", font_path, **kwargs)
        pdf.add_font(FONT_FAMILY, "B", font_path, **kwargs)
    except Exception as e:
        raise RuntimeError(f"加载中文字体失败: {font_path}: {e}") from e

    logger.info("PDF 中文字体: %s", font_path)
    return font_path


def set_cjk_font(
    pdf: FPDF,
    style: str = "",
    size: int = 10,
    *,
    bold: Optional[bool] = None,
) -> None:
    is_bold = bold if bold is not None else str(style).upper() == "B"
    pdf.set_font(FONT_FAMILY, style="B" if is_bold else "", size=size)


def text_width(pdf: FPDF) -> float:
    return max(float(pdf.w - pdf.l_margin - pdf.r_margin), 30.0)


def ensure_vertical_space(pdf: FPDF, needed_mm: float = 12) -> None:
    if pdf.get_y() + needed_mm > pdf.h - pdf.b_margin:
        pdf.add_page()
        pdf.set_x(pdf.l_margin)


def _reset_x(pdf: FPDF) -> None:
    pdf.set_x(pdf.l_margin)


def safe_multi_cell(
    pdf: FPDF,
    text: str,
    *,
    h: float = 5.5,
    bold: bool = False,
    size: int = 9,
) -> None:
    text = _strip_md(text)
    if not text:
        return
    ensure_vertical_space(pdf, needed_mm=h * 3)
    set_cjk_font(pdf, bold=bold, size=size)
    w = text_width(pdf)
    _reset_x(pdf)
    try:
        pdf.multi_cell(w, h, text, new_x="LMARGIN", new_y="NEXT")
    except TypeError:
        pdf.multi_cell(w, h, text)
        _reset_x(pdf)
        pdf.ln(0)


def write_heading(pdf: FPDF, text: str, level: int = 2) -> None:
    sizes = {1: 16, 2: 13, 3: 11}
    safe_multi_cell(pdf, text, h=7, bold=True, size=sizes.get(level, 11))
    pdf.ln(1)


def write_er_pdf_summary(pdf: FPDF, catalog: dict) -> None:
    """ER PDF 正文：结构化摘要，避免整段 Markdown 灌入导致排版错乱。"""
    db = catalog.get("database", "")
    rc = catalog.get("role_counts") or {}
    write_heading(pdf, f"数据库 {db} — 业务实体归纳", level=1)
    safe_multi_cell(
        pdf,
        f"物理表 {catalog.get('table_count', 0)} 张，外键 {catalog.get('fk_count', 0)} 条。",
        size=10,
    )
    pdf.ln(2)

    write_heading(pdf, "表角色统计", level=2)
    labels = {
        "core": "核心实体",
        "entity": "业务表",
        "detail": "明细/从表",
        "bridge": "关联/映射",
        "dict": "字典/配置",
        "log": "日志/审计",
        "job": "任务/调度",
        "technical": "技术/未分类",
    }
    for key, label in labels.items():
        if rc.get(key):
            safe_multi_cell(pdf, f"• {label}: {rc[key]} 张", size=9)

    pdf.ln(2)
    write_heading(pdf, "按业务域的核心实体（摘要）", level=2)
    safe_multi_cell(
        pdf,
        "完整表清单与全部关系请使用 format=markdown 导出。下图按业务域分片展示 ER 关系。",
        size=9,
    )
    pdf.ln(1)

    domains = catalog.get("domains") or {}
    sorted_domains = sorted(
        domains.items(),
        key=lambda x: -sum(1 for t in x[1] if t.get("role") in ("core", "entity")),
    )
    max_domains = 18
    for i, (domain, tables) in enumerate(sorted_domains):
        if i >= max_domains:
            safe_multi_cell(
                pdf,
                f"… 另有 {len(sorted_domains) - max_domains} 个业务域未在本文展开",
                size=9,
            )
            break
        core_n = sum(1 for t in tables if t.get("role") in ("core", "entity"))
        from .er_entity_catalog import _domain_label

        domain_label = _domain_label(domain)
        write_heading(
            pdf,
            f"{domain_label}（{domain}，{len(tables)} 张，核心/业务 {core_n}）",
            level=3,
        )
        shown = 0
        for t in tables:
            if t.get("role") in ("log", "job", "technical"):
                continue
            if shown >= 12:
                safe_multi_cell(pdf, "  • … 本域更多表见 Markdown 完整版", size=8)
                break
            shown += 1
            name = t.get("entity_name") or t.get("table", "")
            role = t.get("role", "")
            line = f"• {name}（{t.get('table', '')}）"
            safe_multi_cell(pdf, line, size=8)
            for a in (t.get("attributes") or [])[:4]:
                safe_multi_cell(pdf, f"    - {a}", size=8, h=5)
        pdf.ln(1)


def write_markdownish_lines(pdf: FPDF, text: str, body_size: int = 9) -> None:
    """将 Markdown 风格文本写入 PDF（已剥离标记，控制行距）。"""
    for line in text.split("\n"):
        stripped = _strip_md(line.strip())
        if not stripped:
            pdf.ln(2)
            _reset_x(pdf)
            continue
        if stripped.startswith("# "):
            write_heading(pdf, stripped[2:], level=1)
            continue
        if stripped.startswith("## "):
            write_heading(pdf, stripped[3:], level=2)
            continue
        if stripped.startswith("### "):
            write_heading(pdf, stripped[4:], level=3)
            continue
        if stripped.startswith("- "):
            prefix = "    " if line.startswith("  ") else "  "
            safe_multi_cell(pdf, f"{prefix}• {stripped[2:]}", size=body_size, h=5.5)
            continue
        if stripped.startswith("> "):
            safe_multi_cell(pdf, stripped, size=max(body_size - 1, 8))
            continue
        if stripped.startswith("|"):
            continue
        safe_multi_cell(pdf, stripped, size=body_size, h=5.5)


def _png_pixel_size(path: str) -> tuple[int, int]:
    with open(path, "rb") as f:
        sig = f.read(24)
    if len(sig) < 24 or sig[:8] != b"\x89PNG\r\n\x1a\n":
        return 800, 600
    w_px = int.from_bytes(sig[16:20], "big")
    h_px = int.from_bytes(sig[20:24], "big")
    return max(w_px, 1), max(h_px, 1)


def place_image_fit_page(pdf: FPDF, image_path: str, caption: Optional[str] = None) -> None:
    """新页放置图片，按页宽缩放。"""
    pdf.add_page()
    _reset_x(pdf)
    if caption:
        safe_multi_cell(pdf, caption, size=10, bold=True)
        pdf.ln(2)

    ew = text_width(pdf)
    max_h = pdf.h - pdf.t_margin - pdf.b_margin - 20
    w_px, h_px = _png_pixel_size(image_path)
    h_mm = ew * h_px / w_px
    w_mm = ew
    if h_mm > max_h:
        h_mm = max_h
        w_mm = h_mm * w_px / h_px
    x = pdf.l_margin + max(0, (ew - w_mm) / 2)
    y = pdf.get_y()
    pdf.image(image_path, x=x, y=y, w=w_mm, h=h_mm)
    pdf.set_y(y + h_mm + 4)
    _reset_x(pdf)
