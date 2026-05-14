import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DOC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "doc")
DOC_FILE = os.path.join(DOC_DIR, "whcenter_数据字典.md")
MAX_CHARS = 300_000

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def write_text(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def split_into_parts(md: str, max_chars: int):
    # 定位首个表级标题（以 "## " 开头的行），保留前面的概要与表汇总作为首片段开头
    lines = md.split("\n")
    header_end_idx = None
    for i, ln in enumerate(lines):
        if ln.startswith("## ") and "表汇总" not in ln:
            header_end_idx = i
            break
    if header_end_idx is None:
        # 没有找到表标题，直接按长度切分
        parts = []
        buf = []
        length = 0
        for ln in lines:
            if length + len(ln) + 1 > max_chars and buf:
                parts.append("\n".join(buf))
                buf = []
                length = 0
            buf.append(ln)
            length += len(ln) + 1
        if buf:
            parts.append("\n".join(buf))
        return parts

    header = "\n".join(lines[:header_end_idx])
    table_blocks = []
    current_block = []
    for ln in lines[header_end_idx:]:
        if ln.startswith("## "):
            if current_block:
                table_blocks.append("\n".join(current_block))
                current_block = []
        current_block.append(ln)
    if current_block:
        table_blocks.append("\n".join(current_block))

    parts = []
    # 首片段以 header 开始
    buf = [header]
    length = len(header) + 1
    for blk in table_blocks:
        if length + len(blk) + 1 > max_chars and buf:
            parts.append("\n".join(buf))
            buf = []
            length = 0
            # 非首片段不重复 header
        buf.append(blk)
        length += len(blk) + 1
    if buf:
        parts.append("\n".join(buf))
    return parts

def main():
    if not os.path.isfile(DOC_FILE):
        print(f"未找到文档文件: {DOC_FILE}")
        sys.exit(1)
    md = read_text(DOC_FILE)
    parts = split_into_parts(md, MAX_CHARS)
    if len(parts) <= 1:
        print("文档内容不足以分片或已是小文件，无需分片")
        sys.exit(0)

    saved = []
    prefix = "whcenter_doc"
    for i, content in enumerate(parts, 1):
        path = os.path.join(DOC_DIR, f"{prefix}_part_{i}.md")
        write_text(path, content)
        saved.append(path)

    # 生成索引文件，覆盖原始字典文件为索引视图
    summary_lines = md.split("\n")[:40]
    idx_lines = ["# whcenter 数据库说明文档（索引）", ""]
    idx_lines.extend(summary_lines)
    idx_lines.append("")
    idx_lines.append("## 分片文件")
    for i, p in enumerate(saved, 1):
        rel = os.path.relpath(p, DOC_DIR).replace("\\", "/")
        idx_lines.append(f"- 第 {i} 片: {rel}")
    write_text(DOC_FILE, "\n".join(idx_lines))

    print(f"已生成 {len(saved)} 个分片文件并更新索引:")
    for p in saved:
        print(f"- {p}")

if __name__ == "__main__":
    main()
