"""
从表结构、表备注、字段备注归纳业务实体（非 1 表 = 1 实体简单罗列）。

- 按命名前缀划分业务域
- 区分核心实体 / 明细从表 / 日志 / 配置字典 / 技术表
- PDF 输出「域 → 实体 → 关键属性」；完整表清单仍可通过 Markdown/OSS 导出
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.engine import Engine

from .db_doc_tool import get_all_tables_with_comments
from .db_er_tool import (
    analyze_implicit_relationships,
    get_foreign_keys,
    get_table_columns_for_er,
)

# 表名模式 → 角色（一张表在 ER 语义上常不是独立「实体」）
_ROLE_PATTERNS: List[Tuple[str, str]] = [
    ("log", r"(?:^|_)(?:log|logs|history|audit|trace)(?:$|_)"),
    ("job", r"(?:hangfire|aggregatedcounter|counter$)"),
    ("dict", r"(?:^basic_|datadictionary|dictionary|^_?sys_|^dict_)"),
    ("detail", r"(?:_detail$|_item$|_line$|_entry$|_record$|明细)"),
    ("bridge", r"(?:_map$|_rel$|_link$|_ref$|_permission$|_role_)"),
]

_DOMAIN_LABELS = {
    "warehouse": "仓储",
    "stock": "库存",
    "material": "物料",
    "instock": "入库",
    "outstock": "出库",
    "supplier": "供应商",
    "customer": "客户",
    "order": "订单",
    "api": "接口/应用",
    "basic": "基础数据",
    "sys": "系统",
    "other": "其他",
}


def _table_domain(table_name: str) -> str:
    n = table_name.lower()
    if n.startswith("tb_"):
        seg = n[3:].split("_")
        return seg[0] if seg else "other"
    if "_" in n:
        return n.split("_")[0]
    return "other"


def _domain_label(domain: str) -> str:
    return _DOMAIN_LABELS.get(domain, domain)


def _guess_role(table_name: str, col_count: int, inbound: int, outbound: int) -> str:
    n = table_name.lower()
    for role, pat in _ROLE_PATTERNS:
        if re.search(pat, n):
            return role
    if col_count <= 5 and inbound >= 1 and outbound >= 1:
        return "bridge"
    if inbound >= 2 and col_count <= 8:
        return "detail"
    if inbound == 0 and outbound >= 2:
        return "core"
    if outbound >= 1 or inbound >= 1:
        return "entity"
    return "technical"


def _display_entity_name(table_name: str, table_comment: str) -> str:
    c = (table_comment or "").strip()
    if c and c.lower() not in (table_name.lower(), "view", "table"):
        return c
    # tb_warehouse → 仓库
    base = table_name
    if base.lower().startswith("tb_"):
        base = base[3:]
    return base.replace("_", " ")


def _key_attributes(cols: List[Dict[str, Any]], max_attrs: int = 12) -> List[str]:
    """提取带备注或主键的关键属性（业务含义）。"""
    attrs: List[str] = []
    for c in cols:
        name = c["column_name"]
        comment = (c.get("comment") or "").strip()
        if c.get("key_type") == "PK":
            line = f"{name} (主键)"
            if comment:
                line += f" — {comment}"
            attrs.append(line)
        elif comment:
            attrs.append(f"{name} — {comment}")
    if len(attrs) > max_attrs:
        extra = len(attrs) - max_attrs
        attrs = attrs[:max_attrs]
        attrs.append(f"… 另有 {extra} 个带备注字段")
    elif not attrs:
        # 无备注时列出主键+前几个字段名
        for c in cols[:6]:
            if c.get("key_type") == "PK":
                attrs.append(f"{c['column_name']} (主键)")
        if not attrs and cols:
            attrs.append(f"{cols[0]['column_name']} 等 {len(cols)} 个字段")
    return attrs


def build_entity_catalog(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
) -> Dict[str, Any]:
    """构建业务实体目录（全库）。"""
    table_columns = get_table_columns_for_er(eng, database, db_type)
    table_meta = {
        r["table_name"]: (r.get("table_comment") or "").strip()
        for r in get_all_tables_with_comments(eng, database, db_type)
    }
    fks = get_foreign_keys(eng, database, db_type)

    inbound: Dict[str, int] = defaultdict(int)
    outbound: Dict[str, int] = defaultdict(int)
    for fk in fks:
        outbound[fk["from_table"]] += 1
        inbound[fk["to_table"]] += 1

    tables_info: List[Dict[str, Any]] = []
    role_counts: Dict[str, int] = defaultdict(int)

    for tname, cols in table_columns.items():
        role = _guess_role(tname, len(cols), inbound[tname], outbound[tname])
        role_counts[role] += 1
        domain = _table_domain(tname)
        tables_info.append(
            {
                "table": tname,
                "domain": domain,
                "domain_label": _domain_label(domain),
                "role": role,
                "table_comment": table_meta.get(tname, ""),
                "entity_name": _display_entity_name(tname, table_meta.get(tname, "")),
                "attributes": _key_attributes(cols),
                "column_count": len(cols),
                "inbound_fk": inbound[tname],
                "outbound_fk": outbound[tname],
            }
        )

    by_domain: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in tables_info:
        by_domain[t["domain"]].append(t)

    for domain in by_domain:
        by_domain[domain].sort(
            key=lambda x: (
                {"core": 0, "entity": 1, "detail": 2, "bridge": 3, "dict": 4, "log": 5, "job": 6, "technical": 7}.get(
                    x["role"], 9
                ),
                -x["inbound_fk"],
                x["table"],
            )
        )

    return {
        "database": database,
        "table_count": len(table_columns),
        "fk_count": len(fks),
        "role_counts": dict(role_counts),
        "domains": dict(by_domain),
        "tables": tables_info,
    }


def _role_label(role: str) -> str:
    return {
        "core": "核心实体",
        "entity": "业务表",
        "detail": "明细/从表",
        "bridge": "关联/映射",
        "dict": "字典/配置",
        "log": "日志/审计",
        "job": "任务/调度",
        "technical": "技术/未分类",
    }.get(role, role)


def format_entity_catalog_markdown(
    catalog: Dict[str, Any],
    *,
    for_pdf: bool = False,
    max_domains: int = 25,
    max_entities_per_domain: int = 20,
    max_attrs: int = 8,
) -> str:
    """
    生成实体说明 Markdown。
    for_pdf=True 时压缩篇幅，完整表级清单见 format=markdown 导出。
    """
    lines: List[str] = []
    db = catalog["database"]
    rc = catalog["role_counts"]
    lines.append(f"# 数据库 {db} — 业务实体归纳\n")
    lines.append(
        f"共 **{catalog['table_count']}** 张物理表，**{catalog['fk_count']}** 条显式外键。"
        " 以下按**业务域**与**表角色**归纳，并非「一表一实体」；"
        "核心实体名称优先取**表备注**，属性优先取**字段备注**。\n"
    )
    lines.append("## 表角色统计\n")
    for role in ("core", "entity", "detail", "bridge", "dict", "log", "job", "technical"):
        if rc.get(role):
            lines.append(f"- {_role_label(role)}: {rc[role]} 张")
    lines.append("")

    domains = sorted(
        catalog["domains"].items(),
        key=lambda x: -sum(1 for t in x[1] if t["role"] in ("core", "entity")),
    )
    if for_pdf:
        lines.append("## 按业务域的核心实体与属性（PDF 摘要）\n")
        lines.append(
            "> 完整 " + str(catalog["table_count"]) + " 张表及全部字段关系请使用 "
            "`format=markdown` 或 OSS 导出查看。\n"
        )
    else:
        lines.append("## 按业务域的实体与属性\n")

    shown_domains = 0
    for domain, tables in domains:
        if for_pdf and shown_domains >= max_domains:
            lines.append(f"\n… 另有 {len(domains) - shown_domains} 个业务域未展开（见 Markdown 完整版）\n")
            break
        shown_domains += 1
        label = _domain_label(domain)
        core_n = sum(1 for t in tables if t["role"] in ("core", "entity"))
        lines.append(f"\n### {label}（`{domain}`，{len(tables)} 张表，核心/业务 {core_n} 张）\n")

        entity_shown = 0
        for t in tables:
            if t["role"] in ("log", "job", "technical") and for_pdf:
                continue
            if for_pdf and entity_shown >= max_entities_per_domain:
                rest = len([x for x in tables if x["role"] not in ("log", "job")]) - entity_shown
                if rest > 0:
                    lines.append(f"- … 本域另有 {rest} 张表（含明细/配置等）\n")
                break
            entity_shown += 1
            role_tag = _role_label(t["role"])
            lines.append(
                f"- **{t['entity_name']}**（表 `{t['table']}`，{role_tag}）"
            )
            if t["table_comment"] and t["table_comment"] != t["entity_name"]:
                lines.append(f"  - 表说明: {t['table_comment']}")
            attrs = t["attributes"][:max_attrs] if for_pdf else t["attributes"]
            for a in attrs:
                lines.append(f"  - {a}")
            if t["inbound_fk"] or t["outbound_fk"]:
                lines.append(
                    f"  - 关联: 被引用 {t['inbound_fk']} 次，引用他表 {t['outbound_fk']} 次"
                )

        if for_pdf:
            log_n = sum(1 for t in tables if t["role"] == "log")
            dict_n = sum(1 for t in tables if t["role"] == "dict")
            if log_n or dict_n:
                parts = []
                if log_n:
                    parts.append(f"日志类 {log_n} 张")
                if dict_n:
                    parts.append(f"字典/配置 {dict_n} 张")
                lines.append(f"- *本域另有 {'、'.join(parts)}（图中通常省略）*\n")

    if not for_pdf:
        lines.append("\n## 物理表索引（简表）\n")
        lines.append("| 表名 | 业务域 | 角色 | 表备注 |")
        lines.append("| --- | --- | --- | --- |")
        for t in catalog["tables"]:
            comment = (t["table_comment"] or "").replace("|", "/")[:40]
            lines.append(
                f"| {t['table']} | {_domain_label(t['domain'])} | {_role_label(t['role'])} | {comment} |"
            )

    return "\n".join(lines)


def tables_for_er_diagram(catalog: Dict[str, Any]) -> List[str]:
    """参与 ER 关系图绘制的表（排除纯日志/任务表）。"""
    skip = {"log", "job"}
    return [
        t["table"]
        for t in catalog["tables"]
        if t["role"] not in skip
    ]


def generate_mermaid_parts_by_domain(
    eng: Engine,
    database: str,
    db_type: str = "mysql",
    include_implicit: bool = True,
    max_tables_per_part: int = 35,
) -> List[str]:
    """按业务域分片生成 Mermaid（仅表名+关系，不含字段块）。"""
    from .db_er_tool import generate_er_mermaid_parts

    catalog = build_entity_catalog(eng, database, db_type)
    allow = set(tables_for_er_diagram(catalog))
    table_columns = get_table_columns_for_er(eng, database, db_type)
    filtered = {k: v for k, v in table_columns.items() if k in allow}
    if not filtered:
        return generate_er_mermaid_parts(
            eng, database, db_type, False, include_implicit, max_tables_per_part, 120000
        )

    # 按域分批调用逻辑：复用 generate_er_mermaid_parts 但只传子集
    fks = get_foreign_keys(eng, database, db_type)
    fks = [fk for fk in fks if fk["from_table"] in allow and fk["to_table"] in allow]

    domains: Dict[str, List[str]] = defaultdict(list)
    for t in allow:
        domains[_table_domain(t)].append(t)

    parts: List[str] = []
    for domain in sorted(domains.keys()):
        names = sorted(domains[domain])
        for i in range(0, len(names), max_tables_per_part):
            chunk = set(names[i : i + max_tables_per_part])
            sub_cols = {k: v for k, v in filtered.items() if k in chunk}
            sub_fks = [
                fk
                for fk in fks
                if fk["from_table"] in chunk and fk["to_table"] in chunk
            ]
            part = _mermaid_from_subset(sub_cols, sub_fks, include_implicit)
            if part:
                label = _domain_label(domain)
                header = f"%% 业务域: {label} ({domain}) 第{i // max_tables_per_part + 1}片\n"
                parts.append(header + part)
    return parts or generate_er_mermaid_parts(
        eng, database, db_type, False, include_implicit, max_tables_per_part, 120000
    )


def _mermaid_from_subset(
    table_columns: Dict[str, List[Dict]],
    fks: List[Dict],
    include_implicit: bool,
) -> str:
    implicit = (
        analyze_implicit_relationships(table_columns, fks) if include_implicit else []
    )

    def safe_name(name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_]", "_", name)

    lines = ["erDiagram"]
    for tname in sorted(table_columns.keys()):
        comment = ""
        sname = safe_name(tname)
        lines.append(f"    {sname} {{")
        lines.append(f"        string _id PK \"{tname}\"")
        lines.append("    }")
    for fk in fks:
        lines.append(
            f'    {safe_name(fk["to_table"])} ||--o{{ {safe_name(fk["from_table"])} : "{fk["from_column"]}"'
        )
    for rel in implicit:
        if rel["from_table"] in table_columns and rel["to_table"] in table_columns:
            lines.append(
                f'    {safe_name(rel["to_table"])} ||--o{{ {safe_name(rel["from_table"])} : "推断"'
            )
    return "\n".join(lines)


def llm_er_business_insights(catalog: Dict[str, Any], *, max_domains: int = 12) -> str:
    """
    用大模型对业务域/实体归纳做简短解读（未启用 LLM 时返回空串）。
    """
    from ..ai.service import is_llm_enabled, llm_ask

    if not is_llm_enabled():
        return ""

    domain_map = catalog.get("domains") or {}
    if not domain_map:
        return ""

    sorted_domains = sorted(
        domain_map.items(),
        key=lambda x: -sum(1 for t in x[1] if t["role"] in ("core", "entity")),
    )
    lines: List[str] = []
    for domain, tables in sorted_domains[:max_domains]:
        label = _domain_label(domain)
        core_n = sum(1 for t in tables if t["role"] in ("core", "entity"))
        names = [t["entity_name"][:40] for t in tables if t["role"] in ("core", "entity")][:8]
        lines.append(
            f"- 域「{label}」({domain}): 核心/业务 {core_n} 张; 代表: {', '.join(names) or '—'}"
        )

    user_prompt = (
        f"数据库共 {catalog.get('table_count', '?')} 张表，"
        f"{len(domain_map)} 个业务域。\n"
        "各域摘要：\n" + "\n".join(lines)
    )
    system_prompt = (
        "你是企业数据架构师。根据数据库表名、表备注归纳出的业务域与实体列表，"
        "用中文写一段 200–400 字的《业务数据模型解读》：说明主要业务板块、核心实体关系；"
        "不要逐表罗列，不要编造不存在的表名。"
    )
    try:
        return (llm_ask(system_prompt, user_prompt) or "").strip()
    except Exception:
        return ""
