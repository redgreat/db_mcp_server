"""杂项接口：/admin 入口跳转、MCP 客户端接入信息"""
import json
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..context import AdminContext


def _read_doc_file(rel_path: str) -> str:
    """读取项目根目录下的文档文件，读取失败返回空串"""
    try:
        path = Path(__file__).resolve().parents[3] / rel_path
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _strip_doc_title(md: str) -> str:
    """去掉 markdown 文档的一级标题行（拼接进合成文档时避免标题层级冲突）"""
    lines = md.strip().splitlines()
    if lines and lines[0].startswith("# "):
        return "\n".join(lines[1:]).strip()
    return md.strip()


def _build_mcp_rules_markdown(sse_url: str, ak: str, config: dict) -> str:
    """拼装可复制/预览的 MCP 使用规范文档：接入配置 + 调用说明 + 工具使用规范"""
    base = sse_url[:-len("/mcp/sse")] if sse_url.endswith("/mcp/sse") else sse_url
    config_json = json.dumps(config, ensure_ascii=False, indent=2)

    client_doc = _read_doc_file(os.path.join("docs", "MCP客户端调用说明.md"))
    rules_doc = _read_doc_file(".ide_mcp_rules.md")

    # 将文档中的示例地址/密钥替换为当前部署的真实值
    for old in ("https://你的域名", "https://mcp.wongcw.cn", "http://localhost:3000"):
        client_doc = client_doc.replace(old, base)
        rules_doc = rules_doc.replace(old, base)
    if ak != "<你的访问密钥>":
        client_doc = client_doc.replace("你的访问密钥", ak).replace("你的密钥", ak)

    parts = [
        "# DB MCP Server · MCP 使用规范\n",
        "## 1. 客户端接入配置\n",
        "```json\n" + config_json + "\n```\n",
    ]
    if client_doc:
        parts.append("## 2. 客户端调用说明\n\n" + _strip_doc_title(client_doc) + "\n")
    if rules_doc:
        parts.append("## 3. AI 智能体工具调用规范\n\n" + _strip_doc_title(rules_doc) + "\n")
    if not client_doc and not rules_doc:
        parts.append("> 规范文档未随服务部署，详见仓库 docs/ 目录与 .ide_mcp_rules.md\n")
    return "\n".join(parts)


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin")
    @router.get("/admin/")
    def admin_index():
        """兼容书签 /admin：Svelte 应用路由在 /connections 等路径，不能在同一 URL 下挂载 index（会触发客户端 Not found）。"""
        static_path = os.path.join(os.path.dirname(__file__), '..', '..', 'static', 'index.html')
        if os.path.exists(static_path):
            return RedirectResponse(url="/connections", status_code=302)
        return HTMLResponse(
            content="<p>Frontend not built. Run: cd frontend && npm run build</p>",
            status_code=503,
        )

    @router.get("/admin/mcp_client_info")
    def mcp_client_info(
        request: Request,
        ak: Optional[str] = None,
        authorization: str = Header(None)
    ):
        """返回 MCP 客户端接入信息：SSE 地址、客户端配置 JSON 与使用规范文档"""
        ctx.auth_service.get_current_user(authorization)

        public = (getattr(ctx.cfg.server, "public_base_url", None) or "").strip().rstrip("/")
        base = public or str(request.base_url).rstrip("/")
        sse_url = f"{base}/mcp/sse"
        key_ak = (ak or "").strip() or "<你的访问密钥>"

        config = {
            "mcpServers": {
                "dbmcp": {
                    "url": sse_url,
                    "headers": {"X-Access-Key": key_ak}
                }
            }
        }

        return {
            "sse_url": sse_url,
            "config": config,
            "config_json": json.dumps(config, ensure_ascii=False, indent=2),
            "rules_markdown": _build_mcp_rules_markdown(sse_url, key_ak, config)
        }

    return router
