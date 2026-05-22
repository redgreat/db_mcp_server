"""将生成的报告/ER 等文件上传到 OSS 或本地 downloads，并返回可访问的下载 URL。"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import Config
from ..services.oss_sts_service import StsOssService
from .object_storage import ObjectStorageClient

logger = logging.getLogger(__name__)

_DOWNLOADS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "downloads"


def _local_public_url(cfg: Config, filename: str) -> str:
    base = (getattr(cfg.server, "public_base_url", None) or "").strip().rstrip("/")
    if base:
        return f"{base}/downloads/{filename}"
    return f"/downloads/{filename}"


def upload_artifact(
    cfg: Config,
    *,
    category: str,
    filename: str,
    data: bytes,
    content_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    上传文件并返回 download_url、object_key 等元数据。
    优先 STS OSS（provider=sre-oss-sts），其次 AK/SK ali-oss，否则写入本地 downloads。
    """
    if not data:
        raise ValueError("上传内容为空")

    os_cfg = cfg.object_storage
    object_key = f"{category.strip('/')}/{filename}"

    if os_cfg and os_cfg.enabled and StsOssService.supports(os_cfg):
        svc = StsOssService(os_cfg)
        meta = svc.upload_bytes(data, filename, object_name=object_key, content_type=content_type)
        if not meta or not meta.get("url"):
            raise RuntimeError("STS OSS 上传失败，请检查 object_storage 配置")
        return {
            "provider": meta.get("provider", "aliyun_oss_sts"),
            "url": meta["url"],
            "download_url": meta["url"],
            "object_key": meta.get("object_key") or meta.get("key"),
            "bucket": meta.get("bucket"),
            "size_bytes": meta.get("size", len(data)),
            "filename": filename,
        }

    if os_cfg and os_cfg.enabled and (os_cfg.provider or "").lower() == "ali-oss":
        osc = ObjectStorageClient(
            provider=os_cfg.provider,
            endpoint=os_cfg.endpoint,
            bucket=os_cfg.bucket,
            access_key_id=os_cfg.access_key_id,
            access_key_secret=os_cfg.access_key_secret,
            region=os_cfg.region,
            public_base_url=os_cfg.public_base_url,
            base_path=os_cfg.path_prefix,
        )
        url, final_key = osc.upload_bytes(object_key, data, content_type=content_type)
        return {
            "provider": "ali-oss",
            "url": url,
            "download_url": url,
            "object_key": final_key,
            "bucket": os_cfg.bucket,
            "size_bytes": len(data),
            "filename": filename,
        }

    _DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    dest = _DOWNLOADS_DIR / filename
    dest.write_bytes(data)
    url = _local_public_url(cfg, filename)
    logger.info("文件已保存到本地 downloads: %s", dest)
    return {
        "provider": "local",
        "url": url,
        "download_url": url,
        "object_key": filename,
        "file_path": str(dest.resolve()),
        "size_bytes": len(data),
        "filename": filename,
    }


def build_download_mcp_content(
    *,
    title: str,
    download_url: str,
    filename: str,
    fmt: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """构造 MCP 工具返回：Markdown 可点击链接 + JSON 元数据。"""
    import json

    lines = [
        f"## {title}",
        "",
        f"**[点击下载 {filename}]({download_url})**",
        "",
        f"- 下载链接: {download_url}",
        f"- 文件名: {filename}",
        f"- 格式: {fmt}",
    ]
    if extra:
        if extra.get("size_bytes") is not None:
            lines.append(f"- 大小: {extra['size_bytes']} 字节")
        if extra.get("table_count") is not None:
            lines.append(f"- 表数量: {extra['table_count']}")

    body: Dict[str, Any] = {
        "success": True,
        "download_url": download_url,
        "filename": filename,
        "format": fmt,
        "message": f"{title}已生成，请通过链接下载：{download_url}",
    }
    if extra:
        body.update({k: v for k, v in extra.items() if v is not None})

    return {
        "content": [
            {"type": "text", "text": "\n".join(lines)},
            {"type": "text", "text": json.dumps(body, ensure_ascii=False)},
        ]
    }
