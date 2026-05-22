"""
企业 OSS（SRE Open API + STS）上传与下载链接，逻辑参考 dbadmin OSSService。
"""
from __future__ import annotations

import logging
import os
import time
import warnings
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, Optional
from urllib.parse import quote, urlsplit

warnings.filterwarnings(
    "ignore",
    message="invalid escape sequence.*",
    category=SyntaxWarning,
)

import oss2
import requests

from ..config import ObjectStorageConfig

logger = logging.getLogger(__name__)

_STS_PROVIDERS = frozenset({"sre-oss-sts", "aliyun_oss_sts", "sts"})


class StsOssService:
    _identity_token_cache: Optional[str] = None
    _identity_token_expire_at: float = 0

    def __init__(self, cfg: ObjectStorageConfig):
        self.cfg = cfg

    @classmethod
    def supports(cls, cfg: Optional[ObjectStorageConfig]) -> bool:
        if not cfg or not cfg.enabled:
            return False
        return (cfg.provider or "").lower() in _STS_PROVIDERS

    def is_enabled(self) -> bool:
        c = self.cfg
        return (
            c.enabled
            and bool(c.bucket)
            and bool(c.app_code)
            and bool(c.identity_url)
            and bool(c.client_id)
            and bool(c.client_secret)
            and bool(c.scope)
        )

    def _build_object_key(self, file_name: str) -> str:
        now = datetime.now()
        safe_name = file_name.replace("\\", "_").replace("/", "_").replace(":", "_")
        prefix = (self.cfg.path_prefix or "db_mcp").strip("/")
        return f"{prefix}/{now.year}/{now.month:02d}/{now.day:02d}/{safe_name}"

    def _guess_sre_base_url(self) -> str:
        for raw in [self.cfg.upload_api_url, self.cfg.direct_download_base_url]:
            if not raw:
                continue
            try:
                parsed = urlsplit(raw.strip())
                if parsed.scheme and parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
            except Exception:
                continue
        return ""

    def _timeout(self) -> int:
        return max(int(self.cfg.request_timeout_seconds or 30), 5)

    def _get_identity_access_token(self) -> Optional[str]:
        now = time.time()
        if self._identity_token_cache and self._identity_token_expire_at - now > 60:
            return self._identity_token_cache

        try:
            token_payload = {
                "grant_type": "client_credentials",
                "client_id": self.cfg.client_id,
                "client_secret": self.cfg.client_secret,
                "scope": self.cfg.scope,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            resp = requests.post(
                self.cfg.identity_url,
                data=token_payload,
                headers=headers,
                timeout=self._timeout(),
            )
            if not resp.ok:
                logger.error(
                    "[OSS] 获取 access token 失败: status=%s body=%s",
                    resp.status_code,
                    resp.text[:500],
                )
                return None

            token_data = resp.json() if resp.text else {}
            access_token = token_data.get("access_token")
            expires_in = int(token_data.get("expires_in") or 3600)
            if not access_token:
                logger.error("[OSS] access_token 为空")
                return None

            StsOssService._identity_token_cache = access_token
            StsOssService._identity_token_expire_at = now + max(expires_in, 60)
            return access_token
        except Exception as e:
            logger.error("[OSS] 获取 access token 异常: %s", e, exc_info=True)
            return None

    def _get_sts_token(self) -> Optional[Dict[str, Any]]:
        try:
            access_token = self._get_identity_access_token()
            if not access_token:
                return None

            sre_base_url = self._guess_sre_base_url()
            if not sre_base_url:
                logger.error("[OSS] 无法解析 SRE OPEN API base url")
                return None

            sts_url = f"{sre_base_url}/api/v1/buckets/sts"
            sts_payload = {
                "bucketName": self.cfg.bucket,
                "appCode": self.cfg.app_code,
            }
            sts_headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            }
            resp = requests.post(
                sts_url, json=sts_payload, headers=sts_headers, timeout=self._timeout()
            )
            if not resp.ok:
                logger.error(
                    "[OSS] 获取 STS token 失败: status=%s body=%s",
                    resp.status_code,
                    resp.text[:500],
                )
                return None

            sts_data = resp.json()
            sts_info = sts_data.get("sts")
            if not sts_info:
                logger.error("[OSS] STS 信息为空")
                return None
            return sts_info
        except Exception as e:
            logger.error("[OSS] 获取 STS token 异常: %s", e, exc_info=True)
            return None

    def _get_sts_download_url(self, object_key: str) -> Optional[str]:
        if not object_key:
            return None
        try:
            access_token = self._get_identity_access_token()
            if not access_token:
                return None

            sre_base_url = self._guess_sre_base_url()
            if not sre_base_url:
                return None

            stsurl = f"{sre_base_url}/api/v1/buckets/stsurl"
            payload = {
                "bucketName": self.cfg.bucket,
                "appCode": self.cfg.app_code,
                "objectName": [object_key],
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            }
            resp = requests.post(
                stsurl, json=payload, headers=headers, timeout=self._timeout()
            )
            if not resp.ok:
                logger.error(
                    "[OSS] 获取 STS 下载链接失败: status=%s body=%s",
                    resp.status_code,
                    resp.text[:500],
                )
                return None

            data = resp.json() if resp.text else {}
            url_obj = data.get("url")
            if isinstance(url_obj, dict):
                if object_key in url_obj and isinstance(url_obj[object_key], str):
                    return url_obj[object_key]
                for v in url_obj.values():
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            elif isinstance(url_obj, str) and url_obj.strip():
                return url_obj.strip()

            logger.error("[OSS] stsurl 返回格式无法识别: %s", data)
            return None
        except Exception as e:
            logger.error("[OSS] 获取 STS 下载链接异常: %s", e, exc_info=True)
            return None

    def sign_download_url(self, object_key: str) -> Optional[str]:
        if not object_key:
            return None
        if str(object_key).startswith(("http://", "https://")):
            return object_key
        base_url = (self.cfg.direct_download_base_url or "").strip().rstrip("/")
        if not base_url:
            return None
        object_key_safe = quote(object_key.lstrip("/"), safe="/")
        return f"{base_url}/{object_key_safe}"

    def resolve_download_url(self, object_key: str) -> Optional[str]:
        sts_url = self._get_sts_download_url(object_key)
        if sts_url:
            return sts_url
        return self.sign_download_url(object_key)

    def upload_bytes(
        self,
        data: bytes,
        file_name: str,
        object_name: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.is_enabled() or not data:
            return None

        try:
            object_key = object_name or self._build_object_key(file_name)
            sts_info = self._get_sts_token()
            if not sts_info:
                return None

            auth = oss2.StsAuth(
                sts_info["sts_AccessId"],
                sts_info["sts_AccessKeySecret"],
                sts_info["securityToken"],
            )
            bucket = oss2.Bucket(auth, sts_info["endpoint"], self.cfg.bucket)

            headers = {}
            if content_type:
                headers["Content-Type"] = content_type
            result = bucket.put_object(object_key, BytesIO(data), headers=headers or None)
            if result.status != 200:
                logger.error("[OSS] 上传失败: status=%s", result.status)
                return None

            remote_url = self.resolve_download_url(object_key)
            logger.info("[OSS] 上传成功: bucket=%s key=%s", self.cfg.bucket, object_key)
            return {
                "provider": "aliyun_oss_sts",
                "bucket": self.cfg.bucket,
                "key": object_key,
                "object_key": object_key,
                "url": remote_url,
                "size": len(data),
                "uploaded_at": datetime.now().isoformat(),
            }
        except Exception as e:
            logger.error("[OSS] 上传异常: %s", e, exc_info=True)
            return None

    def upload_file(
        self, local_file_path: str, object_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        if not local_file_path or not os.path.exists(local_file_path):
            return None
        with open(local_file_path, "rb") as f:
            data = f.read()
        return self.upload_bytes(
            data, os.path.basename(local_file_path), object_name=object_name
        )
