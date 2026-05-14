from typing import Optional, Tuple
from io import BytesIO
import os

class ObjectStorageClient:
    def __init__(
        self,
        provider: str,
        endpoint: Optional[str] = None,
        bucket: Optional[str] = None,
        access_key_id: Optional[str] = None,
        access_key_secret: Optional[str] = None,
        region: Optional[str] = None,
        public_base_url: Optional[str] = None,
        base_path: Optional[str] = None,
    ):
        self.provider = (provider or "").lower()
        self.endpoint = endpoint
        self.bucket = bucket
        self.ak = access_key_id
        self.sk = access_key_secret
        self.region = region
        self.public_base_url = public_base_url.rstrip("/") + "/" if public_base_url else None
        self.base_path = base_path.strip("/") + "/" if base_path else ""
        self._oss_bucket = None
        self._s3_client = None
        if self.provider == "ali-oss":
            try:
                import oss2
                auth = oss2.Auth(self.ak, self.sk)
                self._oss_bucket = oss2.Bucket(auth, self.endpoint, self.bucket)
            except Exception as e:
                raise RuntimeError(f"ali-oss init failed: {e}")
        elif self.provider in ("s3", "minio", "aws-s3"):
            try:
                import boto3
                session = boto3.session.Session(
                    aws_access_key_id=self.ak,
                    aws_secret_access_key=self.sk,
                    region_name=self.region,
                )
                if self.provider == "minio" and self.endpoint:
                    self._s3_client = session.client("s3", endpoint_url=f"https://{self.endpoint}")
                else:
                    self._s3_client = session.client("s3")
            except Exception as e:
                raise RuntimeError(f"s3 init failed: {e}")
        elif self.provider == "local":
            base_dir = self.endpoint or "uploads"
            os.makedirs(base_dir, exist_ok=True)
        else:
            raise ValueError(f"unsupported provider: {self.provider}")

    def _make_key(self, key: str) -> str:
        if self.base_path:
            return f"{self.base_path}{key.lstrip('/')}"
        return key.lstrip("/")

    def upload_bytes(self, key: str, data: bytes, content_type: Optional[str] = None) -> Tuple[str, str]:
        obj_key = self._make_key(key)
        if self.provider == "ali-oss":
            import oss2
            headers = {}
            if content_type:
                headers["Content-Type"] = content_type
            result = self._oss_bucket.put_object(obj_key, data, headers=headers or None)
            if result.status // 100 != 2:
                raise RuntimeError(f"oss put_object failed: {result.status}")
            if self.public_base_url:
                url = f"{self.public_base_url}{obj_key}"
            else:
                url = f"https://{self.bucket}.{self.endpoint}/{obj_key}"
            return url, obj_key
        if self.provider in ("s3", "minio", "aws-s3"):
            extra = {}
            if content_type:
                extra["ContentType"] = content_type
            self._s3_client.put_object(Bucket=self.bucket, Key=obj_key, Body=data, **extra)
            if self.public_base_url:
                url = f"{self.public_base_url}{obj_key}"
            elif self.provider == "minio" and self.endpoint:
                url = f"https://{self.endpoint}/{self.bucket}/{obj_key}"
            else:
                url = f"https://{self.bucket}.s3.{self.region}.amazonaws.com/{obj_key}" if self.region else f"https://{self.bucket}.s3.amazonaws.com/{obj_key}"
            return url, obj_key
        if self.provider == "local":
            base_dir = self.endpoint or "uploads"
            path = os.path.join(base_dir, obj_key.replace("/", os.sep))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
            url = f"file://{os.path.abspath(path)}"
            return url, obj_key
        raise RuntimeError("unreachable")
