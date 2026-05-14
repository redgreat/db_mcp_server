import os
import sys
import yaml
import argparse
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

def load_object_storage_conf(cfg_path: str):
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    obj = data.get("object_storage") or {}
    return {
        "enabled": bool(obj.get("enabled", False)),
        "provider": obj.get("provider", ""),
        "endpoint": obj.get("endpoint"),
        "bucket": obj.get("bucket"),
        "ak": obj.get("access_key_id"),
        "sk": obj.get("access_key_secret"),
        "region": obj.get("region"),
        "path_prefix": obj.get("path_prefix") or "",
    }

def cutoff_ts(days: int) -> float:
    now = datetime.now(timezone.utc)
    return (now - timedelta(days=days)).timestamp()

def cleanup_ali_oss(conf: dict, prefixes, days: int):
    import oss2
    auth = oss2.Auth(conf["ak"], conf["sk"])
    bucket = oss2.Bucket(auth, conf["endpoint"], conf["bucket"])
    cut = cutoff_ts(days)
    base_prefix = (conf["path_prefix"] or "").strip("/")
    for p in prefixes:
        pfx = p.strip("/")
        full_prefix = "/".join([s for s in [base_prefix, pfx] if s])
        if full_prefix:
            full_prefix += "/"
        for obj in oss2.ObjectIterator(bucket, prefix=full_prefix):
            key = obj.key
            if key.endswith("/"):
                continue
            try:
                meta = bucket.get_object_meta(key)
                lm = meta.headers.get("last-modified")
                if lm:
                    dt = parsedate_to_datetime(lm)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    ts = dt.timestamp()
                else:
                    ts = time.time()
                if ts < cut:
                    bucket.delete_object(key)
                    print(f"deleted: {key}")
            except Exception as e:
                print(f"skip {key}: {e}")

def cleanup_local(conf: dict, prefixes, days: int):
    base_dir = conf.get("endpoint") or "uploads"
    base_dir = os.path.abspath(base_dir)
    cut = cutoff_ts(days)
    for p in prefixes:
        d = os.path.join(base_dir, (conf.get("path_prefix") or "").strip("/"), p.strip("/"))
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for name in files:
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                    ts = st.st_mtime
                    if ts < cut:
                        os.remove(path)
                        print(f"deleted: {path}")
                except Exception as e:
                    print(f"skip {path}: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/config.yml")
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--prefix", action="append")
    args = ap.parse_args()
    conf = load_object_storage_conf(args.config)
    prefixes = args.prefix or ["reports/", "er/", "dataflow/"]
    if conf["provider"] == "ali-oss":
        cleanup_ali_oss(conf, prefixes, args.days)
    else:
        cleanup_local(conf, prefixes, args.days)

if __name__ == "__main__":
    main()
