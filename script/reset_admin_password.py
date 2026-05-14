"""
重置管理后台用户密码（写入 admin_users.password_hash）。

适用场景：更换了 config 中的 security.master_key 后，旧哈希无法通过登录校验，
需用「当前配置文件里的 master_key」重新生成哈希并更新数据库。

用法（容器内工作目录一般为 /app）:
  python script/reset_admin_password.py
  python script/reset_admin_password.py --username admin

非交互（避免密码出现在 shell 历史里，仍可能被同机用户从 /proc 看到）:
  ADMIN_NEW_PASSWORD='你的新密码' python script/reset_admin_password.py

指定配置路径:
  CONFIG_PATH=/app/config/config.yml python script/reset_admin_password.py
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import MetaData, Table, select, update  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

from src.config import Config  # noqa: E402
from src.admin.auth import AuthService  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="用当前 master_key 重置 admin 登录密码")
    parser.add_argument("--username", default="admin", help="要重置的用户名，默认 admin")
    parser.add_argument(
        "--config",
        default=os.environ.get("CONFIG_PATH", "config/config.yml"),
        help="配置文件路径，默认 config/config.yml 或环境变量 CONFIG_PATH",
    )
    args = parser.parse_args()

    new_password = os.environ.get("ADMIN_NEW_PASSWORD")
    if not new_password:
        new_password = getpass.getpass("新密码: ")
        confirm = getpass.getpass("再次输入新密码: ")
        if new_password != confirm:
            print("❌ 两次输入不一致", file=sys.stderr)
            sys.exit(1)
    if not new_password:
        print("❌ 密码不能为空", file=sys.stderr)
        sys.exit(1)

    cfg = Config.load(args.config)
    auth = AuthService(
        master_key=cfg.security.master_key,
        jwt_secret=cfg.security.jwt_secret,
        session_timeout=cfg.security.session_timeout,
    )
    new_hash = auth.hash_password(new_password)

    engine = create_engine(cfg.get_admin_db_url(), pool_pre_ping=True)
    meta = MetaData()
    admin_users = Table("admin_users", meta, autoload_with=engine)

    with Session(engine) as session:
        row = session.execute(
            select(admin_users.c.id).where(admin_users.c.username == args.username)
        ).first()
        if not row:
            print(f"❌ 用户不存在: {args.username}", file=sys.stderr)
            sys.exit(1)
        uid = row[0]
        session.execute(
            update(admin_users).where(admin_users.c.id == uid).values(password_hash=new_hash)
        )
        session.commit()

    print(f"✅ 已重置用户 {args.username} 的登录密码（已使用当前 config 中的 master_key 生成哈希）")


if __name__ == "__main__":
    main()
