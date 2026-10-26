"""管理后台 REST 路由聚合入口。

路由按资源拆分在 src/admin/routes/ 下的子路由模块中，
共享依赖（管理库 engine、表缓存、认证、日志器）由 AdminContext 统一管理。
本文件只负责初始化上下文并挂载各子路由。

新增接口请放到对应资源的 routes/*.py 中；新资源新建 routes/<name>.py 并在此 include。
"""
from fastapi import APIRouter

from ..config import Config
from .context import AdminContext
from .routes import (
    auth,
    connections,
    keys,
    llm,
    logs,
    misc,
    permissions,
    users,
    whitelist,
)


def build_admin_router(cfg: Config) -> APIRouter:
    """创建管理后台路由：初始化共享上下文并聚合全部子路由"""
    ctx = AdminContext.create(cfg)

    router = APIRouter()
    router.include_router(auth.build_router(ctx))
    router.include_router(users.build_router(ctx))
    router.include_router(keys.build_router(ctx))
    router.include_router(connections.build_router(ctx))
    router.include_router(permissions.build_router(ctx))
    router.include_router(whitelist.build_router(ctx))
    router.include_router(llm.build_router(ctx))
    router.include_router(logs.build_router(ctx))
    router.include_router(misc.build_router(ctx))
    return router
