"""数据库连接管理接口：CRUD、连通性测试、删除预览"""
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ...db.db_operations import normalize_host_port
from ...security.secret import decrypt_text, encrypt_text
from ...timezone_util import serialize_row
from ..context import AdminContext, test_database_connection
from ..schemas import TestConnectionRequest


def build_router(ctx: AdminContext) -> APIRouter:
    router = APIRouter()

    @router.get("/admin/connections")
    def list_connections(
        page: int = 1,
        page_size: int = 10,
        search: Optional[str] = None,
        sort: Optional[str] = None,
        authorization: str = Header(None)
    ):
        """列出所有数据库连接（需要登录，支持分页、按 ID/名称搜索、按 ID 排序）"""
        ctx.auth_service.get_current_user(authorization)

        # 参数校验
        page = max(1, page)
        page_size = min(max(1, page_size), 1000)
        offset = (page - 1) * page_size

        from sqlalchemy import func, or_

        t = ctx.tbl["db_connections"]
        list_cols = (
            t.c.id,
            t.c.name,
            t.c.host,
            t.c.port,
            t.c.db_type,
            t.c.database,
            t.c.username,
            t.c.description,
            t.c.created_at,
        )

        filters = []
        keyword = (search or "").strip()
        if keyword:
            name_like = t.c.name.ilike(f"%{keyword}%")
            # 数字关键字同时按 ID 精确匹配
            if keyword.isdigit():
                filters.append(or_(t.c.id == int(keyword), name_like))
            else:
                filters.append(name_like)

        order_col = t.c.id.desc() if sort == "id_desc" else t.c.id.asc()

        with Session(ctx.engine) as s:
            count_stmt = select(func.count()).select_from(t)
            query = select(*list_cols)
            for cond in filters:
                count_stmt = count_stmt.where(cond)
                query = query.where(cond)
            total = s.execute(count_stmt).scalar()
            rows = s.execute(
                query.order_by(order_col).offset(offset).limit(page_size)
            ).mappings().all()

        masked = [serialize_row(r) for r in rows]

        return {
            "items": masked,
            "total": total,
            "page": page,
            "page_size": page_size
        }

    @router.post("/admin/connections")
    def create_connection(
        name: str,
        host: str,
        port: int,
        db_type: str,
        database: str,
        username: str,
        password: str,
        description: Optional[str] = "",
        authorization: str = Header(None)
    ):
        """创建数据库连接（仅管理员）"""
        user_data = ctx.auth_service.require_admin(authorization)

        host, port = normalize_host_port(host, port)

        # 加密密码 (使用 master_key)
        pwd_enc = encrypt_text(password, ctx.cfg.security.master_key)

        t = ctx.tbl["db_connections"]
        with Session(ctx.engine) as s:
            s.execute(insert(t).values(
                name=name,
                host=host,
                port=port,
                db_type=db_type,
                database=database,
                username=username,
                password_enc=pwd_enc,
                description=description
            ))
            s.commit()

        # 记录系统日志
        ctx.system_logger.log(
            operation="create_connection",
            resource_type="connection",
            user_id=user_data["user_id"],
            username=user_data["username"],
            details={"name": name, "host": host, "port": port, "db_type": db_type}
        )

        ctx.logger.info(f"创建连接: {name} by {user_data['username']}")
        return {"ok": True}

    @router.post("/admin/connections/test")
    def test_connection(request: Request, req: TestConnectionRequest, authorization: str = Header(None)):
        """测试数据库连接有效性（仅管理员）"""
        user = ctx.auth_service.require_admin(authorization)

        password = req.password or ""
        if not password and req.connection_id is not None:
            t = ctx.tbl["db_connections"]
            with Session(ctx.engine) as s:
                row = s.execute(select(t).where(t.c.id == req.connection_id)).mappings().first()
                if not row:
                    raise HTTPException(status_code=404, detail="连接不存在")
                password = decrypt_text(row["password_enc"], ctx.cfg.security.master_key)

        if not password:
            raise HTTPException(status_code=400, detail="请先填写数据库密码后再测试连接")

        _test_details = {
            "host": req.host,
            "port": req.port,
            "database": req.database,
            "db_type": req.db_type,
            "username": req.username,
        }
        try:
            host, port = normalize_host_port(req.host, req.port)
            test_database_connection(
                db_type=req.db_type,
                host=host,
                port=port,
                database=req.database,
                username=req.username,
                password=password,
            )
        except HTTPException:
            raise
        except SQLAlchemyError as exc:
            ctx.logger.warning(
                "测试数据库连接失败: type=%s host=%s port=%s database=%s user=%s error=%s",
                req.db_type,
                req.host,
                req.port,
                req.database,
                req.username,
                exc,
            )
            ctx.log_system_op(
                "test_connection", "connection",
                user_id=user.get("user_id"), username=user.get("username"),
                resource_id=req.connection_id,
                details={**_test_details, "result": "failed", "reason": str(exc)[:500]},
                request=request,
            )
            raise HTTPException(status_code=400, detail=f"连接失败: {exc}") from exc
        except Exception as exc:
            ctx.logger.warning(
                "测试数据库连接异常: type=%s host=%s port=%s database=%s user=%s error=%s",
                req.db_type,
                req.host,
                req.port,
                req.database,
                req.username,
                exc,
            )
            ctx.log_system_op(
                "test_connection", "connection",
                user_id=user.get("user_id"), username=user.get("username"),
                resource_id=req.connection_id,
                details={**_test_details, "result": "failed", "reason": str(exc)[:500]},
                request=request,
            )
            raise HTTPException(status_code=400, detail=f"连接失败: {exc}") from exc

        ctx.log_system_op(
            "test_connection", "connection",
            user_id=user.get("user_id"), username=user.get("username"),
            resource_id=req.connection_id,
            details={**_test_details, "result": "success"},
            request=request,
        )
        return {"ok": True, "message": "连接测试成功"}

    @router.put("/admin/connections/{conn_id}")
    def update_connection(
        conn_id: int,
        name: str,
        host: str,
        port: int,
        db_type: str,
        database: str,
        username: str,
        password: Optional[str] = None,
        description: Optional[str] = "",
        authorization: str = Header(None)
    ):
        """更新数据库连接（仅管理员）；password 不传或为空则保留原密码"""
        user_data = ctx.auth_service.require_admin(authorization)

        host, port = normalize_host_port(host, port)

        t = ctx.tbl["db_connections"]
        with Session(ctx.engine) as s:
            row = s.execute(select(t).where(t.c.id == conn_id)).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="连接不存在")

            vals = {
                "name": name,
                "host": host,
                "port": port,
                "db_type": db_type,
                "database": database,
                "username": username,
                "description": description or "",
            }
            if password:
                vals["password_enc"] = encrypt_text(password, ctx.cfg.security.master_key)

            s.execute(update(t).where(t.c.id == conn_id).values(**vals))
            s.commit()

        ctx.system_logger.log(
            operation="update_connection",
            resource_type="connection",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=conn_id,
            details={"name": name, "host": host, "port": port, "db_type": db_type},
        )

        ctx.logger.info(f"更新连接 id={conn_id}: {name} by {user_data['username']}")
        return {"ok": True}

    @router.get("/admin/connections/{conn_id}/delete-preview")
    def delete_connection_preview(conn_id: int, authorization: str = Header(None)):
        """删除前预览：统计将影响的关联数据（仅管理员）"""
        ctx.auth_service.require_admin(authorization)

        from sqlalchemy import func, inspect as sa_inspect

        conns = ctx.tbl["db_connections"]
        with Session(ctx.engine) as s:
            row = s.execute(select(conns).where(conns.c.id == conn_id)).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="连接不存在")

            permissions = ctx.tbl["permissions"]
            perm_count = s.execute(
                select(func.count())
                .select_from(permissions)
                .where(permissions.c.connection_id == conn_id)
            ).scalar() or 0

            rule_count = 0
            if "db_rules" in sa_inspect(ctx.engine).get_table_names():
                db_rules = ctx.tbl["db_rules"]
                rule_count = s.execute(
                    select(func.count())
                    .select_from(db_rules)
                    .where(db_rules.c.connection_id == conn_id)
                ).scalar() or 0

            audit_logs = ctx.tbl["audit_logs"]
            audit_count = s.execute(
                select(func.count())
                .select_from(audit_logs)
                .where(audit_logs.c.connection_id == conn_id)
            ).scalar() or 0

        return {
            "connection": {
                "id": row["id"],
                "name": row["name"],
                "host": row["host"],
                "port": row["port"],
                "db_type": row["db_type"],
                "database": row["database"],
                "username": row["username"],
            },
            "permission_count": int(perm_count),
            "db_rule_count": int(rule_count),
            "audit_log_count": int(audit_count),
        }

    @router.delete("/admin/connections/{conn_id}")
    def delete_connection(conn_id: int, authorization: str = Header(None)):
        """删除数据库连接（仅管理员）；先解除/删除关联的权限、规则与审计引用"""
        user_data = ctx.auth_service.require_admin(authorization)

        from sqlalchemy.exc import IntegrityError

        conns = ctx.tbl["db_connections"]
        with Session(ctx.engine) as s:
            row = s.execute(select(conns).where(conns.c.id == conn_id)).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="连接不存在")

            permissions = ctx.tbl["permissions"]
            s.execute(delete(permissions).where(permissions.c.connection_id == conn_id))

            from sqlalchemy import inspect as sa_inspect
            if "db_rules" in sa_inspect(ctx.engine).get_table_names():
                db_rules = ctx.tbl["db_rules"]
                s.execute(delete(db_rules).where(db_rules.c.connection_id == conn_id))

            audit_logs = ctx.tbl["audit_logs"]
            s.execute(
                update(audit_logs)
                .where(audit_logs.c.connection_id == conn_id)
                .values(connection_id=None)
            )

            try:
                s.execute(delete(conns).where(conns.c.id == conn_id))
                s.commit()
            except IntegrityError as exc:
                s.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="无法删除连接：仍存在未清理的关联数据，请稍后重试或联系管理员",
                ) from exc

        ctx.system_logger.log(
            operation="delete_connection",
            resource_type="connection",
            user_id=user_data["user_id"],
            username=user_data["username"],
            resource_id=conn_id,
        )

        ctx.logger.info(f"删除连接 id={conn_id} by {user_data['username']}")
        return {"ok": True}

    return router
