"""
标准 MCP 协议实现 (基于 SSE)
符合 Model Context Protocol 规范
"""
from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, Union
from ..security.client_ip import get_real_client_ip
import json
import asyncio
import logging
import uuid

logger = logging.getLogger(__name__)

# 全局会话管理：session_id -> asyncio.Queue
SESSIONS: Dict[str, asyncio.Queue] = {}


class MCPMessage(BaseModel):
    """MCP 消息基类"""
    jsonrpc: str = "2.0"


class MCPRequest(MCPMessage):
    """MCP 请求"""
    id: Optional[Union[str, int]] = None
    method: str
    params: Optional[Dict[str, Any]] = None


class MCPResponse(MCPMessage):
    """MCP 响应"""
    id: Optional[Union[str, int]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


class MCPNotification(MCPMessage):
    """MCP 通知"""
    method: str
    params: Optional[Dict[str, Any]] = None


def build_standard_mcp_router(
    cfg,
    qp,
    admin_engine,
    audit_logger,
    ip_checker,
    data_masker
):
    """构建标准 MCP 路由器 (SSE)"""
    from ..admin.schema_cache import get_admin_tables

    tbl = get_admin_tables(admin_engine)
    router = APIRouter()

    @router.get("/mcp/sse")
    async def mcp_sse_endpoint(
        request: Request,
        x_access_key: str = Header(default="", alias="X-Access-Key")
    ):
        """
        MCP SSE 端点
        符合 MCP 规范的 Server-Sent Events 接口
        """
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")

        # 验证访问密钥
        from sqlalchemy import select
        from sqlalchemy.orm import Session

        keys = tbl["access_keys"]
        with Session(admin_engine) as session:
            key_row = session.execute(
                select(keys).where(
                    keys.c.ak == x_access_key,
                    keys.c.enabled == True  # noqa: E712
                )
            ).first()

            if not key_row:
                raise HTTPException(status_code=401, detail="无效或已禁用的访问密钥")

        # 生成唯一会话 ID
        session_id = str(uuid.uuid4())
        queue = asyncio.Queue()
        SESSIONS[session_id] = queue

        # 获取当前请求的绝对基础路径，确保 endpoint 是绝对 URL
        # 很多 MCP 客户端在处理相对路径时会有问题
        try:
            # 构造绝对路径
            base_url = str(request.base_url).rstrip('/')
            message_url = f"{base_url}/mcp/message?session_id={session_id}&X-Access-Key={x_access_key}"
        except Exception:
            # 降级方案
            message_url = f"/mcp/message?session_id={session_id}&X-Access-Key={x_access_key}"

        async def event_generator():
            """SSE 事件生成器"""
            logger.info(f"SSE Connection established: session_id={session_id}")
            try:
                # 1. 发送包含绝对路径的 endpoint 事件
                yield f"event: endpoint\ndata: {message_url}\n\n"

                # 2. 持续监听队列并发送消息
                while True:
                    try:
                        # 待发送的消息（由 POST 端点推送到队列）
                        # 缩短超时时间到 15s 以便更频繁地发送心跳
                        msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                        data = json.dumps(msg)
                        logger.debug(f"SSE sending message to {session_id}: {data[:100]}...")
                        yield f"event: message\ndata: {data}\n\n"
                    except asyncio.TimeoutError:
                        # 发送标准 SSE 注释心跳，这种心跳对所有中间件（Nginx/Proxy）更友好
                        # 同时符合 MCP 关于 SSE 保持连接的建议
                        yield ": keep-alive\n\n"

            except asyncio.CancelledError:
                logger.info(f"SSE Connection cancelled: session_id={session_id}")
            except Exception as e:
                logger.error(f"SSE Error for {session_id}: {e}")
            finally:
                # 清理会话
                if session_id in SESSIONS:
                    del SESSIONS[session_id]
                    logger.info(f"MCP Session cleaned up: {session_id}")

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )

    @router.post("/mcp/message")
    async def mcp_message_endpoint(
        request: Request,
        mcp_request: MCPRequest,
        session_id: Optional[str] = None,
        x_access_key: str = Header(default="", alias="X-Access-Key")
    ):
        """
        MCP 消息端点
        处理客户端发送的 JSON-RPC 请求
        """
        if not x_access_key:
            raise HTTPException(status_code=401, detail="缺少访问密钥")

        client_ip = get_real_client_ip(request)

        # IP 白名单检查
        if client_ip and not ip_checker.check_access(client_ip, x_access_key):
            raise HTTPException(
                status_code=403,
                detail=f"IP {client_ip} 不在访问密钥的白名单中"
            )

        # 记录请求日志方便调试
        body_str = await request.body()
        logger.info(f"MCP Request: {body_str.decode()}")

        # 检查会话是否存在
        if not session_id or session_id not in SESSIONS:
            raise HTTPException(status_code=400, detail="Invalid session_id or connection expired")

        queue = SESSIONS[session_id]

        try:
            result = await handle_mcp_request(
                mcp_request,
                x_access_key,
                client_ip,
                cfg,
                qp,
                admin_engine,
                audit_logger,
                data_masker
            )

            # 如果是通知 (id 为空)，按照 JSON-RPC 2.0 规范不应有响应消息
            if mcp_request.id is None:
                return Response(status_code=202)

            # 重要：将响应消息放入对应会话的发送队列中，由 SSE 流发出
            resp = MCPResponse(
                id=mcp_request.id,
                result=result
            )
            data = resp.model_dump(exclude_none=True)
            logger.info(f"Queueing response for {session_id}, id={mcp_request.id}")
            await queue.put(data)
            return Response(status_code=202)  # HTTP 层仅返回已接收

        except Exception as e:
            logger.error(f"MCP Error: {str(e)}")
            if mcp_request.id is None:
                return Response(status_code=202)

            resp = MCPResponse(
                id=mcp_request.id,
                error={
                    "code": -32603,
                    "message": str(e)
                }
            )
            await queue.put(resp.model_dump(exclude_none=True))
            return Response(status_code=202)

    return router


async def handle_mcp_request(
    mcp_request: MCPRequest,
    access_key: str,
    client_ip: Optional[str],
    cfg,
    qp,
    admin_engine,
    audit_logger,
    data_masker
) -> Any:
    """处理 MCP 请求"""
    method = mcp_request.method
    params = mcp_request.params or {}

    if method == "initialize":
        client_version = params.get("protocolVersion", "2024-11-05")
        return {
            "protocolVersion": client_version,  # 协商使用客户端请求的版本
            "capabilities": {
                "tools": {},
                "resources": {}
            },
            "serverInfo": {
                "name": "db-mcp-server",
                "version": "1.0.0"
            }
        }

    elif method == "notifications/initialized":
        # 客户端告知初始化完成，无需返回结果
        logger.info(f"MCP Client initialized: {access_key}")
        return None

    elif method in ("ping", "notifications/ping"):
        # Cursor 等客户端通过 SSE 周期性发送 ping 保活，非错误
        return {}

    elif method == "resources/list":
        return {"resources": []}

    elif method == "resources/templates/list":
        return {"resourceTemplates": []}

    elif method == "prompts/list":
        return {"prompts": []}

    elif method == "roots/list":
        return {"roots": []}

    elif method.startswith("notifications/"):
        logger.debug("MCP notification: %s", method)
        return None

    elif method == "tools/list":
        from .tools import get_tool_definitions
        return {
            "tools": get_tool_definitions()
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        return await execute_mcp_tool(
            tool_name,
            arguments,
            access_key,
            client_ip,
            cfg,
            qp,
            admin_engine,
            audit_logger,
            data_masker
        )

    else:
        raise Exception(f"未知方法: {method}")


async def execute_mcp_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    access_key: str,
    client_ip: Optional[str],
    cfg,
    qp,
    admin_engine,
    audit_logger,
    data_masker
) -> Any:
    """执行 MCP 工具"""
    from ..admin.schema_cache import get_admin_tables
    from ..ai.context import llm_log_context

    tbl = get_admin_tables(admin_engine)
    raw_cid = arguments.get("connection_id")
    try:
        cid = int(raw_cid) if raw_cid is not None else None
    except (TypeError, ValueError):
        cid = None

    with llm_log_context(
        access_key=access_key,
        call_source="mcp",
        tool_name=tool_name,
        connection_id=cid,
    ):
        return await _execute_mcp_tool_inner(
            tool_name,
            arguments,
            access_key,
            client_ip,
            cfg,
            qp,
            admin_engine,
            audit_logger,
            data_masker,
            tbl,
            raw_cid,
        )


async def _execute_mcp_tool_inner(
    tool_name: str,
    arguments: Dict[str, Any],
    access_key: str,
    client_ip: Optional[str],
    cfg,
    qp,
    admin_engine,
    audit_logger,
    data_masker,
    tbl,
    connection_id,
) -> Any:
    import time
    from sqlalchemy import select, text, or_
    from sqlalchemy.orm import Session
    from ..security.secret import decrypt_text
    from ..security.interceptor import intercept_sql

    start_time = time.time()

    # 1. 特殊处理 list_connections，因为它不需要 connection_id
    if tool_name == "list_connections":
        search = arguments.get("search", "")
        keys = tbl["access_keys"]
        perms = tbl["permissions"]
        conns = tbl["db_connections"]
        with Session(admin_engine) as session:
            key_row = session.execute(
                select(keys).where(keys.c.ak == access_key)
            ).mappings().first()

            if not key_row:
                raise Exception("访问密钥不存在")

            stmt = select(
                conns.c.id,
                conns.c.name.label("conn_name"),
                conns.c.db_type,
                conns.c.host,
                conns.c.database
            ).select_from(
                conns.join(perms, conns.c.id == perms.c.connection_id)
            ).where(
                perms.c.key_id == key_row["id"]
            )

            if search:
                # 同时搜索名称和数据库类型
                stmt = stmt.where(
                    or_(
                        conns.c.name.ilike(f"%{search}%"),
                        conns.c.db_type.ilike(f"%{search}%")
                    )
                )

            conn_rows = session.execute(stmt).mappings().all()
            result = {"connections": [dict(r) for r in conn_rows]}

            # 记录审计日志
            duration_ms = int((time.time() - start_time) * 1000)
            audit_logger.log(
                operation=f"mcp_{tool_name}",
                status="success",
                access_key=access_key,
                client_ip=client_ip,
                duration_ms=duration_ms
            )
            # 返回符合 MCP 规范的标准格式
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, ensure_ascii=False)
                    }
                ]
            }

    # 2. 特殊处理 compare_schemas（需要两个 connection_id）
    if tool_name == "compare_schemas":
        src_conn_id = arguments.get("source_connection_id")
        tgt_conn_id = arguments.get("target_connection_id")
        if not src_conn_id or not tgt_conn_id:
            raise Exception("缺少必需参数: source_connection_id, target_connection_id")

        keys = tbl["access_keys"]
        perms = tbl["permissions"]
        conns = tbl["db_connections"]

        def _resolve_connection(session, aid, cid):
            key_row = session.execute(select(keys).where(keys.c.ak == aid)).mappings().first()
            if not key_row:
                raise Exception("访问密钥不存在")
            perm = session.execute(
                select(perms).where(perms.c.key_id == key_row["id"], perms.c.connection_id == cid)
            ).mappings().first()
            if not perm:
                raise Exception(f"该密钥无权访问连接 {cid}")
            crow = session.execute(select(conns).where(conns.c.id == cid)).mappings().first()
            if not crow:
                raise Exception(f"连接 {cid} 不存在")
            pw = decrypt_text(crow["password_enc"], cfg.security.master_key)
            eg = qp.get_engine(crow["host"], int(crow["port"]), crow["username"], pw, crow["database"], crow["db_type"])
            return eg, crow["database"], crow["db_type"]

        with Session(admin_engine) as session:
            eng_src, db_src, dbtype_src = _resolve_connection(session, access_key, src_conn_id)
            eng_tgt, db_tgt, dbtype_tgt = _resolve_connection(session, access_key, tgt_conn_id)

        src_db = arguments.get("source_database") or db_src
        tgt_db = arguments.get("target_database") or db_tgt
        gen_ddl = arguments.get("generate_ddl", True)

        from ..tools.db_compare_tool import compare_schemas as do_compare, generate_sync_ddl
        comparison = do_compare(eng_src, src_db, dbtype_src, eng_tgt, tgt_db, dbtype_tgt)
        result = {"comparison": comparison}
        if gen_ddl:
            result["sync_ddl"] = generate_sync_ddl(comparison, dbtype_tgt)

        duration_ms = int((time.time() - start_time) * 1000)
        audit_logger.log(
            operation="mcp_compare_schemas", status="success",
            access_key=access_key, client_ip=client_ip, duration_ms=duration_ms
        )
        return {
            "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, default=str)}]
        }

    # 3. 其他工具都需要 connection_id
    if not connection_id:
        raise Exception("缺少必需参数: connection_id")

    from ..tools.db_metadata_tool import list_databases, list_tables, list_views, list_procedures, table_info

    keys = tbl["access_keys"]
    perms = tbl["permissions"]
    conns = tbl["db_connections"]
    with Session(admin_engine) as session:
        key_row = session.execute(
            select(keys).where(keys.c.ak == access_key)
        ).mappings().first()

        if not key_row:
            raise Exception("访问密钥不存在")

        perm = session.execute(
            select(perms).where(
                perms.c.key_id == key_row["id"],
                perms.c.connection_id == connection_id
            )
        ).mappings().first()

        if not perm:
            raise Exception("该密钥无权访问此数据库连接")

        conn_row = session.execute(
            select(conns).where(conns.c.id == connection_id)
        ).mappings().first()

        if not conn_row:
            raise Exception("数据库连接不存在")

        # 解密密码
        pwd = decrypt_text(conn_row["password_enc"], cfg.security.master_key)

        # 获取引擎
        engine = qp.get_engine(
            conn_row["host"],
            int(conn_row["port"]),
            conn_row["username"],
            pwd,
            conn_row["database"],
            conn_row["db_type"]
        )

    try:
        # 执行工具
        if tool_name == "list_databases":
            databases = list_databases(engine, conn_row["db_type"])
            result = {"databases": databases}

        elif tool_name == "list_tables":
            database = arguments.get("database") or conn_row["database"]
            tables = list_tables(engine, database, conn_row["db_type"])
            result = {"database": database, "tables": tables}

        elif tool_name == "list_views":
            database = arguments.get("database") or conn_row["database"]
            views = list_views(engine, database, conn_row["db_type"])
            result = {"database": database, "views": views}

        elif tool_name == "list_procedures":
            database = arguments.get("database") or conn_row["database"]
            procs = list_procedures(engine, database, conn_row["db_type"])
            result = {"database": database, "procedures": procs}

        elif tool_name == "describe_table":
            table_name = arguments.get("table")
            database = arguments.get("database") or conn_row["database"]
            if not table_name:
                raise Exception("缺少参数: table")

            info = table_info(engine, database, table_name, conn_row["db_type"])
            result = {"database": database, "table": table_name, "columns": info["columns"]}

        elif tool_name == "execute_query":
            sql = arguments.get("sql")
            if not sql:
                raise Exception("缺少参数: sql")

            # 检查 SQL 类型
            sql_upper = sql.strip().upper()
            is_select = sql_upper.startswith('SELECT') or sql_upper.startswith(
                'SHOW') or sql_upper.startswith('DESCRIBE') or sql_upper.startswith('EXPLAIN')

            # 权限验证
            if perm.get('select_only', True) and not is_select:
                raise Exception("该连接仅允许 SELECT 查询，不允许执行修改操作")

            # SQL 安全检查
            sec = intercept_sql(sql, {"key": access_key})
            if not sec["safe"]:
                raise Exception(f"风险 SQL，阈值: {sec['risk']}")

            # 执行查询
            rows = qp.run_query(engine, sql)
            masked_rows = data_masker.mask_results(rows)
            result = {"rows": masked_rows, "count": len(masked_rows)}

        elif tool_name == "execute_sql":
            sql = arguments.get("sql")
            if not sql:
                raise Exception("缺少参数: sql")

            # 检查 SQL 类型
            sql_upper = sql.strip().upper()
            is_select = sql_upper.startswith('SELECT') or sql_upper.startswith(
                'SHOW') or sql_upper.startswith('DESCRIBE') or sql_upper.startswith('EXPLAIN')
            is_ddl = any(sql_upper.startswith(kw) for kw in ["CREATE", "DROP", "ALTER", "TRUNCATE", "RENAME"])

            # 权限验证
            if perm.get('select_only', True) and not is_select:
                raise Exception("该连接仅允许 SELECT 查询，不允许执行修改操作")

            if is_ddl and not perm.get("allow_ddl", False):
                raise Exception("该连接不允许执行 DDL 操作（CREATE/DROP/ALTER等）")

            # SQL 安全检查
            sec = intercept_sql(sql, {"key": access_key})
            if not sec["safe"]:
                raise Exception(f"风险 SQL，阈值: {sec['risk']}")

            # 执行 SQL
            with engine.connect() as conn:
                result_proxy = conn.execute(text(sql))
                conn.commit()

                try:
                    rows = [dict(r._mapping) for r in result_proxy]
                    masked_rows = data_masker.mask_results(rows)
                    result = {"rows": masked_rows, "count": len(masked_rows)}
                except Exception:
                    result = {"success": True, "message": "SQL 执行成功"}

        elif tool_name == "export_db_doc":
            import time as _time

            from ..tools.db_doc_tool import generate_db_doc_markdown, export_db_doc_pdf
            from ..tools.file_upload import build_download_mcp_content, upload_artifact

            database = arguments.get("database") or conn_row["database"]
            fmt = arguments.get("format", "markdown")
            save_path = arguments.get("save_path")
            upload_to_oss = arguments.get("upload_to_oss")
            if upload_to_oss is None:
                upload_to_oss = bool(cfg.object_storage and cfg.object_storage.enabled)

            if upload_to_oss:
                if fmt == "pdf":
                    pdf_result = export_db_doc_pdf(
                        engine, database, conn_row["db_type"], save_path
                    )
                    import base64 as _b64

                    file_data = _b64.b64decode(pdf_result["pdf_base64"])
                    filename = pdf_result.get("filename") or f"db_doc_{database}.pdf"
                    content_type = "application/pdf"
                    extra = {
                        "size_bytes": pdf_result.get("size_bytes", len(file_data)),
                        "table_count": pdf_result.get("table_count"),
                    }
                else:
                    md = generate_db_doc_markdown(
                        engine, database, conn_row["db_type"]
                    )
                    file_data = md.encode("utf-8")
                    ts = _time.strftime("%Y%m%d_%H%M%S")
                    filename = f"db_doc_{database}_{ts}.md"
                    content_type = "text/markdown; charset=utf-8"
                    extra = {
                        "size_bytes": len(file_data),
                        "table_count": md.count("\n## "),
                    }
                meta = upload_artifact(
                    cfg,
                    category="doc",
                    filename=filename,
                    data=file_data,
                    content_type=content_type,
                )
                extra["provider"] = meta.get("provider")
                extra["object_key"] = meta.get("object_key")
                duration_ms = int((time.time() - start_time) * 1000)
                audit_logger.log(
                    operation=f"mcp_{tool_name}",
                    status="success",
                    access_key=access_key,
                    client_ip=client_ip,
                    connection_id=connection_id,
                    duration_ms=duration_ms,
                )
                return build_download_mcp_content(
                    title="数据字典",
                    download_url=meta["download_url"],
                    filename=filename,
                    fmt=fmt,
                    extra=extra,
                )

            if fmt == "pdf":
                pdf_result = export_db_doc_pdf(engine, database, conn_row["db_type"], save_path)
                duration_ms = int((time.time() - start_time) * 1000)
                audit_logger.log(
                    operation=f"mcp_{tool_name}",
                    status="success",
                    access_key=access_key,
                    client_ip=client_ip,
                    connection_id=connection_id,
                    duration_ms=duration_ms
                )

                resp_content = []
                # 依然返回资源以便界面预览
                resp_content.append({
                    "type": "resource",
                    "resource": {
                        "uri": f"data:application/pdf;base64,{pdf_result['pdf_base64']}",
                        "mimeType": "application/pdf",
                        "blob": pdf_result["pdf_base64"]
                    }
                })

                msg_body = {
                    "filename": pdf_result["filename"],
                    "size_bytes": pdf_result["size_bytes"],
                    "table_count": pdf_result["table_count"],
                    "message": f"PDF 文档已生成：{pdf_result['filename']}（{pdf_result['size_bytes']} 字节）"
                }
                if pdf_result.get("saved_to"):
                    msg_body["saved_to"] = pdf_result["saved_to"]
                    msg_body["message"] += f"，已自动保存到本地：{pdf_result['saved_to']}"

                resp_content.append({
                    "type": "text",
                    "text": json.dumps(msg_body, ensure_ascii=False)
                })

                return {"content": resp_content}
            else:
                md = generate_db_doc_markdown(engine, database, conn_row["db_type"])
                result = {"format": "markdown", "content": md}

        elif tool_name == "generate_er_diagram":
            import os
            from ..tools.db_er_tool import (
                generate_er_mermaid,
                generate_er_text_description,
                export_er_report_pdf,
            )
            from ..tools.file_upload import build_download_mcp_content, upload_artifact

            database = arguments.get("database") or conn_row["database"]
            include_columns = arguments.get("include_columns", True)
            include_implicit = arguments.get("include_implicit", True)
            output_type = arguments.get("output_type", "both")
            fmt = arguments.get("format", "markdown")
            save_path = arguments.get("save_path")
            upload_to_oss = arguments.get("upload_to_oss")
            if upload_to_oss is None:
                upload_to_oss = bool(cfg.object_storage and cfg.object_storage.enabled)

            if upload_to_oss:
                if fmt == "pdf":
                    pdf_result = export_er_report_pdf(
                        engine,
                        database,
                        conn_row["db_type"],
                        include_columns,
                        include_implicit,
                        save_path,
                    )
                    file_path = pdf_result["file_path"]
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                    filename = pdf_result.get("filename") or os.path.basename(file_path)
                    content_type = "application/pdf"
                    extra = {
                        "size_bytes": pdf_result.get("size_bytes", len(file_data)),
                        "table_count": pdf_result.get("table_count"),
                        "mermaid_preview": pdf_result.get("mermaid_preview"),
                        "provider": None,
                    }
                else:
                    mer = generate_er_mermaid(
                        engine,
                        database,
                        conn_row["db_type"],
                        include_columns,
                        include_implicit,
                    )
                    desc = generate_er_text_description(
                        engine, database, conn_row["db_type"], include_implicit
                    )
                    md = (
                        f"# 数据库 ER 图 — {database}\n\n"
                        f"```mermaid\n{mer['mermaid']}\n```\n\n{desc}\n"
                    )
                    file_data = md.encode("utf-8")
                    ts = time.strftime("%Y%m%d_%H%M%S")
                    filename = f"db_er_{database}_{ts}.md"
                    content_type = "text/markdown; charset=utf-8"
                    extra = {
                        "size_bytes": len(file_data),
                        "table_count": mer.get("table_count"),
                    }

                meta = upload_artifact(
                    cfg,
                    category="er",
                    filename=filename,
                    data=file_data,
                    content_type=content_type,
                )
                extra["provider"] = meta.get("provider")
                extra["object_key"] = meta.get("object_key")
                download_url = meta["download_url"]

                duration_ms = int((time.time() - start_time) * 1000)
                audit_logger.log(
                    operation=f"mcp_{tool_name}",
                    status="success",
                    access_key=access_key,
                    client_ip=client_ip,
                    connection_id=connection_id,
                    duration_ms=duration_ms,
                )
                return build_download_mcp_content(
                    title="ER 图",
                    download_url=download_url,
                    filename=filename,
                    fmt=fmt,
                    extra=extra,
                )

            if fmt == "pdf":
                pdf_result = export_er_report_pdf(
                    engine,
                    database,
                    conn_row["db_type"],
                    include_columns,
                    include_implicit,
                    save_path,
                )
                duration_ms = int((time.time() - start_time) * 1000)
                audit_logger.log(
                    operation=f"mcp_{tool_name}",
                    status="success",
                    access_key=access_key,
                    client_ip=client_ip,
                    connection_id=connection_id,
                    duration_ms=duration_ms,
                )
                public = (getattr(cfg.server, "public_base_url", None) or "").strip().rstrip("/")
                rel = pdf_result.get("download_url") or ""
                download_url = f"{public}{rel}" if public else rel
                return build_download_mcp_content(
                    title="ER 图 PDF",
                    download_url=download_url,
                    filename=pdf_result.get("filename") or "er.pdf",
                    fmt="pdf",
                    extra={
                        "size_bytes": pdf_result.get("size_bytes"),
                        "table_count": pdf_result.get("table_count"),
                        "file_path": pdf_result.get("file_path"),
                    },
                )

            result = {}
            if output_type in ("mermaid", "both"):
                result["mermaid_result"] = generate_er_mermaid(
                    engine,
                    database,
                    conn_row["db_type"],
                    include_columns,
                    include_implicit,
                )
            if output_type in ("text", "both"):
                result["text_description"] = generate_er_text_description(
                    engine, database, conn_row["db_type"], include_implicit
                )

        elif tool_name == "generate_data_flow":
            import time as _time

            from ..tools.db_dataflow_tool import (
                generate_dataflow_mermaid,
                generate_dataflow_description,
                export_dataflow_report_pdf,
            )
            from ..tools.file_upload import build_download_mcp_content, upload_artifact

            database = arguments.get("database") or conn_row["database"]
            output_type = arguments.get("output_type", "both")
            fmt = arguments.get("format", "markdown")
            save_path = arguments.get("save_path")
            upload_to_oss = arguments.get("upload_to_oss")
            if upload_to_oss is None:
                upload_to_oss = bool(cfg.object_storage and cfg.object_storage.enabled)

            if upload_to_oss:
                if fmt == "pdf":
                    pdf_result = export_dataflow_report_pdf(
                        engine, database, conn_row["db_type"], save_path
                    )
                    import base64 as _b64

                    file_data = _b64.b64decode(pdf_result["pdf_base64"])
                    filename = pdf_result.get("filename") or f"db_dataflow_{database}.pdf"
                    content_type = "application/pdf"
                    extra = {"size_bytes": pdf_result.get("size_bytes", len(file_data))}
                else:
                    mer = generate_dataflow_mermaid(
                        engine, database, conn_row["db_type"]
                    )
                    desc = generate_dataflow_description(
                        engine, database, conn_row["db_type"]
                    )
                    md = (
                        f"# 数据库数据流图 — {database}\n\n"
                        f"```mermaid\n{mer['mermaid']}\n```\n\n{desc}\n"
                    )
                    file_data = md.encode("utf-8")
                    ts = _time.strftime("%Y%m%d_%H%M%S")
                    filename = f"db_dataflow_{database}_{ts}.md"
                    content_type = "text/markdown; charset=utf-8"
                    extra = {
                        "size_bytes": len(file_data),
                        "table_count": mer.get("table_count"),
                    }
                meta = upload_artifact(
                    cfg,
                    category="dataflow",
                    filename=filename,
                    data=file_data,
                    content_type=content_type,
                )
                extra["provider"] = meta.get("provider")
                extra["object_key"] = meta.get("object_key")
                duration_ms = int((time.time() - start_time) * 1000)
                audit_logger.log(
                    operation=f"mcp_{tool_name}",
                    status="success",
                    access_key=access_key,
                    client_ip=client_ip,
                    connection_id=connection_id,
                    duration_ms=duration_ms,
                )
                return build_download_mcp_content(
                    title="数据流图",
                    download_url=meta["download_url"],
                    filename=filename,
                    fmt=fmt,
                    extra=extra,
                )

            if fmt == "pdf":
                pdf_result = export_dataflow_report_pdf(engine, database, conn_row["db_type"], save_path)
                duration_ms = int((time.time() - start_time) * 1000)
                audit_logger.log(
                    operation=f"mcp_{tool_name}", status="success", access_key=access_key,
                    client_ip=client_ip, connection_id=connection_id, duration_ms=duration_ms
                )

                resp_content = []
                resp_content.append({
                    "type": "resource",
                    "resource": {
                        "uri": f"data:application/pdf;base64,{pdf_result['pdf_base64']}",
                        "mimeType": "application/pdf",
                        "blob": pdf_result["pdf_base64"]
                    }
                })

                msg_body = {
                    "filename": pdf_result["filename"],
                    "size_bytes": pdf_result["size_bytes"],
                    "message": f"数据流报告已生成：{pdf_result['filename']}"
                }
                if pdf_result.get("saved_to"):
                    msg_body["saved_to"] = pdf_result["saved_to"]
                    msg_body["message"] += f"，已自动保存到本地：{pdf_result['saved_to']}"

                resp_content.append({
                    "type": "text",
                    "text": json.dumps(msg_body, ensure_ascii=False)
                })
                return {"content": resp_content}

            result = {}
            if output_type in ("mermaid", "both"):
                result["mermaid_result"] = generate_dataflow_mermaid(
                    engine, database, conn_row["db_type"]
                )
            if output_type in ("text", "both"):
                result["text_description"] = generate_dataflow_description(
                    engine, database, conn_row["db_type"]
                )

        elif tool_name == "suggest_columns":
            from ..tools.db_suggest_tool import get_table_full_info, analyze_impact, suggest_columns
            table_name = arguments.get("table")
            database = arguments.get("database") or conn_row["database"]
            if not table_name:
                raise Exception("缺少参数: table")
            get_info_only = arguments.get("get_table_info", False)
            if get_info_only:
                result = get_table_full_info(engine, database, table_name, conn_row["db_type"])
            else:
                columns_to_add = arguments.get("columns", [])
                if columns_to_add:
                    result = analyze_impact(engine, database, table_name, columns_to_add, conn_row["db_type"])
                else:
                    # 如果没有传入 columns，则走 AI 智能推荐
                    result = suggest_columns(engine, database, table_name, conn_row["db_type"])

        elif tool_name == "analyze_performance":
            from ..tools.db_performance_tool import (
                get_connection_stats, get_slow_queries, get_lock_info,
                get_table_stats, get_index_usage, generate_performance_report
            )
            database = arguments.get("database") or conn_row["database"]
            analysis_type = arguments.get("analysis_type", "full")
            if analysis_type == "full":
                result = generate_performance_report(engine, database, conn_row["db_type"])
            elif analysis_type == "connections":
                result = {"connection_stats": get_connection_stats(engine, conn_row["db_type"])}
            elif analysis_type == "slow_queries":
                result = {"slow_queries": get_slow_queries(engine, conn_row["db_type"])}
            elif analysis_type == "locks":
                result = {"lock_info": get_lock_info(engine, conn_row["db_type"])}
            elif analysis_type == "table_stats":
                result = {"table_stats": get_table_stats(engine, database, conn_row["db_type"])}
            elif analysis_type == "index_usage":
                result = {"index_usage": get_index_usage(engine, database, conn_row["db_type"])}
            else:
                result = generate_performance_report(engine, database, conn_row["db_type"])

        elif tool_name == "generate_mock_data":
            from ..tools.db_mock_tool import generate_mock_data
            table_name = arguments.get("table")
            database = arguments.get("database") or conn_row["database"]
            count = int(arguments.get("count", 10))
            if not table_name:
                raise Exception("缺少参数: table")
            result = generate_mock_data(engine, database, table_name, conn_row["db_type"], count)

        elif tool_name == "analyze_sql":
            from ..tools.db_analyze_sql_tool import analyze_sql as do_analyze_sql
            sql_text = arguments.get("sql")
            database = arguments.get("database") or conn_row["database"]
            if not sql_text:
                raise Exception("缺少参数: sql")
            result = do_analyze_sql(engine, database, sql_text, conn_row["db_type"])

        elif tool_name == "backup_table":
            from ..tools.db_backup_tool import backup_table as do_backup
            table_name = arguments.get("table")
            database = arguments.get("database") or conn_row["database"]
            suffix = arguments.get("suffix")
            if not table_name:
                raise Exception("缺少参数: table")
            result = do_backup(engine, database, table_name, conn_row["db_type"], suffix)

        elif tool_name == "analyze_db_config":
            from ..tools.db_config_tool import analyze_db_config
            result = analyze_db_config(engine, conn_row["db_type"])

        else:
            raise Exception(f"未知工具: {tool_name}")

        # 记录审计日志
        duration_ms = int((time.time() - start_time) * 1000)
        audit_logger.log(
            operation=f"mcp_{tool_name}",
            status="success",
            access_key=access_key,
            client_ip=client_ip,
            connection_id=connection_id,
            sql_text=arguments.get("sql"),
            duration_ms=duration_ms
        )

        # 返回符合 MCP 规范的标准格式
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, ensure_ascii=False)
                }
            ]
        }

    except Exception as e:
        # 记录失败日志
        duration_ms = int((time.time() - start_time) * 1000)
        audit_logger.log(
            operation=f"mcp_{tool_name}",
            status="error",
            access_key=access_key,
            client_ip=client_ip,
            connection_id=connection_id,
            sql_text=arguments.get("sql"),
            duration_ms=duration_ms,
            error_message=str(e)
        )
        # 将错误信息包装成工具返回，而不是直接抛出协议异常，这样 AI 能够理解“为什么执行不成功”
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Error: {str(e)}"
                }
            ],
            "isError": True
        }
