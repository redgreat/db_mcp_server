"""
标准 MCP 协议实现 (基于 SSE)
符合 Model Context Protocol 规范
"""
from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, List, Union
import json
import asyncio
from datetime import datetime
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
        from sqlalchemy import Table, MetaData, select
        from sqlalchemy.orm import Session
        
        with Session(admin_engine) as session:
            meta = MetaData()
            keys = Table("access_keys", meta, autoload_with=admin_engine)
            key_row = session.execute(
                select(keys).where(
                    keys.c.ak == x_access_key,
                    keys.c.enabled == True
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
        except:
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
        
        client_ip = request.client.host if request.client else None
        
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
            return Response(status_code=202) # HTTP 层仅返回已接收
            
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
            "protocolVersion": client_version, # 协商使用客户端请求的版本
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
    import time
    from sqlalchemy import Table, MetaData, select, text
    from sqlalchemy.orm import Session
    from ..security.secret import decrypt_text
    from ..security.interceptor import intercept_sql
    from ..tools.db_metadata_tool import list_tables, table_info
    
    start_time = time.time()
    connection_id = arguments.get("connection_id")
    
    # 1. 特殊处理 list_connections，因为它不需要 connection_id
    if tool_name == "list_connections":
        search = arguments.get("search", "")
        with Session(admin_engine) as session:
            meta = MetaData()
            
            # 获取密钥 ID
            keys = Table("access_keys", meta, autoload_with=admin_engine)
            key_row = session.execute(
                select(keys).where(keys.c.ak == access_key)
            ).mappings().first()
            
            if not key_row:
                raise Exception("访问密钥不存在")
            
            # 查询有权限的连接
            # 关联 permissions 和 db_connections
            perms = Table("permissions", meta, autoload_with=admin_engine)
            conns = Table("db_connections", meta, autoload_with=admin_engine)
            
            stmt = select(
                conns.c.id, 
                conns.c.conn_name, 
                conns.c.db_type, 
                conns.c.host, 
                conns.c.database
            ).select_from(
                conns.join(perms, conns.c.id == perms.c.connection_id)
            ).where(
                perms.c.key_id == key_row["id"]
            )
            
            if search:
                stmt = stmt.where(conns.c.conn_name.ilike(f"%{search}%"))
                
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
            return result

    # 2. 其他工具都需要 connection_id
    if not connection_id:
        raise Exception("缺少必需参数: connection_id")
    
    from ..tools.db_metadata_tool import list_databases, list_tables, list_views, list_procedures, table_info

    # 检查权限并获取连接信息
    with Session(admin_engine) as session:
        meta = MetaData()
        
        # 获取密钥 ID
        keys = Table("access_keys", meta, autoload_with=admin_engine)
        key_row = session.execute(
            select(keys).where(keys.c.ak == access_key)
        ).mappings().first()
        
        if not key_row:
            raise Exception("访问密钥不存在")
        
        # 检查权限
        perms = Table("permissions", meta, autoload_with=admin_engine)
        perm = session.execute(
            select(perms).where(
                perms.c.key_id == key_row["id"],
                perms.c.connection_id == connection_id
            )
        ).mappings().first()
        
        if not perm:
            raise Exception("该密钥无权访问此数据库连接")
        
        # 获取连接信息
        conns = Table("db_connections", meta, autoload_with=admin_engine)
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
            is_select = sql_upper.startswith('SELECT') or sql_upper.startswith('SHOW') or sql_upper.startswith('DESCRIBE') or sql_upper.startswith('EXPLAIN')
            
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
            is_select = sql_upper.startswith('SELECT') or sql_upper.startswith('SHOW') or sql_upper.startswith('DESCRIBE') or sql_upper.startswith('EXPLAIN')
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
                except:
                    result = {"success": True, "message": "SQL 执行成功"}
        
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
        
        return result
        
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
        raise

