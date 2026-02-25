# IDE 智能体与 MCP Server 配置指南

## 目标与适用范围
- 帮助在常用 IDE 中接入 MCP Server，供智能体安全调用仓库数据库工具。
- 说明项目根目录规则文件的作用与约束，提供自定义规则模板。
- 涵盖 TRAE IDE 的原生配置示例与通用 HTTP/JSON-RPC 客户端的调用方法。

## MCP Server 接入要点
- 协议：Model Context Protocol（标准版提供 SSE 与消息端点）
- 认证：HTTP Header 携带 X-Access-Key
- 测试环境端点（我自己电脑搭建的，可能经常挂掉，仅供测试使用）：
  - SSE：`http://mcp.wongcw.cn/mcp/sse`
- 常见工具：list_connections、list_databases、list_tables、describe_table、execute_query、execute_sql


## 在 TRAE IDE 中配置
- 配置文件位置（Windows）：`%APPDATA%\TRAE\mcp_config.json`
- 单环境示例：

```json
{
  "mcpServers": {
    "db-mcp-local": {
      "url": "mcp.wongcw.cn/mcp/sse",
      "transport": "sse",
      "headers": {
        "X-Access-Key": "mcp_key_01"
      }
    }
  }
}
```

- 多环境示例：

```json
{
  "mcpServers": {
    "db-dev": {
      "url": "http://localhost:3000/mcp/sse",
      "transport": "sse",
      "headers": { "X-Access-Key": "dev_key_123" }
    },
    "db-test": {
      "url": "https://db-mcp-test.yourcompany.com/mcp/sse",
      "transport": "sse",
      "headers": { "X-Access-Key": "test_key_456" }
    },
    "db-prod": {
      "url": "https://db-mcp.yourcompany.com/mcp/sse",
      "transport": "sse",
      "headers": { "X-Access-Key": "prod_key_789" }
    }
  }
}
```

- JSON-RPC 调用示例（消息端点）：

```json
{
  "jsonrpc": "2.0",
  "id": "req-conn-1",
  "method": "tools/call",
  "params": {
    "name": "list_connections",
    "arguments": { "search": "" }
  }
}
```

## 通用 HTTP/JSON-RPC 客户端调用
- URL：`http://<server>:3000/mcp/message`
- Headers：
  - `X-Access-Key: <你的密钥>`
  - `Content-Type: application/json`
- Body：使用 JSON-RPC 格式，`method` 为 `tools/call`，`params` 中指定工具名与参数。
- 成功返回时 `result` 字段包含工具输出，如：`{"connections": [...]}`、`{"rows": [...], "count": N}`。

## 项目规则文件（.ide_mcp_rules.md）
- 位置：项目根目录 [\.ide_mcp_rules.md](file:///d:/github/db_mcp_server/.ide_mcp_rules.md)
- 作用：为 IDE 智能体提供数据库工具调用的工作规范，确保安全与一致性。
- 现有要点（摘要）：
  - 先列连接：不猜测 connection_id，先 `list_connections`。
  - 探索结构：`list_databases → list_tables → describe_table`。
  - 只读/写入：只读用 `execute_query`，写入/DDL 用 `execute_sql`（需权限）。
  - 错误说明：权限不足时提示检查 APPKEY 与授权。
  - 结果展示：明确 connection_id 与 database。

## 自定义规则：MCP Server 使用方法（建议模板）
可以在 [\.ide_mcp_rules.md](file:///d:/github/db_mcp_server/.ide_mcp_rules.md) 末尾增加如下规则段落，以适应团队规范：

- 连接发现
  - 总是先调用 `list_connections` 获取 `id/conn_name/db_type/host/database`。
  - 使用 `search` 关键词过滤连接名或类型（mysql/postgres）。
- 数据库选择
  - 有多库时先调用 `list_databases`，否则默认使用连接记录中的 `database`。
- 元数据探索
  - 列表用 `list_tables`，字段用 `describe_table`，视图/存储过程用 `list_views/list_procedures`。
- 查询与权限
  - 只读查询用 `execute_query`（SELECT/SHOW/DESCRIBE/EXPLAIN），避免 DML/DDL。
  - 写入或 DDL 用 `execute_sql`，仅在权限允许时执行；风险 SQL 必须明确告知。
- 审计与展示
  - 输出中包含 `connection_id`、`database`、影响行数/耗时，便于审计。
- 异常与提示
  - `401/403`：检查访问密钥状态与连接授权；`422`：核对请求入参位置（Query vs Body）。

> 说明：TRAE/其他 IDE 的智能体读取规则的方式不同。将规范集中在仓库根（\.ide_mcp_rules.md）可为所有团队成员提供一致的调用准则；如 IDE 支持项目级规则映射，请在 IDE 的自定义规则入口中引用该文件。

## 安全建议
- 生产环境使用强随机 `X-Access-Key`，并开启 IP 白名单。
- 严格区分只读与写入权限；DDL 权限仅授予测试或特定维护场景。
- 审计日志应开启写入数据库，定期检视异常操作与耗时。

## 故障排查
- 401 未认证：确认 `X-Access-Key` 是否有效、启用。
- 403 无权限：该密钥未授权访问目标连接或不具备所需操作权限。
- 422 参数错误：检查调用工具的参数位置（如 JSON Body vs Query）。
- 连接失败：核对 `host/port/db_type/username/password/database` 与网络连通性。

