# 在 TRAE 中使用 DB MCP Server (SSE 方式)

本文档说明如何在 TRAE IDE 中通过 SSE 协议直接连接到 DB MCP Server。

## 架构说明

```
TRAE IDE  <--SSE/HTTP-->  DB MCP Server (远程服务器)
                              |
                              v
                          数据库集群
```

- **协议**: Model Context Protocol over SSE
- **认证**: X-Access-Key Header
- **端点**: `http://your-server:3000/mcp/sse`

## 前提条件

1. ✅ DB MCP Server 已部署并可通过网络访问
2. ✅ 已在管理后台创建访问密钥
3. ✅ 已为该密钥配置数据库连接权限
4. ✅ （可选）配置 IP 白名单限制访问来源

## 配置步骤

### 1. 获取服务器信息

- **服务器地址**: 例如 `https://db-mcp.yourcompany.com`
- **MCP SSE 端点**: `https://db-mcp.yourcompany.com/mcp/sse`
- **MCP 消息端点**: `https://db-mcp.yourcompany.com/mcp/message`

### 2. 创建访问密钥

登录管理后台（例如 `https://db-mcp.yourcompany.com/admin`）：

1. 进入 **"访问密钥"** 页面
2. 点击 **"添加密钥"** 创建新密钥（例如：`trae_production_key`）
3. 记录下这个密钥
4. 点击该密钥行的 **"+ 授权连接"** 按钮
5. 勾选需要授权的数据库连接
6. 选择权限级别（只读/读写）

### 3. 配置 TRAE

根据 TRAE 文档，MCP 配置文件位于：
- **Windows**: `%APPDATA%\TRAE\mcp_config.json`
- **macOS**: `~/Library/Application Support/TRAE/mcp_config.json`
- **Linux**: `~/.config/TRAE/mcp_config.json`

添加以下配置：

```json
{
  "mcpServers": {
    "db-mcp-production": {
      "url": "https://db-mcp.yourcompany.com/mcp/sse",
      "transport": "sse",
      "headers": {
        "X-Access-Key": "trae_production_key"
      }
    }
  }
}
```

**配置说明**：
- `url`: MCP SSE 端点地址
- `transport`: 传输协议，使用 `"sse"`
- `headers.X-Access-Key`: 您在步骤2中创建的访问密钥

### 4. 多环境配置示例

如果您有多个环境（开发、测试、生产），可以这样配置：

```json
{
  "mcpServers": {
    "db-dev": {
      "url": "http://localhost:3000/mcp/sse",
      "transport": "sse",
      "headers": {
        "X-Access-Key": "dev_key_123"
      }
    },
    "db-test": {
      "url": "https://db-mcp-test.yourcompany.com/mcp/sse",
      "transport": "sse",
      "headers": {
        "X-Access-Key": "test_key_456"
      }
    },
    "db-prod": {
      "url": "https://db-mcp.yourcompany.com/mcp/sse",
      "transport": "sse",
      "headers": {
        "X-Access-Key": "prod_key_789"
      }
    }
  }
}
```

### 5. 重启 TRAE

配置完成后，重启 TRAE IDE 使配置生效。

## 可用工具

DB MCP Server 提供以下标准 MCP 工具：

### 1. list_tables
列出数据库中的所有表

**参数**：
```json
{
  "connection_id": 1
}
```

**返回**：
```json
{
  "tables": ["users", "orders", "products"]
}
```

### 2. describe_table
查看表结构详情

**参数**：
```json
{
  "connection_id": 1,
  "table": "users"
}
```

**返回**：
```json
{
  "table": "users",
  "columns": [
    {"name": "id", "type": "int", "nullable": false},
    {"name": "username", "type": "varchar(50)", "nullable": false}
  ]
}
```

### 3. execute_query
执行 SQL 查询（只读）

**参数**：
```json
{
  "connection_id": 1,
  "sql": "SELECT * FROM users LIMIT 10"
}
```

**返回**：
```json
{
  "rows": [...],
  "count": 10
}
```

### 4. execute_sql
执行 SQL 语句（包括 DDL，需要权限）

**参数**：
```json
{
  "connection_id": 1,
  "sql": "CREATE TABLE test (id INT)"
}
```

**返回**：
```json
{
  "success": true,
  "message": "SQL 执行成功"
}
```

## 使用示例

配置成功后，在 TRAE 中与 AI 对话：

**👤 用户**: 请查看生产数据库中有哪些表

**🤖 AI**: （自动调用 `list_tables` 工具）
我发现生产数据库中有以下表：
- users (用户表)
- orders (订单表)
- products (产品表)
- ...

**👤 用户**: 请查询 users 表的前 10 条记录

**🤖 AI**: （自动调用 `execute_query` 工具）
查询结果如下：
| id | username | email | created_at |
|----|----------|-------|------------|
| 1  | admin    | ...   | ...        |
...

## 获取 connection_id

`connection_id` 是最重要的参数，表示要访问的数据库连接。

**获取方法**：
1. 登录管理后台
2. 进入 **"连接管理"** 页面
3. 查看每个连接的 ID（第一列）

**提示**：您可以在 TRAE 中询问 AI：
> "我的 connection_id 是多少？"

然后手动告诉 AI 对应的 ID，AI 会记住并在后续对话中使用。

## 安全配置

### 1. HTTPS 部署（强烈推荐）

生产环境务必使用 HTTPS：

```bash
# 使用 Nginx 反向代理
server {
    listen 443 ssl http2;
    server_name db-mcp.yourcompany.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # SSE 特殊配置
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400;
    }
}
```

### 2. IP 白名单

在管理后台配置 IP 白名单：

1. 进入 **"访问密钥"** 页面
2. 找到对应的密钥
3. 配置允许访问的 IP 地址或 CIDR 范围

例如：
- `192.168.1.100` - 单个 IP
- `192.168.1.0/24` - IP 段
- `0.0.0.0/0` - 允许所有（不推荐）

### 3. 密钥管理最佳实践

- ✅ 为不同用途创建不同的密钥
- ✅ 定期轮换密钥
- ✅ 使用描述性名称（如 `trae_prod_readonly`）
- ✅ 最小权限原则：只授权必要的连接
- ✅ 监控审计日志，及时发现异常访问

## 故障排查

### 1. 连接失败

**症状**: TRAE 显示 "无法连接到 MCP Server"

**排查步骤**:
```bash
# 测试服务器可达性
curl https://db-mcp.yourcompany.com/mcp/sse \
  -H "X-Access-Key: your_key"

# 应该返回 SSE 流
```

**常见原因**:
- 服务器未启动
- 防火墙阻止
- HTTPS 证书问题
- URL 配置错误

### 2. 认证失败

**症状**: 返回 401 Unauthorized

**排查步骤**:
1. 检查 `X-Access-Key` 是否正确
2. 在管理后台确认密钥状态为"启用"
3. 确认密钥未过期或被删除

### 3. 权限不足

**症状**: 返回 403 Forbidden 或 "该密钥无权访问此数据库连接"

**排查步骤**:
1. 检查 `connection_id` 是否正确
2. 在管理后台确认该密钥已授权此连接
3. 如果执行 DDL，确认权限中 `allow_ddl` 已启用

### 4. SSE 连接中断

**症状**: 连接频繁断开

**解决方案**:
- 检查网络稳定性
- 增加 Nginx 的 `proxy_read_timeout`
- 检查防火墙是否有超时限制

## API 端点说明

### GET /mcp/sse
SSE 连接端点，用于建立长连接

**Headers**:
- `X-Access-Key`: 访问密钥

**Response**: 
- `Content-Type: text/event-stream`
- 持续推送 SSE 事件

### POST /mcp/message
消息处理端点，用于发送 JSON-RPC 请求

**Headers**:
- `X-Access-Key`: 访问密钥
- `Content-Type: application/json`

**Body**:
```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "tools/call",
  "params": {
    "name": "list_tables",
    "arguments": {
      "connection_id": 1
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "tables": ["users", "orders"]
  }
}
```

## 监控与审计

所有通过 MCP 的操作都会记录在审计日志中：

1. 登录管理后台
2. 进入 **"审计日志"** 页面
3. 查看操作记录，包括：
   - 时间戳
   - 访问密钥
   - 客户端 IP
   - 操作类型
   - SQL 语句
   - 执行结果
   - 耗时

## 相关链接

- [TRAE MCP 文档](https://docs.trae.ai/ide/model-context-protocol?_lang=zh)
- [MCP 官方文档](https://modelcontextprotocol.io/docs/getting-started/intro)
- [DB MCP Server 管理后台](http://localhost:3000/admin)
