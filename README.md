# DB MCP Server

企业级数据库访问代理系统，支持 MySQL 和 PostgreSQL。通过访问密钥、连接级权限控制、IP 白名单与审计日志，提供安全、可审计的数据库访问。所有真实数据库凭证集中管理，客户端无需知道数据库账号密码。

## 项目简介

- 🔐 访问控制：按“访问密钥 × 连接”授权（只读/读写/DDL）
- 🛡️ 安全防护：SQL 风险拦截、IP 白名单、数据脱敏
- 🔄 事务支持：开启/提交/回滚/状态/清理
- 📊 多数据库：支持 MySQL 与 PostgreSQL
- 📡 标准 MCP：提供 HTTP API 与 SSE 标准协议
- 📝 审计日志：完整记录操作与耗时
- 🌐 Web 管理：图形化管理连接、密钥、权限、白名单、**大模型配置**
- 🤖 智能分析：SQL 审查、性能/参数调优、字段建议、ER 业务解读（可选 LLM，见 `src/ai/`）
- 📦 对象存储：文档/ER/报表可上传 OSS 并返回下载链接（`object_storage` 配置）
- 🐳 Docker 部署：supervisord 管理，非 root 运行

## 架构图

```mermaid
graph TB
    subgraph Clients["客户端"]
        AI["AI 客户端 / IDE<br/>(TRAE, Cursor 等)"]
        HTTP["HTTP 客户端"]
        WEB["Web 管理界面<br/>Svelte SPA（/login 等）"]
    end

    subgraph Server["DB MCP Server — FastAPI（单进程、同端口）"]
        direction TB

        subgraph Entry["入口层"]
            SSE["/mcp/sse — SSE 端点"]
            MSG["/mcp/message — MCP 消息"]
            API["/query — HTTP 查询"]
            ADMIN_API["/admin/* — 管理接口"]
        end

        subgraph MCP_Layer["MCP 协议层 · src/mcp/"]
            TOOLS_DEF["tools.py 工具定义"]
            STD_PROTO["standard_protocol.py SSE 协议"]
            MCP_SRV["server.py HTTP 协议"]
            PERM_CHK["permissions.py 权限检查"]
        end

        subgraph Security_Layer["安全层 · src/security/"]
            INTERCEPT["SQL 风险拦截"]
            WHITELIST["IP 白名单"]
            MASKER["数据脱敏"]
            SECRET["密码加解密"]
        end

        subgraph Tools_Layer["工具层 · src/tools/ + src/ai/"]
            META_TOOL["db_metadata_tool.py 元数据"]
            DB_TOOL["db_tool.py 查询"]
            DOC_TOOL["db_doc_tool.py 文档导出"]
            ER_TOOL["db_er_tool.py ER 图"]
            FLOW_TOOL["db_dataflow_tool.py 数据流"]
            SUGGEST_TOOL["db_suggest_tool.py 字段建议"]
            PERF_TOOL["db_performance_tool.py 性能分析"]
            AI_SVC["ai/service.py 大模型"]
        end

        subgraph Core["核心层"]
            QP["QueryProxy 数据库操作"]
            CFG["Config 配置加载"]
            AUDIT["AuditLogger 审计日志"]
        end

        subgraph Admin_Mod["管理模块 · src/admin/"]
            MODELS["models.py 数据模型"]
            AUTH["auth.py JWT 认证"]
            WEB_ADMIN["web.py 管理路由"]
        end
    end

    subgraph Target_DB["目标数据库"]
        MYSQL[("MySQL")]
        PG_TARGET[("PostgreSQL")]
    end

    ADMIN_DB[("PostgreSQL<br/>管理库")]

    AI -->|"SSE + JSON-RPC"| SSE
    AI -->|"POST"| MSG
    HTTP -->|"REST"| API
    WEB -->|"REST + 静态资源"| ADMIN_API

    SSE --> STD_PROTO
    MSG --> STD_PROTO
    API --> Security_Layer
    ADMIN_API --> WEB_ADMIN

    STD_PROTO --> PERM_CHK
    STD_PROTO --> Security_Layer
    MCP_SRV --> PERM_CHK
    MCP_SRV --> Security_Layer

    Security_Layer --> Tools_Layer
    Tools_Layer --> QP
    QP --> MYSQL
    QP --> PG_TARGET
    WEB_ADMIN --> MODELS
    MODELS --> ADMIN_DB
    AUDIT --> ADMIN_DB
```

## 快速开始

### 前置要求

- Docker 20.10+
- Docker Compose 1.29+

### 使用 Docker Compose 部署

1. 克隆项目

```bash
git clone https://github.com/redgreat/zr_db_mcp_server.git
cd zr_db_mcp_server
```

2. 配置文件

```bash
cp config/config.yml.example config/config.yml
# 编辑 config/config.yml，至少修改 security.master_key、admin_database 访问参数
```

3. 启动服务

```bash
docker-compose up -d
```

4. 检查服务状态

```bash
docker-compose ps
docker-compose logs -f
```

5. 访问管理界面（Web）

本地默认端口见 `config.yml` 的 `server.port`（示例为 **3000**）。管理界面为 **Svelte 单页应用**，与 MCP、管理 API **共用同一端口**，通过 **路径** 区分：

| 场景 | 地址（本地示例） |
|------|------------------|
| 根路径 | `http://localhost:3000/` → **302** 跳转至 **`/login`**（未登录时地址栏即为登录页） |
| 登录页 | `http://localhost:3000/login` |
| 登录后主界面 | `http://localhost:3000/connections`（以及 `/keys`、`/audit` 等） |
| 旧书签 `/admin` | `http://localhost:3000/admin` → **302** 跳转至 **`/connections`**（避免在 `/admin` 下挂载 SPA 导致客户端路由 Not found） |

已保存登录态（本地 token）时访问 `/` 会先进入 `/login`，前端校验通过后自动进入 `/connections`。

## 手动部署

```bash
# 安装依赖
pip install -r requirements.txt

# 配置文件
cp config/config.yml.example config/config.yml
# 编辑 config/config.yml，设置 master_key 和 PostgreSQL 管理库

# 初始化管理数据库（PostgreSQL，在项目根目录执行）
python src/init_admin_db.py

# 启动服务
uvicorn src.server:app --host 0.0.0.0 --port 3000
```

## 反向代理与 MCP（HTTPS · Caddy 等）

- **对外**：建议只开放 **443**（及可选 **80** 跳转 HTTPS），由 **Caddy / Nginx** 等将 `https://你的域名` 反代到本机 `http://127.0.0.1:3000`（或容器内应用端口）。用户与 IDE **配置里写 `https://域名/...`，无需写 `:3000`**。
- **Web 与 MCP 不拆端口**：浏览器访问后台与 IDE 连接 MCP，均为 **HTTPS + 不同路径**（如 `/login` 与 `/mcp/sse`），不会与根路径「抢路由」。
- **Caddy 提示**：反代块中建议为 SSE 增加 **`flush_interval -1`**，减轻 `/mcp/sse` 长连接缓冲导致的事件延迟。

示例（域名与上游请按实际修改）：

```caddyfile
db-mcp.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:3000 {
        flush_interval -1
    }
}
```

## 配置说明（YAML）

配置文件路径：config/config.yml（示例参见 config/config.yml.example）

关键项：

- server：服务监听地址与端口
- security：主密钥、JWT 密钥、会话超时
- admin_database：PostgreSQL 管理库连接信息（用于存储连接、密钥、权限、审计日志等）
- database：数据库连接池参数
- logging：日志级别、目录、审计日志写入位置

示例片段：

```yaml
server:
  host: 0.0.0.0
  port: 3000

security:
  master_key: change_this_master_key_in_production
  jwt_secret: change_this_jwt_secret_in_production
  session_timeout: 3600

admin_database:
  host: localhost
  port: 5432
  database: zr_db_mcp_admin
  username: dbmcp_admin
  password: change_this_password

logging:
  level: INFO
  dir: logs
  audit_to_database: true
  audit_to_file: false
```

**重要**：生产环境必须使用强随机 master_key，并正确配置 PostgreSQL 管理库。

## 目录结构

```
db_mcp_server/
├── config/              # 配置文件目录
├── docker/              # Docker 内 supervisord 等
├── frontend/            # Svelte 管理前端源码（构建产物输出到 src/static）
├── script/              # 运维与辅助脚本
├── src/                 # 源代码目录
│   ├── admin/           # 管理后台 API（web.py）
│   ├── static/          # 前端构建输出与静态资源（npm run build 后生成）
│   ├── db/              # 数据库操作模块
│   ├── security/        # 安全（IP 白名单、加密、拦截器等）
│   ├── tools/           # 元数据与工具模块
│   ├── mcp/             # MCP 协议与工具路由
│   ├── config.py        # 配置加载（YAML）
│   ├── server.py        # 服务主文件
│   ├── logging_utils.py # 日志工具
│   └── init_admin_db.py # 管理库初始化（PostgreSQL）
├── data/                # 数据目录（可选挂载）
├── logs/                # 日志目录（挂载卷）
├── .ide_mcp_rules.md    # AI IDE 调用 MCP 工具的规范（建议加入 Cursor Rules）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 使用指南（连接级权限模型）

### 1. 管理员登录并获取令牌

```bash
curl -X POST http://localhost:3000/admin/login \
  -H "Content-Type: application/json" \
  -d '{ "username": "admin", "password": "admin123" }'
# 返回: { "token": "...", "user": { ... } }
```

> 后续所有 /admin/* 接口都需要在 Header 中携带 Authorization: Bearer <token>

### 2. 创建数据库连接

```bash
curl -X POST http://localhost:3000/admin/connections \
  -H "Authorization: Bearer <token>" \
  -d 'name=主库&host=192.168.1.100&port=3306&db_type=mysql&database=myapp_db&username=db_user&password=SecureP@ss&description=生产环境主库'
```

支持的 db_type：mysql、postgresql。密码会使用 master_key 加密存储。

### 3. 创建访问密钥

```bash
curl -X POST http://localhost:3000/admin/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{ "ak": "api_key_001", "description": "客户端A", "enabled": true }'
```

### 4. 为密钥授权连接与权限级别

```bash
curl -X POST http://localhost:3000/admin/permissions \
  -H "Authorization: Bearer <token>" \
  -d 'key_id=1&connection_id=1&select_only=true&allow_ddl=false'
```

- select_only=true：仅允许只读查询（SELECT/SHOW/DESCRIBE/EXPLAIN）
- allow_ddl=true：允许 DDL（CREATE/DROP/ALTER/TRUNCATE/RENAME）

### 5. （可选）配置 IP 白名单

```bash
curl -X POST http://localhost:3000/admin/whitelist \
  -H "Authorization: Bearer <token>" \
  -d 'key_id=1&cidr=203.0.113.100&description=办公室固定IP'
```

### 6. 客户端执行查询

```bash
curl -X POST http://localhost:3000/query \
  -H "x-access-key: api_key_001" \
  -d 'connection_id=1&sql=SELECT * FROM users LIMIT 10'
```

### 7. 使用 SSE 流式查询

```bash
curl -N "http://localhost:3000/sse/query?connection_id=1&sql=SELECT%20COUNT(*)%20FROM%20users" \
  -H "x-access-key: api_key_001"
```

### 8. 集成 IDE / TRAE（标准 MCP 协议 · SSE）

- **SSE 入口**：`GET /mcp/sse`，Header 携带 **`X-Access-Key`**（与后台「访问密钥」一致）。
- **消息入口**：`POST /mcp/message`（JSON-RPC），同样需携带访问密钥（见 `src/mcp/standard_protocol.py`）。
- 生产环境将示例中的 `http://localhost:3000` 换成 **`https://你的域名`**（经反代后**不要**在 URL 里写应用端口）。

TRAE MCP 配置示例（Windows）：`%APPDATA%\TRAE\mcp_config.json`

```json
{
  "mcpServers": {
    "db-mcp-local": {
      "url": "http://localhost:3000/mcp/sse",
      "transport": "sse",
      "headers": {
        "X-Access-Key": "api_key_001"
      }
    }
  }
}
```

Cursor 等 IDE：在 MCP 远程服务器配置中填写 **`https://<域名>/mcp/sse`**，并添加 Header **`X-Access-Key`**。具体 UI 以当前 IDE 版本为准。

调用工具示例（JSON-RPC 请求到 `http://localhost:3000/mcp/message` 或生产环境同路径的 **https** 地址）：

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "method": "tools/call",
  "params": {
    "name": "list_connections",
    "arguments": { "search": "" }
  }
}
```

返回中 `connections` 数组长度即为当前密钥可访问的连接数。

### 9. MCP 工具一览（共 20 个）

工具定义见 `src/mcp/tools.py`；IDE 智能体调用规范见仓库根目录 **[`.ide_mcp_rules.md`](.ide_mcp_rules.md)**；命令行调用见 **[`docs/MCP客户端调用说明.md`](docs/MCP客户端调用说明.md)**。

| 工具名 | 说明 | 权限 | 依赖 LLM |
|--------|------|------|----------|
| `list_connections` | 列出当前密钥可访问的连接 | - | |
| `list_databases` | 列出库 | 读 | |
| `list_tables` / `list_views` / `list_procedures` | 表 / 视图 / 存储过程 | 读 | |
| `describe_table` | 表结构 | 读 | |
| `execute_query` | 只读 SELECT 等 | 读 | |
| `execute_sql` | 任意 SQL（含 DML/DDL） | 写 / DDL | |
| `export_db_doc` | 数据字典（markdown/pdf，可 OSS） | 读 | |
| `generate_er_diagram` | ER 图（Mermaid/pdf，可 OSS） | 读 | 可选（业务域解读） |
| `generate_data_flow` | 数据流图（markdown/pdf，可 OSS） | 读 | |
| `suggest_columns` | 加字段 DDL 与依赖分析 | 读 | 可选（生成 DDL 时） |
| `analyze_performance` | 连接/慢 SQL/锁/表统计等 | 读 | 可选 |
| `analyze_sql` | EXPLAIN + 规则建议 | 读 | 可选 |
| `analyze_db_config` | 参数与运行态调优 | 读 | 可选 |
| `compare_schemas` | 两连接 Schema 对比与同步 DDL | 读 | |
| `generate_mock_data` | 生成测试 INSERT（不执行） | 读 | |
| `backup_table` | CTAS 表备份 | DDL | |
| `generate_db_rule` | 生成 `RULE.md`（项目 + 管理库） | 读 | |
| `render_report_oss` | 查库生成 xlsx/csv 上传 OSS | 读 | |

**大模型**：在 Web 管理端 **「大模型配置」**（`/ai-settings`）激活模型并填写 API Key 后，上表中标注的工具会附加 `ai_assessment` / `ai_analysis` / `ai_suggestions` 等字段；未启用时仍返回规则分析结果。调用日志可在 `/llm-logs` 查看。

**对象存储**：`export_db_doc`、`generate_er_diagram`、`generate_data_flow`、`render_report_oss` 支持 `upload_to_oss`；`config.yml` 中 `object_storage.enabled=true` 时默认上传并返回下载链接。

### 10. 测试 MCP 工具

**在 Cursor / Trae 中（推荐）**：配置 MCP 的 `url` + `X-Access-Key` 后，在对话中让 AI 调用工具即可（与生产用法一致）。

**列出工具定义（HTTP）**：

```bash
curl -s http://localhost:3000/mcp/tools -H "X-Access-Key: api_key_001"
```

**同步调用单个工具（HTTP，`POST /mcp/call`）**：

```bash
curl -s -X POST http://localhost:3000/mcp/call \
  -H "X-Access-Key: api_key_001" \
  -H "Content-Type: application/json" \
  -d '{"tool":"list_connections","arguments":{}}'
```

**命令行（SSE，适合 CI）**：

```bash
# PowerShell
$env:MCP_SSE_URL = "http://localhost:3000/mcp/sse"
$env:MCP_ACCESS_KEY = "api_key_001"
python script/mcp_call.py --tool list_connections
python script/mcp_call.py --tool analyze_sql --args "{\"connection_id\":1,\"sql\":\"SELECT 1\"}"
```

建议测试顺序：只读元数据 → `execute_query` → `analyze_sql` / `analyze_db_config`（验证 LLM）→ 文档/ER（耗时较长）→ 写操作类（测试库 + `allow_ddl`）。

## API 文档（摘要）

### MCP 与查询

- GET `/mcp/tools`（Headers: `X-Access-Key`）— 列出工具 schema
- POST `/mcp/call`（Headers: `X-Access-Key`；Body: `tool`, `arguments`）— 同步调用工具
- GET `/mcp/sse`、POST `/mcp/message` — 标准 MCP SSE / JSON-RPC

### 查询与元数据

- POST /query（Headers: x-access-key；Body: connection_id, sql）
- GET /sse/query（Headers: x-access-key；Query: connection_id, sql）
- GET /metadata/tables（Headers: x-access-key；Query: connection_id）
- GET /metadata/table_info（Headers: x-access-key；Query: connection_id, table）

### 事务接口

- POST /transaction/begin（Body: connection_id, txn_id, timeout?）
- POST /transactions/commit（Body: txn_id）
- POST /transactions/rollback（Body: txn_id）
- GET /transaction/status（Query: txn_id）
- GET /transaction/list
- POST /transaction/cleanup

### 管理接口（需 Authorization）

- POST /admin/login、POST /admin/logout、GET /admin/me
- GET/POST/PATCH/DELETE /admin/keys
- GET/POST/DELETE /admin/connections
- GET/POST/DELETE /admin/permissions
- GET/POST/DELETE /admin/whitelist
- GET /admin/audit/logs
- 大模型：管理端 `/ai-settings`、调用日志 `/llm-logs`（对应 `src/admin/` 与 `src/ai/`）
- GET /admin、GET /admin/（**302** 至 `/connections`，兼容旧书签；SPA 入口为 `/login` 等）

更多说明见：

- [`docs/IDE智能体与MCPServer配置指南.md`](docs/IDE智能体与MCPServer配置指南.md) — IDE 接入
- [`docs/MCP客户端调用说明.md`](docs/MCP客户端调用说明.md) — `script/mcp_call.py` 与 OSS/PDF 注意项
- [`.ide_mcp_rules.md`](.ide_mcp_rules.md) — AI 智能体工具调用规范（建议加入 Cursor Rules）

## 安全特性

- SQL 风险拦截：黑名单关键字、注入模式、风险评分
- 密码加密：使用 master_key（Fernet）加密存储数据库密码
- 权限控制：select_only 与 allow_ddl 两级控制
- IP 白名单：绑定到访问密钥，来源限制
- 数据脱敏：查询结果敏感信息脱敏
- 审计日志：记录访问密钥、客户端 IP、SQL、行数、耗时与状态

## 运维指南

### 查看日志

```bash
docker-compose logs
docker exec db_mcp_server cat /var/log/db_mcp_server/web.out.log
docker exec db_mcp_server cat /var/log/db_mcp_server/audit.log
```

### 重启与更新

```bash
docker-compose restart
git pull && docker-compose up -d --build
```

## 开发指南

```bash
# 创建虚拟环境
python -m venv venv
venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 初始化管理数据库（在项目根目录执行）
python src/init_admin_db.py

# 启动开发服务器
uvicorn src.server:app --reload --host 0.0.0.0 --port 3000
```

## 故障排查

- **Docker 构建阶段 `npm ci` 报 ECONNRESET / network**：多为拉取 npm 包时网络不稳定。Dockerfile 已加大重试与缓存；本地可显式指定镜像：  
  `docker build --build-arg NPM_REGISTRY=https://registry.npmmirror.com -t db-mcp .`  
  需严格走官方源时用 `--build-arg NPM_REGISTRY=https://registry.npmjs.org`（并依赖网络稳定）。
- 缺少访问密钥：检查请求 Header x-access-key
- 风险 SQL 拦截：检查语句是否包含危险操作或注入模式
- 权限不足：检查 select_only/allow_ddl 授权是否满足
- 连接失败：核对 host、port、db_type、用户与密码；检查网络与数据库白名单
- MCP 工具无 AI 分析：在管理后台检查「大模型配置」是否已激活且 API Key 有效
- PDF/ER 乱码或空白：镜像需含中文字体；ER/数据流默认输出 Mermaid 与摘要，若需 PDF 内嵌图片可额外安装 `mermaid-cli`（见 `docs/MCP客户端调用说明.md`）
- 报表/文档无下载链接：检查 `config.yml` 的 `object_storage` 是否启用

## 许可证

本项目采用 MIT License

## 技术支持

如有问题请提交 Issue 或联系技术支持团队。
