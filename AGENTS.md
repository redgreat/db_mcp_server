# AGENTS.md — DB MCP Server

> 本文件是 AI 编码智能体迭代本仓库的入口指引。先读这里，再按引用深入具体文件。
> 面向「工具调用方」的规范见 `.ide_mcp_rules.md` / `.cursor_mcp_rules.md`，本文件面向「代码修改方」。

## 1. 项目是什么

企业级数据库访问代理（MCP Server）。客户端（AI IDE、HTTP 调用方）通过**访问密钥 + 连接级授权**访问 MySQL/PostgreSQL，不直接接触真实数据库凭证。凭证加密存放在独立的 **PostgreSQL 管理库**中。

核心能力：
- 标准 MCP 协议（SSE + JSON-RPC）+ 简化 HTTP API，**同一 FastAPI 进程、同一端口**
- 安全：SQL 风险拦截、连接级权限（只读/写/DDL）、IP 白名单、数据脱敏、审计日志
- 20 个 MCP 工具：元数据浏览、查询执行、文档/ER/数据流导出、SQL 审查、性能分析、Schema 对比、Mock 数据、报表上传 OSS 等
- 可选 LLM 增强（`src/ai/`）：SQL 审查、调优建议、ER 业务解读
- SvelteKit 管理后台（构建产物在 `src/static/`，与后端同源同端口）

## 2. 技术栈与运行

| 层 | 技术 |
|---|---|
| 后端 | Python 3.13 · FastAPI · SQLAlchemy（Core 风格，`Table`+`autoload`）· Uvicorn |
| 管理库 | PostgreSQL（表结构由 `src/admin/models.py: ensure_schema()` 用 `meta.create_all` 管理，**无迁移工具**） |
| 前端 | SvelteKit 2 · Svelte 5（runes）· TypeScript · Tailwind 4 + DaisyUI · adapter-static |
| 部署 | Docker（`python:3.13-slim`，supervisord，非 root）· GitHub Actions 打 `v*` tag 推阿里云 ACR |

常用命令：

```bash
# 后端（项目根目录，配置文件必需）
cp config/config.yml.example config/config.yml   # 改 master_key / admin_database
pip install -r requirements.txt
python src/init_admin_db.py                       # 初始化管理库（建表+默认admin/admin123）
uvicorn src.server:app --reload --host 0.0.0.0 --port 3000

# 前端（构建产物输出到 ../src/static/）
cd frontend && npm install && npm run build       # 改前端必须重新 build
cd frontend && npm run check                      # svelte-check 类型检查

# 验证（Makefile；Windows 下用 git-bash 跑 make，或直接跑下面的命令）
pytest test/                                      # Python 测试（目前仅占位+sql_guard）
flake8 src/ test/                                 # lint（仓库历史代码有既有告警，只保证不新增）
cd frontend && npm run check

# MCP 工具联调（需服务已启动且有有效密钥）
python script/mcp_call.py --tool list_connections
```

配置文件通过 `CONFIG_PATH` 环境变量可覆盖，默认 `config/config.yml`（相对项目根目录，`src/config.py` 用 dataclass 强校验加载）。

## 3. 目录结构（改动前先定位层）

```
src/
├── server.py            # FastAPI 应用工厂：静态挂载、/query、/sse/query、/metadata/*、/transaction/*、SPA 兜底
├── config.py            # YAML → dataclass 配置（新增配置项要改这里 + config.yml.example）
├── init_admin_db.py     # 管理库初始化脚本入口
├── logging_utils.py     # get_logger(name, log_dir)：滚动文件日志，日志时间走 timezone_util
├── timezone_util.py     # 时区序列化/日志时间
├── mcp/
│   ├── tools.py             # ★ 工具 schema 注册表 MCP_TOOLS（改工具定义改这里）
│   ├── server.py            # HTTP 协议路由 /mcp/tools、/mcp/call → _execute_tool 分发
│   ├── standard_protocol.py # ★ SSE 协议路由 /mcp/sse、/mcp/message → _execute_mcp_tool_inner 分发
│   └── permissions.py       # MCP 侧访问密钥/连接权限校验
├── security/            # sql_guard(权限分级) / sql_analyzer+interceptor(风险评分) /
│                        # ip_whitelist / data_masker / secret(Fernet加解密) / client_ip
├── tools/               # 20 个工具的业务实现，db_*_tool.py 命名；纯函数风格，接收 engine 参数
├── db/db_operations.py  # QueryProxy：engine 缓存池 + 事务管理（txn_map + 清理线程）
├── admin/
│   ├── web.py               # /admin/* 路由聚合入口（include 各子路由）
│   ├── context.py           # ★ AdminContext：engine/tbl/auth/日志器等共享依赖 + 测试连接 helpers
│   ├── schemas.py           # pydantic 请求模型
│   ├── routes/              # ★ 子路由按资源拆分：auth/users/keys/connections/permissions/
│   │                        #   whitelist/llm/logs/misc，各导出 build_router(ctx)
│   ├── models.py            # ensure_schema() 定义管理库全部表 + 默认数据初始化
│   ├── auth.py              # JWT + bcrypt 认证
│   └── schema_cache.py      # 管理库 Table 反射缓存（autoload_with 只反射一次）
├── ai/                  # llm_client(读库取激活配置) / service(llm_ask 统一入口) / context / llm_active
├── logging/             # audit_logger(写库) / llm_call_logger / system_logger
├── services/oss_sts_service.py  # STS 临时凭证上传
└── static/              # 前端 build 产物，勿手改

frontend/src/routes/     # (app)/ 下是受保护页面：connections/keys/audit/llm-logs/ai-settings/users；login/ 独立
frontend/src/lib/api.ts  # 同源 fetch 封装，Bearer token，401 自动跳登录
config/config.yml.example  # 配置模板，新增配置项必须同步更新
script/                # mcp_call.py(SSE测试) / redeploy.sh / release.sh / dockerbuild.ps1 / reset_admin_password.py
docs/                  # 面向使用者的中文文档
test/                  # pytest，测试基建很薄，新增逻辑请补测试
.github/workflows/     # build-deploy.yml：push v* tag → buildx → 阿里云 ACR
```

## 4. 关键架构约定（改代码前必读）

### 4.1 新增/修改一个 MCP 工具，要动 3 处

工具在**两套协议（HTTP `/mcp/call` 与 SSE `/mcp/message`）背后共用同一分发逻辑**，但代码上是两条链：

1. `src/mcp/tools.py` — 在 `MCP_TOOLS` 列表注册 `MCPTool(name, description, input_schema)`（JSON Schema）
2. `src/mcp/standard_protocol.py: _execute_mcp_tool_inner()` — 加 `elif tool_name == "xxx":` 分支，调用 `src/tools/` 下实现；这是主协议
3. `src/mcp/server.py: _execute_tool()` — HTTP 协议的分发处，保持两份逻辑一致

工具实现放在 `src/tools/db_*_tool.py`：**纯函数，接收 `engine`/连接信息，返回 dict**，不碰 FastAPI 对象。OSS 上传/下载链接统一走 `src/tools/file_upload.py`（`upload_artifact`、`build_download_mcp_content`）。改完同步更新 README 工具表和 `.ide_mcp_rules.md` 速查表。

### 4.2 权限与安全的固定调用顺序

每个受保护端点（`/query`、工具分发）按此顺序，**新增端点必须沿用**：

```
X-Access-Key 非空校验 → IP 白名单(ip_checker.check_access) →
密钥×连接权限(_check_permission → select_only/allow_ddl) →
ensure_sql_allowed(sql_guard 按语句类型分级) →
intercept_sql(风险评分, 受密钥 sql_risk_check_enabled 开关) →
执行 → data_masker.mask_results → audit_logger.log(成功/失败都要写)
```

权限模型：**访问密钥(access_keys.ak) × 连接(db_connections.id)** 在 `permissions` 表授权；`select_only=true` 只允许 SELECT/SHOW/DESCRIBE/EXPLAIN/WITH/VALUES/TABLE，`allow_ddl` 额外放行 CREATE/DROP/ALTER/TRUNCATE/RENAME。语句分类逻辑在 `src/security/sql_guard.py`，改关键字集合时同步跑 `test/test_sql_guard.py`。

### 4.3 管理库访问模式

- 管理库连接串：`cfg.get_admin_db_url()`（PostgreSQL + psycopg2）
- 表结构**只**在 `src/admin/models.py: ensure_schema()` 中声明（`meta.create_all` 幂等建表）。注意：**无迁移工具，`create_all` 只建缺失表、不会给存量表加列**——新增列需自行处理存量部署（手工 ALTER 或在 `ensure_schema` 中加幂等补丁）
- 查询用 SQLAlchemy Core：`Table("x", meta, autoload_with=admin_engine)` + `Session`。热路径（MCP 每请求）用 `src/admin/schema_cache.py` 的反射缓存，**不要每次请求重复 autoload**
- 数据库密码：`secret.encrypt_text/decrypt_text`（master_key → Fernet），**禁止明文落库、禁止进日志**

### 4.4 连接执行层

- 目标库 engine 由 `QueryProxy.get_engine()` 缓存（key=`host:port:user:db`），池化参数已调优，**不要绕开它自建 engine**
- `get_engine` 内 `normalize_host_port()` 会容错处理 `host:port`、`scheme://`、IPv6 等形式——传入 host 前不要自己再裁剪
- 事务：`qp.begin_transaction/commit/rollback`，`txn_map` 有守护线程按超时回滚；select_only 连接禁止开事务
- `standard_protocol.py` 中所有阻塞 DB 调用必须经 `run_blocking()` 进线程池执行，**禁止在 async 处理函数里直接跑同步 SQL**（会阻塞 SSE 事件循环）

### 4.5 前端 ↔ 后端路由边界

- SPA 由 `server.py` 末尾 catch-all 兜底返回 `index.html`；`/admin` 裸路径 302 → `/connections`；`admin/*`、`mcp*` 前缀**不进** SPA
- 新增后台页面：`frontend/src/routes/(app)/xxx/+page.svelte`（`(app)` 组有登录守卫 layout），API 走 `lib/api.ts`
- 新增 `/admin/*` 接口：在 `src/admin/routes/` 对应资源文件的 `build_router(ctx)` 中加路由，共享资源一律从 `ctx` 取（`ctx.engine`/`ctx.tbl`/`ctx.auth_service`/`ctx.system_logger`/`ctx.log_system_op`）；新资源类型则新建 `routes/<name>.py` 并在 `web.py` 中 `include_router`
- 新增非 admin/mcp 前缀的后端路由会被 SPA 兜底吃掉，需在 `server.py` catch-all 的排除前缀里补充

## 5. 代码风格

- 中文注释/docstring 与中文 commit message（`type(scope): 描述`，如 `feat(审计页面): ...`）是既有惯例，保持一致
- 后端：模块级 `from ..xxx import yyy` 相对导入；工具/路由内**延迟 import** 重依赖（`standard_protocol.py` 里大量函数内 import，是为启动速度有意为之，保留该模式）
- 异常边界：工具分发层捕获后统一写审计日志并包成 JSON-RPC error / HTTPException，不在每个工具函数里重复 try/except
- 日志：`get_logger(name, cfg.logging.dir)`，业务日志写 `logs/<name>.log`；审计写库走 `AuditLogger`，**不要在审计里记明文密码**
- 前端：Svelte 5 runes（`$state`/`$derived`），不用旧 store 写法新增页面；样式 Tailwind+DaisyUI 原子类

## 6. 安全红线

- `config/config.yml`、真实密钥、`.env` 永不入库（.gitignore 已覆盖，review 时确认）
- `master_key`、`jwt_secret` 改动会破坏存量加密数据/会话，涉及此处变更必须提示用户
- 用户输入 SQL 只在 `sql_guard`+`interceptor` 之后执行；**禁止新增绕过这两道检查的端点**
- 日志、审计、错误响应中不得输出数据库密码、master_key、api_key 明文

## 7. 测试与验证清单

- 后端改动：`pytest test/` + `flake8 src/ test/`
- 前端改动：`cd frontend && npm run check && npm run build`，并确认 `src/static/` 产物已更新
- MCP 工具改动：起服务后用 `script/mcp_call.py --tool <name> --args '{...}'` 实测；两条协议路径（`/mcp/call` 与 SSE）都要覆盖到
- 权限/安全改动：必须验证 select_only、allow_ddl、IP 白名单、sql_risk_check_enabled 四个开关各自生效

## 8. 相关文件速查

| 想了解 | 看这里 |
|---|---|
| 完整 API/部署/排障 | `README.md` |
| AI 调用 MCP 工具的行为规范 | `.ide_mcp_rules.md`（通用）、`.cursor_mcp_rules.md`（Cursor） |
| MCP 客户端调用/OSS/PDF 细节 | `docs/MCP客户端调用说明.md` |
| IDE 接入配置 | `docs/IDE智能体与MCPServer配置指南.md`、`docs/TRAE_SSE配置指南.md` |
| 权限模型设计 | `docs/基于连接的权限控制.md` |
| Docker/supervisord | `Dockerfile`、`docker/supervisord.conf`、`docker-compose.yml` |
| 发版 | `make release` / `script/release.sh`（打 v* tag 触发 CI 构建推送 ACR） |
