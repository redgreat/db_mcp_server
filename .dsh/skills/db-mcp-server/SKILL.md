---
name: db-mcp-server
description: 企业级数据库访问 MCP 工具集。提供安全的数据库查询、元数据探索、文档生成、ER 图、性能分析、SQL 审查等 22 个工具。支持 MySQL 和 PostgreSQL。通过 MCP 协议远程调用，无需本地数据库凭证。
whenToUse: 用户需要查询数据库、查看表结构、生成文档/ER图、分析性能、审查SQL、备份数据、对比Schema，或任何与数据库相关的操作时使用此技能。
metadata:
  author: db-mcp-server
  version: "1.0.0"
  protocol: MCP (streamable-http)
  endpoint: https://mcp.lunz.cn/mcp/message
---

# 数据库 MCP 工具使用指南

## 🎯 核心原则

1. **先查连接，再操作** — 不知道 `connection_id` 时必须先调 `mcp__dbmcp__list_connections`，禁止猜测 ID
2. **逐层探索** — 按 `list_connections` → `list_databases` → `list_tables` → `describe_table` 的顺序探索
3. **只读优先** — 查询用 `mcp__dbmcp__execute_query`，写入/DDL 用 `mcp__dbmcp__execute_sql`（需确认权限）
4. **默认数据库** — 大部分工具的 `database` 参数可选，不传则使用连接的默认数据库
5. **明确告知** — 每次操作后向用户说明 `connection_id`、`database`、工具名称；若返回 OSS 链接须给出可点击地址
6. **大表慎用** — `execute_query` 必须带 `LIMIT`；文档/ER 库表过多时优先 markdown 或 `include_columns: false`

**支持的数据库类型**：`mysql`、`postgresql`

## 🔧 可用工具列表（22 个）

所有工具名前缀为 `mcp__dbmcp__`，例如：`mcp__dbmcp__list_connections`

### 基础探索工具

| 工具 | 用途 | 必需参数 | 示例 |
|------|------|----------|------|
| `list_connections` | 列出所有可用数据库连接 | 无 | `{"search": "mysql"}` |
| `list_databases` | 列出指定连接的数据库 | `connection_id` | `{"connection_id": 1}` |
| `list_tables` | 列出指定数据库的表 | `connection_id` | `{"connection_id": 1, "database": "mydb"}` |
| `list_views` | 列出视图 | `connection_id` | `{"connection_id": 1}` |
| `list_procedures` | 列出存储过程 | `connection_id` | `{"connection_id": 1}` |
| `describe_table` | 查看表结构（字段、类型、键） | `connection_id`, `table` | `{"connection_id": 1, "table": "users"}` |

### 查询与执行工具

| 工具 | 用途 | 必需参数 | 权限 |
|------|------|----------|------|
| `execute_query` | 执行 SELECT 查询（只读） | `connection_id`, `sql` | 读 |
| `execute_sql` | 执行任意 SQL（DDL/写入） | `connection_id`, `sql` | 写/DDL |

**⚠️ 重要提示：**
- `execute_query` 只能执行 SELECT/SHOW/DESCRIBE/EXPLAIN 等只读语句
- `execute_sql` 可以执行 INSERT/UPDATE/DELETE/CREATE/DROP/ALTER 等语句，需要相应权限
- 所有 SQL 查询必须带 LIMIT，避免返回大量数据

### 文档与图表工具

| 工具 | 用途 | 必需参数 | 特色功能 |
|------|------|----------|----------|
| `export_db_doc` | 导出数据字典文档 | `connection_id` | 支持 markdown/pdf，可上传 OSS |
| `generate_er_diagram` | 生成 ER 图 | `connection_id` | 业务域分析 + Mermaid 图，支持 pdf/markdown |
| `generate_data_flow` | 生成数据流图 | `connection_id` | 分析表间数据流向 |
| `export_ddl` | 导出完整 DDL | `connection_id` | 包含表、视图、存储过程、触发器 |

**📊 输出格式选项：**
- `format: "markdown"` - Markdown 文本（适合预览和编辑）
- `format: "pdf"` - PDF 文件（需要服务器安装中文字体）
- `upload_to_oss: true` - 上传到对象存储并返回下载链接

### 分析与优化工具

| 工具 | 用途 | 必需参数 | AI 增强 |
|------|------|----------|----------|
| `analyze_performance` | 数据库性能分析 | `connection_id` | ✅ 连接数、慢查询、锁等待、表统计 |
| `analyze_sql` | SQL 语句审查 | `connection_id`, `sql` | ✅ EXPLAIN 分析 + 改写建议 |
| `analyze_db_config` | 配置参数调优 | `connection_id` | ✅ Buffer Pool、连接数、临时表分析 |

**💡 AI 增强说明：** 需要在服务端 Web 管理界面启用大模型配置。启用后返回 `ai_assessment`、`ai_analysis` 等智能分析结果。

### 高级工具

| 工具 | 用途 | 必需参数 | 说明 |
|------|------|----------|------|
| `suggest_columns` | 字段添加建议 | `connection_id`, `table` | 生成 ALTER TABLE DDL + 影响分析 |
| `compare_schemas` | Schema 对比 | `source_connection_id`, `target_connection_id` | 生成同步 DDL |
| `generate_mock_data` | 生成测试数据 | `connection_id`, `table`, `count` | 自动处理外键和约束 |
| `backup_table` | 表级备份 | `connection_id`, `table` | CREATE TABLE AS SELECT 方式 |
| `render_report_oss` | 生成报表上传 OSS | `connection_id`, `source`, `fields` | 支持 xlsx/csv |
| `generate_db_rule` | 生成 RULE.md 规则文档 | `connection_id` | 保存到项目或管理数据库 |

## 📝 使用示例

### 示例 1：探索数据库结构

```
用户：帮我看看有哪些数据库连接

AI：让我先列出可用的数据库连接。
[调用 mcp__dbmcp__list_connections]
根据结果，您有以下连接：
- ID: 1, 名称: warehouse-mysql, 类型: mysql, 数据库: whcenter
- ID: 2, 名称: analytics-pg, 类型: postgresql, 数据库: analytics

用户：看看 warehouse 的表结构

AI：好的，让我列出 warehouse 数据库的表。
[调用 mcp__dbmcp__list_tables {"connection_id": 1}]
[调用 mcp__dbmcp__describe_table {"connection_id": 1, "table": "orders"}]
```

### 示例 2：执行查询

```
用户：查询最近10个订单

AI：好的，我将执行查询（已添加 LIMIT 限制）。
[调用 mcp__dbmcp__execute_query {
  "connection_id": 1,
  "sql": "SELECT order_id, customer_name, total_amount, created_at FROM orders ORDER BY created_at DESC LIMIT 10"
}]
查询完成，共返回 10 条记录...
```

### 示例 3：生成文档

```
用户：生成这个数据库的 ER 图

AI：好的，我将为您生成 ER 图（使用 markdown 格式以便预览）。
[调用 mcp__dbmcp__generate_er_diagram {
  "connection_id": 1,
  "format": "markdown",
  "include_columns": true
}]
ER 图已生成！包含以下业务域：
- 订单域：orders, order_items, customers
- 商品域：products, categories
- ...
```

## ⚠️ 注意事项

### 权限与安全
- 访问密钥（X-Access-Key）已配置在系统中，无需用户提供
- 不同密钥可能有不同的连接权限和操作权限（读/写/DDL）
- 如果遇到 401/403 错误，提示用户检查密钥权限
- DDL 操作（CREATE/DROP/ALTER）需要特殊权限，执行前务必确认

### 性能建议
- **必须使用 LIMIT**：所有 SELECT 查询都应限制返回行数
- **避免 SELECT ***：明确指定需要的字段
- **大表操作谨慎**：对百万级表的操作要提醒用户可能耗时
- **文档生成优化**：表过多时使用 `include_columns: false` 或分批生成

### 错误处理
- **401 未认证**：检查访问密钥是否有效
- **403 无权限**：该密钥未授权目标连接或操作
- **422 参数错误**：检查参数类型和必填项
- **连接失败**：检查网络、数据库服务状态、连接配置

## 🔄 与其他 IDE 的区别

本 Skill 为 DeepSeek Harness 专用。工具名称格式为 `mcp__dbmcp__<工具名>`。

在 Cursor/Trae 中使用时，工具名称不带前缀，直接使用原始名称（如 `list_connections`），配置文件见 `.ide_mcp_rules.md`。

## 📚 相关资源

- 完整 API 文档：见项目 README.md 和 docs/ 目录
- 配置文件：DSH MCP 客户端配置在 `~/.dsh/profiles/web/cordis.patch.yml`
- 服务端管理：通过 Web 管理界面管理连接、密钥、权限、IP 白名单
