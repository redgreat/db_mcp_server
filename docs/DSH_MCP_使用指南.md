# DeepSeek Harness (DSH) 中使用 DB MCP Server 指南

## 📌 快速开始：在其他项目中启用 MCP 工具

### 方法 1：在系统提示词/Instructions 中添加（推荐）

在你的项目 Instructions 或 System Prompt 中添加以下内容：

```
## 可用工具：数据库 MCP 服务

你可以通过 MCP 协议访问远程数据库服务，所有工具名前缀为 `mcp__dbmcp__`。

### 核心工具（最常用）
- `mcp__dbmcp__list_connections` - 列出数据库连接（必先调用此工具获取 connection_id）
- `mcp__dbmcp__list_databases` - 列出数据库
- `mcp__dbmcp__list_tables` - 列出表
- `mcp__dbmcp__describe_table` - 查看表结构
- `mcp__dbmcp__execute_query` - 执行 SELECT 查询（只读，必须带 LIMIT）
- `mcp__dbmcp__execute_sql` - 执行 SQL（写入/DDL，需权限）

### 文档与分析工具
- `mcp__dbmcp__export_db_doc` - 导出数据字典（支持 markdown/pdf）
- `mcp__dbmcp__generate_er_diagram` - 生成 ER 图
- `mcp__dbmcp__analyze_performance` - 性能分析
- `mcp__dbmcp__analyze_sql` - SQL 审查

### 使用规则
1. **必须先调用 `list_connections` 获取 connection_id**，禁止猜测 ID
2. 按顺序探索：connections → databases → tables → describe_table
3. 只读查询用 `execute_query`，写入用 `execute_sql`
4. 所有 SELECT 必须带 LIMIT
5. 操作后告知用户 connection_id 和 database 名称

当用户需要查询数据库、查看表结构、生成文档、分析性能时，优先使用这些工具。
```

### 方法 2：复制 Skill 到其他项目

如果你想在其他 DSH 项目中也使用这个 Skill：

```bash
# 在目标项目根目录执行
mkdir -p .dsh/skills/db-mcp-server
# 复制 SKILL.md 文件到该目录
```

或者创建符号链接（推荐）：
```bash
# 在目标项目根目录
ln -s /vol1/1000/Code/db_mcp_server/.dsh/skills/db-mcp-server .dsh/skills/db-mcp-server
```

### 方法 3：全局配置（所有项目可用）

将 Skill 放到用户级别的 DSH skills 目录：

```bash
mkdir -p ~/.dsh/skills/db-mcp-server
cp /vol1/1000/Code/db_mcp_server/.dsh/skills/db-mcp-server/SKILL.md ~/.dsh/skills/db-mcp-server/
```

这样所有项目都能自动加载这个 Skill。

---

## 🔧 配置说明

### 当前 MCP 配置位置
`~/.dsh/profiles/web/cordis.patch.yml`

```yaml
- id: mcp-db-server
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: dbmcp
    transport: streamable-http
    url: https://mcp.lunz.cn/mcp/message
    headers:
      X-Access-Key: Hg7g2vbLQybZ5Eh42rtwB7WErC2zwJrY
```

### 工具命名规则
- MCP 工具在 DSH 中的名称格式：`mcp__<serverName>__<原始工具名>`
- 例如：`list_connections` → `mcp__dbmcp__list_connections`
- 这个命名规则确保不会与其他工具冲突

---

## 🎯 常见场景提示词示例

### 场景 1：让 AI 帮你查数据

```
我需要查询数据库中的订单信息。请先列出可用的连接，
然后查询最近的10条订单记录。
```

### 场景 2：让 AI 生成文档

```
请帮我生成当前数据库的 ER 图和数据字典文档，
使用 markdown 格式。
```

### 场景 3：让 AI 分析性能

```
分析一下数据库的性能状况，看看有没有慢查询或
需要优化的地方。
```

### 场景 4：让 AI 审查 SQL

```
帮我审查这条 SQL 是否有性能问题：
SELECT * FROM orders WHERE status = 'pending'
```

---

## ❓ 故障排查

### 问题：AI 说找不到工具 `mcp__dbmcp__*`

**原因：**
1. DSH 服务未重启，MCP 客户端未加载
2. 项目中没有配置相关 Skill 或提示词
3. MCP 服务连接失败

**解决方案：**
1. 重启 DSH Web 服务（`pnpm run dev:web`）
2. 在项目 Instructions 中添加方法 1 的提示词
3. 复制 Skill 到项目（方法 2 或 3）
4. 检查网络连接和 MCP 服务状态

### 问题：调用工具返回 401/403 错误

**原因：** 访问密钥权限不足或过期

**解决方案：**
- 联系管理员检查密钥权限
- 确认密钥已授权目标数据库连接
- 检查 IP 白名单设置

### 问题：工具调用超时

**原因：** 网络延迟或查询数据量过大

**解决方案：**
- 确保 SQL 带 LIMIT
- 大表操作时分批处理
- 检查网络连接稳定性

---

## 📚 相关文件

- **Skill 定义**: `.dsh/skills/db-mcp-server/SKILL.md`
- **IDE 规则**: `.ide_mcp_rules.md`（给 Cursor/Trae 用）
- **MCP 配置**: `~/.dsh/profiles/web/cordis.patch.yml`
- **完整文档**: `README.md`, `docs/MCP客户端调用说明.md`

---

## 💡 最佳实践

1. **总是从 `list_connections` 开始** - 不要硬编码 connection_id
2. **明确告诉 AI 使用 MCP 工具** - 在提示词中提及 `mcp__dbmcp__` 前缀
3. **提供上下文** - 告诉 AI 你想操作哪个数据库/表
4. **分步骤请求** - 复杂任务拆分成多个简单步骤
5. **确认权限** - 写入操作前让 AI 确认是否有权限

---

**最后更新**: 2025-09-01
**适用版本**: DSH + @deepseek-ai/dsh-mcp-client
