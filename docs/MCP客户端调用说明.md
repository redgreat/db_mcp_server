# MCP 客户端调用说明

## 在 Cursor / Trae 里用（推荐）

**不需要**在本机执行 `script/mcp_sse_call.py` 或任何 Python 脚本。

1. 打开 IDE → Settings → MCP
2. 添加服务器（示例）：

```json
{
  "mcpServers": {
    "db-mcp-warehouse": {
      "url": "https://你的域名/mcp/sse",
      "headers": {
        "X-Access-Key": "你的访问密钥"
      }
    }
  }
}
```

3. 在对话里直接让 AI 调用工具，例如：`generate_er_diagram`、`export_db_doc`
4. 改工具、换参数都由 IDE 的 MCP 客户端自动完成，与 `mcp_sse_call.py` 无关

## 命令行 / CI / 其他工具（通用脚本）

使用 **`script/mcp_call.py`**（包装 SSE，支持任意工具名）：

```bash
# Windows PowerShell
$env:MCP_SSE_URL = "https://mcp.wongcw.cn/mcp/sse"
$env:MCP_ACCESS_KEY = "你的密钥"

# 列出连接
python script/mcp_call.py --tool list_connections

# 生成 ER PDF 并上传 OSS（参数放 json 文件）
python script/mcp_call.py --tool generate_er_diagram --args script/er_pdf_args.json
```

`er_pdf_args.json` 示例：

```json
{
  "connection_id": 1,
  "database": "whcenter",
  "format": "pdf",
  "upload_to_oss": true
}
```

### 简易 HTTP 模式（若服务端开启了 `/mcp/call`）

```bash
python script/mcp_call.py --http --base https://mcp.wongcw.cn \
  --tool list_tables --args "{\"connection_id\":1}"
```

## PDF ER 图说明

- 中文乱码/叠字：镜像须内置 **NotoSansCJKsc-Regular.otf**（`Dockerfile` 构建时下载）；勿优先用 `.ttc`（fpdf2 易错 face 索引）。部署后日志应出现 `PDF 中文字体: ...NotoSansCJKsc-Regular.otf`
- ER **图形**：需镜像安装 **mermaid-cli (`mmdc`)** + Chromium，PDF 内为 PNG 分片图，不是 Mermaid 源码堆砌
- 表特别多（如 400+）会按约 40 张表一张图分片

## 与 `mcp_sse_call.py` 的关系

- `mcp_sse_call.py`：底层 SSE 实现，一般被 `mcp_call.py` 调用
- 新工具只需改 `--tool` 和 `--args`，不必再写新脚本
