# syntax=docker/dockerfile:1
# 阶段一：前端构建
FROM node:22-alpine AS frontend-builder

WORKDIR /app/frontend

# 国内 CI/构建机若遇 npm 官方源 ECONNRESET，可传: --build-arg NPM_REGISTRY=https://registry.npmmirror.com
ARG NPM_REGISTRY=
RUN npm config set fetch-retries 10 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000 && \
    npm config set fetch-timeout 600000 && \
    if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY"; fi

COPY frontend/package*.json ./
# 缓存 + 多次重试，缓解跨区/不稳定网络下 npm ci 中断
RUN --mount=type=cache,target=/root/.npm \
    sh -ec 'for n in 1 2 3 4 5; do npm ci && exit 0; echo "npm ci failed, retry $n in 15s..."; sleep 15; done; exit 1'

COPY frontend/ ./
RUN npm run build

# 阶段二：Python 运行时
FROM python:3.13-slim

# supervisor + 中文字体 + Chromium（Mermaid 渲染 ER 图）
RUN apt-get update && \
    apt-get install -y supervisor tini fonts-noto-cjk fonts-wqy-microhei fontconfig chromium && \
    rm -rf /var/lib/apt/lists/*

# Mermaid CLI：将 erDiagram 渲染为 PNG 嵌入 PDF
RUN apt-get update && \
    apt-get install -y nodejs npm && \
    npm install -g @mermaid-js/mermaid-cli@11 && \
    rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN useradd -m -u 1000 dbmcp

WORKDIR /app

# 安装Python依赖
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 复制项目文件
COPY . /app

# 复制前端构建产物（覆盖 src/static）
COPY --from=frontend-builder /app/src/static /app/src/static

# 中文字体：从 apt 复制到项目目录（不依赖外网下载，避免 GitHub 404）
RUN mkdir -p /app/src/static/fonts && \
    set -e; \
    DEST=""; \
    for name in NotoSansCJK-Regular.ttc wqy-microhei.ttc; do \
      SRC=$(find /usr/share/fonts -type f -iname "$name" 2>/dev/null | head -1); \
      if [ -n "$SRC" ]; then \
        cp "$SRC" "/app/src/static/fonts/$name"; \
        DEST="/app/src/static/fonts/$name"; \
        break; \
      fi; \
    done; \
    if [ -z "$DEST" ] || [ ! -s "$DEST" ]; then \
      echo "ERROR: 未找到 fonts-noto-cjk / fonts-wqy-microhei 字体" >&2; \
      find /usr/share/fonts -iname '*noto*' -o -iname '*wqy*' 2>/dev/null | head -20 >&2; \
      exit 1; \
    fi; \
    ls -la /app/src/static/fonts/

# 创建必要的目录并设置权限
RUN mkdir -p /var/log/db_mcp_server /data/admin && \
    chown -R dbmcp:dbmcp /app /var/log/db_mcp_server /data

# 切换到非root用户
USER dbmcp

# 环境变量
ENV TZ=Asia/Shanghai
ENV HOST=0.0.0.0
ENV PORT=3000
ENV LOG_DIR=/var/log/db_mcp_server

EXPOSE 3000

# tini 作 PID 1 回收 mmdc/Chromium 子进程；supervisord 只管理 web/init_db
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["supervisord", "-c", "/app/docker/supervisord.conf"]
