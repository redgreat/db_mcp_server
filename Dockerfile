FROM python:3.11-slim

# 安装supervisor
RUN apt-get update && \
    apt-get install -y supervisor && \
    rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN useradd -m -u 1000 dbmcp

WORKDIR /app

# 安装Python依赖
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 复制项目文件
COPY . /app

# 创建必要的目录并设置权限
RUN mkdir -p /var/log/db_mcp_server /data/admin && \
    chown -R dbmcp:dbmcp /app /var/log/db_mcp_server /data

# 切换到非root用户
USER dbmcp

# 环境变量
ENV HOST=0.0.0.0
ENV PORT=3000
ENV ADMIN_DB_PATH=/data/admin/admin.db
ENV LOG_DIR=/var/log/db_mcp_server

EXPOSE 3000

# 使用supervisord启动
CMD ["supervisord", "-c", "/app/docker/supervisord.conf"]


