#!/bin/bash

# 进入指定的绝对路径目录
cd /root/dbmcp || { echo "进入目录失败，中止执行"; exit 1; }

echo "=========================================="
echo "    开始重新部署 dbmcp 容器环境"
echo "=========================================="

echo "➤ 1. 停止并移除旧容器: dbmcp..."
docker compose stop dbmcp
docker compose rm -f dbmcp

echo "➤ 2. 删除本地所有的 dbmcp 镜像记录..."
# 注意：这会查找带有 dbmcp 名称的镜像，并按 ID 强制删除
docker images | grep 'dbmcp' | awk '{print $3}' | xargs -r docker rmi -f

echo "➤ 3. 清理所有旧的日志数据..."
# 删除根目录下 ./log/ 内的所有文件及文件夹
rm -rf ./log/*
echo "日志清理完成。"

echo "➤ 4. 重新拉取最新镜像并后台启动..."
docker compose pull dbmcp
docker compose up -d dbmcp

echo "等待 2 秒检查容器状态..."
sleep 2

echo "➤ 5. 当前 dbmcp 容器运行状态:"
docker ps -a --filter "name=dbmcp"

echo "=========================================="
echo "    容器已更新并重启完成！"
echo "    重置密码命令："
echo "docker exec -e ADMIN_NEW_PASSWORD='这里填新密码' db_mcp_server python script/reset_admin_password.py --username admin"
echo "=========================================="
