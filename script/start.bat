@echo off
REM DB MCP Server 启动脚本
REM 用途: 启动 Docker Compose 服务

echo ========================================
echo   DB MCP Server 启动脚本
echo ========================================
echo.

REM 检查 Docker 是否运行
echo [1/4] 检查 Docker 服务...
docker version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] Docker 服务未运行或未安装
    echo 请先启动 Docker Desktop
    pause
    exit /b 1
)
echo [成功] Docker 服务正常运行
echo.

REM 检查 docker-compose.yml 是否存在
echo [2/4] 检查配置文件...
if not exist "docker-compose.yml" (
    echo [错误] 找不到 docker-compose.yml 文件
    pause
    exit /b 1
)
echo [成功] docker-compose.yml 存在

if not exist "config\config.yml" (
    echo [错误] 找不到 config\config.yml 文件
    pause
    exit /b 1
)
echo [成功] config\config.yml 存在
echo.

REM 停止并移除旧容器（如果存在）
echo [3/4] 清理旧容器...
docker-compose down >nul 2>&1
echo [成功] 旧容器已清理
echo.

REM 启动服务
echo [4/4] 启动 Docker Compose 服务...
echo.
docker-compose up -d --build

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo   服务启动成功!
    echo ========================================
    echo.
    echo 服务信息:
    echo   - 管理后台: http://localhost:3000/admin
    echo   - MCP 接口: http://localhost:3000/mcp
    echo.
    echo 查看日志:
    echo   docker-compose logs -f
    echo.
    echo 停止服务:
    echo   docker-compose down
    echo.
    echo 容器状态:
    docker-compose ps
) else (
    echo.
    echo ========================================
    echo   服务启动失败!
    echo ========================================
    echo.
    echo 请检查日志:
    echo   docker-compose logs
    pause
    exit /b 1
)

pause
