# DB MCP Server 启动脚本
# 用途: 启动 Docker Compose 服务

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DB MCP Server 启动脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 检查 Docker 是否运行
Write-Host "[1/4] 检查 Docker 服务..." -ForegroundColor Yellow
try {
    $dockerVersion = docker version --format '{{.Server.Version}}' 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker 未运行"
    }
    Write-Host "✓ Docker 服务正常运行 (版本: $dockerVersion)" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker 服务未运行或未安装" -ForegroundColor Red
    Write-Host "  请先启动 Docker Desktop" -ForegroundColor Red
    exit 1
}

# 检查 docker-compose.yml 是否存在
Write-Host ""
Write-Host "[2/4] 检查配置文件..." -ForegroundColor Yellow
$projectRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $projectRoot "docker-compose.yml"
$configFile = Join-Path $projectRoot "config\config.yml"

if (-not (Test-Path $composeFile)) {
    Write-Host "✗ 找不到 docker-compose.yml 文件" -ForegroundColor Red
    exit 1
}
Write-Host "✓ docker-compose.yml 存在" -ForegroundColor Green

if (-not (Test-Path $configFile)) {
    Write-Host "✗ 找不到 config/config.yml 文件" -ForegroundColor Red
    exit 1
}
Write-Host "✓ config/config.yml 存在" -ForegroundColor Green

# 停止并移除旧容器（如果存在）
Write-Host ""
Write-Host "[3/4] 清理旧容器..." -ForegroundColor Yellow
Set-Location $projectRoot
docker-compose down 2>$null
Write-Host "✓ 旧容器已清理" -ForegroundColor Green

# 启动服务
Write-Host ""
Write-Host "[4/4] 启动 Docker Compose 服务..." -ForegroundColor Yellow
Write-Host ""
docker-compose up -d --build

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  服务启动成功!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "服务信息:" -ForegroundColor Cyan
    Write-Host "  - 管理后台: http://localhost:3000/admin" -ForegroundColor White
    Write-Host "  - MCP 接口: http://localhost:3000/mcp" -ForegroundColor White
    Write-Host ""
    Write-Host "查看日志:" -ForegroundColor Cyan
    Write-Host "  docker-compose logs -f" -ForegroundColor White
    Write-Host ""
    Write-Host "停止服务:" -ForegroundColor Cyan
    Write-Host "  docker-compose down" -ForegroundColor White
    Write-Host ""
    
    # 显示容器状态
    Write-Host "容器状态:" -ForegroundColor Cyan
    docker-compose ps
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  服务启动失败!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "请检查日志:" -ForegroundColor Yellow
    Write-Host "  docker-compose logs" -ForegroundColor White
    exit 1
}
