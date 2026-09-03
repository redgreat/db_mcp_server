#!/bin/bash

# ============================================================
# Docker Tag 发布脚本 (Linux 版本)
# 功能：自动计算版本号、创建 Git 标签并推送到远程
# 用法：./scripts/release.sh [版本标签]
# 示例：./scripts/release.sh v0.0.3
# ============================================================

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() { echo -e "${BLUE}➤ $1${NC}"; }
log_success() { echo -e "${GREEN}✔ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
log_error() { echo -e "${RED}✖ $1${NC}" >&2; }

# 显示帮助信息
show_usage() {
    cat << 'EOF'
用法: ./scripts/release.sh [版本标签]
示例: ./scripts/release.sh v0.0.3

参数:
  版本标签    Git 标签版本 (留空则自动计算)
  -h, --help  显示帮助信息
EOF
}

# 检查 git 是否安装
ensure_git() {
    if ! command -v git &> /dev/null; then
        log_error "未找到 git 命令，请先安装 Git"
        exit 1
    fi
}

# 获取最新标签（按语义版本排序）
get_latest_tag() {
    local latest
    latest=$(git tag --list 'v*' --sort=-version:refname 2>/dev/null | head -n1 || true)
    if [[ -n "$latest" ]]; then
        echo "$latest" | tr -d '[:space:]'
    else
        echo ""
    fi
}

# 将版本号尾数 +1
# 优先识别 vMAJOR.MINOR.PATCH，否则对末尾数字增量
bump_version() {
    local tag="$1"

    # 如果为空，返回默认版本
    if [[ -z "$tag" ]]; then
        echo "v0.0.1"
        return
    fi

    # 尝试匹配语义版本 vMAJOR.MINOR.PATCH
    if [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"
        local patch="${BASH_REMATCH[3]}"
        local new_patch=$((patch + 1))
        echo "v${major}.${minor}.${new_patch}"
        return
    fi

    # 尝试匹配通用格式：前缀+数字
    if [[ "$tag" =~ ^(.*[^0-9])([0-9]+)$ ]]; then
        local prefix="${BASH_REMATCH[1]}"
        local num="${BASH_REMATCH[2]}"
        local new_num=$((num + 1))
        echo "${prefix}${new_num}"
        return
    fi

    # 都不匹配，追加 -1
    echo "${tag}-1"
}

# 显示 Banner
show_banner() {
    echo -e "${Blue}==============================================${NC}"
    echo -e "${Blue}Docker Tag 发布脚本 (Linux)${NC}"
    echo -e "${Blue}版本: ${VERSION}${NC}"
    echo -e "${Blue}==============================================${NC}"
}

# 主逻辑
main() {
    local VERSION=""

    # 解析参数
    if [[ $# -gt 0 ]]; then
        case "$1" in
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                VERSION="$1"
                ;;
        esac
    fi

    # 检查 git
    ensure_git

    # 如果未提供版本号，则自动计算
    if [[ -z "$VERSION" ]]; then
        local latest
        latest=$(get_latest_tag)

        if [[ -n "$latest" ]]; then
            log_info "检测到当前最新标签: ${latest}"
            VERSION=$(bump_version "$latest")
            log_info "自动计算版本: ${VERSION}"
        else
            log_warn "未发现任何标签，使用默认 v0.0.1"
            VERSION="v0.0.1"
        fi
    fi

    # 显示 Banner
    echo ""
    echo -e "${BLUE}==============================================${NC}"
    echo -e "${BLUE}Docker Tag 发布脚本 (Linux)${NC}"
    echo -e "${BLUE}版本: ${VERSION}${NC}"
    echo -e "${BLUE}==============================================${NC}"
    echo ""

    # 创建 Git 标签
    log_info "创建 Git 标签 ${VERSION}"

    if git tag -l | grep -q "^${VERSION}$"; then
        log_warn "标签 ${VERSION} 已存在，跳过创建"
    else
        local branch
        branch=$(git branch --show-current 2>/dev/null || echo "detached")
        branch=$(echo "$branch" | tr -d '[:space:]')

        git tag "${VERSION}"
        log_success "标签 ${VERSION} 创建成功（分支 ${branch}）"
    fi

    # 推送标签到远程
    log_info "推送标签到远程 origin"
    if git push origin "${VERSION}"; then
        log_success "标签 ${VERSION} 推送完成"
    else
        log_error "推送标签失败"
        exit 1
    fi

    echo ""
    log_success "发布流程完成！GitHub Actions 将自动构建并部署。"
    echo ""
}

# 执行主函数
main "$@"
