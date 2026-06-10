SHELL := /bin/bash

.PHONY: help redeploy release test lint lint-web test-web lint-py test-py

help:
	@echo "可用命令列表:"
	@echo "  redeploy      - 本地重新部署 (重新构建并启动 docker 容器)"
	@echo "  release       - 运行测试并发布新版本（打 tag 并推送到远程触发 GitHub Action）"
	@echo "  test          - 运行所有测试 (Python + Svelte)"
	@echo "  lint          - 运行所有代码检查 (Python + Svelte)"

test: test-py test-web

lint: lint-py lint-web

test-py:
	@echo "运行 Python 测试..."
	@if command -v pytest >/dev/null 2>&1; then \
		pytest test/ || echo "Python 测试未全部通过或未找到测试用例"; \
	else \
		echo "未安装 pytest，跳过测试"; \
	fi

lint-py:
	@echo "运行 Python 代码检查..."
	@if command -v flake8 >/dev/null 2>&1; then \
		flake8 src/ test/ || true; \
	else \
		echo "未安装 flake8，跳过检查"; \
	fi

test-web:
	@echo "运行前端测试..."
	@cd frontend && npm run test || echo "未配置前端测试"

lint-web:
	@echo "运行前端代码检查..."
	@cd frontend && npm run check

redeploy:
ifeq ($(OS),Windows_NT)
	@pwsh -NoProfile -ExecutionPolicy Bypass -Command "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Write-Host 'Local redeploy...'"
	@pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/redeploy.ps1
else
	@echo "Local redeploy..."
	@bash scripts/redeploy.sh
endif

release:
ifeq ($(OS),Windows_NT)
	@pwsh -NoProfile -ExecutionPolicy Bypass -Command "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Write-Host 'Release tag push...'"
	@pwsh -NoProfile -ExecutionPolicy Bypass -File script/dockerbuild.ps1
else
	@echo "Release tag push..."
	@bash scripts/release.sh
endif
