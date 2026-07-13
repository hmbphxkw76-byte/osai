# RedTeam_AI — Makefile
# 常用 Python 开发命令的快捷入口。
#
# Windows 上需要先装 make：
#   choco install make        (Chocolatey)
#   scoop install make        (Scoop)
#   或用 Git Bash 自带的 make

.PHONY: help install dev test lint format check clean build run wizard docs

PYTHON := python
PIP := pip
RUFF := ruff
PYTEST := pytest

# ---- 默认目标 ----
help:  ## 显示所有可用目标
	@echo "RedTeam_AI Makefile 可用目标："
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---- 环境安装 ----
install:  ## 安装项目依赖 + 可编辑模式安装本包
	$(PIP) install -r requirements.txt
	$(PIP) install -e . --no-deps

dev: install  ## 完整开发环境（依赖 + 包 + 预提交钩子）
	@echo "[dev] 开发环境就绪"

# ---- 代码质量 ----
lint:  ## 运行 Ruff 代码检查
	$(RUFF) check redteam/ tests/

format:  ## 运行 Ruff 自动格式化
	$(RUFF) format redteam/ tests/

check: lint test  ## 运行完整代码检查（lint + test）

# ---- 测试 ----
test:  ## 运行全部单元测试
	$(PYTEST) tests/ -q

test-cov:  ## 运行测试并输出覆盖率报告
	$(PYTEST) tests/ -q --cov=redteam --cov-report=term-missing

test-verbose:  ## 运行测试（详细输出）
	$(PYTEST) tests/ -v

# ---- 构建 ----
build:  ## 构建 wheel 包
	$(PYTHON) -m build --wheel

reinstall:  ## 重新安装包（代码修改后立即生效，替代手动 pip install）
	$(PYTHON) -m pip install -e . --no-deps
	@echo "✓ 重新安装完成，代码修改已生效"

# ---- 运行 ----
wizard:  ## 启动交互式攻击向导（使用已安装的 redteam 命令）
	redteam wizard

dev-wizard:  ## 开发模式：直接运行源代码（无需重新安装，修改立即生效）
	$(PYTHON) -m redteam.cli

dev-run:  ## 开发模式：直接运行源代码执行攻击（用法：make dev-run T=https://target.ai）
	$(PYTHON) -m redteam.cli run -t $(T)

dev-recon:  ## 开发模式：直接运行源代码执行侦察（用法：make dev-recon T=https://target.ai）
	$(PYTHON) -m redteam.cli recon -t $(T)

run-target:  ## 对目标执行完整攻击链（用法：make run-target T=https://target.ai）
	redteam run -t $(T)

run-recon:  ## 仅执行侦察阶段（用法：make run-recon T=https://target.ai）
	redteam recon -t $(T)

# ---- 清理 ----
watch:  ## 监控代码变更，自动重新安装包（开发模式）
	$(PYTHON) scripts/auto_reinstall.py

clean:  ## 清理构建产物与缓存（PowerShell 兼容）
	@echo "清理 .pyc / __pycache__ / build / dist / egg-info / .pytest_cache / .ruff_cache / .coverage / pytest_output.txt ..."
	@powershell -NoProfile -Command "Get-ChildItem -Recurse -Force -Directory -Name '__pycache__','.pytest_cache','.ruff_cache' 2>$$null | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Get-ChildItem -Recurse -File -Filter '*.pyc' 2>$$null | Remove-Item -Force -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Remove-Item -Recurse -Force build/,dist/,*.egg-info/ -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Remove-Item -Force .coverage,pytest_output.txt -ErrorAction SilentlyContinue"
	@rm -rf build/ dist/ *.egg-info 2>/dev/null; true
	@rm -f .coverage pytest_output.txt 2>/dev/null; true
	@echo "清理完成"

# ---- 文档 ----
docs:  ## 查看项目 README
	@cat README.md
