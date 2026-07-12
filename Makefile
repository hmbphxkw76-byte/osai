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

# ---- 运行 ----
wizard:  ## 启动交互式攻击向导
	redteam wizard

run-target:  ## 对目标执行完整攻击链（用法：make run-target T=https://target.ai）
	redteam run -t $(T)

run-recon:  ## 仅执行侦察阶段（用法：make run-recon T=https://target.ai）
	redteam recon -t $(T)

# ---- 清理 ----
clean:  ## 清理构建产物与缓存（PowerShell 兼容）
	@echo "清理 .pyc / __pycache__ / build / dist / egg-info / .pytest_cache / .ruff_cache ..."
	@powershell -NoProfile -Command "Get-ChildItem -Recurse -Force -Directory -Name '__pycache__','.pytest_cache','.ruff_cache' 2>$$null | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Get-ChildItem -Recurse -File -Filter '*.pyc' 2>$$null | Remove-Item -Force -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Remove-Item -Recurse -Force build/,dist/,*.egg-info/ -ErrorAction SilentlyContinue"
	@rm -rf build/ dist/ *.egg-info 2>/dev/null; true
	@echo "清理完成"

# ---- 文档 ----
docs:  ## 查看项目 README
	@cat README.md
