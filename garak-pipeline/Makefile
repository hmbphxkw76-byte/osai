# ============================================================================
# Garak-Pipeline Makefile — 自动化命令行工具集
# ============================================================================
# 三库通用规则 R-015: ruff + pytest 全量测试标准
# ============================================================================

PYTHON := python
CYAN := \033[36m
GREEN := \033[32m
RESET := \033[0m
BOLD := \033[1m

.PHONY: help install install-dev lint format typecheck test test-fast check check-full clean

help: ## 显示帮助
	@echo "$(BOLD)Garak-Pipeline 命令$(RESET)"
	@echo ""
	@echo "$(BOLD)代码质量$(RESET)"
	@echo "  $(GREEN)make lint$(RESET)              代码检查 (ruff, 全量 pipeline/scripts/tests)"
	@echo "  $(GREEN)make format$(RESET)            代码格式化 (ruff format)"
	@echo "  $(GREEN)make check$(RESET)             一键检查 (lint + test)"
	@echo "  $(GREEN)make check-full$(RESET)        全量检查 (ruff + pytest -v, 三库标准 R-015)"
	@echo ""
	@echo "$(BOLD)测试$(RESET)"
	@echo "  $(GREEN)make test$(RESET)              运行全部测试"
	@echo "  $(GREEN)make test-fast$(RESET)          快速测试 (仅上次失败的)"

# ============================================================================
# 代码质量 (三库标准 R-015)
# ============================================================================
lint: ## 代码检查 (ruff, 全量 pipeline/tests)
	@echo "$(CYAN)[LINT]$(RESET) 代码检查 (ruff)..."
	ruff check pipeline/ tests/ main.py

format: ## 代码格式化 (ruff format)
	@echo "$(CYAN)[FORMAT]$(RESET) 代码格式化 (ruff format)..."
	ruff format pipeline/ tests/ main.py
	ruff check --fix pipeline/ tests/ main.py

check: lint test ## 一键检查 (lint + test)
	@echo "$(GREEN)[OK]$(RESET) 所有检查通过"

check-full: ## 全量检查 (ruff + pytest -v, 三库标准 R-015)
	@echo "$(CYAN)[CHECK-FULL]$(RESET) 三库标准全量检查 (ruff + pytest)..."
	@echo "  [1/2] ruff check pipeline/ tests/ main.py"
	ruff check pipeline/ tests/ main.py
	@echo "  [2/2] pytest -v --tb=short"
	$(PYTHON) -m pytest tests/ -v --tb=short
	@echo "$(GREEN)[OK]$(RESET) 全量检查通过 (ruff + pytest)"

# ============================================================================
# 测试
# ============================================================================
test: ## 运行全部测试
	$(PYTHON) -m pytest -v

test-fast: ## 快速测试 (仅上次失败的)
	$(PYTHON) -m pytest -v --lf

# ============================================================================
# 安装
# ============================================================================
install: ## 安装依赖
	pip install -r requirements.txt

install-dev: ## 安装开发依赖 (含 pytest/ruff)
	pip install -r requirements.txt
	pip install pytest ruff

# ============================================================================
# 清理
# ============================================================================
clean: ## 清理临时文件
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
