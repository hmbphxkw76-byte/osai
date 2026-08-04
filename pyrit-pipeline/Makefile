# ============================================================================
# PyRIT-Pipeline Makefile — 自动化命令行工具集
# ============================================================================
# 用法: make <target>
# 查看: make help
# ============================================================================

# ── 项目元信息 ──
PROJECT_NAME := pyrit-pipeline
VERSION := 7.1.0
PYTHON := python

# ── 包管理器检测 (uv 优先, pip 兜底) ──
UV := $(shell command -v uv 2>/dev/null)
PIP_INSTALL := pip install
ifeq ($(UV),)
	INSTALL_CMD := $(PIP_INSTALL)
	SYNC_CMD := $(PIP_INSTALL) -e ".[dev]"
else
	INSTALL_CMD := uv pip install
	SYNC_CMD := uv sync
endif

# ── R-012: UTF-8 编码强制设置 ──
export PYTHONIOENCODING := utf-8

# ── 颜色定义 (终端美化) ──
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
BOLD := \033[1m
RESET := \033[0m

# ============================================================================
# 帮助
# ============================================================================
.PHONY: help
help: ## 显示所有可用命令
	@echo ""
	@echo "$(BOLD)$(PROJECT_NAME) v$(VERSION)$(RESET) — ASR 驱动的端到端 AI Red Team 流水线"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  环境安装$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make install$(RESET)           安装核心依赖 (uv sync)"
	@echo "  $(GREEN)make install-dev$(RESET)       安装开发依赖 (含 pytest/ruff/mypy/pre-commit)"
	@echo "  $(GREEN)make install-all$(RESET)       安装全量依赖 (含 web-redteam/gcg/fuzzer/reports)"
	@echo "  $(GREEN)make install-web$(RESET)        安装 Web Red Team 依赖 (playwright)"
	@echo "  $(GREEN)make install-gcg$(RESET)        安装 GCG 对抗后缀依赖 (torch)"
	@echo "  $(GREEN)make install-fuzzer$(RESET)     安装 Fuzzer MCTS 变异依赖"
	@echo "  $(GREEN)make install-reports$(RESET)    安装 HTML/PDF 报告依赖 (weasyprint)"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  环境配置$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
@echo "  $(GREEN)make env-setup$(RESET)         从 .env.example 创建 .env"
@echo "  $(GREEN)make env-check$(RESET)         验证环境 (.env / config/.pyrit_conf / PyRIT)"
	@echo "  $(GREEN)make pre-commit$(RESET)        安装 pre-commit git hooks"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  流水线运行$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make run$(RESET)               运行流水线 (默认配置)"
	@echo "  $(GREEN)make run-small$(RESET)         快速运行 (max-dataset-size=10)"
	@echo "  $(GREEN)make run-html$(RESET)           运行并生成 HTML 报告"
	@echo "  $(GREEN)make run-exhaustive$(RESET)     全技术评估模式"
	@echo "  $(GREEN)make run-target-url$(RESET)     攻击 LLM Web URL (--target-url)"
	@echo "  $(GREEN)make run-mcp$(RESET)            启用 MCP 协议级攻击"
	@echo "  $(GREEN)make run-recon$(RESET)          从 JSON 加载侦察结果"
	@echo "  $(GREEN)make run-web$(RESET)           运行 Web Red Team"
	@echo "  $(GREEN)make run-custom ARGS=\"...\"$(RESET)  自定义参数运行"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  测试$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make test$(RESET)              运行全部测试"
	@echo "  $(GREEN)make test-pipeline$(RESET)     运行 pipeline 测试"
	@echo "  $(GREEN)make test-web$(RESET)          运行 web_redteam 测试"
	@echo "  $(GREEN)make test-cov$(RESET)          运行测试并生成覆盖率报告"
	@echo "  $(GREEN)make test-fast$(RESET)          快速测试 (仅上次失败的)"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  代码质量$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make lint$(RESET)              代码检查 (ruff, 全量 pipeline/scripts/tests)"
	@echo "  $(GREEN)make format$(RESET)            代码格式化 (ruff format)"
	@echo "  $(GREEN)make typecheck$(RESET)         类型检查 (mypy)"
	@echo "  $(GREEN)make check$(RESET)             一键检查 (lint + test)"
	@echo "  $(GREEN)make check-full$(RESET)        全量检查 (ruff + pytest -v, 三库标准 R-015)"
	@echo "  $(GREEN)make precommit-run$(RESET)     运行 pre-commit (所有文件)"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  数据管理$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make download-datasets$(RESET)  下载远程数据集 (核心)"
	@echo "  $(GREEN)make download-all$(RESET)       下载全部远程数据集"
	@echo "  $(GREEN)make download-list$(RESET)      列出可用数据集"
	@echo "  $(GREEN)make download-check$(RESET)     检查本地缓存状态"
@echo "  $(GREEN)make curate-seeds$(RESET)        精简种子集 (去重+均衡+聚类+模型感知)"
@echo "  $(GREEN)make curate-model$(RESET)         模型感知精简 (需 MODEL=变量)"
@echo "  $(GREEN)make script-benchmark_curate$(RESET)  种子精简性能基准 (10K 合成种子)"
	@echo "  $(GREEN)make sync-asr$(RESET)           同步 ASR 先验数据 (JailbreakBench)"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  清理$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make clean$(RESET)             清理 Python 临时文件 (__pycache__/.pyc)"
	@echo "  $(GREEN)make clean-output$(RESET)      清理旧报告 (保留最近 7 天)"
	@echo "  $(GREEN)make clean-all$(RESET)         清理全部临时文件和旧报告"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  Docker$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make docker-build$(RESET)      构建 Docker 镜像"
	@echo "  $(GREEN)make docker-run$(RESET)        运行 Docker 容器"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  文档 & 基准$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make docs$(RESET)              构建 Sphinx 文档"
	@echo "  $(GREEN)make docs-clean$(RESET)         清理文档构建缓存"
	@echo "  $(GREEN)make benchmark$(RESET)          运行性能基准测试"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  验证$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make verify-integration$(RESET)  验证模块集成"
	@echo "  $(GREEN)make verify-all$(RESET)         完整验证 (env + integration + test)"
	@echo ""
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "$(BOLD)  脚本自动发现 (无需注册)$(RESET)"
	@echo "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)"
	@echo "  $(GREEN)make scripts-list$(RESET)        自动列出 scripts/ 下所有脚本"
	@echo "  $(GREEN)make scripts-check$(RESET)       检测未在 Makefile 注册的脚本"
	@echo "  $(GREEN)make script-<name>$(RESET)       自动运行 scripts/<name>.py"
	@echo "  $(GREEN)make script-<name> ARGS=\"...\"$(RESET)  带参数运行脚本"
	@echo ""

# ============================================================================
# 环境安装
# ============================================================================
.PHONY: install install-dev install-all install-web install-gcg install-fuzzer install-reports
install: ## 安装核心依赖
	@echo "$(CYAN)[INSTALL]$(RESET) 安装核心依赖..."
	$(SYNC_CMD)

install-dev: ## 安装开发依赖
	@echo "$(CYAN)[INSTALL]$(RESET) 安装开发依赖..."
ifeq ($(UV),)
	$(PIP_INSTALL) -e ".[dev]"
else
	uv sync --extra dev
endif

install-all: ## 安装全量依赖
	@echo "$(CYAN)[INSTALL]$(RESET) 安装全量依赖..."
ifeq ($(UV),)
	$(PIP_INSTALL) -e ".[all,dev]"
else
	uv sync --extra all --extra dev
endif

install-web: ## 安装 Web Red Team 依赖
	@echo "$(CYAN)[INSTALL]$(RESET) 安装 Web Red Team 依赖..."
ifeq ($(UV),)
	$(PIP_INSTALL) -e ".[web-redteam]"
else
	uv sync --extra web-redteam
endif

install-gcg: ## 安装 GCG 依赖
	@echo "$(CYAN)[INSTALL]$(RESET) 安装 GCG 对抗后缀依赖..."
ifeq ($(UV),)
	$(PIP_INSTALL) -e ".[gcg]"
else
	uv sync --extra gcg
endif

install-fuzzer: ## 安装 Fuzzer 依赖
	@echo "$(CYAN)[INSTALL]$(RESET) 安装 Fuzzer MCTS 变异依赖..."
ifeq ($(UV),)
	$(PIP_INSTALL) -e ".[fuzzer]"
else
	uv sync --extra fuzzer
endif

install-reports: ## 安装报告依赖
	@echo "$(CYAN)[INSTALL]$(RESET) 安装 HTML/PDF 报告依赖..."
ifeq ($(UV),)
	$(PIP_INSTALL) -e ".[reports]"
else
	uv sync --extra reports
endif

# ============================================================================
# 环境配置
# ============================================================================
.PHONY: env-setup env-check pre-commit
env-setup: ## 从 .env.example 创建 .env
	@echo "$(CYAN)[ENV]$(RESET) 创建 .env 配置文件..."
	@if [ -f .env ]; then \
		echo "$(YELLOW)[WARN]$(RESET) .env 已存在, 跳过"; \
	else \
		cp .env.example .env; \
		echo "$(GREEN)[OK]$(RESET) 已创建 .env, 请编辑填入 API Key"; \
	fi

env-check: ## 验证环境配置
	@echo "$(CYAN)[ENV]$(RESET) 验证环境配置..."
	$(PYTHON) scripts/verify_env.py

pre-commit: ## 安装 pre-commit git hooks
	@echo "$(CYAN)[SETUP]$(RESET) 安装 pre-commit hooks..."
	pre-commit install
	@echo "$(GREEN)[OK]$(RESET) pre-commit 已安装"

# ============================================================================
# 流水线运行 (R-012: PYTHONIOENCODING=utf-8 已在头部 export)
# ============================================================================
.PHONY: run run-small run-html run-exhaustive run-target-url run-mcp run-recon run-web run-custom
run: ## 运行流水线 (默认配置)
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (默认配置)..."
	$(PYTHON) main.py

run-small: ## 快速运行 (max-dataset-size=10)
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (快速模式)..."
	$(PYTHON) main.py --max-dataset-size 10

run-html: ## 运行并生成 HTML 报告
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (HTML 报告)..."
	$(PYTHON) main.py --html-report

run-exhaustive: ## 全技术评估模式
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (EXHAUSTIVE 全技术评估)..."
	$(PYTHON) main.py --exhaustive

run-target-url: ## 攻击 LLM Web URL (--target-url, 自动判别 Web/API, 认证+MFA)
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (LLM Web URL 攻击)..."
	$(PYTHON) main.py --target-url $(or $(TARGET_URL),https://chat.example.com) --load-owasp-local

run-mcp: ## 启用 MCP 协议级攻击 (--mcp-attack, 8 探针)
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (MCP 协议级攻击)..."
	$(PYTHON) main.py --load-owasp-local --mcp-attack

run-recon: ## 从 JSON 文件加载侦察结果 (--recon-json, 两流水线完全独立)
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (Recon JSON 加载)..."
	$(PYTHON) main.py --load-owasp-local --recon-json $(or $(RECON_JSON),outputs/evidence/recon_report.json)

run-web: ## 运行 Web Red Team
	@echo "$(CYAN)[RUN]$(RESET) 启动 Web Red Team..."
	$(PYTHON) -m web_redteam.run --target-profile web_redteam/targets/same_domain/example_portal.yaml --attack-type prompt_sending

run-custom: ## 自定义参数运行 (make run-custom ARGS="--datasets harmbench --max-dataset-size 5")
	@echo "$(CYAN)[RUN]$(RESET) 启动流水线 (自定义参数)..."
	$(PYTHON) main.py $(ARGS)

# ============================================================================
# 测试
# ============================================================================
.PHONY: test test-pipeline test-web test-cov test-fast
test: ## 运行全部测试
	@echo "$(CYAN)[TEST]$(RESET) 运行全部测试..."
	$(PYTHON) -m pytest -v

test-pipeline: ## 运行 pipeline 测试
	@echo "$(CYAN)[TEST]$(RESET) 运行 pipeline 测试..."
	$(PYTHON) -m pytest tests/pipeline/ -v

test-web: ## 运行 web_redteam 测试
	@echo "$(CYAN)[TEST]$(RESET) 运行 web_redteam 测试..."
	$(PYTHON) -m pytest web_redteam/tests/ -v

test-cov: ## 运行测试并生成覆盖率报告
	@echo "$(CYAN)[TEST]$(RESET) 运行测试 (含覆盖率)..."
	$(PYTHON) -m pytest --cov=pipeline --cov=web_redteam --cov-report=term-missing --cov-report=html

test-fast: ## 快速测试 (仅上次失败的)
	@echo "$(CYAN)[TEST]$(RESET) 快速测试 (仅上次失败的)..."
	$(PYTHON) -m pytest -v --lf

# ============================================================================
# 代码质量
# ============================================================================
.PHONY: lint format typecheck check check-full precommit-run
lint: ## 代码检查 (ruff, 全量 pipeline/scripts/tests)
	@echo "$(CYAN)[LINT]$(RESET) 代码检查 (ruff)..."
	ruff check pipeline/ scripts/ tests/ conftest.py

format: ## 代码格式化 (ruff format)
	@echo "$(CYAN)[FORMAT]$(RESET) 代码格式化 (ruff format)..."
	ruff format pipeline/ scripts/ tests/ conftest.py
	ruff check --fix pipeline/ scripts/ tests/ conftest.py

typecheck: ## 类型检查 (mypy)
	@echo "$(CYAN)[TYPE]$(RESET) 类型检查 (mypy)..."
	mypy pipeline/ web_redteam/

check: lint test ## 一键检查 (lint + test)
	@echo "$(GREEN)[OK]$(RESET) 所有检查通过"

check-full: ## 全量检查 (ruff + pytest -v, 三库标准 R-021)
	@echo "$(CYAN)[CHECK-FULL]$(RESET) 三库标准全量检查 (ruff + pytest)..."
	@echo "  [1/2] ruff check pipeline/ scripts/ tests/ conftest.py"
	ruff check pipeline/ scripts/ tests/ conftest.py
	@echo "  [2/2] pytest -v --tb=short"
	$(PYTHON) -m pytest tests/ -v --tb=short
	@echo "$(GREEN)[OK]$(RESET) 全量检查通过 (ruff + pytest)"

precommit-run: ## 运行 pre-commit (所有文件)
	@echo "$(CYAN)[PRE-COMMIT]$(RESET) 运行 pre-commit..."
	pre-commit run --all-files

# ============================================================================
# 数据管理
# ============================================================================
.PHONY: download-datasets download-all download-list download-check curate-seeds sync-asr
download-datasets: ## 下载远程数据集 (核心)
	@echo "$(CYAN)[DATA]$(RESET) 下载核心数据集..."
	$(PYTHON) scripts/download_datasets.py

download-all: ## 下载全部远程数据集
	@echo "$(CYAN)[DATA]$(RESET) 下载全部远程数据集..."
	$(PYTHON) scripts/download_datasets.py --all

download-list: ## 列出可用数据集
	@echo "$(CYAN)[DATA]$(RESET) 列出可用数据集..."
	$(PYTHON) scripts/download_datasets.py --list

download-check: ## 检查本地缓存状态
	@echo "$(CYAN)[DATA]$(RESET) 检查本地缓存状态..."
	$(PYTHON) scripts/download_datasets.py --check

curate-seeds: ## 精简种子集 v2 (去重+均衡+聚类+ASR+模态+Tier分层)
	@echo "$(CYAN)[DATA]$(RESET) 种子精简 v2..."
	$(PYTHON) scripts/curate_seeds.py

curate-model: ## 模型感知精简 (MODEL=gpt-4o, MODALITY=text)
	@if [ -z "$$MODEL" ]; then echo "Usage: make curate-model MODEL=gpt-4o MODALITY=text"; exit 1; fi
	@echo "$(CYAN)[DATA]$(RESET) 模型感知精简: $$MODEL ($$MODALITY)..."
	$(PYTHON) scripts/curate_seeds.py --model "$$MODEL" --modality "$${MODALITY:-text}" --target-count 50

sync-asr: ## 同步 ASR 先验数据
	@echo "$(CYAN)[DATA]$(RESET) 同步 ASR 先验数据..."
	$(PYTHON) scripts/sync_asr_priors.py --auto

# ============================================================================
# 清理
# ============================================================================
.PHONY: clean clean-output clean-all
clean: ## 清理 Python 临时文件
	@echo "$(CYAN)[CLEAN]$(RESET) 清理 Python 临时文件..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)[OK]$(RESET) 临时文件已清理"

clean-output: ## 清理旧报告 (保留最近 7 天)
	@echo "$(CYAN)[CLEAN]$(RESET) 清理旧报告..."
	$(PYTHON) scripts/clean_outputs.py

clean-all: clean clean-output ## 清理全部临时文件和旧报告
	@echo "$(GREEN)[OK]$(RESET) 全部清理完成"

# ============================================================================
# Docker
# ============================================================================
.PHONY: docker-build docker-run
docker-build: ## 构建 Docker 镜像
	@echo "$(CYAN)[DOCKER]$(RESET) 构建镜像..."
	docker build -t $(PROJECT_NAME):$(VERSION) .

docker-run: ## 运行 Docker 容器
	@echo "$(CYAN)[DOCKER]$(RESET) 运行容器..."
	docker run --rm --env-file .env $(PROJECT_NAME):$(VERSION)

# ============================================================================
# 文档 & 基准
# ============================================================================
.PHONY: docs docs-clean benchmark
docs: ## 构建 Sphinx 文档
	@echo "$(CYAN)[DOCS]$(RESET) 构建 Sphinx 文档..."
	@cd docs && $(MAKE) html

docs-clean: ## 清理文档构建缓存
	@echo "$(CYAN)[DOCS]$(RESET) 清理文档缓存..."
	@cd docs && $(MAKE) clean

benchmark: ## 运行性能基准测试
	@echo "$(CYAN)[BENCH]$(RESET) 运行性能基准测试..."
	$(PYTHON) -m benchmark.run_benchmarks

# ============================================================================
# 验证
# ============================================================================
.PHONY: verify-integration verify-all
verify-integration: ## 验证模块集成
	@echo "$(CYAN)[VERIFY]$(RESET) 验证模块集成..."
	$(PYTHON) scripts/verify_integration.py

verify-all: env-check verify-integration test ## 完整验证 (env + integration + test)
	@echo "$(GREEN)[OK]$(RESET) 全部验证通过"

# ============================================================================
# 脚本自动发现 (无需手动注册即可运行 scripts/ 下任意脚本)
# ============================================================================
# 用法:
#   make script-verify_env              → python scripts/verify_env.py
#   make script-download_datasets ARGS="--all"  → python scripts/download_datasets.py --all
#
# 新增脚本时:
#   1. 将文件放入 scripts/ 目录即可用 make script-<name> 调用
#   2. 高频使用的脚本建议在此手动注册独立 target (如 download-datasets)
#   3. 运行 make scripts-check 检查是否有未注册的高频脚本
# ============================================================================
.PHONY: scripts-list scripts-check

# 自动列出 scripts/ 下所有 .py 脚本 (含 docstring 首行)
scripts-list: ## 自动列出 scripts/ 下所有脚本
	@echo "$(CYAN)[SCRIPTS]$(RESET) scripts/ 目录脚本清单:"
	@echo ""
	@for script in scripts/*.py; do \
		name=$$(basename "$$script" .py); \
		doc=$$(head -20 "$$script" | grep -m1 '^"""' | sed 's/"""//g' | sed 's/^ *//'); \
		if [ -z "$$doc" ]; then \
			doc=$$(head -20 "$$script" | grep -m1 "^'" | sed "s/^'//"); \
		fi; \
		if [ -z "$$doc" ]; then doc="(无 docstring)"; fi; \
		printf "  $(GREEN)make script-%s$(RESET)  %s\n" "$$name" "$$doc"; \
	done
	@echo ""
	@echo "$(YELLOW)提示$(RESET): 高频脚本建议在 Makefile 中注册独立 target"

# 检测 scripts/ 下未在 Makefile 注册的脚本
scripts-check: ## 检测未注册脚本
	@echo "$(CYAN)[CHECK]$(RESET) 检测未注册脚本..."
	@echo ""
	@registered="download_datasets sync_asr_priors verify_env verify_integration clean_outputs final_verify check_native_api2 deep_investigate2"; \
	found=0; \
	for script in scripts/*.py; do \
		name=$$(basename "$$script" .py); \
		is_registered=0; \
		for reg in $$registered; do \
			if [ "$$name" = "$$reg" ]; then is_registered=1; break; fi; \
		done; \
		if [ $$is_registered -eq 0 ]; then \
			echo "  $(YELLOW)[UNREG]$(RESET) $$name — 可用 make script-$$name 运行"; \
			found=1; \
		fi; \
	done; \
	if [ $$found -eq 0 ]; then \
		echo "  $(GREEN)[OK]$(RESET) 所有脚本均已注册"; \
	else \
		echo ""; \
		echo "  $(YELLOW)提示$(RESET): 高频脚本建议在 Makefile 中注册独立 target"; \
	fi

# 通配 target: make script-<name> → python scripts/<name>.py
# 支持 ARGS 传参: make script-<name> ARGS="--flag value"
.PHONY: script-%
script-%:
	@script_path="scripts/$*.py"; \
	if [ -f "$$script_path" ]; then \
		echo "$(CYAN)[SCRIPT]$(RESET) 运行 $$script_path"; \
		$(PYTHON) "$$script_path" $(ARGS); \
	else \
		echo "$(RED)[ERROR]$(RESET) 脚本不存在: $$script_path"; \
		exit 1; \
	fi

# ============================================================================
# 默认目标
# ============================================================================
.DEFAULT_GOAL := help
