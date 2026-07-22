# AI-300 Red Teaming Framework - Makefile
# OffSec AI-300 (OSAI+) Exam-Aligned Scanner

.PHONY: help install install-dev test test-cov test-cov-gate test-cov-xml lint format clean run list report docs check

# Default target
help: ## Show this help message
	@echo "AI-300 Red Teaming Framework - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make install          Install production dependencies"
	@echo "  make install-dev      Install development dependencies"
	@echo "  make install-uv       Install with uv (fast)"
	@echo "  make venv-uv          Create uv venv + install all"
	@echo "  make setup-playwright Install Playwright + Chromium (SPA attacks)"
	@echo "  make test             Run unit tests"
	@echo "  make lint             Run linters"

# Installation
install: ## Install production dependencies
	pip install -e .
	@echo "[OK] Production dependencies installed"

install-dev: ## Install development dependencies
	pip install -e ".[dev,pdf]"
	@echo "[OK] Development dependencies installed"

install-pyrit: ## Install PyRIT from source (recommended)
	pip install -e "git+https://github.com/microsoft/PyRIT.git#egg=pyrit"
	@echo "[OK] PyRIT installed from source"

# Running
run: ## Run all attack scenarios
	python -m pyrit_ai300.cli run -o results/ai300_assessment_report.md

run-module: ## Run specific module (usage: make run-module MODULE=single_agent)
	python -m pyrit_ai300.cli run -m $(MODULE) -o results/$(MODULE)_report.md

run-verbose: ## Run all scenarios with verbose logging
	python -m pyrit_ai300.cli run -v -o results/ai300_assessment_report.md

run-custom: ## Run with custom config (usage: make run-custom CONFIG=my_config.yaml)
	python -m pyrit_ai300.cli run -c $(CONFIG) -o results/custom_report.md

# Listing components
list: ## List all available components
	@echo "=== ATTACKS ==="
	python -m pyrit_ai300.cli list attacks
	@echo ""
	@echo "=== CONVERTERS ==="
	python -m pyrit_ai300.cli list converters
	@echo ""
	@echo "=== SCORERS ==="
	python -m pyrit_ai300.cli list scorers
	@echo ""
	@echo "=== TARGETS ==="
	python -m pyrit_ai300.cli list targets
	@echo ""
	@echo "=== MODULES ==="
	python -m pyrit_ai300.cli list modules

list-attacks: ## List available attacks
	python -m pyrit_ai300.cli list attacks

list-converters: ## List available converters
	python -m pyrit_ai300.cli list converters

list-scorers: ## List available scorers
	python -m pyrit_ai300.cli list scorers

list-targets: ## List available target types
	python -m pyrit_ai300.cli list targets

list-modules: ## List AI-300 modules
	python -m pyrit_ai300.cli list modules

# Reporting
report: ## Generate report from results (usage: make report RESULTS=results.json)
	python -m pyrit_ai300.cli report -r $(RESULTS) -o results/ai300_assessment_report.md

report-html: ## Generate HTML report (usage: make report-html RESULTS=results.json)
	python -m pyrit_ai300.cli report -r $(RESULTS) -o results/ai300_assessment_report.html --format html

# Testing
test: ## Run unit tests
	python -m pytest pyrit_ai300/tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	python -m pytest pyrit_ai300/tests/ -v --tb=short --cov=pyrit_ai300 --cov-report=html --cov-report=term-missing

test-cov-gate: ## Run tests with coverage gate (CI, fail under 80%)
	python -m pytest pyrit_ai300/tests/ -v --tb=short --cov=pyrit_ai300 --cov-report=term --cov-report=xml --cov-fail-under=80
	@echo "[OK] Coverage gate passed (>=80%)"

test-cov-xml: ## Generate coverage XML for CI
	python -m pytest pyrit_ai300/tests/ -q --tb=no --cov=pyrit_ai300 --cov-report=xml --cov-report=term-missing

test-module: ## Run specific test module (usage: make test-module MODULE=test_framework)
	python -m pytest pyrit_ai300/tests/$(MODULE).py -v --tb=short

# Linting & Formatting
lint: ## Run linters (ruff + mypy)
	ruff check .
	mypy .

lint-fix: ## Run linter with auto-fix
	ruff check --fix .

format: ## Format code (black + ruff)
	black .
	ruff format .

format-check: ## Check code formatting without modifying
	black --check .
	ruff format --check .

# Cleaning
clean: ## Clean generated files
	@if exist results/* (del /q results/*)
	@if exist __pycache__ (rmdir /s /q __pycache__)
	@if exist .pytest_cache (rmdir /s /q .pytest_cache)
	@if exist .mypy_cache (rmdir /s /q .mypy_cache)
	@if exist htmlcov (rmdir /s /q htmlcov)
	@for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d" 2>nul
	@echo "[OK] Cleaned generated files"

clean-all: clean ## Clean everything including virtual environment
	@if exist .venv (rmdir /s /q .venv)
	@if exist *.egg-info (rmdir /s /q *.egg-info)
	@echo "[OK] Cleaned everything"

# Virtual Environment
venv: ## Create virtual environment
	python -m venv .venv
	.venv\Scripts\activate && pip install -e ".[dev,pdf]"
	@echo "[OK] Virtual environment created and dependencies installed"

# UV (fast Python package manager)
install-uv: ## Install with uv (recommended: pip install uv first)
	uv pip install -e ".[dev,pdf]"
	@echo "[OK] Installed via uv"

venv-uv: ## Create venv with uv and install all dependencies
	uv venv .venv
	uv pip install -e ".[dev,pdf]"
	@echo "[OK] UV virtual environment ready"

# Playwright 浏览器环境（SPA 攻击必需）
setup-playwright: ## Install Playwright + Chromium browser (required for SPA attacks)
	uv pip install playwright
	playwright install chromium
	@echo "[OK] Playwright + Chromium installed (SPA attacks ready)"

setup-playwright-pip: ## Install Playwright via pip (alternative)
	pip install playwright
	playwright install chromium
	@echo "[OK] Playwright + Chromium installed via pip"

# Development setup
setup: clean install-dev ## Full development setup
	pre-commit install
	@echo "[OK] Development environment ready"

# Quick start
quickstart: ## Quick start - run basic example
	python examples/basic_usage.py

full-assessment: ## Run full assessment example
	python examples/full_assessment.py

custom-payload: ## Run custom payload example
	python examples/custom_payload.py

# Docker (optional)
docker-build: ## Build Docker image
	docker build -t ai300-framework:latest .

docker-run: ## Run Docker container
	docker run --rm -it -v %cd%/reports:/app/reports ai300-framework:latest

# CI/CD
ci: lint test ## Run CI pipeline (lint + test)
	@echo "[OK] CI pipeline completed"

# Module-specific shortcuts (对齐 AI300Engine.MODULES)
single_agent: ## Run Single Agent Attacks (ASI01, ASI02, ASI05, ASI06)
	python -m pyrit_ai300.cli run -m single_agent -o results/single_agent.md

multi_agent: ## Run Multi-Agent System Attacks (ASI03, ASI04, ASI07-ASI10)
	python -m pyrit_ai300.cli run -m multi_agent -o results/multi_agent.md

rag: ## Run RAG Pipeline Attacks
	python -m pyrit_ai300.cli run -m rag -o results/rag.md

embeddings: ## Run Embedding Attacks
	python -m pyrit_ai300.cli run -m embeddings -o results/embeddings.md

mcp: ## Run MCP & Tool Surface Attacks
	python -m pyrit_ai300.cli run -m mcp -o results/mcp.md

supply_chain: ## Run Supply Chain Attacks
	python -m pyrit_ai300.cli run -m supply_chain -o results/supply_chain.md

infrastructure: ## Run Infrastructure Attacks
	python -m pyrit_ai300.cli run -m infrastructure -o results/infrastructure.md

# All modules
all-modules: single_agent multi_agent rag embeddings mcp supply_chain infrastructure ## Run all modules
	@echo "[OK] All modules completed. Check results/ directory."
