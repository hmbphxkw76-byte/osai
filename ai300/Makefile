# AI-300 三项目 Monorepo Makefile
#
# 使用说明：
#   make install                         # 安装所有项目依赖
#   make test                            # 运行全部测试
#   make run-recon URL=<目标URL>          # 执行侦察
#   make run-attack-dry                  # 根据最新 recon 输出预览攻击策略
#   make run-eval-dry                    # 根据最新 recon 输出预览评估策略
#   make run-all-dry URL=<目标URL>        # 一键 recon → attack → eval（dry-run）

PYTHON := python
RECON_DIR := ai300-recon
ATTACK_DIR := ai300-attack
EVAL_DIR := ai300-eval-kit
SCHEMAS_DIR := ai300-schemas

.PHONY: install test test-unit test-integration test-system run-recon run-attack-dry run-eval-dry run-all-dry clean

install:
	$(PYTHON) -m pip install -e ./$(SCHEMAS_DIR)
	$(PYTHON) -m pip install -r ./$(RECON_DIR)/requirements.txt
	$(PYTHON) -m pip install -e ./$(ATTACK_DIR)[dev]
	$(PYTHON) -m pip install -e ./$(EVAL_DIR)[dev]

test: test-unit test-integration test-system

test-unit:
	$(PYTHON) -m pytest $(ATTACK_DIR)/tests/unit $(EVAL_DIR)/tests/unit -v

test-integration:
	$(PYTHON) -m pytest $(ATTACK_DIR)/tests/integration $(EVAL_DIR)/tests/integration -v

test-system:
	$(PYTHON) -m pytest tests/system -v

run-recon:
ifndef URL
	$(error URL is required, e.g., make run-recon URL=http://127.0.0.1:18080)
endif
	PYTHONPATH=$(RECON_DIR)/src:$(SCHEMAS_DIR)/src $(PYTHON) $(RECON_DIR)/main.py $(URL) --headless --no-template

run-attack-dry:
	ai300-attack --dry-run

run-eval-dry:
	ai300-eval --dry-run

run-all-dry: run-recon run-attack-dry run-eval-dry

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
