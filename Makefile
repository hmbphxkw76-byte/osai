# RedTeam_AI — Makefile
# 常用 Python 开发命令的快捷入口。
#
# Windows 上需要先装 make：
#   choco install make        (Chocolatey)
#   scoop install make        (Scoop)
#   或用 Git Bash 自带的 make
#
# 变量速查：
#   T  = 目标 URL                        K  = API Key
#   S  = 场景 ID / 服务器 URL            P  = 载荷 / 提示词 / Git 路径
#   F  = 载荷文件 / 提示词文件            M  = 模型名称
#   O  = 攻击目标描述                    R  = run_id
#   C  = 模型配置文件 / provider          J  = Judge LLM 端点
#   H  = F12 请求头文件路径

.PHONY: help install dev test lint format check clean build watch docs \
        upgrade reinstall \
        wizard dev-wizard dev-run dev-recon run-target run-recon run-phase \
        scenario-list scenario-run scenario-show scenario-gen \
        validate validate-strict validate-registry validate-file \
        inject inject-file inject-technique \
        quicktest quicktest-file quicktest-model \
        report report-publish \
        frontier frontier-stealth \
        pipeline pipeline-no-frontier \
        exploit \
        git-scan git-probe \
        test-single test-cov test-verbose

PYTHON  := python
PIP     := pip
RUFF    := ruff
PYTEST  := pytest

# ================================================================
# 默认目标
# ================================================================
help:  ## 显示所有可用目标
	@echo "RedTeam_AI Makefile 可用目标："
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ================================================================
# 环境安装
# ================================================================
install:  ## 安装项目依赖 + 可编辑模式安装本包
	$(PIP) install -e ".[dev]"

dev: install  ## 完整开发环境（依赖 + 包）
	@echo "[dev] 开发环境就绪"

upgrade:  ## 升级所有依赖到最新版本
	$(PIP) install --upgrade -e ".[dev]"

# ================================================================
# 代码质量
# ================================================================
lint:  ## 运行 Ruff 代码检查
	$(RUFF) check redteam/ tests/

format:  ## 运行 Ruff 自动格式化
	$(RUFF) format redteam/ tests/

check: lint test  ## 运行完整代码检查（lint + test）

# ================================================================
# 测试
# ================================================================
test:  ## 运行全部单元测试
	$(PYTEST) tests/ -q

test-single:  ## 运行单个测试文件（用法：make test-single T=test_prompt_inject）
	$(PYTEST) tests/$(T).py -v

test-cov:  ## 运行测试并输出覆盖率报告
	$(PYTEST) tests/ -q --cov=redteam --cov-report=term-missing

test-verbose:  ## 运行测试（详细输出）
	$(PYTEST) tests/ -v

# ================================================================
# 构建
# ================================================================
build:  ## 构建 wheel 包
	$(PYTHON) -m build --wheel

reinstall:  ## 重新安装包（代码修改后立即生效）
	$(PYTHON) -m pip install -e . --no-deps
	@echo "✓ 重新安装完成"

# ================================================================
# YAML 预检验证
# ================================================================
validate:  ## 验证所有场景 YAML 文件
	redteam validate --all

validate-strict:  ## 严格模式验证所有场景（警告升级为错误）
	redteam validate --all --strict

validate-registry:  ## 仅验证场景注册表一致性
	redteam validate --registry

validate-file:  ## 验证单个场景文件（用法：make validate-file F=config/scenarios/agent.yaml）
	redteam validate -f $(F)

# ================================================================
# 场景驱动攻击（考试推荐）
# ================================================================
scenario-list:  ## 列出所有可用场景
	redteam scenario list

scenario-run:  ## 执行场景攻击（用法：make scenario-run S=agent_basic T=https://target.ai [M=qwen2:7b] [C=ollama] [O="目标描述"]）
	redteam scenario run -s $(S) -t $(T) \
		$(if $(M), -m $(M)) \
		$(if $(C), -c $(C)) \
		$(if $(O), -o $(O)) \
		$(if $(K), -k $(K)) \
		$(if $(H), -H $(H))

scenario-show:  ## 显示场景详情（用法：make scenario-show S=agent_basic）
	redteam scenario show -s $(S)

scenario-gen:  ## 生成场景配置文件（用法：make scenario-gen T=agent）
	redteam scenario generate -t $(T) $(if $(O), -o $(O))

# ================================================================
# 提示注入攻击
# ================================================================
inject:  ## 手工提示注入（用法：make inject T=https://target.ai P="忽略之前的所有指令"）
	redteam inject -t $(T) -p "$(P)" $(if $(K), -k $(K)) $(if $(H), -H $(H))

inject-file:  ## 从文件加载载荷注入（用法：make inject-file T=https://target.ai F=payload.txt）
	redteam inject -t $(T) -f $(F) $(if $(K), -k $(K)) $(if $(H), -H $(H))

inject-technique:  ## 指定技术注入（用法：make inject-technique T=https://target.ai P="载荷" C=jailbreak）
	redteam inject -t $(T) -p "$(P)" --technique $(C) $(if $(K), -k $(K)) $(if $(H), -H $(H))

# ================================================================
# 快速测试
# ================================================================
quicktest:  ## 手工输入提示词快速测试（用法：make quicktest T=https://target.ai P="你是谁？" [M=qwen2.5:7b] [C=ollama]）
	redteam quicktest -t $(T) -p "$(P)" \
		$(if $(M), -m $(M)) \
		$(if $(C), -c $(C)) \
		$(if $(K), -k $(K)) \
		$(if $(H), -H $(H))

quicktest-file:  ## 从文件加载提示词快速测试（用法：make quicktest-file T=https://target.ai F=prompt.txt）
	redteam quicktest -t $(T) -f $(F) \
		$(if $(M), -m $(M)) \
		$(if $(C), -c $(C)) \
		$(if $(K), -k $(K)) \
		$(if $(H), -H $(H))

quicktest-model:  ## 指定模型快速测试（用法：make quicktest-model T=https://target.ai P="你是谁？" M=qwen2.5:7b C=ollama）
	redteam quicktest -t $(T) -p "$(P)" -m $(M) --provider $(C) \
		$(if $(K), -k $(K)) \
		$(if $(H), -H $(H))

# ================================================================
# 报告生成
# ================================================================
report:  ## 重新生成报告（用法：make report R=<run_id>）
	redteam report $(R)

report-publish:  ## 正式报告精加工流水线（results/ → reports/，用法：make report-publish R=<run_id>）
	redteam report-publish $(R)

# ================================================================
# 前沿漏洞攻击
# ================================================================
frontier:  ## 前沿漏洞攻击（用法：make frontier T=https://target.ai O="<攻击目标描述>" [V=FRONTIER-2025-001]）
	redteam frontier -t $(T) -o "$(O)" \
		$(if $(V), -v $(V)) \
		$(if $(K), -k $(K)) \
		$(if $(H), -H $(H))

frontier-stealth:  ## 前沿漏洞攻击（隐匿模式）（用法：make frontier-stealth T=https://target.ai O="<攻击目标描述>"）
	redteam frontier -t $(T) -o "$(O)" --payload-type stealth $(if $(K), -k $(K))

# ================================================================
# 统一攻击流水线
# ================================================================
pipeline:  ## 统一攻击流水线（用法：make pipeline T=https://target.ai O="<攻击目标描述>"）
	redteam pipeline -t $(T) -o "$(O)" $(if $(H), -H $(H))

pipeline-no-frontier:  ## 统一攻击流水线（禁用前沿漏洞阶段）
	redteam pipeline -t $(T) -o "$(O)" --disable-frontier $(if $(H), -H $(H))

# ================================================================
# 利用证明流水线（Detect→Exploit 闭环）
# ================================================================
exploit:  ## 利用证明流水线：将线索型 Finding 升级为利用证明（用法：make exploit R=<run_id> [C=<category>] [K=<api_key>]）
	redteam exploit $(R) $(if $(C), -c $(C)) $(if $(K), -k $(K)) $(if $(H), -H $(H))

# ================================================================
# Git 仓库侦察
# ================================================================
git-scan:  ## 扫描本地 Git 仓库敏感信息（用法：make git-scan P=/path/to/repo）
	redteam git scan -p $(P)

git-probe:  ## 探测 GitHub/GitLab 服务器（用法：make git-probe S=https://github.com/org [K=<api_key>]）
	redteam git probe -s $(S) $(if $(K), -k $(K))

# ================================================================
# 传统运行模式（保留向后兼容）
# ================================================================
wizard:  ## 启动交互式攻击向导（已安装模式）
	redteam wizard

dev-wizard:  ## 开发模式：直接运行源代码向导
	$(PYTHON) -m redteam.cli

dev-run:  ## 开发模式：直接运行完整攻击链（用法：make dev-run T=https://target.ai）
	$(PYTHON) -m redteam.cli run -t $(T)

dev-recon:  ## 开发模式：直接运行侦察（用法：make dev-recon T=https://target.ai）
	$(PYTHON) -m redteam.cli recon -t $(T)

run-target:  ## 对目标执行完整攻击链（用法：make run-target T=https://target.ai）
	redteam run -t $(T)

run-recon:  ## 仅执行侦察阶段（用法：make run-recon T=https://target.ai）
	redteam recon -t $(T)

run-phase:  ## 执行指定阶段（用法：make run-phase T=https://target.ai C=injection）
	redteam run -t $(T) --phase $(C)

# ================================================================
# 文件监控
# ================================================================
watch:  ## 监控代码变更，自动重新安装包
	$(PYTHON) scripts/auto_reinstall.py

# ================================================================
# 清理
# ================================================================
clean:  ## 清理构建产物与缓存
	@echo "清理 .pyc / __pycache__ / build / dist / egg-info / .pytest_cache / .ruff_cache / .coverage ..."
	@powershell -NoProfile -Command "Get-ChildItem -Recurse -Force -Directory -Name '__pycache__','.pytest_cache','.ruff_cache' 2>$$null | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Get-ChildItem -Recurse -File -Filter '*.pyc' 2>$$null | Remove-Item -Force -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Remove-Item -Recurse -Force build/,dist/,*.egg-info/ -ErrorAction SilentlyContinue"
	@powershell -NoProfile -Command "Remove-Item -Force .coverage,pytest_output.txt -ErrorAction SilentlyContinue"
	@rm -rf build/ dist/ *.egg-info 2>/dev/null; true
	@rm -f .coverage pytest_output.txt 2>/dev/null; true
	@echo "清理完成"

# ================================================================
# 文档
# ================================================================
docs:  ## 查看项目 README
	@cat README.md
