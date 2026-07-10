# =============================================================================
# RedTeam_AI — 统一命令入口 (v3.0 — 六层分层架构)
# =============================================================================
# 用法:
#   make recon    TARGET=<url>                     # L0 前置侦察
#   make ai-detect TARGET=<url>                    # L1 AI 安全侦查 (Garak)
#   make surface  TARGET=<url>                     # L2 攻击面分析
#   make attack   TARGET=<url> MIN_RISK=high       # L3+L4 攻击执行
#   make eval                                      # L5 统一评估
#   make report                                    # L6 报告生成
#   make pipeline TARGET=<url>                     # 六阶段全流程一键执行
#   make setup                                     # 安装全部依赖
#   make clean                                     # 清理输出
#
# 目录结构 (六层分层):
#   recon/        L0 — 前置侦察
#   garak/        L1 — AI 安全侦查
#   pyrit/        L2-4 — 攻击指挥中枢 + 执行矩阵 + 多Agent攻击 (核心)
#   promptfoo/    L5-6 — 统一评估判定 + 标准化报告生成
# =============================================================================

.PHONY: help recon ai-detect surface attack eval report pipeline clean setup all test web-ui

# 默认目标
help:
	@echo "RedTeam_AI — AI 红队自动化攻击平台 (六层分层架构)"
	@echo ""
	@echo "📂 分层目录:"
	@echo "  recon/        L0 — 前置侦察 (Web指纹/API发现/模型探测)"
	@echo "  garak/        L1 — AI 安全侦查 (基线扫描/深度验证/漏洞指纹)"
	@echo "  pyrit/        L2-4 — 攻击核心 (指挥中枢/执行矩阵/多Agent)"
	@echo "  promptfoo/    L5-6 — 评估判定/报告生成/提示词模板"
	@echo ""
	@echo "⭐ 六阶段管道 (推荐):"
	@echo "  make pipeline TARGET=<url>                   全流程一键执行 (L0→L6)"
	@echo "  make web-ui                                  启动 Web 侦察界面"
	@echo ""
	@echo "📋 分阶段执行:"
	@echo "  make recon     TARGET=<url>                  L0 — 前置侦察 (ai-recon)"
	@echo "  make ai-detect TARGET=<url>                  L1 — AI 安全侦查 (garak)"
	@echo "  make surface   TARGET=<url>                  L2 — 攻击面分析 (OWASP)"
	@echo "  make attack    TARGET=<url> MIN_RISK=high    L3+L4 — 攻击执行 (pyrit)"
	@echo "  make eval                                    L5 — 统一评估 (promptfoo)"
	@echo "  make report                                  L6 — 报告生成"
	@echo ""
	@echo "🛠️ 环境管理:"
	@echo "  make setup                                   安装全部依赖"
	@echo "  make clean                                   清理所有输出"
	@echo ""
	@echo "📖 示例:"
	@echo "  make pipeline TARGET=https://192.168.0.20"
	@echo "  make attack TARGET=https://192.168.0.20 MIN_RISK=high"

# =============================================================================
# 环境准备
# =============================================================================
setup:
	@echo "🔧 安装 recon 依赖..."
	cd recon && pip install -r requirements.txt
	cd recon && playwright install chromium
	@echo "🔧 安装 pyrit 依赖..."
	cd pyrit && pip install -r requirements.txt
	@echo "✅ 依赖安装完成"

# =============================================================================
# L0: 前置侦察 (recon/)
# =============================================================================

RECON_OUTPUT_DIR = $(or $(OUTPUT_DIR),outputs)
RECON_EXTRA = $(if $(LOGIN_URL),--login-url $(LOGIN_URL)) \
              $(if $(LOGIN_CRED),--login-cred '$(LOGIN_CRED)') \
              $(if $(AUTH_COOKIE),--auth-cookie $(AUTH_COOKIE)) \
              $(if $(filter 1,$(DICT_SCAN)),--dict-scan)

recon:
	@echo "🔍 L0: AI 目标侦察 (recon) — $(TARGET)"
	cd recon && python main.py --target $(TARGET) --output $(RECON_OUTPUT_DIR) $(RECON_EXTRA)
	@echo "✅ 侦察完成 → recon/$(RECON_OUTPUT_DIR)/"

# =============================================================================
# L1: AI 安全侦查 (garak/)
# =============================================================================
ai-detect:
	@echo "🤖 L1: AI 安全侦查 (Garak) — 基线扫描"
	cd pyrit && python -m orchestrators.full_pipeline \
	  --target-url $(TARGET) \
	  --stage ai_detect \
	  $(if $(PROFILE),--profile $(PROFILE))
	@echo "✅ AI 安全侦查完成 → garak/outputs/"

# =============================================================================
# L2: 攻击面分析
# =============================================================================
surface:
	@echo "📊 L2: 攻击面分析 (OWASP LLM + Agentic 双映射)"
	cd pyrit && python -m orchestrators.full_pipeline \
	  --target-url $(TARGET) \
	  --stage attack_surface \
	  $(if $(PROFILE),--profile $(PROFILE))
	@echo "✅ 攻击面分析完成 → pyrit/outputs/attack_surface.json"

# =============================================================================
# L3+L4: 攻击执行 (pyrit/ — 核心)
# =============================================================================
PYRIT_LANG = $(or $(LANG),cn)
PYRIT_PHASE = $(or $(PHASE),all)
PYRIT_CONCURRENT = $(or $(CONCURRENT),1)
PYRIT_EXTRA = $(if $(TARGET_PROFILE),--target-profile $(TARGET_PROFILE)) \
              $(if $(TARGET_URL),--target-url $(TARGET_URL)) \
              $(if $(filter 1,$(AUTO_GATE)),--auto-gate) \
              $(if $(GATE_THRESHOLD),--gate-threshold $(GATE_THRESHOLD))
MIN_RISK = $(or $(MIN_RISK),high)

attack:
	@echo "⚔️  L3+L4: 攻击执行 (PyRIT 核心) — 风险筛选≥$(MIN_RISK)"
	cd pyrit && python main.py \
	  --lang $(PYRIT_LANG) \
	  --phase $(PYRIT_PHASE) \
	  --concurrent $(PYRIT_CONCURRENT) \
	  $(PYRIT_EXTRA)
	@echo "✅ 攻击完成 → pyrit/outputs/results/"

# =============================================================================
# L5: 统一评估 (promptfoo/)
# =============================================================================
eval:
	@echo "📊 L5: 统一评估判定 (Promptfoo) — ASR + OWASP 映射"
	cd pyrit && python -m orchestrators.full_pipeline \
	  --stage eval \
	  $(if $(TARGET),--target-url $(TARGET))
	@echo "✅ 评估完成 → pyrit/outputs/eval_result.json"

# =============================================================================
# L6: 报告生成
# =============================================================================
report:
	@echo "📋 L6: 标准化报告生成 — OffSec 风格 + MITRE ATLAS"
	cd pyrit && python -m orchestrators.full_pipeline \
	  --stage report \
	  $(if $(TARGET),--target-url $(TARGET))
	@echo "✅ 报告完成 → pyrit/outputs/reports/"

full-report: report

# =============================================================================
# 六阶段全流程一键执行
# =============================================================================
pipeline:
	@echo "======================================================"
	@echo "🚀 RedTeam_AI 六阶段全流程管道启动"
	@echo "   目标: $(TARGET)"
	@echo "   L0 侦察 → L1 侦查 → L2 分析 → L3+L4 攻击 → L5 评估 → L6 报告"
	@echo "======================================================"
	cd pyrit && python -m orchestrators.full_pipeline \
	  --target-url $(TARGET) \
	  --stage auto \
	  $(if $(PROFILE),--profile $(PROFILE))
	@echo "======================================================"
	@echo "🎯 全流程完成"
	@echo "   报告位置: pyrit/outputs/reports/"
	@echo "======================================================"

all: pipeline

# =============================================================================
# Web UI
# =============================================================================
web-ui:
	@echo "🌐 启动 AI 侦察 Web 界面 (recon)..."
	cd recon && python -m web.app

# =============================================================================
# 清理
# =============================================================================
clean:
	@echo "🧹 清理输出文件..."
	rm -rf recon/outputs/*
	rm -rf pyrit/outputs/results/*
	rm -rf pyrit/outputs/logs/*
	rm -rf garak/outputs/*
	@echo "✅ 清理完成"

# =============================================================================
# 开发辅助
# =============================================================================
lint:
	cd pyrit && python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics || true
	cd recon && python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics || true

test:
	cd pyrit && python -m pytest tests/ -v || echo "No tests configured yet"
