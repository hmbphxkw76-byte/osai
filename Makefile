# =============================================================================
# RedTeam_AI — 统一命令入口 (v4.0 — 六阶段分层架构)
# =============================================================================
# 用法:
#   make pipeline TARGET=<url>                         全流程一键执行 (L0→L5)
#   make recon   TARGET=<url>                         L0 前置侦察
#   make garak   TARGET=<url>                         L1 AI模型侦查 (Garak)
#   make bridge  TARGET=<url>                         L2 桥接映射 (Garak→Seeds)
#   make promptfoo TARGET=<url>                       L3 提示词模板 (Promptfoo)
#   make attack  TARGET=<url>                         L4 深度攻击 (PyRIT)
#   make report                                       L5 统一报告 (OffSec规范)
#   make setup                                        安装全部依赖
#   make clean                                        清理输出
#
# 六阶段流水线架构:
#   L0: recon/        前置侦察 — URL枚举/端口扫描/资产发现/服务指纹
#   L1: garak/        AI模型侦查 — Garak基线扫描(6类探针全覆盖)
#   L2: bridge/       桥接映射 — Garak JSONL→Seeds JSON (解析+过滤+风险分类)
#   L3: promptfoo/    提示词模板 — YAML模板/断言规则/变量插值/多场景配置
#   L4: pyrit/        深度攻击 — Crescendo多轮/编码绕过/自适应LLM/ASR量化
#   L5: 报告生成      统一报告 — Garak ASR + PyRIT证据 + promptfoo断言 → OffSec
# =============================================================================

.PHONY: help pipeline recon garak bridge promptfoo attack report eval setup clean web-ui all

# 默认目标 — 展示帮助
help:
	@echo "RedTeam_AI — 完整 AI 红队自动化攻击流水线"
	@echo ""
	@echo "⭐ 六阶段全流程 (推荐):"
	@echo "  make pipeline TARGET=<url>                      全流程一键执行 (L0→L5)"
	@echo ""
	@echo "📋 分阶段执行:"
	@echo "  make recon     TARGET=<url>                     L0 — 前置侦察"
	@echo "  make garak     TARGET=<url>                     L1 — AI模型侦查 (Garak)"
	@echo "  make bridge    TARGET=<url>                     L2 — 桥接映射 (Garak→Seeds)"
	@echo "  make promptfoo TARGET=<url>                     L3 — 提示词模板 (Promptfoo)"
	@echo "  make attack    TARGET=<url>                     L4 — 深度攻击 (PyRIT)"
	@echo "  make report                                     L5 — 统一报告 (OffSec)"
	@echo ""
	@echo "🛠️ 环境管理:"
	@echo "  make setup                                      安装全部依赖"
	@echo "  make clean                                      清理所有输出"
	@echo "  make web-ui                                     启动 Web 侦察界面"
	@echo ""
	@echo "📖 示例:"
	@echo "  make pipeline TARGET=https://192.168.0.20:11434"
	@echo "  make attack TARGET=https://target.com/api"
	@echo "  make report"

# ═══════════════════════════════════════════════════════════════════════
# 环境准备
# ═══════════════════════════════════════════════════════════════════════
setup:
	@echo "🔧 安装全部依赖..."
	pip install -r requirements.txt
	playwright install chromium
	@echo "✅ 依赖安装完成"
	@echo ""
	@echo "💡 可选安装:"
	@echo "  pip install garak        # Garak 模型侦查 (L1)"
	@echo "  npm install -g promptfoo  # Promptfoo 模板管理 (L3)"

# ═══════════════════════════════════════════════════════════════════════
# 六阶段全流程 (推荐)
# ═══════════════════════════════════════════════════════════════════════
pipeline:
	@echo "======================================================"
	@echo "🚀 RedTeam_AI 六阶段全流程管道启动"
	@echo "   目标: $(TARGET)"
	@echo "   L0 侦察 → L1 Garak → L2 Bridge → L3 Promptfoo → L4 PyRIT → L5 Report"
	@echo "   每阶段自动输出专家指导 (Expert Guidance)"
	@echo "======================================================"
	python pipeline.py --target $(TARGET) --mode auto
	@echo "======================================================"
	@echo "🎯 全流程完成"
	@echo "   报告: outputs/reports/"
	@echo "   种子: outputs/seeds/"
	@echo "======================================================"

all: pipeline

# ═══════════════════════════════════════════════════════════════════════
# L0: 前置侦察
# ═══════════════════════════════════════════════════════════════════════
RECON_EXTRA = $(if $(LOGIN_URL),--login-url $(LOGIN_URL)) \
              $(if $(LOGIN_CRED),--login-cred '$(LOGIN_CRED)') \
              $(if $(AUTH_COOKIE),--auth-cookie $(AUTH_COOKIE)) \
              $(if $(filter 1,$(DICT_SCAN)),--dict-scan)

recon:
	@echo "🔍 L0: 前置侦察 — URL枚举/端口扫描/资产发现/服务指纹"
	python pipeline.py --target $(TARGET) --stage recon

# ═══════════════════════════════════════════════════════════════════════
# L1: AI 模型侦查 (Garak)
# ═══════════════════════════════════════════════════════════════════════
GARAK_MODE = $(or $(GARAK_MODE),baseline)

garak:
	@echo "🤖 L1: AI模型侦查 — Garak $(GARAK_MODE) 扫描"
	@echo "  探针覆盖: promptinject | jailbreak | encoding | leakage | toxicity | hallucination"
	python pipeline.py --target $(TARGET) --stage garak

# ═══════════════════════════════════════════════════════════════════════
# L2: 桥接映射 (Garak → Seeds)
# ═══════════════════════════════════════════════════════════════════════
bridge:
	@echo "🔗 L2: 桥接映射 — Garak JSONL → Seeds JSON"
	@echo "  流程: 解析JSONL → 过滤 → 风险类别映射 → OWASP标注 → Seeds JSON + YAML"
	python pipeline.py --target $(TARGET) --stage bridge

# ═══════════════════════════════════════════════════════════════════════
# L3: 提示词模板 (Promptfoo)
# ═══════════════════════════════════════════════════════════════════════
promptfoo:
	@echo "📝 L3: 提示词模板 — YAML模板/断言规则/变量插值/多场景配置"
	python pipeline.py --target $(TARGET) --stage promptfoo

# ═══════════════════════════════════════════════════════════════════════
# L4: 深度攻击 (PyRIT)
# ═══════════════════════════════════════════════════════════════════════
attack:
	@echo "⚔️  L4: PyRIT 深度攻击"
	@echo "  策略: Crescendo多轮 | 编码绕过(Base64/Flip/Morse) | 自适应LLM | 模板注入 | ASR量化"
	python pipeline.py --target $(TARGET) --stage pyrit

# ═══════════════════════════════════════════════════════════════════════
# L5: 统一报告
# ═══════════════════════════════════════════════════════════════════════
report:
	@echo "📊 L5: 统一报告生成 — OffSec 规范"
	@echo "  包含: Garak ASR + PyRIT证据 + promptfoo断言 + OWASP双映射 + MITRE ATLAS"
	python pipeline.py --target $(TARGET) --stage report

eval: report

# ═══════════════════════════════════════════════════════════════════════
# Web UI
# ═══════════════════════════════════════════════════════════════════════
web-ui:
	@echo "🌐 启动 AI 侦察 Web 界面 (recon)..."
	cd recon && python -m web.app

# ═══════════════════════════════════════════════════════════════════════
# 清理 (保留 .recon 虚拟环境)
# ═══════════════════════════════════════════════════════════════════════
clean:
	@echo "🧹 清理输出文件..."
	if exist outputs\ rmdir /s /q outputs\
	if exist recon\outputs\* del /q recon\outputs\*
	if exist pyrit\outputs\results\* del /q pyrit\outputs\results\*
	if exist pyrit\outputs\logs\* del /q pyrit\outputs\logs\*
	if exist garak\outputs\* del /q garak\outputs\*
	@echo "✅ 清理完成"
