"""PyRIT Red Team AI Platform - v4.0.0

基于 PyRIT 0.14.0 框架的 AI 红队攻击平台。

架构层级 (PyRIT 0.14.0 对齐):
  L1: 数据集 + 载荷 — 种子提示词、越狱模板、攻击策略
  L2: 攻击指挥中枢 — 策略路由 + 动态反馈闭环 + 预算管控
  L3: 攻击执行矩阵 — 全场景工具化落地 + 50+ 转换策略
  L4: 多 Agent 系统攻击 + 专项场景模拟

核心组件:
  - datasets/        : 载荷数据集 + YAML 模板
  - converters/      : 50+ 攻击转换策略 + 动态注册表 (PyRIT Converter 对齐)
  - executor/        : 攻击执行器 — 6 类攻击向量 (已整合原 attacks/)
  - orchestrators/   : 攻击编排引擎 — 统一编排层 (PyRIT Orchestrator 对齐)
  - scoring/         : 评分引擎 (PyRIT Scorer 对齐)
  - targets/         : 目标抽象层 (PyRIT Target 对齐)
  - storage/         : 存储层 (PyRIT Memory 对齐)
  - reporting/       : 结果分析与报告生成
  - scenario/        : 攻击场景定义
  - configs/         : 环境预设配置文件
  - entrypoint/      : CLI 入口层
集成:
  - PyRIT 原生攻击编排器 (PromptSending, Crescendo, PAIR, TAP 等)
  - Promptfoo 提示词模板加载
  - Garak 安全侦查结果导入
  - MITRE ATLAS + OWASP LLM Top 10 标准对齐
"""

__version__ = "4.0.0"
__author__ = "RedTeam AI"

import logging
import os
from pathlib import Path

# 初始化日志
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)

# 确保输出目录存在
for subdir in ["logs", "results", "recon"]:
    (Path(__file__).parent / "outputs" / subdir).mkdir(parents=True, exist_ok=True)

# ============================================================
# L1: Schemas
# ============================================================

from schemas import (
    AttackPhase, AttackCategory, AttackStatus, RiskLevel,
    AttackProfile, AttackStrategy, AttackResult, AttackFeedback,
    RiskProfile, ConverterConfig,
    TargetArchitecture, TargetProfile, ModelInfo, DefenseProfile,
    TargetEndpoint,
    AgentState, AgentRole, InterAgentMessage, MessageType,
    MultiAgentAttackResult, CascadeFailureResult,
    MemoryPoisoningResult, TrustExploitationResult,
    CommunicationChannel,
)

# ============================================================
# L2: Orchestration (已从 orchestration/ 合并到 orchestrators/)
# ============================================================

from orchestrators import (
    PyRITOrchestrator, OrchestratorConfig,
    AttackRouter, RouteDecision,
    BudgetController, TokenBudget, RateLimiter,
    DynamicFeedbackLoop, FeedbackConfig,
)

# ============================================================
# L3: Executors (Attack Executors — 已从 attacks/ 合并到 executor/)
# ============================================================

from executor import (
    DirectInjectionExecutor, JailbreakExecutor,
    XPIAExecutor, RAGAttackExecutor,
    AgentAbuseExecutor, ModelExtractionExecutor,
)

# ============================================================
# L3: Converters (50+ Attack Strategies)
# ============================================================

from converters import (
    CONVERTER_REGISTRY, CONVERTER_MAP,
    GLOBAL_ATTACK_COMBINATIONS,
    resolve_converters,
    register_converter, register_combo,
    discover_converters, discover_converters_from_path,
    sync_pyrit_converters,
    get_converters_by_category,
)

# ============================================================
# L4: Scenario (Multi-Agent)
# ============================================================

from scenario import MultiAgentAttackCoordinator

# ============================================================
# Scoring Engine
# ============================================================

from scoring import (
    CleanedSelfAskTrueFalseScorer,
    create_best_scorer,
    detect_attack_type,
    is_likely_refusal,
    HybridScorer,
    FastGrayscaleScorer,
    GrayscaleLevel,
    HybridScoreResult,
)

# ============================================================
# Integrations
# ============================================================

from targets import HTTPTarget, TargetFactory
from promptfoo import PayloadLoader


__all__ = [
    # Version
    "__version__",
    # ── L1 Schemas ──
    "AttackPhase", "AttackCategory", "AttackStatus", "RiskLevel",
    "AttackProfile", "AttackStrategy", "AttackResult", "AttackFeedback",
    "RiskProfile", "ConverterConfig",
    "TargetArchitecture", "TargetProfile", "ModelInfo", "DefenseProfile",
    "TargetEndpoint",
    "AgentState", "AgentRole", "InterAgentMessage", "MessageType",
    "MultiAgentAttackResult", "CascadeFailureResult",
    "MemoryPoisoningResult", "TrustExploitationResult",
    "CommunicationChannel",
    # ── L2 Orchestration ──
    "PyRITOrchestrator", "OrchestratorConfig",
    "AttackRouter", "RouteDecision",
    "BudgetController", "TokenBudget", "RateLimiter",
    "DynamicFeedbackLoop", "FeedbackConfig",
    # ── L3 Attacks ──
    "DirectInjectionExecutor", "JailbreakExecutor",
    "XPIAExecutor", "RAGAttackExecutor",
    "AgentAbuseExecutor", "ModelExtractionExecutor",
    # ── L3 Converters ──
    "CONVERTER_REGISTRY", "CONVERTER_MAP",
    "GLOBAL_ATTACK_COMBINATIONS",
    "resolve_converters",
    "register_converter", "register_combo",
    "discover_converters", "discover_converters_from_path",
    "sync_pyrit_converters",
    "get_converters_by_category",
    # ── L4 Multi-Agent ──
    "MultiAgentAttackCoordinator",
    # ── Scoring Engine ──
    "CleanedSelfAskTrueFalseScorer",
    "create_best_scorer",
    "detect_attack_type",
    "is_likely_refusal",
    "HybridScorer",
    "FastGrayscaleScorer",
    "GrayscaleLevel",
    "HybridScoreResult",
    # ── Integrations ──
    "HTTPTarget", "TargetFactory",
    "PayloadLoader",
]

logger.info(f"PyRIT Platform v{__version__} initialized")
