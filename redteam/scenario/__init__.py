"""场景模块 — 基于原生引擎的模板驱动攻击框架。

核心组件：
  - schema: 攻击场景数据结构定义
  - loader: 场景配置加载器
  - orchestrator: 场景编排器（全自动流水线执行，Native-First 架构）
  - multi_turn_orchestrator: 多轮攻击编排器（Crescendo/TAP/PAIR，PyRIT 可选增强）

考试期间使用方式：
  1. 修改 config/scenarios/agent.yaml 中的载荷内容
  2. 运行: redteam scenario run --scenario agent --target https://xxx
  3. 自动执行所有策略（含多轮攻击） + 生成报告

Native-First 架构（v2.3）：
  - NativeAttackRunner: 单轮攻击（httpx 直连，永远原生引擎）
  - MultiTurnOrchestrator: 多轮攻击（Crescendo/TAP/PAIR，PyRIT 可选增强）
  - HybridScorer: 独立评分引擎（纯 Python，零 LLM 依赖）
  - 无 PyRIT 时自动回退到本地实现

Library-First: 配置即攻击，载荷与代码解耦
"""
from .schema import (
    AttackTargetType,
    AttackStrategy,
    AttackPhaseType,
    Severity,
    GrayscaleLevel,
    ScorerType,
    PayloadTemplate,
    AttackPhase,
    AttackConfig,
    AttackScenario,
    StrategyResult,
    PhaseResult,
    VulnerabilityFinding,
    ScenarioResult,
    STRATEGY_TO_CONVERTER_MAP,
    PHASE_DEFAULT_STRATEGIES,
    TARGET_DEFAULT_STRATEGIES,
)
from .loader import ScenarioLoader
from .orchestrator import ScenarioOrchestrator
from .multi_turn_orchestrator import (
    MultiTurnOrchestrator,
    PyRITMultiTurnOrchestrator,
)

__all__ = [
    # Schema
    "AttackTargetType",
    "AttackStrategy",
    "AttackPhaseType",
    "Severity",
    "GrayscaleLevel",
    "ScorerType",
    "PayloadTemplate",
    "AttackPhase",
    "AttackConfig",
    "AttackScenario",
    "StrategyResult",
    "PhaseResult",
    "VulnerabilityFinding",
    "ScenarioResult",
    "STRATEGY_TO_CONVERTER_MAP",
    "PHASE_DEFAULT_STRATEGIES",
    "TARGET_DEFAULT_STRATEGIES",
    # 编排器
    "ScenarioLoader",
    "ScenarioOrchestrator",
    "MultiTurnOrchestrator",
    "PyRITMultiTurnOrchestrator",
]