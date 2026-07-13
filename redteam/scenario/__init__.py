"""场景模块 — 基于PyRIT的模板驱动攻击框架。

核心组件：
  - schema: 攻击场景数据结构定义
  - loader: 场景配置加载器
  - orchestrator: 场景编排器（全自动流水线执行，支持 PyRIT 双引擎）
  - pyrit_orchestrator: PyRIT 多轮攻击编排器（Crescendo/TAP/PAIR）
  - reporter: 场景报告器（OSCP标准报告生成）

考试期间使用方式：
  1. 修改 config/scenarios/agent.yaml 中的载荷内容
  2. 运行: redteam scenario run --scenario agent --target https://xxx
  3. 自动执行所有策略（含多轮攻击） + 生成报告

PyRIT 双引擎架构：
  - PyRITAttackRunner: 单轮攻击，支持转换器链 + LLM-as-Judge
  - PyRITMultiTurnOrchestrator: 多轮攻击（Crescendo/TAP/PAIR）
  - PyRITScoringOrchestrator: 独立评分引擎
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
from .pyrit_orchestrator import (
    PyRITMultiTurnOrchestrator,
    PyRITScoringOrchestrator,
)
from .reporter import ScenarioReporter

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
    "PyRITMultiTurnOrchestrator",
    "PyRITScoringOrchestrator",
    "ScenarioReporter",
]