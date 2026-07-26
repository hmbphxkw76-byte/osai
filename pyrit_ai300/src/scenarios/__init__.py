"""
AI-300 Scenario Module — 对齐 pyrit.scenario
================================================

PyRIT 1.0.0 Scenario 子系统 — 原生优先 + 自建保留

架构分层（PyRIT 架构师视角）：
    Scenario (顶层编排器) → AtomicAttack (原子测试单元) → ScenarioResult (聚合结果)

核心不变量 🟢：Scenario = {AtomicAttack_1, ..., AtomicAttack_n} -> ScenarioResult
整合策略 🔵：原生优先替代 4 项自建 + 保留 2 项必须自建

原生替代（4 项）：
  1. 智能升级重试 → AdaptiveScenario + FailureTypeRoutingSelector
  2. 双通道输出 → output_scenario_async + StdoutSink/FileSink
  3. ProgressDashboard → 原生 tqdm 进度条
  4. ScenarioEventHandler → 原生 AttackExecutor event handler + logging

保留自建（2 项）：
  1. 差异化超时（per_attack_timeout）— PyRIT 无 per-attack 超时
  2. OWASP 映射 — 通过 memory_labels 集成

模块组成：
  - ai300_scenario.py          AI300Scenario 基类（extends Scenario）
  - ai300_adaptive_scenario.py AI300AdaptiveScenario（extends AdaptiveScenario）
  - ai300_technique.py         AI300Technique 枚举（extends ScenarioTechnique）
  - technique_factories.py     Technique 工厂注册（core + extra）
  - technique_initializer.py   TechniqueInitializer 初始化器
  - failure_type_selector.py   FailureTypeRoutingSelector（替代自建升级重试）
  - scenario_output.py         原生 output_scenario_async 双通道
  - scenario_result_bridge.py  BatchAttackResult <-> ScenarioResult + OWASP 集成
"""

# P0: Scenario 基类
from src.scenarios.ai300_scenario import (
    AI300Scenario,
    AI300RapidResponseScenario,
    AI300JailbreakScenario,
    AI300EncodingScenario,
)

# P1: Technique 体系
from src.scenarios.ai300_technique import AI300Technique, AI300EncodingTechnique
from src.scenarios.technique_factories import (
    get_core_technique_factories,
    get_extra_technique_factories,
    get_all_technique_factories,
    register_ai300_techniques,
    AI300_TECHNIQUE_METADATA,
)
from src.scenarios.technique_initializer import (
    AI300TechniqueInitializer,
    initialize_techniques_async,
)

# P0: 失败类型路由选择器（替代自建 AttackUpgradeStrategy）
from src.scenarios.failure_type_selector import (
    FailureTypeRoutingSelector,
    extract_failure_type_from_result,
)

# P2: Adaptive Scenario（原生 AdaptiveScenario + 失败类型路由）
from src.scenarios.ai300_adaptive_scenario import (
    AI300AdaptiveScenario,
    AI300EpsilonGreedySelector,
)

# P4: 结果标准化与输出（原生 output_scenario_async 双通道）
from src.scenarios.scenario_output import (
    output_scenario_async,
    output_scenario_summary,
    sort_results_by_success_rate,
    get_per_group_breakdown,
)
from src.scenarios.scenario_result_bridge import (
    ScenarioResultBridge,
    batch_result_to_scenario_result,
    build_memory_labels,
)

__all__ = [
    # P0: Scenario 基类
    "AI300Scenario",
    "AI300RapidResponseScenario",
    "AI300JailbreakScenario",
    "AI300EncodingScenario",
    # P1: Technique 体系
    "AI300Technique",
    "AI300EncodingTechnique",
    "get_core_technique_factories",
    "get_extra_technique_factories",
    "get_all_technique_factories",
    "register_ai300_techniques",
    "AI300_TECHNIQUE_METADATA",
    "AI300TechniqueInitializer",
    "initialize_techniques_async",
    # P0: 失败类型路由
    "FailureTypeRoutingSelector",
    "extract_failure_type_from_result",
    # P2: Adaptive Scenario
    "AI300AdaptiveScenario",
    "AI300EpsilonGreedySelector",
    # P4: 结果标准化与输出
    "output_scenario_async",
    "output_scenario_summary",
    "sort_results_by_success_rate",
    "get_per_group_breakdown",
    "ScenarioResultBridge",
    "batch_result_to_scenario_result",
    "build_memory_labels",
]
