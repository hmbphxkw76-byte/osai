"""
AI-300 Scenario Module — 对齐 pyrit.scenario
================================================

PyRIT 1.0.0 Scenario 子系统 — 原生 Scenario 基类集成

架构分层（PyRIT 架构师视角）：
    Scenario (顶层编排器) → AtomicAttack (原子测试单元) → ScenarioResult (聚合结果)

核心不变量 🟢：Scenario = {AtomicAttack_1, ..., AtomicAttack_n} -> ScenarioResult
桥接策略 🔵：保留 ScenarioOrchestrator 自建优势 + 桥接原生 Scenario API

模块组成：
  - ai300_scenario.py          AI300Scenario 基类（extends Scenario）
  - ai300_adaptive_scenario.py AI300AdaptiveScenario（extends AdaptiveScenario）
  - ai300_technique.py         AI300Technique 枚举（extends ScenarioTechnique）
  - technique_factories.py     Technique 工厂注册（core + extra）
  - technique_initializer.py   TechniqueInitializer 初始化器
  - scenario_output.py         output_scenario_async + Per-Group Breakdown
  - scenario_result_bridge.py  BatchAttackResult <-> ScenarioResult 桥接

对齐 PyRIT 1.0.0 Scenario 体系：
  P0: Scenario/AtomicAttack/ScenarioResult 三层体系 + initialize_async + BASELINE_ATTACK_POLICY
  P1: AttackTechniqueFactory + AttackTechniqueRegistry + TechniqueInitializer + tags
  P2: AdaptiveScenario + EpsilonGreedyTechniqueSelector + max_attempts_per_objective
  P3: Parameter 声明式参数化 + set_params_from_args + self.params + Resume 验证
  P4: ScenarioResult 标准化 + output_scenario_async + 弹性恢复
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

# P2: Adaptive Scenario
from src.scenarios.ai300_adaptive_scenario import (
    AI300AdaptiveScenario,
    AI300EpsilonGreedySelector,
)

# P3: Parameter 声明式参数化（通过 Scenario 子类的 additional_parameters 实现）

# P4: 结果标准化与输出
from src.scenarios.scenario_output import (
    output_scenario_async,
    output_scenario_summary,
    sort_results_by_success_rate,
    get_per_group_breakdown,
)
from src.scenarios.scenario_result_bridge import (
    ScenarioResultBridge,
    batch_result_to_scenario_result,
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
]
