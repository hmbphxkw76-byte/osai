"""
===============================================================================
OffSec AI-300 — PyRIT 原生 Orchestrator 层
===============================================================================
PyRIT 0.14.0 框架对齐:
  ✅ Memory:  SQLiteMemory + CentralMemory（PyRIT 最佳实践，替代手动 DuckDB）
  ✅ 单轮:   PromptSendingAttack（替代 engines/single.py）
  ✅ 多轮:   CrescendoAttack（替代 engines/crescendo.py，原生多轮自适应攻击）
  ✅ 场景:   pyrit.scenario.Scenario（替代手动阶段编排）

模块结构:
  orchestrator/pyrit_orchestrator.py — AI300Orchestrator（统一调度器）
  orchestrator/scenario_runner.py   — A300ScenarioRunner（PyRIT Scenarios 集成）

使用方式:
  from orchestrator.pyrit_orchestrator import AI300Orchestrator, AttackConfig
  orch = AI300Orchestrator(
      scorer_target=scorer_target,
      attack_config=AttackConfig.from_preset("deep"),
  )
  results = await orch.run_campaign(cases, attack_target, phase="all")
===============================================================================
"""
from orchestrators.pyrit_orchestrator import AI300Orchestrator, AttackPhase, AttackConfig
from orchestrators.scenario_runner import A300ScenarioRunner

__all__ = [
    "AI300Orchestrator",
    "AttackPhase",
    "AttackConfig",
    "A300ScenarioRunner",
]
