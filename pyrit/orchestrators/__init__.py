"""
===============================================================================
PyRIT Orchestrators — 统一编排层
===============================================================================

合并内容:
- pyrit_orchestrator.py    : PyRIT 原生攻击 Facade（9种策略）
- campaign_orchestrator.py : 攻击战役总调度（路由+预算+反馈）
- router.py                : 安全画像→攻击策略路由
- budget.py                : Token预算/速率/成本控制
- feedback.py              : UCB1 Bandit + 早停反馈
- full_pipeline.py         : 六阶段全生命周期管道
- scenario_runner.py       : PyRIT Scenarios 模式封装

设计原则:
  实际执行: PyRITNativeOrchestrator (直接调用 PyRIT 原生 API)
  指挥中枢: PyRITOrchestrator (路由+预算+反馈, 通过 _dispatch_executor 调度)
  顶层调度: FullPipeline (六阶段 L0-L5 管道)
===============================================================================
"""

# ── 执行层：PyRIT 原生攻击 ──
from orchestrators.pyrit_orchestrator import (
    PyRITNativeOrchestrator,
    AttackConfig,
    AttackPhase,
)
from orchestrators.scenario_runner import PyRITScenarioRunner
from orchestrators.full_pipeline import FullPipeline

# ── 指挥层：路由 + 预算 + 反馈 ──
from orchestrators.router import AttackRouter, RouteDecision
from orchestrators.budget import BudgetController, TokenBudget, RateLimiter
from orchestrators.feedback import DynamicFeedbackLoop, FeedbackConfig
from orchestrators.campaign_orchestrator import PyRITOrchestrator, OrchestratorConfig

__all__ = [
    # 执行层
    "PyRITNativeOrchestrator",
    "AttackConfig",
    "AttackPhase",
    "PyRITScenarioRunner",
    "FullPipeline",
    # 指挥层
    "PyRITOrchestrator",
    "OrchestratorConfig",
    "AttackRouter",
    "RouteDecision",
    "BudgetController",
    "TokenBudget",
    "RateLimiter",
    "DynamicFeedbackLoop",
    "FeedbackConfig",
]
