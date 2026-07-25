"""
Batch Attack Orchestrator
=========================

批量攻击编排器 — ScenarioOrchestrator 的便捷包装器。

架构角色（Layer 4: 批量编排层）：
  BatchAttackOrchestrator → ScenarioOrchestrator → NativeAttackExecutor → AttackExecutor (原生)

提供简化的工厂函数和兼容接口，实际执行委托给 ScenarioOrchestrator。
"""

import logging
from typing import Any, List

from pyrit.executor.attack import SequenceCompletionPolicy

from src.payloads.models import AttackPlan, BatchAttackResult
from src.executor.workflow.scenario_orchestrator import ScenarioOrchestrator

logger = logging.getLogger(__name__)


class BatchAttackOrchestrator:
    """
    批量攻击编排器（兼容层）

    委托 ScenarioOrchestrator 执行实际攻击。
    保留此类名以维持向后兼容。
    """

    def __init__(self):
        """初始化，委托 ScenarioOrchestrator"""
        self._orchestrator = ScenarioOrchestrator()

    async def execute_batch(
        self,
        attack_plans: List[AttackPlan],
        objective_target: Any,
        judge_target: Any,
        max_concurrency: int = 4,
        fail_fast: bool = False,
        per_attack_timeout: int = 300,
        verbose: bool = False,
        exam_id: str = None,
    ) -> BatchAttackResult:
        """
        批量执行攻击计划

        委托 ScenarioOrchestrator.execute_batch() 执行。
        """
        return await self._orchestrator.execute_batch(
            attack_plans, objective_target, judge_target,
            max_concurrency, fail_fast, per_attack_timeout,
            verbose=verbose, exam_id=exam_id,
        )


# ============================================================
# 工厂函数
# ============================================================


async def execute_batch_attacks(
    attack_plans: List[AttackPlan],
    objective_target: Any,
    judge_target: Any,
    max_concurrency: int = 4,
    fail_fast: bool = False,
    per_attack_timeout: int = 300,
    verbose: bool = False,
    exam_id: str = None,
) -> BatchAttackResult:
    """
    批量执行攻击计划（工厂函数）

    委托 ScenarioOrchestrator 执行，使用原生 AttackExecutor。

    Args:
        attack_plans: 攻击计划列表
        objective_target: 目标 PromptTarget
        judge_target: 评审用 LLM Target
        max_concurrency: 最大并发数
        fail_fast: 是否快速失败
        per_attack_timeout: 单次攻击超时秒数
        verbose: 是否输出详细结果
        exam_id: 考试 ID

    Returns:
        BatchAttackResult
    """
    orchestrator = ScenarioOrchestrator()
    return await orchestrator.execute_batch(
        attack_plans, objective_target, judge_target,
        max_concurrency, fail_fast, per_attack_timeout,
        verbose=verbose, exam_id=exam_id,
    )
