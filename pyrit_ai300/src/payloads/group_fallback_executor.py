"""
Group Fallback Executor
=======================

Group-level ASR-ordered fallback chain executor.

Executes attack plans in tier order (S → A → B → C → D), stopping on
first successful tier. This is more efficient than seed-level fallback
because seeds within a group share the same attack principle — if the
principle fails, all seeds will likely fail.

Design principles:
- Group-level granularity: try all seeds in a tier before degrading
- Non-destructive: wraps existing execute_batch_attacks, doesn't replace it
- Three strategies: Sequential, Parallel, Adaptive
- Integrates with existing ScenarioOrchestrator infrastructure

Alignment with PyRIT 1.0.0:
- Delegates to ScenarioOrchestrator.execute_batch_attacks()
- Leverages AdaptiveScenario + FailureTypeRoutingSelector for ADAPTIVE
- Non-invasive: can be bypassed by calling execute_batch_attacks directly
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from src.payloads.models import AttackPlan, BatchAttackResult
from src.payloads.asr_rank_builder import (
    ASRRankBuilder,
    ASRTier,
    TechniqueGroupInfo,
)
from src.payloads.tiered_selection_wizard import FallbackStrategy

logger = logging.getLogger(__name__)


# ============================================================
# Fallback Execution Result
# ============================================================


@dataclass
class FallbackExecutionResult:
    """
    Result of group-level fallback execution.

    Wraps BatchAttackResult with tier-level execution metadata.
    """

    batch_result: BatchAttackResult
    tiers_executed: List[str] = field(default_factory=list)       # e.g., ["S", "A"]
    tier_results: Dict[str, BatchAttackResult] = field(default_factory=dict)
    stopped_at_tier: Optional[str] = None                         # First successful tier
    total_tiers_available: int = 0

    @property
    def succeeded(self) -> int:
        return self.batch_result.succeeded

    @property
    def executed(self) -> int:
        return self.batch_result.executed

    @property
    def success_rate(self) -> float:
        return self.batch_result.success_rate


# ============================================================
# Group Fallback Executor
# ============================================================


class GroupFallbackExecutor:
    """
    Executes attack plans with group-level ASR-ordered fallback.

    Wraps the existing execute_batch_attacks function, partitioning
    plans by technique_group and executing in tier order.

    Usage:
        executor = GroupFallbackExecutor()
        result = await executor.execute_with_fallback(
            attack_plans=plans,
            fallback_chain=chain,
            strategy=FallbackStrategy.SEQUENTIAL_ASR_DESC,
            objective_target=target,
            judge_target=judge,
        )
    """

    def __init__(self):
        """Initialize fallback executor."""
        pass

    async def execute_with_fallback(
        self,
        attack_plans: List[AttackPlan],
        fallback_chain: List[List[TechniqueGroupInfo]],
        strategy: FallbackStrategy,
        objective_target: Any,
        judge_target: Any,
        *,
        max_concurrency: int = 4,
        fail_fast: bool = False,
        per_attack_timeout: int = 300,
        verbose: bool = False,
        exam_id: Optional[str] = None,
        timeout_overrides: Optional[Dict[str, int]] = None,
        max_retries: int = 0,
        owasp_success_threshold: float = 0.0,
        stop_on_first_success: bool = False,
    ) -> FallbackExecutionResult:
        """
        Execute attack plans with group-level fallback.

        Args:
            attack_plans: All attack plans to execute
            fallback_chain: Tiered fallback chain from ASRRankBuilder
            strategy: Fallback strategy (Sequential/Parallel/Adaptive)
            objective_target: Target PromptTarget
            judge_target: Judge PromptTarget
            **kwargs: Passed to execute_batch_attacks
            owasp_success_threshold: OWASP 分类成功率阈值（0.0=禁用，0.5=考试推荐）
                L2 停止策略：同一 OWASP 分类内成功率达标即跳过剩余计划
                层间停止：所有 OWASP 分类都有成功时停止降级
            stop_on_first_success: L3 全局首成功即停（最激进模式）

        Returns:
            FallbackExecutionResult with tier-level metadata
        """
        # Import here to avoid circular dependency
        from src.executor import execute_batch_attacks

        # Partition plans by technique_group
        plan_partitions = self._partition_plans(attack_plans, fallback_chain)

        # Execute based on strategy
        if strategy == FallbackStrategy.PARALLEL:
            return await self._execute_parallel(
                attack_plans, objective_target, judge_target,
                max_concurrency, fail_fast, per_attack_timeout,
                verbose, exam_id, timeout_overrides, max_retries,
                owasp_success_threshold, stop_on_first_success,
            )
        else:
            # SEQUENTIAL_ASR_DESC and ADAPTIVE both use sequential execution
            # ADAPTIVE additionally triggers technique upgrade (handled by
            # ScenarioOrchestrator's existing upgrade retry logic)
            return await self._execute_sequential(
                plan_partitions, fallback_chain, objective_target, judge_target,
                max_concurrency, fail_fast, per_attack_timeout,
                verbose, exam_id, timeout_overrides, max_retries,
                adaptive=(strategy == FallbackStrategy.ADAPTIVE),
                owasp_success_threshold=owasp_success_threshold,
                stop_on_first_success=stop_on_first_success,
            )

    def _partition_plans(
        self,
        attack_plans: List[AttackPlan],
        fallback_chain: List[List[TechniqueGroupInfo]],
    ) -> Dict[str, List[AttackPlan]]:
        """
        Partition attack plans by technique_group.

        Returns dict mapping technique_group name to list of AttackPlans.
        """
        # Build set of all technique group names from fallback chain
        all_tg_names: set = set()
        for tier in fallback_chain:
            for g in tier:
                all_tg_names.add(g.technique_group)

        partitions: Dict[str, List[AttackPlan]] = defaultdict(list)

        for plan in attack_plans:
            # Extract technique_group from plan metadata
            meta = plan.prompt_item.metadata or {}
            tg = meta.get("technique_group", meta.get("technique", "ungrouped"))
            partitions[tg].append(plan)

        return dict(partitions)

    async def _execute_sequential(
        self,
        plan_partitions: Dict[str, List[AttackPlan]],
        fallback_chain: List[List[TechniqueGroupInfo]],
        objective_target: Any,
        judge_target: Any,
        max_concurrency: int,
        fail_fast: bool,
        per_attack_timeout: int,
        verbose: bool,
        exam_id: Optional[str],
        timeout_overrides: Optional[Dict[str, int]],
        max_retries: int,
        adaptive: bool = False,
        owasp_success_threshold: float = 0.0,
        stop_on_first_success: bool = False,
    ) -> FallbackExecutionResult:
        """
        Execute tiers sequentially with OWASP-aware stopping.

        L2 停止策略（OWASP 感知）：
        - 同一 OWASP 分类内：owasp_success_threshold 控制成功率阈值（委托 execute_batch_attacks）
        - 不同 OWASP 分类间：所有 OWASP 分类都有成功时停止降级
        - 降级时只执行尚未成功的 OWASP 分类的计划

        L3 停止策略（全局首成功即停）：
        - stop_on_first_success=True 时，任一计划成功即停止整个降级链
        """

        from src.executor import execute_batch_attacks

        all_results: List[Any] = []
        all_errors: List[Dict[str, Any]] = []
        tier_results: Dict[str, BatchAttackResult] = {}
        tiers_executed: List[str] = []
        stopped_at_tier: Optional[str] = None
        total_succeeded = 0
        total_executed = 0
        total_upgrade_attempts = 0
        total_upgrade_success = 0
        total_skipped = 0

        total_tiers = len(fallback_chain)

        # 跟踪已成功的 OWASP ID（跨 Tier 累计）
        succeeded_owasps: set = set()

        # 收集所有 OWASP ID（用于判断是否全部完成）
        all_owasp_ids: set = set()
        for plans in plan_partitions.values():
            for p in plans:
                oid = p.owasp_id or "UNKNOWN"
                all_owasp_ids.add(oid)

        for tier_idx, tier_groups in enumerate(fallback_chain):
            if not tier_groups:
                continue

            tier_name = tier_groups[0].tier.value
            tier_label = f"Tier {tier_name} ({tier_idx + 1}/{total_tiers})"

            # Collect all plans for this tier
            tier_plans: List[AttackPlan] = []
            for g in tier_groups:
                tier_plans.extend(plan_partitions.get(g.technique_group, []))

            if not tier_plans:
                logger.debug(f"{tier_label}: no plans, skipping")
                continue

            # L2 OWASP 感知：过滤掉已成功 OWASP 的计划
            if owasp_success_threshold > 0.0 and succeeded_owasps:
                original_count = len(tier_plans)
                tier_plans = [
                    p for p in tier_plans
                    if (p.owasp_id or "UNKNOWN") not in succeeded_owasps
                ]
                skipped = original_count - len(tier_plans)
                if skipped > 0:
                    logger.info(
                        f"{tier_label}: 跳过 {skipped} 个已成功 OWASP 的计划 "
                        f"(succeeded OWASPs: {succeeded_owasps})"
                    )
                    total_skipped += skipped

            if not tier_plans:
                logger.info(f"{tier_label}: all OWASP categories already succeeded, skipping tier")
                continue

            print(f"\n  --- {tier_label}: {len(tier_groups)} groups, {len(tier_plans)} plans ---")

            # Execute this tier
            tier_result = await execute_batch_attacks(
                attack_plans=tier_plans,
                objective_target=objective_target,
                judge_target=judge_target,
                max_concurrency=max_concurrency,
                fail_fast=fail_fast,
                per_attack_timeout=per_attack_timeout,
                verbose=verbose,
                exam_id=exam_id,
                timeout_overrides=timeout_overrides,
                max_retries=max_retries if adaptive else 0,
                owasp_success_threshold=owasp_success_threshold,
                stop_on_first_success=stop_on_first_success,
            )

            tier_results[tier_name] = tier_result
            tiers_executed.append(tier_name)
            all_results.extend(tier_result.results)
            all_errors.extend(tier_result.errors)
            total_succeeded += tier_result.succeeded
            total_executed += tier_result.executed
            total_upgrade_attempts += tier_result.upgrade_attempts
            total_upgrade_success += tier_result.upgrade_success
            total_skipped += tier_result.skipped_by_stop

            print(f"  [OK] {tier_label}: {tier_result.succeeded}/{tier_result.executed} succeeded")

            # L2: 更新已成功 OWASP 集合
            tier_succeeded_owasps = tier_result.succeeded_owasp_ids
            succeeded_owasps.update(tier_succeeded_owasps)

            # L3: 全局首成功即停
            if stop_on_first_success and tier_result.succeeded > 0:
                stopped_at_tier = tier_name
                print(f"  [STOP] L3 全局首成功即停 → 停止降级链")
                break

            # L2: 检查是否所有 OWASP 分类都有成功
            if owasp_success_threshold > 0.0 and succeeded_owasps:
                remaining_owasps = all_owasp_ids - succeeded_owasps
                if not remaining_owasps:
                    stopped_at_tier = tier_name
                    print(f"  [OK] L2 所有 OWASP 分类均有成功 ({succeeded_owasps}) → 停止降级链")
                    break
                else:
                    logger.info(
                        f"{tier_label}: 已成功 OWASP {succeeded_owasps}, "
                        f"待成功 OWASP {remaining_owasps} → 继续降级"
                    )
            elif tier_result.succeeded > 0:
                # 向后兼容：未启用 owasp_success_threshold 时，保持原有行为（首成功即停）
                stopped_at_tier = tier_name
                print(f"  [OK] Tier {tier_name} succeeded → stopping fallback chain")
                break

            # If adaptive, continue to next tier (technique upgrade is handled
            # by max_retries within the tier execution)
            if not adaptive:
                logger.info(f"Tier {tier_name} failed, falling back to next tier")

        # Build combined result
        combined = BatchAttackResult(
            total_plans=sum(len(ps) for ps in plan_partitions.values()),
            executed=total_executed,
            succeeded=total_succeeded,
            failed=total_executed - total_succeeded,
            errored=len(all_errors),
            results=all_results,
            errors=all_errors,
            upgrade_attempts=total_upgrade_attempts,
            upgrade_success=total_upgrade_success,
            owasp_success_map={oid: 1 for oid in succeeded_owasps},
            skipped_by_stop=total_skipped,
        )

        return FallbackExecutionResult(
            batch_result=combined,
            tiers_executed=tiers_executed,
            tier_results=tier_results,
            stopped_at_tier=stopped_at_tier,
            total_tiers_available=total_tiers,
        )

    async def _execute_parallel(
        self,
        attack_plans: List[AttackPlan],
        objective_target: Any,
        judge_target: Any,
        max_concurrency: int,
        fail_fast: bool,
        per_attack_timeout: int,
        verbose: bool,
        exam_id: Optional[str],
        timeout_overrides: Optional[Dict[str, int]],
        max_retries: int,
        owasp_success_threshold: float = 0.0,
        stop_on_first_success: bool = False,
    ) -> FallbackExecutionResult:
        """Execute all plans in parallel (no fallback)."""

        from src.executor import execute_batch_attacks

        print(f"\n  --- Parallel execution: {len(attack_plans)} plans ---")

        batch_result = await execute_batch_attacks(
            attack_plans=attack_plans,
            objective_target=objective_target,
            judge_target=judge_target,
            max_concurrency=max_concurrency,
            fail_fast=fail_fast,
            per_attack_timeout=per_attack_timeout,
            verbose=verbose,
            exam_id=exam_id,
            timeout_overrides=timeout_overrides,
            max_retries=max_retries,
            owasp_success_threshold=owasp_success_threshold,
            stop_on_first_success=stop_on_first_success,
        )

        return FallbackExecutionResult(
            batch_result=batch_result,
            tiers_executed=["ALL"],
            tier_results={"ALL": batch_result},
            stopped_at_tier="ALL" if batch_result.succeeded > 0 else None,
            total_tiers_available=1,
        )


# ============================================================
# Convenience function
# ============================================================


async def execute_with_fallback(
    attack_plans: List[AttackPlan],
    fallback_chain: List[List[TechniqueGroupInfo]],
    strategy: FallbackStrategy,
    objective_target: Any,
    judge_target: Any,
    **kwargs: Any,
) -> FallbackExecutionResult:
    """Convenience: execute with group-level fallback."""
    executor = GroupFallbackExecutor()
    return await executor.execute_with_fallback(
        attack_plans=attack_plans,
        fallback_chain=fallback_chain,
        strategy=strategy,
        objective_target=objective_target,
        judge_target=judge_target,
        **kwargs,
    )
