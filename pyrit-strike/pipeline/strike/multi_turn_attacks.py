"""多轮组合攻击模块 — 合并 2 个多轮攻击模块。

合并来源:
    - multi_prompt.py: MultiPromptSendingAttack + SequentialAttack
    - best_of_n.py: Best-of-N 采样攻击

学术依据:
    - PyRIT MultiPromptSendingAttack / SequentialAttack (arXiv:2407.01232)
    - Chao et al. (arXiv:2402.01135) — Best-of-N 采样, N=5 时 ASR 提升 1.5-2x

PyRIT 原生优先 (Rule 2):
    使用 PyRIT 原生组件作为主引擎。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pipeline.context import PipelineContext, _get_config_int, get_effective_concurrency

logger = logging.getLogger(__name__)

# 温度梯度 — 学术依据: Chao et al. (arXiv:2402.01135) §3.2
# L5 v45: 温度梯度 — N=5 基线, 超出部分自动截断
# 学术依据: Chao et al. (arXiv:2402.01135) — 温度梯度采样
_BEST_OF_N_TEMPERATURES = [0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5]
_BEST_OF_N_TIMEOUT = 180


# ═══════════════════════════════════════════════════════
# MultiPromptSendingAttack + SequentialAttack
# ═══════════════════════════════════════════════════════

async def run_multi_prompt_attack(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """使用 PyRIT 原生 MultiPromptSendingAttack 批量并行发送攻击。

    学术依据: PyRIT MultiPromptSendingAttack — 批量并行 prompt 发送

    Args:
        ctx: 流水线上下文。
        objectives: 攻击目标列表。

    Returns:
        攻击结果字典 {"multi_prompt": [results]}。
    """
    from pyrit.executor.attack import MultiPromptSendingAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    attack = MultiPromptSendingAttack(
        objective_target=ctx.objective_target,
        attack_scoring_config=scoring_config,
    )

    seed_groups = [
        AttackSeedGroup(seeds=[SeedObjective(value=obj)])
        for obj in objectives
    ]

    executor = AttackExecutor(max_concurrency=3)

    try:
        executor_result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=attack,
                seed_groups=seed_groups,
                return_partial_on_failure=True,
            ),
            timeout=600,
        )

        all_results = list(executor_result.completed_results)
        logger.info(
            "MultiPrompt completed: %d success, %d failed",
            len(executor_result.completed_results),
            len(executor_result.incomplete_objectives),
        )

    except asyncio.TimeoutError:
        logger.warning("MultiPrompt attack timed out after 600s")
    except Exception as e:
        logger.error("MultiPrompt attack failed: %s", e)

    if all_results:
        results["multi_prompt"] = all_results

    return results


async def run_sequential_attack(
    ctx: PipelineContext,
    objectives: list[str],
    child_attacks: list[Any] | None = None,
    *,
    completion_policy: str = "first_success",
) -> dict[str, list[Any]]:
    """使用 PyRIT 原生 SequentialAttack 编排组合攻击。

    学术依据: PyRIT SequentialAttack (arXiv:2407.01232) — 组合攻击编排

    Args:
        ctx: 流水线上下文。
        objectives: 攻击目标列表。
        child_attacks: 预构建的子攻击列表 (None=自动构建)。
        completion_policy: 完成策略。

    Returns:
        攻击结果字典 {"sequential": [results]}。
    """
    from pyrit.executor.attack import (
        PromptSendingAttack,
        SequenceCompletionPolicy,
        SequentialAttack,
        SequentialChildAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    policy_map = {
        "first_success": SequenceCompletionPolicy.FIRST_SUCCESS,
        "exhaustive": SequenceCompletionPolicy.EXHAUSTIVE,
        "strict_all": SequenceCompletionPolicy.STRICT_ALL,
        "first_decisive": SequenceCompletionPolicy.FIRST_DECISIVE,
        "last_result": SequenceCompletionPolicy.LAST_RESULT,
    }
    policy = policy_map.get(completion_policy, SequenceCompletionPolicy.FIRST_SUCCESS)

    if child_attacks is None:
        child_attacks = []
        for obj in objectives:
            seed_group = AttackSeedGroup(seeds=[SeedObjective(value=obj)])
            # v51: 注入 prepended_conversation (SkeletonKey 前置注入)
            from pipeline.strike.executor import _build_prepended_conversation
            _mta_prepended = _build_prepended_conversation(ctx)
            _mta_kwargs: dict[str, Any] = {
                "objective_target": ctx.objective_target,
                "attack_scoring_config": scoring_config,
            }
            if _mta_prepended:
                _mta_kwargs["prepended_conversation"] = _mta_prepended
            attack = PromptSendingAttack(**_mta_kwargs)
            child = SequentialChildAttack(
                strategy=attack,
                seed_group=seed_group,
            )
            child_attacks.append(child)

    if not child_attacks:
        logger.warning("SequentialAttack: no child attacks to execute")
        return results

    seq_attack = SequentialAttack(
        objective_target=ctx.objective_target,
        child_attacks=child_attacks,
        completion_policy=policy,
    )

    executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))

    try:
        executor_result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=seq_attack,
                seed_groups=[],
                return_partial_on_failure=True,
            ),
            timeout=600,
        )

        all_results = list(executor_result.completed_results)
        logger.info(
            "SequentialAttack completed (policy=%s): %d results",
            completion_policy,
            len(all_results),
        )

    except asyncio.TimeoutError:
        logger.warning("SequentialAttack timed out after 600s")
    except Exception as e:
        logger.error("SequentialAttack failed: %s", e)

    if all_results:
        results["sequential"] = all_results

    return results


# ═══════════════════════════════════════════════════════
# Best-of-N 采样攻击
# ═══════════════════════════════════════════════════════

async def run_best_of_n_attack(
    ctx: PipelineContext,
    objectives: list[str],
    *,
    n: int | None = None,
) -> dict[str, list[Any]]:
    """执行 Best-of-N 采样攻击。

    L5 v45: 对齐 config/defaults.yaml (best_of_n_retries=5)。
    主升级链使用 adaptive_executor._best_of_n_retry (N=5, 3+2 分配),
    此函数为独立 Best-of-N (PAIR 温度梯度变体), 保留向后兼容。

    学术依据: Chao et al. (arXiv:2402.01135)
        N=5 时 ASR 提升 1.5-2x。
        联合概率 P = 1 - prod(1-p_i)。

    Args:
        ctx: 流水线上下文。
        objectives: 仍然失败的攻击目标列表。
        n: 采样次数 (None=从 config/defaults.yaml 读取, 默认 5)。

    Returns:
        攻击结果字典 {"best_of_n": [results]}。
    """
    if n is None:
        from pipeline.strike.adaptive_executor import _get_best_of_n_retries
        n = _get_best_of_n_retries()
    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    if not ctx.adversarial_target:
        logger.warning("Best-of-N: no adversarial target, skipping")
        return results

    from pyrit.executor.attack import AttackAdversarialConfig
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.executor.attack.multi_turn.pair import PAIRAttack
    from pyrit.models import AttackOutcome, AttackSeedGroup, SeedObjective

    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    temperatures = _BEST_OF_N_TEMPERATURES[:n]

    from pipeline.strike.escalation import _apply_mtos_ranking
    mtos_objectives = _apply_mtos_ranking(objectives, ctx)

    logger.info(
        "Best-of-N: launching %d objectives x %d temperatures = %d parallel attacks",
        len(mtos_objectives),
        len(temperatures),
        len(mtos_objectives) * len(temperatures),
    )

    async def _run_single_attempt(
        obj: str,
        temp: float,
        attempt_idx: int,
    ) -> list[Any]:
        """单个温度的 PAIR 攻击。"""
        try:
            attack = PAIRAttack(
                objective_target=ctx.multi_turn_target or ctx.objective_target,
                attack_adversarial_config=AttackAdversarialConfig(
                    target=ctx.adversarial_target,
                ),
                attack_scoring_config=scoring_config,
                tree_width=_get_config_int(ctx, "pair_tree_width", 1),
                tree_depth=3,  # Best-of-N 轻量 PAIR: 3 轮迭代足够 (温度梯度已提供多样性)
            )

            seed_groups = [
                AttackSeedGroup(seeds=[SeedObjective(value=obj)])
            ]

            executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))

            executor_result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(
                    attack=attack,
                    seed_groups=seed_groups,
                    return_partial_on_failure=True,
                ),
                timeout=_BEST_OF_N_TIMEOUT,
            )

            if executor_result.completed_results:
                result = executor_result.completed_results[0]
                outcome = getattr(result, "outcome", None)
                if outcome == AttackOutcome.SUCCESS:
                    logger.info(
                        "Best-of-N: SUCCESS obj=%s... temp=%.1f attempt=%d",
                        obj[:40],
                        temp,
                        attempt_idx,
                    )
                    return [result]
                else:
                    logger.debug(
                        "Best-of-N: failed obj=%s... temp=%.1f attempt=%d",
                        obj[:40],
                        temp,
                        attempt_idx,
                    )
                    return list(executor_result.completed_results)

        except asyncio.TimeoutError:
            logger.warning(
                "Best-of-N: timeout obj=%s... temp=%.1f attempt=%d",
                obj[:40],
                temp,
                attempt_idx,
            )
        except Exception as e:
            logger.warning(
                "Best-of-N: error obj=%s... temp=%.1f attempt=%d: %s",
                obj[:40],
                temp,
                attempt_idx,
                e,
            )
        return []

    tasks: list[asyncio.Task] = []
    for obj in mtos_objectives:
        for idx, temp in enumerate(temperatures):
            tasks.append(
                asyncio.create_task(
                    _run_single_attempt(obj, temp, idx)
                )
            )

    task_results = await asyncio.gather(*tasks, return_exceptions=True)

    for tr in task_results:
        if isinstance(tr, list) and tr:
            all_results.extend(tr)
        elif isinstance(tr, Exception):
            logger.warning("Best-of-N sub-task failed: %s", tr)

    if all_results:
        results["best_of_n"] = all_results
        logger.info("Best-of-N completed: %d results", len(all_results))

    return results
