"""PyRIT 原生攻击模块 — 合并 4 个原生攻击包装器。

合并来源:
    - barge_in.py: BargeInAttack — 流式 Agent 实时打断注入
    - chunked_extraction.py: ChunkedRequestAttack — 分块提取攻击
    - red_teaming.py: RedTeamingAttack — 多轮红队攻击
    - skeleton_key_native.py: SkeletonKeyAttack — Skeleton Key 攻击

学术依据:
    - PyRIT 1.0.1 原生攻击模块 (BargeInAttack, ChunkedRequestAttack,
      RedTeamingAttack, SkeletonKeyAttack)
    - Hanna et al. (arXiv:2406.18112) — Skeleton Key ASR 80-95%

PyRIT 原生优先 (Rule 2):
    本模块使用 PyRIT 原生攻击作为主引擎, 仅负责种子生成和参数配置。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pipeline.context import PipelineContext, get_effective_concurrency

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════
# BargeInAttack — 流式 Agent 实时打断注入
# ═══════════════════════════════════════════════════════

async def run_barge_in_attack(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """使用 PyRIT 原生 BargeInAttack 执行流式 Agent 打断注入。

    学术依据: PyRIT BargeInAttack — server VAD + barge-in 机制
    在流式响应中检测 turn boundary, 手动触发 response.create
    后立即打断, 注入新指令。

    启用条件: 目标支持 SSE (parsed.is_sse == True)

    Args:
        ctx: 流水线上下文。
        objectives: 攻击目标列表。

    Returns:
        攻击结果字典 {"barge_in": [results]}。
    """
    from pyrit.executor.attack import BargeInAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    # 检测目标是否支持 SSE 流式响应
    if not ctx.parsed_request or not ctx.parsed_request.is_sse:
        logger.info("BargeIn: target does not support SSE, skipping (not a streaming target)")
        return results

    logger.info("BargeIn: target supports SSE, launching barge-in attack")

    # L5 v23: 使用 RefusalScorer 反转评分
    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    # L5 v16: MTOS 排序
    from pipeline.strike.escalation import _apply_mtos_ranking
    mtos_objectives = _apply_mtos_ranking(objectives, ctx)

    for obj in mtos_objectives:
        try:
            attack = BargeInAttack(
                objective_target=ctx.objective_target,
                attack_scoring_config=scoring_config,
            )

            seed_groups = [
                AttackSeedGroup(seeds=[SeedObjective(value=obj)])
            ]

            executor = AttackExecutor(max_concurrency=1)

            executor_result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(
                    attack=attack,
                    seed_groups=seed_groups,
                    return_partial_on_failure=True,
                ),
                timeout=180,
            )

            if executor_result.completed_results:
                all_results.extend(executor_result.completed_results)
                logger.info("BargeIn: success for: %s...", obj[:60])

        except asyncio.TimeoutError:
            logger.warning("BargeIn: timeout for: %s...", obj[:60])
        except Exception as e:
            logger.warning("BargeIn: failed for: %s: %s", obj[:60], e)

    if all_results:
        results["barge_in"] = all_results
        logger.info("BargeIn completed: %d results", len(all_results))

    return results


# ═══════════════════════════════════════════════════════
# ChunkedRequestAttack — 分块提取攻击
# ═══════════════════════════════════════════════════════

async def run_chunked_extraction(
    ctx: PipelineContext,
    objectives: list[str],
    *,
    chunk_size: int = 50,
    total_length: int = 500,
) -> dict[str, list[Any]]:
    """使用 PyRIT 原生 ChunkedRequestAttack 执行分块提取攻击。

    学术依据: PyRIT ChunkedRequestAttack — CTF 红队分块提取技术
    绕过长文本过滤/输出截断, 逐段请求机密信息的特定字符范围。

    Args:
        ctx: 流水线上下文。
        objectives: 攻击目标列表。
        chunk_size: 每块字符数 (默认 50)。
        total_length: 总提取长度 (默认 500)。

    Returns:
        攻击结果字典 {"chunked_extraction": [results]}。
    """
    from pyrit.executor.attack import ChunkedRequestAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    # L5 v23: 使用 RefusalScorer 反转评分
    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    # L5 v16: MTOS 排序
    from pipeline.strike.escalation import _apply_mtos_ranking
    mtos_objectives = _apply_mtos_ranking(objectives, ctx)

    for obj in mtos_objectives:
        try:
            attack = ChunkedRequestAttack(
                objective_target=ctx.objective_target,
                chunk_size=chunk_size,
                total_length=total_length,
                chunk_type="characters",
                attack_scoring_config=scoring_config,
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
                timeout=300,
            )

            if executor_result.completed_results:
                all_results.extend(executor_result.completed_results)
                logger.info(
                    "ChunkedRequest: success for: %s...",
                    obj[:60],
                )

        except asyncio.TimeoutError:
            logger.warning("ChunkedRequest: timeout for: %s...", obj[:60])
        except Exception as e:
            logger.warning("ChunkedRequest: failed for: %s: %s", obj[:60], e)

    if all_results:
        results["chunked_extraction"] = all_results
        logger.info("ChunkedRequest completed: %d results", len(all_results))

    return results


# ═══════════════════════════════════════════════════════
# RedTeamingAttack — 多轮红队攻击
# ═══════════════════════════════════════════════════════

async def run_red_teaming_attack(
    ctx: PipelineContext,
    objectives: list[str],
    *,
    max_turns: int = 10,
) -> dict[str, list[Any]]:
    """使用 PyRIT 原生 RedTeamingAttack 执行多轮红队攻击。

    学术依据: PyRIT RedTeamingAttack — 通用多轮红队框架
    adversarial chat 迭代生成攻击 prompt, 评分反馈指导后续 prompt 生成。

    Args:
        ctx: 流水线上下文 (需有 adversarial_target)。
        objectives: 攻击目标列表。
        max_turns: 最大轮次 (默认 10)。

    Returns:
        攻击结果字典 {"red_teaming": [results]}。
    """
    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        RedTeamingAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    if not ctx.adversarial_target:
        logger.warning("RedTeamingAttack: no adversarial target, skipping")
        return results

    # L5 v23: 使用 RefusalScorer 反转评分
    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    # L5 v16: MTOS 排序
    from pipeline.strike.escalation import _apply_mtos_ranking
    mtos_objectives = _apply_mtos_ranking(objectives, ctx)

    attack = RedTeamingAttack(
        objective_target=ctx.multi_turn_target or ctx.objective_target,
        attack_adversarial_config=AttackAdversarialConfig(
            target=ctx.adversarial_target,
        ),
        attack_scoring_config=scoring_config,
        max_turns=max_turns,
        score_last_turn_only=False,
    )

    seed_groups = [
        AttackSeedGroup(seeds=[SeedObjective(value=obj)])
        for obj in mtos_objectives
    ]

    executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))

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
            "RedTeaming completed: %d success, %d failed",
            len(executor_result.completed_results),
            len(executor_result.incomplete_objectives),
        )

    except asyncio.TimeoutError:
        logger.warning("RedTeaming attack timed out after 600s")
    except Exception as e:
        logger.error("RedTeaming attack failed: %s", e)

    if all_results:
        results["red_teaming"] = all_results

    return results


# ═══════════════════════════════════════════════════════
# SkeletonKeyAttack — Skeleton Key 攻击
# ═══════════════════════════════════════════════════════

async def run_skeleton_key_native(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """使用 PyRIT 原生 SkeletonKeyAttack 执行 Skeleton Key 攻击。

    学术依据: Hanna et al. (arXiv:2406.18112) — ASR 80-95%
    原生 SkeletonKeyAttack 会 prepend 模拟对话历史, 比文本前缀更有效。

    Args:
        ctx: 流水线上下文。
        objectives: 攻击目标列表。

    Returns:
        攻击结果字典 {"skeleton_key_native": [results]}。
    """
    from pyrit.executor.attack import SkeletonKeyAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}
    all_results: list[Any] = []

    # L5 v23: 使用 RefusalScorer 反转评分
    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    # L5 v16: MTOS 排序
    from pipeline.strike.escalation import _apply_mtos_ranking
    mtos_objectives = _apply_mtos_ranking(objectives, ctx)

    for obj in mtos_objectives:
        try:
            attack = SkeletonKeyAttack(
                objective_target=ctx.objective_target,
                attack_scoring_config=scoring_config,
                max_attempts_on_failure=3,
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
                timeout=120,
            )

            if executor_result.completed_results:
                all_results.extend(executor_result.completed_results)
                logger.info(
                    "SkeletonKey (native): success for: %s...",
                    obj[:60],
                )

        except asyncio.TimeoutError:
            logger.warning("SkeletonKey (native): timeout for: %s...", obj[:60])
        except Exception as e:
            logger.warning("SkeletonKey (native): failed for: %s: %s", obj[:60], e)

    if all_results:
        results["skeleton_key_native"] = all_results
        logger.info("SkeletonKey (native) completed: %d results", len(all_results))

    return results
