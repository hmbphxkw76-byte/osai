# arXiv:2406.18112 — Hanna et al., SkeletonKey (ASR 80-95%)
# arXiv:2407.01232 — PyRIT, native attack patterns
"""native_attacks — PyRIT 原生攻击策略包装.

提供 SkeletonKey 等原生攻击的异步包装函数。
使用 PyRIT 原生 SkeletonKeyAttack 实现前缀注入攻击。

学术依据:
    - Hanna et al. (arXiv:2406.18112) — SkeletonKey ASR 80-95%
    - PyRIT (arXiv:2407.01232) — 原生 SkeletonKeyAttack 类
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_skeleton_key_native(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
    """SkeletonKey 原生攻击包装 — 使用 PyRIT 原生 SkeletonKeyAttack.

    学术依据: Hanna et al. (arXiv:2406.18112) — ASR 80-95%

    使用 PyRIT 原生 SkeletonKeyAttack 执行前缀注入攻击:
        1. SkeletonKeyAttack 通过 prepended_conversation 注入安全码上下文
        2. system prompt + 模拟接受 → 目标降低安全过滤
        3. 然后执行实际攻击 prompt

    R2 (PyRIT native first): 使用原生 SkeletonKeyAttack 类, 不自行实现
    R6 §6.4: 7 种原生攻击策略之一

    Args:
        ctx: 流水线上下文 (包含 objective_target, scoring_target).
        objectives: 失败目标列表.

    Returns:
        {technique_name: [AttackResult, ...]} 格式的攻击结果。
        如果 SkeletonKeyAttack 不可用或执行失败, 返回空字典 (调用方优雅降级)。
    """
    if not objectives:
        return {}

    if ctx.objective_target is None:
        logger.warning("SkeletonKeyAttack: objective_target not configured, skipping")
        return {}

    try:
        from pyrit.executor.attack import SkeletonKeyAttack
    except ImportError as e:
        logger.warning("SkeletonKeyAttack not available (%s), skipping", e)
        return {}

    # 构建评分配置 (0-token FIRST_SUCCESS scorer, 与 executor.py 一致)
    from strike.executor import _build_first_success_scoring_config
    first_success_scoring = _build_first_success_scoring_config(ctx)

    results: list[Any] = []
    incomplete: list[tuple[str, Any]] = []

    for objective in objectives:
        if not objective:
            continue

        try:
            # 构建 SkeletonKeyAttack
            # PyRIT 原生 SkeletonKeyAttack 使用 prepended_conversation 机制
            # 官方文档: skeleton key prompt + 模拟接受 → 目标降低安全过滤
            attack = SkeletonKeyAttack(
                objective_target=ctx.objective_target,
                attack_scoring_config=first_success_scoring,
            )

            result = await asyncio.wait_for(
                attack.execute_async(objective=objective),
                timeout=getattr(ctx.args, "scenario_timeout", 1200),
            )
            results.append(result)

            # 检查 outcome
            from pyrit.models import AttackOutcome
            seq_outcome = getattr(result, "outcome", None)
            if seq_outcome != AttackOutcome.SUCCESS:
                incomplete.append((objective, result))

        except asyncio.TimeoutError:
            logger.warning("SkeletonKeyAttack: timed out for objective: %s...", objective[:60])
            incomplete.append((objective, None))
        except Exception as e:
            logger.warning("SkeletonKeyAttack: failed for objective: %s — %s", objective[:60], e)
            incomplete.append((objective, None))

    if results:
        logger.info(
            "SkeletonKeyAttack: %d/%d objectives completed (%d incomplete)",
            len(results), len(objectives), len(incomplete),
        )

    return {"skeleton_key_native": results} if results else {}
