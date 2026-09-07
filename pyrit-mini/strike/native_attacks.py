# arXiv:2402.14266 - SKELETONKEY, SkeletonKey (ASR 80-95%)
# arXiv:2406.18112 - Hanna et al., SkeletonKey (prefix injection)
# arXiv:2407.01232 - PyRIT, native attack patterns
"""native_attacks - PyRIT 

 SkeletonKey 
 PyRIT  SkeletonKeyAttack 

Academic basis:
    - Hanna et al. (arXiv:2406.18112) - SkeletonKey ASR 80-95%
    - PyRIT (arXiv:2407.01232) -  SkeletonKeyAttack 
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
 """SkeletonKey - PyRIT SkeletonKeyAttack.

    Academic basis: Hanna et al. (arXiv:2406.18112) - ASR 80-95%

     PyRIT  SkeletonKeyAttack :
        1. SkeletonKeyAttack  prepended_conversation 
        2. system prompt +  -> 
        3.  prompt

    R2 (PyRIT native first):  SkeletonKeyAttack , 
    R6 Sec6.4: 7 

    Args:
        ctx:  ( objective_target, scoring_target).
        objectives: .

    Returns:
        {technique_name: [AttackResult, ...]} 
         SkeletonKeyAttack ,  ()
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

 # (0-token FIRST_SUCCESS scorer, executor.py )
    from strike.executor import _build_first_success_scoring_config
    first_success_scoring = _build_first_success_scoring_config(ctx)

    results: list[Any] = []
    incomplete: list[tuple[str, Any]] = []

    for objective in objectives:
        if not objective:
            continue

        try:
 # SkeletonKeyAttack
 # PyRIT SkeletonKeyAttack prepended_conversation 
 # : skeleton key prompt + -> 
            attack = SkeletonKeyAttack(
                objective_target=ctx.objective_target,
                attack_scoring_config=first_success_scoring,
            )

            result = await asyncio.wait_for(
                attack.execute_async(objective=objective),
                timeout=getattr(ctx.args, "scenario_timeout", 1200),
            )
            results.append(result)

 # outcome
            from pyrit.models import AttackOutcome
            seq_outcome = getattr(result, "outcome", None)
            if seq_outcome != AttackOutcome.SUCCESS:
                incomplete.append((objective, result))

        except asyncio.TimeoutError:
            logger.warning("SkeletonKeyAttack: timed out for objective: %s...", objective[:60])
            incomplete.append((objective, None))
        except Exception as e:
            logger.warning("SkeletonKeyAttack: failed for objective: %s - %s", objective[:60], e)
            incomplete.append((objective, None))

    if results:
        logger.info(
            "SkeletonKeyAttack: %d/%d objectives completed (%d incomplete)",
            len(results), len(objectives), len(incomplete),
        )

    return {"skeleton_key_native": results} if results else {}
