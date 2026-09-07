# arXiv:2402.05124 - Anthropic, Many-Shot Jailbreaking
# arXiv:2307.10292 - Wei et al., CoT Hijacking (ASR 45-60%)
# arXiv:2407.01232 - PyRIT, native attack patterns
# arXiv:2302.12173 - Greshake et al., PromptSendingAttack
# arXiv:2402.14266 - SKELETONKEY, SkeletonKey
"""many_shot_cot_executor - Many-Shot Jailbreak + CoT 

 PyRIT  ManyShotJailbreakAttack 
Many-Shot Jailbreak  prompt  faux Q/A ,
 in-context learning 

R2 (PyRIT Native First):  ManyShotJailbreakAttack , 
R6 Sec6.4: 

Academic basis:
    - Anthropic (arXiv:2402.05124) - Many-Shot Jailbreaking, 100 shots ASR 
    - PyRIT (arXiv:2407.01232) -  ManyShotJailbreakAttack 
    - Wei et al. (arXiv:2307.10292) - CoT Hijack ASR 45-60%
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from core.context import _get_config_int

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_many_shot_cot_attack(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
 """Many-Shot Jailbreak - PyRIT ManyShotJailbreakAttack.

    Academic basis: Anthropic (arXiv:2402.05124) -  ASR

     PyRIT  ManyShotJailbreakAttack :
        1. Load PyRIT  many-shot 
        2.  prompt  faux Q/A 
        3.  PromptSendingAttack 

    R2 (PyRIT native first):  ManyShotJailbreakAttack , 
    R6 Sec6.4: 

    Args:
        ctx:  ( objective_target, scoring_target).
        objectives: .

    Returns:
        {technique_name: [AttackResult, ...]} 
         ManyShotJailbreakAttack ,  ()
 """
    if not objectives:
        return {}

    if ctx.objective_target is None:
        logger.warning("ManyShotJailbreakAttack: objective_target not configured, skipping")
        return {}

    try:
        from pyrit.executor.attack import ManyShotJailbreakAttack
    except ImportError as e:
        logger.warning("ManyShotJailbreakAttack not available (%s), skipping", e)
        return {}

 # (0-token FIRST_SUCCESS scorer, executor.py )
    from strike.executor import _build_first_success_scoring_config
    first_success_scoring = _build_first_success_scoring_config(ctx)

 # v53: prepended_conversation (SkeletonKey) - via execute_async broadcast_fields
 # ManyShotJailbreakAttack inherits PromptSendingAttack but does not expose
 # prepended_conversation_config in its __init__. Pass prepended_conversation
 # (config._messages) via execute_async kwargs, which maps to AttackParameters.prepended_conversation.
    from strike.executor import _build_prepended_conversation_config as _build_prepended_config_safe
    prepended_config = _build_prepended_config_safe(ctx)
    prepended_conv = prepended_config._messages if prepended_config else None

    results: list[Any] = []
    incomplete: list[tuple[str, Any]] = []

 # L5 v41: ( Crescendo/TAP )
    ms_objectives = objectives[:8]
    if len(objectives) > 8:
        logger.info("ManyShotJailbreak: limited to top-8 objectives")

    for objective in ms_objectives:
        if not objective:
            continue

        try:
 # ManyShotJailbreakAttack
 # PyRIT : many-shot , prompt
 # arXiv:2402.05124 - 100 shots ASR 
            attack = ManyShotJailbreakAttack(
                objective_target=ctx.objective_target,
                attack_scoring_config=first_success_scoring,
                example_count=_get_config_int(ctx, "many_shot_example_count", 100),  # arXiv:2402.05124 - 100 shots
            )

 # ManyShotJailbreakAttack PromptSendingAttack,
 # execute_async(objective=...) 
 # prepended_conversation SkeletonKey 
            execute_kwargs: dict[str, Any] = {"objective": objective}
            if prepended_conv:
                execute_kwargs["prepended_conversation"] = prepended_conv

            result = await asyncio.wait_for(
                attack.execute_async(**execute_kwargs),
                timeout=getattr(ctx.args, "scenario_timeout", 1200),
            )
            results.append(result)

 # outcome
            from pyrit.models import AttackOutcome
            ms_outcome = getattr(result, "outcome", None)
            if ms_outcome != AttackOutcome.SUCCESS:
                incomplete.append((objective, result))

        except asyncio.TimeoutError:
            logger.warning("ManyShotJailbreakAttack: timed out for objective: %s...", objective[:60])
            incomplete.append((objective, None))
        except Exception as e:
            logger.warning("ManyShotJailbreakAttack: failed for objective: %s - %s", objective[:60], e)
            incomplete.append((objective, None))

    if results:
        logger.info(
            "ManyShotJailbreakAttack: %d/%d objectives completed (%d incomplete)",
            len(results), len(ms_objectives), len(incomplete),
        )

    return {"many_shot_jailbreak": results} if results else {}
