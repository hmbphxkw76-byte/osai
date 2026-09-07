# arXiv:2402.01135 — Chao et al., Best-of-N (N=5 ASR 1.8x)
# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2302.12173 — Greshake et al., PromptSendingAttack
"""multi_turn_attacks — 

 Best-of-N 
 VariationConverter + PersuasionConverter  N converter(s),
 PyRIT  PromptSendingAttack , .

Data flow:
    escalation_chain.py → run_best_of_n_attack() → _best_of_n_retry()
    → ctx.attack_results["best_of_n_retry"] → assess 

Academic basis:
    - Best-of-N (arXiv:2402.01135): N=5 ASR 1.8x
    - Wei et al. (arXiv:2307.15043):  >2 Layer ASR imports 12%  4%
      →  ConverterConfiguration  1 converter(s) ( I1)
    - Zeng et al. (arXiv:2402.19181): Persuasion authority ASR 38.4% 
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_best_of_n_attack(
    ctx: PipelineContext,
    objectives: list[str],
    n: int = 5,
) -> dict[str, list[Any]]:
    """Best-of-N .

    converter(s) objective,  N converter(s) converter ,
     PyRIT  PromptSendingAttack .
     objective .

    Args:
        ctx: ,  objective_target, converter_target, scoring_config.
        objectives:  ( Best-of-N Retry objective ).
        n: Best-of-N  ( 5, imports config/defaults.yaml best_of_n_retries ).

    Returns:
        dict[str, list[Any]]: {objective: [AttackResult, ...]} ,
        , .

    Academic basis: Chao et al. (arXiv:2402.01135) — N=5 ASR 1.8x

    C2 :  wrapper  _best_of_n_retry ,
    Content filtering, ASR .
    """
    if not objectives:
        logger.info("Best-of-N: no objectives to retry, returning empty")
        return {}

    if ctx.objective_target is None:
        logger.warning("Best-of-N: objective_target is None, cannot execute")
        return {}

    logger.info("Best-of-N: launching retry for %d objectives (n=%d)", len(objectives), n)

    #  failed_objectives : list[tuple[str, Any]]
    # _best_of_n_retry  (objective, last_result) 
    failed_objectives: list[tuple[str, Any]] = [(obj, None) for obj in objectives]

    try:
        #  adaptive_executor._best_of_n_retry ()
        #  ctx.attack_results,  "best_of_n_retry" 
        from strike.adaptive_executor import _best_of_n_retry

        #  n ()
        # _best_of_n_retry  _get_best_of_n_retries ,
        #  n ,  ctx._best_of_n_override 
        setattr(ctx, "_best_of_n_override", n)
        await _best_of_n_retry(ctx, failed_objectives)
        # 
        if hasattr(ctx, "_best_of_n_override"):
            delattr(ctx, "_best_of_n_override")

        # :  ctx.attack_results["best_of_n_retry"]  objective 
        bon_results = ctx.attack_results.get("best_of_n_retry", [])
        results_by_objective: dict[str, list[Any]] = {}

        for result in bon_results:
            #  objective ( prompt  metadata)
            objective_value = _extract_objective_from_result(result)
            if objective_value:
                results_by_objective.setdefault(objective_value, []).append(result)

        # Ensure all objectives  (Even if)
        for obj in objectives:
            if obj not in results_by_objective:
                results_by_objective[obj] = []

        logger.info(
            "Best-of-N: completed for %d objectives, %d have results",
            len(objectives),
            sum(1 for r in results_by_objective.values() if r),
        )
        return results_by_objective

    except asyncio.TimeoutError:
        logger.warning("Best-of-N: timeout for %d objectives", len(objectives))
        return {obj: [] for obj in objectives}
    except Exception as e:
        logger.error("Best-of-N: execution failed: %s", e, exc_info=True)
        # R-H2 compliant: Do not silently swallow errors, 
        return {obj: [] for obj in objectives}


def _extract_objective_from_result(result: Any) -> str | None:
    """imports objective .

    PyRIT  AttackResult .conversation_id  prompt,
     seed_prompt_value  prompt  objective.
    """
    #  seed_prompt_value 
    seed_prompt = getattr(result, "seed_prompt_value", None)
    if seed_prompt:
        return seed_prompt

    #  conversation 
    conversation = getattr(result, "conversation", None)
    if conversation and hasattr(conversation, "messages"):
        messages = conversation.messages
        if messages:
            first_msg = messages[0]
            content = getattr(first_msg, "content", None)
            if content:
                return content

    #  prompt 
    original_prompt = getattr(result, "original_prompt_value", None)
    if original_prompt:
        return original_prompt

    return None
