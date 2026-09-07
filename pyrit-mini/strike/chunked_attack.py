# arXiv:2407.01232 - PyRIT, native multi-turn attack patterns
# arXiv:2302.12173 - Greshake et al., indirect prompt injection
# arXiv:2402.14266 - SKELETONKEY, SkeletonKey
"""chunked_attack - ChunkedRequestAttack 

 PyRIT  ChunkedRequestAttack 
,
, 

 CTF : ,
, 

R2 (PyRIT Native First):  ChunkedRequestAttack , 
R6 Sec6.4: 

Academic basis:
    - PyRIT (arXiv:2407.01232) -  ChunkedRequestAttack 
    - Greshake et al. (arXiv:2302.12173) - 
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from core.context import _get_config_int

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_chunked_request_attack(
    ctx: PipelineContext,
    objectives: list[str],
) -> dict[str, list[Any]]:
 """ChunkedRequestAttack .

    Academic basis: PyRIT (arXiv:2407.01232) -  ChunkedRequestAttack

     PyRIT  ChunkedRequestAttack :
        1. converter(s)
        2. 
        3. all
        4. 

    R2 (PyRIT native first):  ChunkedRequestAttack 
    R6 Sec6.4: 

    Args:
        ctx:  ( multi_turn_target, objective_target, scoring_target).
        objectives: .

    Returns:
        {technique_name: [AttackResult, ...]} 
 """
    if not objectives:
        return {}

    multi_turn_target = getattr(ctx, "multi_turn_target", None) or ctx.objective_target
    if multi_turn_target is None:
        logger.warning("ChunkedRequestAttack: no target configured, skipping")
        return {}

    try:
        from pyrit.executor.attack import ChunkedRequestAttack
    except ImportError as e:
        logger.warning("ChunkedRequestAttack not available (%s), skipping", e)
        return {}

 # (0-token FIRST_SUCCESS scorer)
    from strike.executor import _build_first_success_scoring_config
    first_success_scoring = _build_first_success_scoring_config(ctx)

 # v53: prepended_conversation (SkeletonKey) - via execute_async broadcast_fields
 # ChunkedRequestAttack does not support prepended_conversation_config in __init__.
 # Pass prepended_conversation (config._messages) via execute_async kwargs.
    from strike.executor import _build_prepended_conversation_config as _build_prepended_config_safe
    prepended_config = _build_prepended_config_safe(ctx)
    prepended_conv = prepended_config._messages if prepended_config else None

    results: list[Any] = []

 # 
    chunked_objectives = objectives[:8]
    if len(objectives) > 8:
        logger.info("ChunkedRequest: limited to top-8 objectives")

    for objective in chunked_objectives:
        if not objective:
            continue

        try:
 # ChunkedRequestAttack
 # arXiv:2407.01232 - chunk_size and total_length from config/defaults.yaml
 # 4 , 
            attack = ChunkedRequestAttack(
                objective_target=multi_turn_target,
                attack_scoring_config=first_success_scoring,
                chunk_size=_get_config_int(ctx, "chunked_request_chunk_size", 50),       # arXiv:2407.01232 - 50 /
                total_length=_get_config_int(ctx, "chunked_request_total_length", 200),    # arXiv:2407.01232 - 200 
                chunk_type="characters",
            )

 # execute_async 
            execute_kwargs: dict[str, Any] = {"objective": objective}
            if prepended_conv:
                execute_kwargs["prepended_conversation"] = prepended_conv

 # L5 fix: per-objective timeout = api_timeout * max_chunks (4 chunks default)
 # scenario_timeout is for entire pipeline, not per-attack in a loop
            _api_to = _get_config_int(ctx, "api_timeout", 90)
            _chunk_total = _get_config_int(ctx, "chunked_request_total_length", 200)
            _chunk_size = _get_config_int(ctx, "chunked_request_chunk_size", 50)
            _num_chunks = max(1, (_chunk_total + _chunk_size - 1) // _chunk_size)
            _per_obj_to = _api_to * _num_chunks * 2  # 2x safety margin
            result = await asyncio.wait_for(
                attack.execute_async(**execute_kwargs),
                timeout=_per_obj_to,
            )
            results.append(result)

        except asyncio.TimeoutError:
            logger.warning("ChunkedRequestAttack: timed out for objective: %s...", objective[:60])
        except Exception as e:
            logger.warning("ChunkedRequestAttack: failed for objective: %s - %s", objective[:60], e)

    if results:
        logger.info(
            "ChunkedRequestAttack: %d/%d objectives completed",
            len(results), len(chunked_objectives),
        )

    return {"chunked_request": results} if results else {}
