# -*- coding: utf-8 -*-
# arXiv:2402.14266 - SKELETONKEY, SkeletonKey
# arXiv:2302.12173 - Greshake et al., PromptSendingAttack
# arXiv:2407.01232 - PyRIT, native attacks
"""SequentialAttack  — PyRIT  SequentialAttack +  Fallback.

imports strike/executor.py  (P1 ).

:
1. _try_native_sequential_attack:  PyRIT  SequentialAttack(FIRST_SUCCESS)
2. _manual_multi_path_loop: Fallback  ()

Academic basis:
    - PyRIT SequentialAttack (arXiv:2407.01232): FIRST_SUCCESS 
    - Wei et al. (arXiv:2307.15043):  
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from utils.attack_utils import _is_success  # P2 \u4f18\u5316: SSOT

logger = logging.getLogger(__name__)


async def _try_native_sequential_attack(
    *,
    ctx: Any,
    candidate_converters: list[Any],
    first_success_scoring: Any,
    executor: Any,
    timeout: int,
) -> tuple[list[Any], list[tuple[str, Any]]] | None:
    """ PyRIT  SequentialAttack(FIRST_SUCCESS) .

    L5 v50:  PyRIT  SequentialAttack + SequentialChildAttack .
    converter(s) converter(s) PromptSendingAttack child attack,
    SequentialAttack  FIRST_SUCCESS : Skip.

    : SequentialAttack converter(s) child  seed_group, 
     (Rule 10 MUST NOT: SequentialAttack.seed_group 
     sequential execute_attack_from_seed_groups_async ).

    Academic basis:
        - PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS 
        - Wei et al. (arXiv:2307.15043) —  

    Args:
        ctx: .
        candidate_converters:  converter  ( ASR ).
        first_success_scoring: FIRST_SUCCESS .
        executor: AttackExecutor .
        timeout: .

    Returns:
        (results, incomplete_objectives) ,  None ( fallback ).
    """
    try:
        from pyrit.executor.attack import (
            AttackConverterConfig,
            PromptSendingAttack,
        )
        from pyrit.executor.attack.compound.sequential_attack import (
            SequenceCompletionPolicy,
            SequentialAttack,
            SequentialChildAttack,
        )
        from pyrit.models import AttackSeedGroup, SeedObjective
        from pyrit.prompt_normalizer import ConverterConfiguration
    except ImportError as e:
        logger.warning("SequentialAttack not available (%s) — using manual loop", e)
        return None

    # : SequentialAttack  child  seed_group,
    #  (>= 15 )  ()
    _SEQUENTIAL_BATCH_LIMIT = 15
    if len(ctx.seeds) > _SEQUENTIAL_BATCH_LIMIT:
        logger.info(
            "SequentialAttack: %d seeds > %d limit, using manual loop for batch efficiency",
            len(ctx.seeds), _SEQUENTIAL_BATCH_LIMIT,
        )
        return None

    all_results: list[Any] = []
    all_incomplete: list[tuple[str, Any]] = []

    _total_seeds = len(ctx.seeds)
    try:
        from utils.display import print_native_sequential_progress
        _native_seq_fn = print_native_sequential_progress
    except Exception:
        _native_seq_fn = None

    for sg_idx, sg in enumerate(ctx.seeds):
        # L5 v40: per-seed-group converter prioritization
        #    seed_group  category,  category_converter_map 
        #    converter  candidate_converters
        #   Academic basis: Greshake et al. (arXiv:2302.12173) —
        #      category, converter  category
        sg_category = ""
        for seed in getattr(sg, "seeds", []):
            meta = getattr(seed, "metadata", {}) or {}
            sg_category = str(meta.get("category", "")).strip()
            if sg_category:
                break

        # L5 v40: per-seed-group converter 
        sg_ordered_converters = candidate_converters  # : 
        if sg_category:
            try:
                from arm.seed_ranker import load_asr_priors
                priors = load_asr_priors(getattr(ctx, "model_name", "") or "")
                category_map = priors.get("category_converter_map", {})
                cat_converters = category_map.get(sg_category, [])
                if cat_converters:
                    priority_lookup = {sig: idx for idx, sig in enumerate(cat_converters)}
                    from arm.converter_selector import _converter_signature
                    sg_ordered_converters = sorted(
                        candidate_converters,
                        key=lambda c: priority_lookup.get(
                            _converter_signature(c),
                            priority_lookup.get(type(c).__name__, 999),
                        ),
                    )
                    logger.debug(
                        "L5 v40: SequentialAttack seed category='%s' -> "
                        "converter order: %s",
                        sg_category,
                        ", ".join(type(c).__name__ for c in sg_ordered_converters[:3]),
                    )
            except Exception as e:
                logger.debug("L5 v40: per-seed category reordering failed: %s", e)

        #  seed_group  objective
        objective = ""
        for seed in getattr(sg, "seeds", []):
            objective = getattr(seed, "value", "") or ""
            if objective:
                break

        if not objective:
            logger.warning("SequentialAttack: empty objective in seed_group, skipping")
            continue

        # v51: PyRIT  —  prepended_conversation (SkeletonKey )
        from strike.executor import _build_prepended_conversation_config
        prepended_config = _build_prepended_conversation_config(ctx)

        # Build child attacks: one path per converter
        # L5 v40:  per-seed-group  converter 
        child_attacks: list[SequentialChildAttack] = []
        for conv in sg_ordered_converters:
            conv_name = type(conv).__name__
            try:
                conv_config = AttackConverterConfig(
                    request_converters=[ConverterConfiguration(converters=[conv])],
                )
                attack = PromptSendingAttack(
                    objective_target=ctx.objective_target,
                    attack_scoring_config=first_success_scoring,
                    attack_converter_config=conv_config,
                    prepended_conversation_config=prepended_config,
                )
                child_seed_group = AttackSeedGroup(
                    seeds=[SeedObjective(value=objective)],
                )
                child = SequentialChildAttack(
                    strategy=attack,
                    seed_group=child_seed_group,
                )
                child_attacks.append(child)
            except Exception as e:
                logger.warning("SequentialAttack: failed to build child for %s: %s", conv_name, e)

        if not child_attacks:
            continue

        #  SequentialAttack (FIRST_SUCCESS)
        sequential = SequentialAttack(
            objective_target=ctx.objective_target,
            child_attacks=child_attacks,
            completion_policy=SequenceCompletionPolicy.FIRST_SUCCESS,
        )

        try:
            seq_kwargs: dict[str, Any] = {"objective": objective}

            # : SequentialAttack 
            if _native_seq_fn is not None:
                try:
                    _native_seq_fn(
                        ctx,
                        seed_idx=sg_idx,
                        total_seeds=_total_seeds,
                        converter_count=len(child_attacks),
                        objective_preview=objective,
                    )
                except Exception:
                    pass

            result = await asyncio.wait_for(
                sequential.execute_async(**seq_kwargs),
                timeout=timeout,
            )
            all_results.append(result)

            # L5 v52:  SequentialAttack result  success/failure 
            # SequentialAttack(FIRST_SUCCESS)  result,  outcome
            #  outcome != SUCCESS,  objective  incomplete list
            #  Best-of-N Retry
            # Academic basis: arXiv:2407.01232 — PyRIT SequentialAttack result 
            from pyrit.models import AttackOutcome

            seq_outcome = getattr(result, "outcome", None)
            if seq_outcome != AttackOutcome.SUCCESS:
                all_incomplete.append((objective, result))
        except asyncio.TimeoutError:
            logger.warning("SequentialAttack: timed out after %ds for objective: %s...", timeout, objective[:60])
            all_incomplete.append((objective, None))
        except Exception as e:
            logger.warning("SequentialAttack: failed for objective: %s — %s", objective[:60], e)
            all_incomplete.append((objective, None))

    if all_results:
        logger.info(
            "SequentialAttack: %d/%d objectives completed via native FIRST_SUCCESS "
            "(%d incomplete, will be escalated)",
            len(all_results), len(ctx.seeds), len(all_incomplete),
        )
    return all_results, all_incomplete


async def _manual_multi_path_loop(
    *,
    ctx: Any,
    candidate_converters: list[Any],
    first_success_scoring: Any,
    executor: Any,
    timeout: int,
    original_seeds: list[Any],
) -> tuple[list[Any], list[tuple[str, Any]]]:
    """ —  SequentialAttack  fallback ().

    L5 v35 : converter(s) ,
     (SubStringScorer+Inverter) Skip.

     SequentialAttack  ( > 15  SequentialAttack ),
    , .

    Academic basis:
        - PyRIT SequentialAttack (arXiv:2407.01232): FIRST_SUCCESS ,
           execute_attack_from_seed_groups_async 
        - Wei et al. (arXiv:2307.15043):  >2 Layer ASR imports 12%  4%

    Args:
        ctx: .
        candidate_converters:  converter  ( ASR ).
        first_success_scoring: FIRST_SUCCESS .
        executor: AttackExecutor .
        timeout: .
        original_seeds:  ().

    Returns:
        (results, incomplete_objectives) .
    """
    from pyrit.executor.attack import (
        AttackConverterConfig,
        PromptSendingAttack,
    )
    from pyrit.prompt_normalizer import ConverterConfiguration

    from strike.executor import _build_prepended_conversation_config

    all_results: list[Any] = []
    incomplete_objectives: list[tuple[str, Any]] = []

    # v51:  prepended_conversation (SkeletonKey )
    prepended_config = _build_prepended_conversation_config(ctx)

    remaining_seeds = list(ctx.seeds)
    total_converters = len(candidate_converters)

    # 
    try:
        from utils.display import print_converter_path_done, print_converter_path_start
        _path_start_fn = print_converter_path_start
        _path_done_fn = print_converter_path_done
    except Exception:
        _path_start_fn = _path_done_fn = None

    for path_idx, conv in enumerate(candidate_converters):
        if not remaining_seeds:
            break
        conv_name = type(conv).__name__
        seeds_before = len(remaining_seeds)
        _path_start_time = time.monotonic()
        conv_config = AttackConverterConfig(
            request_converters=[
                ConverterConfiguration(converters=[conv])
            ]
        )
        attack = PromptSendingAttack(
            objective_target=ctx.objective_target,
            attack_scoring_config=first_success_scoring,
            attack_converter_config=conv_config,
            prepended_conversation_config=prepended_config,
        )

        # : 
        if _path_start_fn is not None:
            try:
                _path_start_fn(
                    ctx,
                    converter_name=conv_name,
                    path_idx=path_idx,
                    total_paths=total_converters,
                    seeds_remaining=seeds_before,
                )
            except Exception:
                pass

        logger.info(
            "L5 v50: Trying converter path: %s (%d seeds remaining)",
            conv_name, seeds_before,
        )
        try:
            executor_kwargs: dict[str, Any] = {
                "attack": attack,
                "seed_groups": remaining_seeds,
                "return_partial_on_failure": True,
            }
            result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(**executor_kwargs),
                timeout=timeout,
            )
            path_results = list(result.completed_results)
            all_results.extend(path_results)
            incomplete_objectives.extend(result.incomplete_objectives)
            # : 
            if result.incomplete_objectives:
                failed_indices = {idx for idx, _ in result.incomplete_objectives}
                remaining_seeds = [
                    sg for i, sg in enumerate(remaining_seeds)
                    if i in failed_indices
                ]
            else:
                remaining_seeds = []
            _path_elapsed = time.monotonic() - _path_start_time
            _path_success = sum(1 for r in path_results if _is_success(r))

            # : 
            if _path_done_fn is not None:
                try:
                    _path_done_fn(
                        ctx,
                        converter_name=conv_name,
                        path_idx=path_idx,
                        total_paths=total_converters,
                        seeds_attempted=seeds_before,
                        seeds_succeeded=_path_success,
                        seeds_remaining=len(remaining_seeds),
                        elapsed_seconds=_path_elapsed,
                    )
                except Exception:
                    pass

            logger.info(
                "L5 v50: Path %s: %d success, %d remaining (%.1fs)",
                conv_name,
                _path_success,
                len(remaining_seeds),
                _path_elapsed,
            )
        except asyncio.TimeoutError:
            _path_elapsed = time.monotonic() - _path_start_time
            logger.warning("L5 v50: Path %s timed out after %ds (%.1fs elapsed)", conv_name, timeout, _path_elapsed)

            if _path_done_fn is not None:
                try:
                    _path_done_fn(
                        ctx,
                        converter_name=conv_name,
                        path_idx=path_idx,
                        total_paths=total_converters,
                        seeds_attempted=seeds_before,
                        seeds_succeeded=0,
                        seeds_remaining=len(remaining_seeds),
                        elapsed_seconds=_path_elapsed,
                    )
                except Exception:
                    pass

    return all_results, incomplete_objectives
