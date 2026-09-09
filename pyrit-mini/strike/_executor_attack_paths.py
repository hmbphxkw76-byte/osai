# -*- coding: utf-8 -*-
# arXiv:2407.01232 - PyRIT SequentialAttack + FIRST_SUCCESS
"""Attack path execution: SequentialAttack + manual multi-path loop.

Extracted from strike/executor.py to comply with R-DELIVERY-1 (<=300 lines per module).

Contains:
    - _try_native_sequential_attack: PyRIT SequentialAttack wrapper (FIRST_SUCCESS)
    - _manual_multi_path_loop: Fallback converter path loop (with stealth timing)
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


async def _try_native_sequential_attack(
    *,
    ctx: Any,
    candidate_converters: list[Any],
    first_success_scoring: Any,
    executor: Any,
    timeout: int,
) -> tuple[list[Any], list[tuple[str, Any]]] | None:
    """PyRIT SequentialAttack (FIRST_SUCCESS).

    Uses native PyRIT SequentialAttack + SequentialChildAttack.
    Each converter becomes a PromptSendingAttack child attack,
    SequentialAttack stops at FIRST_SUCCESS: skip remaining converters.

    Returns:
        (results, incomplete_objectives) on success, None if fallback needed.
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

    all_results: list[Any] = []
    all_incomplete: list[tuple[str, Any]] = []

    _total_seeds = len(ctx.seeds)
    try:
        from utils.display import print_native_sequential_progress
        _native_seq_fn = print_native_sequential_progress
    except Exception:
        _native_seq_fn = None

    # Stealth: Initialize timing executor from ctx config (SequentialAttack path)
    _stealth_exec_seq = None
    _stealth_config_seq = getattr(ctx, "stealth_config", None)
    if _stealth_config_seq and getattr(_stealth_config_seq, "enabled", False):
        from strike.stealth_exec import StealthExecutor
        _stealth_exec_seq = StealthExecutor(_stealth_config_seq)

    for sg_idx, sg in enumerate(ctx.seeds):
        # Stealth: Apply human-paced delay between seed groups
        if _stealth_exec_seq is not None and sg_idx > 0:
            try:
                _delay = await _stealth_exec_seq.pre_request_delay()
                if _delay > 1.0:
                    logger.debug("[Stealth] SeqAttack inter-seed delay: %.1fs", _delay)
            except Exception:
                pass

        sg_category = ""
        for seed in getattr(sg, "seeds", []):
            meta = getattr(seed, "metadata", {}) or {}
            sg_category = str(meta.get("category", "")).strip()
            if sg_category:
                break

        sg_ordered_converters = candidate_converters
        if sg_category:
            try:
                from arm.seed_ranking import load_asr_priors
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
            except Exception:
                pass

        objective = ""
        for seed in getattr(sg, "seeds", []):
            objective = getattr(seed, "value", "") or ""
            if objective:
                break

        if not objective:
            continue

        from strike._executor_helpers import _build_prepended_conversation_config
        prepended_config = _build_prepended_conversation_config(ctx)

        child_attacks: list[SequentialChildAttack] = []
        for conv in sg_ordered_converters:
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
            except Exception:
                continue

        if not child_attacks:
            continue

        sequential = SequentialAttack(
            objective_target=ctx.objective_target,
            child_attacks=child_attacks,
            completion_policy=SequenceCompletionPolicy.FIRST_SUCCESS,
        )

        try:
            seq_kwargs: dict[str, Any] = {"objective": objective}
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

            from pyrit.models import AttackOutcome
            seq_outcome = getattr(result, "outcome", None)
            if seq_outcome != AttackOutcome.SUCCESS:
                all_incomplete.append((objective, result))
        except asyncio.TimeoutError:
            all_incomplete.append((objective, None))
        except Exception:
            all_incomplete.append((objective, None))

    if all_results:
        logger.info(
            "SequentialAttack: %d/%d objectives via FIRST_SUCCESS (%d incomplete)",
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
    """Fallback: manual converter path loop (when seeds > limit).

    Tries each converter sequentially, removing successful seeds from remaining.
    """
    from pyrit.executor.attack import (
        AttackConverterConfig,
        PromptSendingAttack,
    )
    from pyrit.prompt_normalizer import ConverterConfiguration

    all_results: list[Any] = []
    incomplete_objectives: list[tuple[str, Any]] = []

    from strike._executor_helpers import _build_prepended_conversation_config
    prepended_config = _build_prepended_conversation_config(ctx)
    remaining_seeds = list(ctx.seeds)
    total_converters = len(candidate_converters)

    try:
        from utils.display import print_converter_path_done, print_converter_path_start
        _path_start_fn = print_converter_path_start
        _path_done_fn = print_converter_path_done
    except Exception:
        _path_start_fn = _path_done_fn = None

    # Stealth: Initialize timing executor from ctx config
    _stealth_exec = None
    _stealth_config = getattr(ctx, "stealth_config", None)
    if _stealth_config and getattr(_stealth_config, "enabled", False):
        from strike.stealth_exec import StealthExecutor
        _stealth_exec = StealthExecutor(_stealth_config)
        logger.info(
            "[Stealth] SIEM evasion enabled: level=%s, base_delay=%.1fs, burst_size=%d",
            _stealth_config.level,
            _stealth_config.base_delay,
            _stealth_config.burst_size,
        )

    for path_idx, conv in enumerate(candidate_converters):
        if not remaining_seeds:
            break
        # Stealth: Apply human-paced delay before starting next converter path
        if _stealth_exec is not None:
            try:
                _delay = await _stealth_exec.pre_request_delay()
                if _delay > 1.0:
                    logger.debug("[Stealth] Pre-path delay: %.1fs (converter=%s)", _delay, type(conv).__name__)
            except Exception:
                pass

        conv_name = type(conv).__name__
        seeds_before = len(remaining_seeds)
        _path_start_time = time.monotonic()
        conv_config = AttackConverterConfig(
            request_converters=[ConverterConfiguration(converters=[conv])]
        )
        attack = PromptSendingAttack(
            objective_target=ctx.objective_target,
            attack_scoring_config=first_success_scoring,
            attack_converter_config=conv_config,
            prepended_conversation_config=prepended_config,
        )

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
        except asyncio.TimeoutError:
            logger.warning("Path %s timed out after %ds", conv_name, timeout)
        except Exception as e:
            logger.warning("Path %s failed: %s", conv_name, e)

    return all_results, incomplete_objectives


def _is_success(result: Any) -> bool:
    """Check if an attack result is successful."""
    from utils.attack_utils import _is_success as _utils_is_success
    return _utils_is_success(result)
