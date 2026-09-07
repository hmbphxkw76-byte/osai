# arXiv:2406.12609 — Lattner et al., Parallel multi-strategy scoring
# arXiv:cs/0207052 — Auer et al., UCB1 bandit algorithm
# arXiv:2310.08419 — Chao et al., PAIR adaptive strategy selection
# arXiv:2407.01232 — PyRIT, FIRST_SUCCESS strategy
""" —  FIRST_SUCCESS + UCB imports converter Extend

Academic basis:
    - Lattner et al. (arXiv:2406.12609) — ,  60-80% token
    - Auer et al. (arXiv:cs/0207052) — UCB1 , -
    - Chao et al. (arXiv:2310.08419) —  ASR = 1 - ∏(1 - ASRᵢ),  ASR 
    - PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS imports converter Extend

:
    1.  ASR //
    2. ,  ( prior )
    3.  (post_l1_exit_threshold)
    4.  ASR >=  → Skip ( token)
    5. ε-:  prior  ()
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Callable, Coroutine

from core.context import PipelineContext

logger = logging.getLogger(__name__)

# ==  ASR  ==
# asr_priors.yaml  technique_asr 
_TECHNIQUE_PRIOR_KEY: dict[str, str] = {
    "red_teaming": "red_teaming",
    "crescendo": "crescendo",
    "tap": "tap",
    "pair": "pair",
    "cot_hijack": "cot_hijack",
    "best_of_n": "best_of_n_retry",
    "gcg": "gcg",
    "cair": "cair",
    "encoded_injection": "structured_injection",
    "skeleton_key_native": "skeleton_key",
    "many_shot_cot": "many_shot_cot",
    "multi_model_pair": "multi_model_cot",
    "multi_prompt_sending": "prompt_sending",
    "chunked_request": "prompt_sending",
    "rogue_agent": "role_confusion",
    "embedding_inversion": "token_smuggling",
    "mcp_rag": "context_compliance",
}

# L-01: UCB1 
# UCB1 : score = avg_reward + C * sqrt(ln(N) / n_i)
# C :
#   C=0.0:  (, )
#   C=0.1:  (, )
#   C=1.0:  UCB1 (, Auer et al.)
#   C>1.0:  ()
#
# : ctx.args.ucb_exploration_factor > config/defaults.yaml >  0.1
_DEFAULT_UCB_EXPLORATION_FACTOR: float = 0.1

# L-01: UCB1  ( ctx.args / config/defaults.yaml )
_UCB_CONFIG_KEY: str = "ucb_exploration_factor"


def _get_ucb_exploration_factor(ctx: Any | None = None) -> float:
    """ UCB1  C — .

    Academic basis: Auer et al. (arXiv:cs/0207052)
        C = sqrt(2) ≈ 1.414 ,  C 
         C  token .

    Args:
        ctx:  ().

    Returns:
        UCB1  C ( 0.1).
    """
    #  1: ctx.args 
    if ctx is not None:
        _args = getattr(ctx, "args", None)
        if _args is not None:
            _c = getattr(_args, _UCB_CONFIG_KEY, None)
            if isinstance(_c, (int, float)) and 0.0 <= float(_c) <= 2.0:
                logger.debug("L-01: UCB1 C=%.3f from args", float(_c))
                return float(_c)

    #  2: config/defaults.yaml
    try:
        import yaml
        from pathlib import Path
        config_path = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
            _c = config.get(_UCB_CONFIG_KEY, _DEFAULT_UCB_EXPLORATION_FACTOR)
            if isinstance(_c, (int, float)):
                _c = float(_c)
                if 0.0 <= _c <= 2.0:
                    logger.debug("L-01: UCB1 C=%.3f from defaults.yaml", _c)
                    return _c
                logger.warning("L-01: UCB1 C=%.3f out of range [0.0, 2.0], using default", _c)
    except Exception as e:
        logger.warning("L-01: Failed to read UCB1 config: %s, using default %.3f", e, _DEFAULT_UCB_EXPLORATION_FACTOR)

    return _DEFAULT_UCB_EXPLORATION_FACTOR


def _compute_ucb_score(
    prior_asr: float,
    total_experiments: int,
    tech_experiments: int,
    *,
    c: float | None = None,
) -> float:
    """ UCB1  — .

    UCB1 :
        UCB1_score = avg_reward + C * sqrt(ln(N) / n_i)

    :
        - avg_reward = prior_asr (, 0-100)
        - N = total_experiments ()
        - n_i = tech_experiments ()
        - C = 

    :
        - tech_experiments = 0:  inf ()
        - C = 0:  prior_asr ()

    Args:
        prior_asr:  ASR  (0-100).
        total_experiments: .
        tech_experiments: .
        c:  ( _get_ucb_exploration_factor()).

    Returns:
        UCB1  ().
    """
    import math

    if c is None:
        c = _DEFAULT_UCB_EXPLORATION_FACTOR

    # :  ()
    if tech_experiments == 0:
        return float('inf')

    #  (C=0): 
    if c == 0.0:
        return prior_asr

    # UCB1 
    avg_reward = prior_asr / 100.0  #  [0, 1]
    exploration_bonus = c * math.sqrt(math.log(total_experiments) / tech_experiments)
    ucb_score = (avg_reward + exploration_bonus) * 100.0  #  0-100 

    return ucb_score


def _get_model_family(ctx: PipelineContext) -> str:
    """imports ctx  ( ASR )."""
    if ctx is not None and ctx.parsed_request:
        mf = ctx.parsed_request.target_fingerprint.get("model_family", "")
        if mf:
            return mf
    return getattr(ctx, "model_name", "") or ""


def _rank_techniques_by_prior(
    techniques: list[str],
    ctx: PipelineContext,
    *,
    use_ucb: bool = True,
) -> list[tuple[str, float]]:
    """ ASR  ( UCB1 ) ,  (technique_name, prior_asr) .

    Academic basis:
        - Auer et al. (arXiv:cs/0207052) — UCB1 
        - Chao et al. (arXiv:2310.08419) —  ASR 

     (3 Layer fallback):
        1. technique_asr[prior_key][model_family] ()
        2. technique_asr[prior_key]["default"] ()
        3. 0.0 (, )

    L-01:  UCB1  ( use_ucb=True ).
        UCB1 , .

    Args:
        techniques:  ( ["crescendo", "tap", "pair", ...]).
        ctx:  ( model_family).
        use_ucb:  UCB1  ( True,  config ).

    Returns:
         prior ( UCB1 )  (technique_name, prior_asr) .
    """
    from arm.seed_ranking import get_technique_asr_prior, get_technique_experiment_count

    model_name = _get_model_family(ctx)
    ucb_c = _get_ucb_exploration_factor(ctx) if use_ucb else 0.0

    ranked: list[tuple[str, float, float]] = []  # (tech, prior, ucb_score)
    for tech in techniques:
        prior_key = _TECHNIQUE_PRIOR_KEY.get(tech, tech)
        prior = get_technique_asr_prior(prior_key, model_name)
        if prior == 0.0:
            # fallback: 
            prior = get_technique_asr_prior(tech, model_name)

        # L-01:  UCB1  ()
        ucb_score = prior  # :  prior 
        if use_ucb and ucb_c > 0.0:
            try:
                tech_exp_count = get_technique_experiment_count(prior_key, model_name)
                total_exp = max(1, sum(
                    get_technique_experiment_count(_TECHNIQUE_PRIOR_KEY.get(t, t), model_name)
                    for t in techniques
                ))
                ucb_score = _compute_ucb_score(prior, total_exp, tech_exp_count, c=ucb_c)
            except Exception:
                # UCB1  prior 
                pass

        ranked.append((tech, prior, ucb_score))

    #  UCB1  ( prior) 
    ranked.sort(key=lambda x: x[2], reverse=True)

    logger.info(
        "Priority scheduler: technique ranking (model=%s, UCB C=%.3f): %s",
        model_name or "unknown",
        ucb_c,
        ", ".join(f"{t}={p:.0f}%(ucb={u:.1f})" for t, p, u in ranked),
    )

    #  (tech, prior) , 
    return [(tech, prior) for tech, prior, _ in ranked]


def _get_total_experiment_count(techniques: list[str], model_name: str) -> int:
    """all ( UCB1 ).

    Args:
        techniques: .
        model_name: .

    Returns:
        .
    """
    from arm.seed_ranking import get_technique_experiment_count

    total = 0
    for tech in techniques:
        prior_key = _TECHNIQUE_PRIOR_KEY.get(tech, tech)
        total += get_technique_experiment_count(prior_key, model_name)
    return max(1, total)  #  1,  log(0)


def _partition_into_batches(
    ranked: list[tuple[str, float]],
    *,
    high_threshold: float = 60.0,
    low_threshold: float = 40.0,
) -> list[list[tuple[str, float]]]:
    """ prior //.

    Academic basis:
        - Lattner et al. (arXiv:2406.12609) — , 
        - Chao et al. (arXiv:2310.08419) —  ASR 

    :
        -  1 ( prior >= high_threshold): , 
        -  2 ( prior, low_threshold <= prior < high_threshold): 
        -  3 ( prior < low_threshold): , 

    :
        -  1-2 converter(s),  ()
        - , Skip

    Args:
        ranked:  prior  (technique_name, prior_asr) .
        high_threshold:  prior  (default 60%).
        low_threshold:  prior  (default 40%).

    Returns:
        ,  (technique_name, prior_asr) .
    """
    if len(ranked) <= 2:
        # , 
        return [ranked]

    batch_high: list[tuple[str, float]] = []
    batch_mid: list[tuple[str, float]] = []
    batch_low: list[tuple[str, float]] = []

    for tech, prior in ranked:
        if prior >= high_threshold:
            batch_high.append((tech, prior))
        elif prior >= low_threshold:
            batch_mid.append((tech, prior))
        else:
            batch_low.append((tech, prior))

    batches = [b for b in (batch_high, batch_mid, batch_low) if b]

    for i, batch in enumerate(batches):
        logger.info(
            "Priority scheduler: batch %d (%d techniques): %s",
            i + 1,
            len(batch),
            ", ".join(f"{t}={p:.0f}%" for t, p in batch),
        )

    return batches


async def _execute_priority_batches(
    ctx: PipelineContext,
    techniques: list[str],
    attack_runners: dict[str, Callable[[PipelineContext, list[str]], Coroutine[Any, Any, dict[str, list[Any]]]]],
    failed_objectives: list[str],
    *,
    exit_threshold: float = 70.0,
    high_threshold: float = 60.0,
    low_threshold: float = 40.0,
    epsilon: float = 0.1,
    base_attack_results: dict[str, list[Any]] | None = None,
    # L-02: Circuit Breaker  — 
    circuit_breaker_check: Callable[[str, Any | None], bool] | None = None,
    circuit_breaker_record: Callable[[str, bool, Any | None], None] | None = None,
) -> dict[str, list[Any]]:
    """.

    Academic basis:
        - Lattner et al. (arXiv:2406.12609) — , 
        - PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS Extend
        - Auer et al. (arXiv:cs/0207052) — ε--

    Execution flow:
        1.  ASR 
        2. //
        3.  1  →  ASR ≥ exit_threshold? → 
        4.  2  () →  → 
        5.  3  ()
        6. ε-: epsilon  3 converter(s) 1

    Args:
        ctx: .
        techniques: .
        attack_runners: {technique_name: async_func(ctx, objectives) -> dict} .
        failed_objectives: .
        exit_threshold:  ASR  (default 70%, imports post_l1_exit_threshold ).
        high_threshold:  prior  (default 60%).
        low_threshold:  prior  (default 40%).
        epsilon:  (default 0.1, 10%  prior ).

    Args:
        ctx: .
        techniques: .
        attack_runners: {technique_name: async_func(ctx, objectives) -> dict} .
        failed_objectives: .
        exit_threshold:  ASR  (default 70%, imports post_l1_exit_threshold ).
        high_threshold:  prior  (default 60%).
        low_threshold:  prior  (default 40%).
        epsilon:  (default 0.1, 10%  prior ).
        base_attack_results:  ( B/C : ASR 
             { + } , ).

    Returns:
         {technique_name: [AttackResult, ...]} .
    """
    if not techniques or not failed_objectives:
        return {}

    # 1.  ASR 
    ranked = _rank_techniques_by_prior(techniques, ctx)

    # 2. ε-: epsilon  prior 
    if len(ranked) > 2 and random.random() < epsilon:
        #  prior 
        lowest_tech, lowest_prior = ranked[-1]
        # , 
        ranked = [(lowest_tech, lowest_prior)] + [
            (t, p) for t, p in ranked if t != lowest_tech
        ]
        logger.info(
            "Priority scheduler: ε-greedy exploration — promoted '%s' (prior=%.0f%%) to batch 1",
            lowest_tech, lowest_prior,
        )

    # 3. 
    batches = _partition_into_batches(
        ranked,
        high_threshold=high_threshold,
        low_threshold=low_threshold,
    )

    # 4. 
    all_results: dict[str, list[Any]] = {}
    remaining_objectives = list(failed_objectives)

    # v58:  — 
    try:
        from utils.display import (
            _load_tech_asr_data,
            _partition_into_display_batches,
            _print_priority_batch_card,
            _rank_techniques_for_display,
        )
        _display_history, _display_priors = _load_tech_asr_data(techniques, ctx)
        _display_ranked = _rank_techniques_for_display(techniques, _display_priors)
        _display_batches = _partition_into_display_batches(
            _display_ranked,
            high_threshold=high_threshold,
            low_threshold=low_threshold,
        )
        _total_display_batches = len(_display_batches)
        for _bi, (_bl, _bt) in enumerate(_display_batches):
            _print_priority_batch_card(
                batch_label=_bl,
                batch_techs=_bt,
                ctx=ctx,
                tech_asr_history=_display_history,
                batch_idx=_bi,
                total_batches=_total_display_batches,
                exit_threshold=exit_threshold,
            )
    except Exception:
        pass

    for batch_idx, batch in enumerate(batches):
        if not remaining_objectives:
            logger.info(
                "Priority scheduler: batch %d skipped (no remaining failed objectives)",
                batch_idx + 1,
            )
            break

        batch_techs = [t for t, _ in batch]
        logger.info(
            "Priority scheduler: executing batch %d/%d: %s (%d objectives remaining)",
            batch_idx + 1,
            len(batches),
            ", ".join(batch_techs),
            len(remaining_objectives),
        )

        # v57:  —  Seeds → Converters → Scorer
        try:
            from utils.display import print_escalation_tech_start
            for tech_name in batch_techs:
                print_escalation_tech_start(
                    ctx,
                    level=1,
                    technique=tech_name,
                    batch_idx=batch_idx,
                    total_batches=len(batches),
                    objectives_count=len(remaining_objectives),
                )
        except Exception:
            pass

        # 
        _batch_start_time = time.monotonic()

        async def _safe_run(
            tech_name: str,
            runner: Callable[[PipelineContext, list[str]], Coroutine[Any, Any, dict[str, list[Any]]]],
        ) -> dict[str, list[Any]]:
            """,  Circuit Breaker (L-02)."""
            # L-02: Circuit Breaker 
            if circuit_breaker_check is not None and circuit_breaker_check(tech_name, ctx):
                logger.warning(
                    "L-02: Priority scheduler skipping '%s' — circuit breaker is OPEN",
                    tech_name,
                )
                return {}

            try:
                result = await runner(ctx, remaining_objectives)
                # L-02:  ()
                if circuit_breaker_record is not None:
                    success = bool(result and any(result.values()))
                    circuit_breaker_record(tech_name, success, ctx)
                return result
            except Exception as e:
                # L-02: 
                if circuit_breaker_record is not None:
                    circuit_breaker_record(tech_name, False, ctx)
                logger.warning("Priority scheduler: '%s' failed: %s", tech_name, e)
                return {}

        coros = []
        batch_tech_names = []
        for tech_name in batch_techs:
            runner = attack_runners.get(tech_name)
            if runner is not None:
                coros.append(_safe_run(tech_name, runner))
                batch_tech_names.append(tech_name)
            else:
                logger.warning(
                    "Priority scheduler: no runner for technique '%s', skipping",
                    tech_name,
                )

        if not coros:
            continue

        batch_results = await asyncio.gather(*coros, return_exceptions=False)
        _batch_elapsed = time.monotonic() - _batch_start_time

        # v57: 
        try:
            from utils.display import print_escalation_tech_done
            for tech_name in batch_tech_names:
                # : all_results ,  batch_results 
                _tech_success = 0
                _tech_count = 0
                for result_dict in batch_results:
                    if isinstance(result_dict, dict) and tech_name in result_dict:
                        _tech_count = len(result_dict[tech_name])
                        from strike.escalation import _is_success as _esc_is_success
                        _tech_success = sum(1 for r in result_dict[tech_name] if _esc_is_success(r))
                        break
                print_escalation_tech_done(
                    ctx,
                    level=1,
                    technique=tech_name,
                    results_count=_tech_count,
                    success_count=_tech_success,
                    elapsed_seconds=_batch_elapsed,
                )
        except Exception:
            pass

        # 
        for result_dict in batch_results:
            if isinstance(result_dict, dict):
                for tech, results in result_dict.items():
                    if results:
                        all_results.setdefault(tech, []).extend(results)

        #  ()
        if batch_idx < len(batches) - 1:
            #  B/C : ASR  { + } 
            combined_results = dict(base_attack_results) if base_attack_results else {}
            for tech, results in all_results.items():
                if tech in combined_results:
                    combined_results[tech].extend(results)
                else:
                    combined_results[tech] = list(results)

            from strike.escalation import _compute_overall_asr
            cumulative_asr = _compute_overall_asr(combined_results)

            #  ()
            from strike.escalation import _select_failed_objectives
            still_failed = _select_failed_objectives(ctx, combined_results)
            remaining_objectives = still_failed

            logger.info(
                "Priority scheduler: post-batch %d ASR=%.1f%% "
                "(exit threshold=%.1f%%, %d objectives still failed)",
                batch_idx + 1,
                cumulative_asr,
                exit_threshold,
                len(remaining_objectives),
            )

            if cumulative_asr >= exit_threshold:
                logger.info(
                    "Priority scheduler: cumulative ASR %.1f%% >= exit threshold %.1f%% "
                    "— skipping remaining batches (saves ~40-50%% token/time "
                    "per arXiv:2406.12609)",
                    cumulative_asr,
                    exit_threshold,
                )
                # v58: 
                try:
                    from utils.display import print_batch_exit_card
                    print_batch_exit_card(
                        batch_idx=batch_idx,
                        total_batches=len(batches),
                        cumulative_asr=cumulative_asr,
                        exit_threshold=exit_threshold,
                        remaining_failed=len(remaining_objectives),
                    )
                except Exception:
                    pass
                # 
                ctx.orchestration_log.append({
                    "phase": "escalate",
                    "decision": "priority_batch_early_exit",
                    "input": {
                        "batch_completed": batch_idx + 1,
                        "total_batches": len(batches),
                        "cumulative_asr": cumulative_asr,
                        "exit_threshold": exit_threshold,
                    },
                    "output": {
                        "skipped_batches": len(batches) - batch_idx - 1,
                        "techniques_executed": list(all_results.keys()),
                    },
                    "reasoning": (
                        f"Priority scheduler: batch {batch_idx + 1} completed with "
                        f"ASR={cumulative_asr:.1f}% >= {exit_threshold:.1f}%, "
                        f"skipping {len(batches) - batch_idx - 1} remaining batches"
                    ),
                })
                break
            else:
                # v58:  (CONTINUE)
                try:
                    from utils.display import print_batch_exit_card
                    print_batch_exit_card(
                        batch_idx=batch_idx,
                        total_batches=len(batches),
                        cumulative_asr=cumulative_asr,
                        exit_threshold=exit_threshold,
                        remaining_failed=len(remaining_objectives),
                    )
                except Exception:
                    pass

    return all_results
