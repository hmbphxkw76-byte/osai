""" ASSESS  + ASR .

Academic basis:
    - arXiv:2308.07920 (Judge )
    - Wilson Score CI ()
    - Cohen's Kappa ()
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

async def _run_assess_phase(
        ctx: "PipelineContext") -> None:
    """(5) ASSESS : + ASR """
    from utils.display import print_assess_card, print_phase, print_status

    args = ctx.args
    print_phase(
        "ASSESS", " Judge  & ASR ...")

    from assess.asr_manager import (
        collect_dual_judge_stats,
        compute_asr,
        compute_overall_asr,
        compute_wilson_score_interval,
        save_asr_history,
    )
    from assess.asr_stats import (
        compute_cohens_kappa,
    )
    from assess.score_pipeline import precompute_outcomes_async
    from core.phases._helpers import _log_dual_judge_stats

    _assess_reset_stats = not getattr(
        ctx.args, "escalation", True)
    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False, reset_stats=_assess_reset_stats, ctx=ctx)
    except Exception as e:
        logger.error(
            ": %s - ", e)

    ctx.asr_per_technique = compute_asr(
        ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(
        ctx.asr_per_technique)
    save_asr_history(
        ctx.asr_per_technique, attack_results=ctx.attack_results)

    # asr_priors.yaml
    if ctx.parsed_request:
        model_family = ctx.parsed_request.target_fingerprint.get(
            "model_family")
        if model_family:
            from arm.seed_ranker import update_asr_priors
            update_asr_priors(
                model_family, ctx.asr_per_technique)

    # Wilson
    # Score
    # CI
    from assess.asr_stats import _get_outcome as _get_attack_outcome
    total_successes = sum(
        1 for results in ctx.attack_results.values()
        for r in results
        if _get_attack_outcome(r) == "success"
    )
    total_decided = sum(
        1 for results in ctx.attack_results.values()
        for r in results
        if _get_attack_outcome(r) in ("success", "failure")
    )
    wilson_lower, wilson_upper = compute_wilson_score_interval(
        total_successes, total_decided)
    logging.info(
        "ASR Wilson Score 95%% CI: [%.1f%%, %.1f%%] (: %.1f%%)",
        wilson_lower, wilson_upper, ctx.overall_asr,
    )
    ctx.wilson_ci = (
        wilson_lower, wilson_upper)

    # Judge
    ctx.dual_judge_stats = collect_dual_judge_stats(
        ctx)
    if ctx.dual_judge_stats:
        kappa = compute_cohens_kappa(
            ctx.dual_judge_stats.get(
                "agreements", 0),
            ctx.dual_judge_stats.get(
                "disagreements", 0),
        )
        ctx.dual_judge_stats[
            "cohens_kappa"] = kappa
        _log_dual_judge_stats(
            ctx.dual_judge_stats)

    #
    print_assess_card(
        ctx)

    # --stage assess
    if getattr(
            args, "stage", None) == "assess":
        print_status(
            "ASSESS", "DONE", "", ok=True)
        return

    # ASSESS
    _dual_judge_enabled = getattr(
        ctx.args, "dual_judge_enabled", True)
    _wilson_level = getattr(
        ctx.args, "wilson_confidence_level", 0.95)
    ctx.orchestration_log.append({
        "phase": "assess",
        "decision": "scoring_assessment",
        "input": {
            "total_attacks": sum(len(v) for v in ctx.attack_results.values()),
            "scoring_model": "T0->J1->J2 OR  ( 2-LLM)" if _dual_judge_enabled else "T0->J1 (single judge)",
            "dual_judge_enabled": _dual_judge_enabled,
            "wilson_confidence_level": _wilson_level,
        },
        "output": {
            "overall_asr": ctx.overall_asr,
            "wilson_ci": list(ctx.wilson_ci),
            "asr_per_technique": ctx.asr_per_technique,
            "dual_judge_invoked": ctx.dual_judge_stats.get("dual_judge_invoked", 0),
            "cohens_kappa": ctx.dual_judge_stats.get("cohens_kappa", 0.0),
        },
        "reasoning": (
            "arXiv:2308.07920  Judge  + T0  (0 token) + "
            "Wilson Score 95% CI + Cohen's Kappa "
        ),
    })

    # === 数据流完整性快照: post_assess ===
    try:
        from tools.data_flow_hooks import snapshot_hook
        snapshot_hook(ctx, "post_assess")
    except Exception as e:
        logger.debug("[Assess] Data flow snapshot skipped: %s", e)
