"""module."""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from core.context import PipelineContext
logger = logging.getLogger(__name__)
async def _run_assess_phase(ctx: "PipelineContext") -> None:
    from utils.display import print_assess_card, print_phase, print_status
    args = ctx.args
    from assess.asr_manager import (
    from assess.score_pipeline import precompute_outcomes_async
    _assess_reset_stats = not getattr(ctx.args, "escalation", True)
    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False, reset_stats=_assess_reset_stats)
    except Exception as e:
    ctx.asr_per_technique = compute_asr(ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(ctx.asr_per_technique)
    save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)
    if ctx.parsed_request:
        model_family = ctx.parsed_request.target_fingerprint.get("model_family")
        if model_family:
            from arm.seed_ranker import update_asr_priors
    from assess.asr_stats import _get_outcome as _get_attack_outcome
    total_successes = sum(
        for r in results
        if _get_attack_outcome(r) == "success"
    total_decided = sum(
        for r in results
        if _get_attack_outcome(r) in ("success", "failure")
    wilson_lower, wilson_upper = compute_wilson_score_interval(total_successes, total_decided)
    ctx.wilson_ci = (wilson_lower, wilson_upper)
    ctx.dual_judge_stats = collect_dual_judge_stats(ctx)
    if ctx.dual_judge_stats:
        from assess.asr_stats import compute_cohens_kappa
        kappa = compute_cohens_kappa(
        ctx.dual_judge_stats["cohens_kappa"] = kappa
        from core.phases._helpers import _log_dual_judge_stats
    if getattr(args, "stage", None) == "assess":
        print_status("ASSESS", "DONE", "", ok=True)
        return
    _dual_judge_enabled = getattr(ctx.args, "dual_judge_enabled", True)
    _wilson_level = getattr(ctx.args, "wilson_confidence_level", 0.95)