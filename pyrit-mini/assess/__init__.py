"""assess — Scoring phase.

Attack pipeline step 5: Score attack results, calculate ASR, dual Judge cross-validation.

Core modules (SSOT):
    - score_pipeline: Scoring pipeline (response parsing + async precompute, merged from precompute + response_parser)
    - asr_manager: ASR unified management (statistics + history + joint ASR, merged from asr_compute + asr_history + joint_asr)
    - asr_stats: Dual Judge statistics + Cohen's Kappa + Wilson Score CI (global counter SSOT)
    - scorer: Scorer registration (AdaptiveDualJudgeScorer + fallback)
    - adaptive_dual_judge: Adaptive dual Judge (high confidence direct return)
    - judge_manager: LLM dual judging + arbitration + concurrent judging
"""

from assess.asr_manager import (
    compute_asr,
    compute_overall_asr,
    compute_wilson_score_interval,
    save_asr_history,
)
from assess.asr_stats import compute_cohens_kappa
from assess.score_pipeline import precompute_outcomes_async
from assess.scorer import create_objective_scorer

__all__ = [
    "create_objective_scorer",
    "precompute_outcomes_async",
    "compute_asr",
    "compute_overall_asr",
    "compute_wilson_score_interval",
    "compute_cohens_kappa",
    "save_asr_history",
]
