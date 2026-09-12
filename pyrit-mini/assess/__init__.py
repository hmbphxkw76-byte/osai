"""assess — Scoring phase.

Attack pipeline step 5: Score attack results, calculate ASR, dual Judge cross-validation.

Core modules (SSOT):
    - score_pipeline: Scoring pipeline (response parsing + async precompute, merged from precompute + response_parser)
    - asr_manager: ASR unified management (statistics + history + joint ASR, merged from asr_compute + asr_history + joint_asr)
    - asr_stats: Dual Judge statistics + Cohen's Kappa + Wilson Score CI (global counter SSOT)
    - scorer: Scorer registration (AdaptiveDualJudgeScorer + fallback)
    - adaptive_dual_judge: Adaptive dual Judge (high confidence direct return)
    - judge_manager: LLM dual judging + arbitration + concurrent judging
    - component_scorers: Component-specific T0 heuristics (MCP/A2A/Model)
    - component_router: Component-aware scoring router (classification + dispatch)
"""

from assess.asr_manager import (
    compute_asr,
    compute_overall_asr,
    compute_wilson_score_interval,
    save_asr_history,
)
from assess.asr_stats import compute_cohens_kappa
from assess.component_router import classify_component_from_result, run_component_t0
from assess.component_scorers import (
    get_all_component_types,
    get_component_rubric_path,
    get_t0_checker,
    is_component_rubric_available,
    t0_a2a_agent_integrity_check,
    t0_mcp_tool_poisoning_check,
    t0_model_behavior_shift_check,
    t0_rag_pipeline_check,
    t0_session_memory_check,
    t0_web_api_check,
)
from assess.score_pipeline import precompute_outcomes_async

__all__ = [
    "precompute_outcomes_async",
    "compute_asr",
    "compute_overall_asr",
    "compute_wilson_score_interval",
    "compute_cohens_kappa",
    "save_asr_history",
    # L5 v60: Component-specific scoring
    "classify_component_from_result",
    "run_component_t0",
    "t0_mcp_tool_poisoning_check",
    "t0_a2a_agent_integrity_check",
    "t0_model_behavior_shift_check",
    "t0_rag_pipeline_check",
    "t0_session_memory_check",
    "t0_web_api_check",
    "is_component_rubric_available",
    "get_all_component_types",
    "get_component_rubric_path",
    "get_t0_checker",
]
