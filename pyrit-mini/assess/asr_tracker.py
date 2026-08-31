# arXiv:2308.07920 - Zhang et al., Dual Judge cross-validation
# arXiv:2406.12609 - Lattner et al., Parallel scoring throughput
# arXiv:2402.04249 - Mazeika et al., HarmBench scoring baseline
# arXiv:2306.05685 - Zheng et al., LLM-as-a-Judge robustness
# arXiv:2307.08673 - Zou et al., GCG
"""ASR (Attack Success Rate) 统计 + 历史写入。

重构说明 (v57):
    本文件已从 656 行拆分为以下模块:
    - assess/precompute.py   — precompute_outcomes_async (异步预计算管线)
    - assess/asr_compute.py  — compute_asr, compute_wilson_score_interval, collect_dual_judge_stats
    - assess/asr_stats.py    — 全局统计工具函数 (compute_cohens_kappa, compute_overall_asr 等)
    - assess/asr_history.py  — ASR 历史持久化
    - assess/dual_judge.py   — LLM 双 Judge 初始化和评分

    本文件保留为 re-export 层, 供向后兼容。
    下游代码可通过 `from assess.asr_tracker import precompute_outcomes_async` 继续使用。
"""

# ── 从拆分模块 re-export (向后兼容) ──
# 以下函数从拆分模块导入以保持向后兼容
from assess.asr_compute import (  # noqa: F401, E402
    collect_dual_judge_stats,
    compute_asr,
    compute_wilson_score_interval,
)
from assess.asr_history import (  # noqa: F401, E402
    _save_converter_asr_history,
    _save_gcg_suffix_asr_history,
    save_asr_history,
)
from assess.asr_stats import (  # noqa: F401, E402
    _dual_judge_agreements,
    _dual_judge_disagreements,
    _dual_judge_judge1_successes,
    _dual_judge_judge2_successes,
    _dual_judge_third_arbitrated_success,
    _dual_judge_third_invoked,
    _dual_judge_total_scored,
    _get_outcome,
    _reset_dual_judge_stats,
    compute_cohens_kappa,
    compute_overall_asr,
    get_dual_judge_stats,
)
from assess.precompute import precompute_outcomes_async  # noqa: F401, E402

__all__ = [
    # precompute
    "precompute_outcomes_async",
    # asr_compute
    "compute_asr",
    "compute_wilson_score_interval",
    "collect_dual_judge_stats",
    # asr_history
    "save_asr_history",
    "_save_converter_asr_history",
    "_save_gcg_suffix_asr_history",
    # asr_stats
    "compute_cohens_kappa",
    "compute_overall_asr",
    "get_dual_judge_stats",
    "_reset_dual_judge_stats",
    "_get_outcome",
    "_dual_judge_total_scored",
    "_dual_judge_agreements",
    "_dual_judge_disagreements",
    "_dual_judge_judge1_successes",
    "_dual_judge_judge2_successes",
    "_dual_judge_third_invoked",
    "_dual_judge_third_arbitrated_success",
]
