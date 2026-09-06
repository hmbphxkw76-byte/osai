"""assess — 评分判定阶段。

攻击链路第 5 步: 对攻击结果进行评分, 计算 ASR, 双 Judge 交叉验证。

核心模块:
    - scorer: 评分器注册 (AdaptiveDualJudgeScorer + fallback)
    - asr_tracker: ASR 统计 + 双 Judge 预计算
    - asr_stats: Cohen's Kappa + Wilson Score CI
    - adaptive_dual_judge: 自适应双 Judge (高置信度直接返回)
    - dual_judge: LLM 双判 + 仲裁 + 并发式判
"""

from assess.asr_compute import compute_asr
from assess.asr_stats import compute_overall_asr
from assess.precompute import precompute_outcomes_async
from assess.scorer import create_objective_scorer

__all__ = [
    "create_objective_scorer",
    "precompute_outcomes_async",
    "compute_asr",
    "compute_overall_asr",
]
