"""assess — 评分判定阶段。

攻击链路第 5 步: 对攻击结果进行评分, 计算 ASR, 双 Judge 交叉验证。

核心模块 (SSOT):
    - score_pipeline: 评分管线 (响应解析 + 异步预计算, 原 precompute + response_parser 合并)
    - asr_manager: ASR 统一管理 (统计 + 历史 + 联合 ASR, 原 asr_compute + asr_history + joint_asr 合并)
    - asr_stats: 双 Judge 统计 + Cohen's Kappa + Wilson Score CI (全局计数器 SSOT)
    - scorer: 评分器注册 (AdaptiveDualJudgeScorer + fallback)
    - adaptive_dual_judge: 自适应双 Judge (高置信度直接返回)
    - judge_manager: LLM 双判 + 仲裁 + 并发式判
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
