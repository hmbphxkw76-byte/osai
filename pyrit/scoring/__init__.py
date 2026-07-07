"""
===============================================================================
OffSec AI-300 — 评分引擎模块 (Scoring)
===============================================================================
PyRIT 对齐：从 executor/scorer.py 提取独立评分包。
包含：CleanedSelfAskTrueFalseScorer、评分器工厂、拒绝检测等。

使用方式:
  from scoring import CleanedSelfAskTrueFalseScorer, create_best_scorer, is_likely_refusal
===============================================================================
"""
from executor.scorer import (
    CleanedSelfAskTrueFalseScorer,
    create_best_scorer,
    detect_attack_type,
    is_likely_refusal,
)

__all__ = [
    "CleanedSelfAskTrueFalseScorer",
    "create_best_scorer",
    "detect_attack_type",
    "is_likely_refusal",
]
