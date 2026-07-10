"""
===============================================================================
PyRIT Red Team — 评分引擎模块 (Scoring)
===============================================================================
PyRIT 对齐：从 executor/scorer.py 提取独立评分包。

包含:
  - CleanedSelfAskTrueFalseScorer: 防假阴性评分器
  - create_best_scorer: 智能评分器工厂
  - detect_attack_type: 攻击类型检测
  - is_likely_refusal: 快速拒绝检测

  🆕 P0-P1 新评分器:
  - HybridScorer: 多层次混合评分器 (Weighted Voting Ensemble)
  - FastGrayscaleScorer: 快速灰度评分器 (0-1 连续评分)
  - GrayscaleLevel: 灰度等级枚举
  - HybridScoreResult: 混合评分结果

使用方式:
  from scoring import (
      CleanedSelfAskTrueFalseScorer, create_best_scorer, is_likely_refusal,
      HybridScorer, FastGrayscaleScorer, GrayscaleLevel,
  )
===============================================================================
"""
from executor.scorer import (
    CleanedSelfAskTrueFalseScorer,
    create_best_scorer,
    detect_attack_type,
    is_likely_refusal,
)

from scoring.hybrid import (
    HybridScorer,
    FastGrayscaleScorer,
    GrayscaleLevel,
    HybridScoreResult,
    KeywordDensityScorer,
    RefusalPatternScorer,
)

__all__ = [
    "CleanedSelfAskTrueFalseScorer",
    "create_best_scorer",
    "detect_attack_type",
    "is_likely_refusal",
    "HybridScorer",
    "FastGrayscaleScorer",
    "GrayscaleLevel",
    "HybridScoreResult",
    "KeywordDensityScorer",
    "RefusalPatternScorer",
]
