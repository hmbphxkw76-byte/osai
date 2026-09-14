# -*- coding: utf-8 -*-
"""Embedding Similarity Behavior Analysis — 分析 embedding 相似度分布（coverage 策略 similarity_behavior_analysis）。

真实解析：对一组 embedding 向量计算余弦相似度分布（均值/最值/标准差），判断是否归一化，
并给出检索操纵可用的相似度阈值建议。纯数学实现，无需网络。

Constitution compliance:
    - R-H3: 单一职责 — similarity behavior analysis only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SimilarityBehaviorResult:
    """相似度行为分析结果。"""

    pair_count: int = 0
    mean_similarity: float = 0.0
    min_similarity: float = 0.0
    max_similarity: float = 0.0
    std_similarity: float = 0.0
    is_normalized: bool = False
    recommended_threshold: float = 0.0
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict。"""
        return {
            "pair_count": self.pair_count,
            "mean_similarity": self.mean_similarity,
            "min_similarity": self.min_similarity,
            "max_similarity": self.max_similarity,
            "std_similarity": self.std_similarity,
            "is_normalized": self.is_normalized,
            "recommended_threshold": self.recommended_threshold,
            "success": self.success,
        }


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def run_similarity_behavior_analysis(embeddings: Any) -> SimilarityBehaviorResult:
    """分析 embedding 相似度行为。

    Args:
        embeddings: list[list[float]]，待比较的向量集合

    Returns:
        SimilarityBehaviorResult
    """
    result = SimilarityBehaviorResult()
    if not isinstance(embeddings, list) or len(embeddings) < 2:
        return result
    vecs = [v for v in embeddings if isinstance(v, list) and v]
    if len(vecs) < 2:
        return result

    norms = [math.sqrt(sum(x * x for x in v)) for v in vecs]
    result.is_normalized = all(abs(n - 1.0) < 0.05 for n in norms)

    sims: list[float] = []
    for i in range(len(vecs)):
        for j in range(i + 1, len(vecs)):
            sims.append(_cosine(vecs[i], vecs[j]))
    if not sims:
        return result

    result.pair_count = len(sims)
    result.min_similarity = min(sims)
    result.max_similarity = max(sims)
    result.mean_similarity = sum(sims) / len(sims)
    var = sum((s - result.mean_similarity) ** 2 for s in sims) / len(sims)
    result.std_similarity = math.sqrt(var)
    # 阈值建议：均值 + 1 标准差，作为"高相似"判定线
    result.recommended_threshold = min(1.0, result.mean_similarity + result.std_similarity)
    result.success = True
    return result
