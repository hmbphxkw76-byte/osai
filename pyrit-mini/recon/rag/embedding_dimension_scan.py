# -*- coding: utf-8 -*-
"""RAG Embedding Dimension Scan — 推断检索器 embedding 维度（coverage 策略 embedding_dimension_scan）。

真实解析：扫描检索 chunks 中的 embedding / vector 字段推断向量维度；若响应仅含分数，
则基于分数分布与已知模型维度表给出候选维度（黑盒推断，不执行 HTTP）。

Black-box 假设（R-S1 不硬编码目标）：维度仅从观测数据与公开模型线索推断。

Constitution compliance:
    - R-H3: 单一职责 — embedding dimension scan only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# 常见 embedding 模型维度线索（仅作推断参考，不硬编码目标）
_KNOWN_DIM_HINTS = {
    "ada-002": 1536,
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "bge": 1024,
    "e5": 1024,
    "mpnet": 768,
    "mini": 384,
}


@dataclass
class EmbeddingDimensionScanResult:
    """embedding 维度扫描结果。"""

    observed_dimension: int = 0
    candidate_dimensions: list[int] = field(default_factory=list)
    score_min: float = 0.0
    score_max: float = 0.0
    inferred_from: str = ""
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict。"""
        return {
            "observed_dimension": self.observed_dimension,
            "candidate_dimensions": self.candidate_dimensions,
            "score_min": self.score_min,
            "score_max": self.score_max,
            "inferred_from": self.inferred_from,
            "success": self.success,
        }


def _scan_vector(chunks: list[Any]) -> int:
    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        for key in ("embedding", "vector", "vec"):
            v = chunk.get(key)
            if isinstance(v, list) and v:
                return len(v)
        meta = chunk.get("metadata", {})
        if isinstance(meta, dict):
            v = meta.get("embedding") or meta.get("vector")
            if isinstance(v, list) and v:
                return len(v)
    return 0


def run_embedding_dimension_scan(response: Any, *, model_hint: str | None = None) -> EmbeddingDimensionScanResult:
    """推断检索器的 embedding 维度。

    Args:
        response: RAG 响应 dict（含 chunks）或直接为 chunks 列表
        model_hint: 可选模型族提示，用于匹配维度线索

    Returns:
        EmbeddingDimensionScanResult
    """
    result = EmbeddingDimensionScanResult()
    if isinstance(response, dict):
        chunks = response.get("chunks") or response.get("results") or []
    elif isinstance(response, list):
        chunks = response
    else:
        chunks = []
    if not isinstance(chunks, list):
        chunks = [chunks]

    dim = _scan_vector(chunks)
    if dim:
        result.observed_dimension = dim
        result.inferred_from = "vector_field"
        result.success = True
        return result

    # 仅分数：从分数分布给候选维度
    scores: list[float] = []
    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        for k in ("score", "similarity", "distance"):
            try:
                scores.append(float(chunk.get(k)))
            except (TypeError, ValueError):
                pass
    if scores:
        result.score_min, result.score_max = min(scores), max(scores)
        result.inferred_from = "score_distribution"
    if model_hint:
        for name, d in _KNOWN_DIM_HINTS.items():
            if name in str(model_hint).lower():
                result.candidate_dimensions.append(d)
    result.success = bool(result.candidate_dimensions) or bool(scores)
    return result
