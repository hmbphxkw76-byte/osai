# -*- coding: utf-8 -*-
"""Embedding Extraction — 从 embedding API 响应抽取向量（coverage 策略 embedding_extraction）。

真实解析：从 OpenAI 风格 embedding 响应 {"data":[{"embedding":[...]}]} 中抽取向量与维度；
client 由调用方注入，便于 mock（R-S4），不在此处发起网络请求。

Constitution compliance:
    - R-H3: 单一职责 — embedding extraction only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EmbeddingExtractionResult:
    """embedding 抽取结果。"""

    embedding: list[float] = field(default_factory=list)
    dimension: int = 0
    model: str = ""
    index: int = 0
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict。"""
        return {
            "dimension": self.dimension,
            "model": self.model,
            "index": self.index,
            "preview": self.embedding[:8],
            "success": self.success,
        }


def run_embedding_extraction(response: Any) -> EmbeddingExtractionResult:
    """从 embedding API 响应抽取首条向量。

    Args:
        response: dict，含 "data" 列表，每项有 "embedding" 向量

    Returns:
        EmbeddingExtractionResult
    """
    result = EmbeddingExtractionResult()
    if not isinstance(response, dict):
        return result
    data = response.get("data") or []
    if not isinstance(data, list) or not data:
        return result
    first = data[0] if isinstance(data[0], dict) else {}
    vec = first.get("embedding") or []
    if not isinstance(vec, list) or not vec:
        return result
    try:
        result.embedding = [float(x) for x in vec]
    except (TypeError, ValueError):
        return result
    result.dimension = len(result.embedding)
    result.model = str(response.get("model", first.get("model", "")))
    result.index = int(first.get("index", 0))
    result.success = True
    return result
