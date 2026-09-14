# -*- coding: utf-8 -*-
"""RAG Metadata Extraction — 从 RAG 检索响应抽取结构化元数据（coverage 策略 metadata_extraction）。

真实解析：遍历检索返回的 chunks，按别名识别 source / chunk_id / score / title / timestamp 等
元数据字段，构建 KB 元数据画像，供后续定向投毒与抽取（PoisonedRAG / Document Enumeration）。

Black-box 假设（R-S1 不硬编码目标）：chunk 结构由响应推断，仅做字段别名匹配。

Academic basis:
    - Kandpal et al. (arXiv:2308.14032) — Document Enumeration
    - Zou et al. (arXiv:2406.04245) — PoisonedRAG

Constitution compliance:
    - R-H3: 单一职责 — metadata extraction only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_SOURCE_ALIASES = ("source", "src", "path", "file", "document", "doc_id", "url", "doc")
_CHUNK_ID_ALIASES = ("chunk_id", "chunk", "cid", "index", "position", "id")
_SCORE_ALIASES = ("score", "similarity", "relevance", "rank", "distance", "bm25")
_TITLE_ALIASES = ("title", "name", "heading", "topic")
_TS_ALIASES = ("timestamp", "created", "updated", "date", "time")


@dataclass
class MetadataExtractionResult:
    """元数据抽取结果。"""

    sources: list[str] = field(default_factory=list)
    chunk_ids: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    score_range: tuple[float, float] = (0.0, 0.0)
    field_coverage: dict[str, int] = field(default_factory=dict)
    chunks_seen: int = 0
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict。"""
        return {
            "sources": self.sources,
            "chunk_ids": self.chunk_ids,
            "titles": self.titles,
            "timestamps": self.timestamps,
            "score_range": list(self.score_range),
            "field_coverage": self.field_coverage,
            "chunks_seen": self.chunks_seen,
            "success": self.success,
        }


def _grab(chunk: dict[str, Any], aliases: tuple[str, ...]) -> list[Any]:
    """按别名从 chunk（或 chunk.metadata）抽取字段值。"""
    found: list[Any] = []
    meta = chunk.get("metadata", chunk)
    if isinstance(meta, dict):
        for key, value in meta.items():
            if str(key).lower() in aliases and value not in (None, ""):
                found.append(value)
    return found


def _to_float(values: list[Any]) -> list[float]:
    out: list[float] = []
    for v in values:
        try:
            out.append(float(v))
        except (TypeError, ValueError):
            pass
    return out


def run_metadata_extraction(response: dict[str, Any]) -> MetadataExtractionResult:
    """从 RAG 检索响应抽取结构化元数据。

    Args:
        response: 解析后的 RAG 响应，含 "chunks" / "results" 列表，
            每个元素为含 metadata 字段的 dict

    Returns:
        MetadataExtractionResult，含抽取到的 source / chunk_id / score 等画像
    """
    result = MetadataExtractionResult()
    if not isinstance(response, dict):
        return result

    chunks = response.get("chunks") or response.get("results") or response.get("documents") or []
    if not isinstance(chunks, list):
        chunks = [chunks]
    result.chunks_seen = len(chunks)

    scores: list[float] = []
    coverage = {"source": 0, "chunk_id": 0, "score": 0, "title": 0, "timestamp": 0}

    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        sources = [str(s) for s in _grab(chunk, _SOURCE_ALIASES)]
        ids = [str(s) for s in _grab(chunk, _CHUNK_ID_ALIASES)]
        titles = [str(s) for s in _grab(chunk, _TITLE_ALIASES)]
        tss = [str(s) for s in _grab(chunk, _TS_ALIASES)]
        sc = _to_float(_grab(chunk, _SCORE_ALIASES))

        result.sources.extend(sources)
        result.chunk_ids.extend(ids)
        result.titles.extend(titles)
        result.timestamps.extend(tss)
        scores.extend(sc)

        if sources:
            coverage["source"] += 1
        if ids:
            coverage["chunk_id"] += 1
        if sc:
            coverage["score"] += 1
        if titles:
            coverage["title"] += 1
        if tss:
            coverage["timestamp"] += 1

    result.sources = list(dict.fromkeys(result.sources))
    result.chunk_ids = list(dict.fromkeys(result.chunk_ids))
    result.field_coverage = coverage
    if scores:
        result.score_range = (min(scores), max(scores))
    result.success = result.chunks_seen > 0
    return result
