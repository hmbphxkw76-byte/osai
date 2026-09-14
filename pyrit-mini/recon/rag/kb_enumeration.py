# -*- coding: utf-8 -*-
"""RAG Knowledge Base Enumeration — 枚举 KB 结构与规模（coverage 策略 kb_enumeration）。

真实解析：汇总多轮查询返回的 chunks，去重统计 distinct source / document，基于 chunk_id
取值范围估计索引规模与分片数，输出 KB 结构画像（Document Enumeration）。

Black-box 假设（R-S1 不硬编码目标）：结构从观测 chunk 推断，无白盒假设。

Constitution compliance:
    - R-H3: 单一职责 — knowledge base enumeration only
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_SOURCE_ALIASES = ("source", "src", "path", "file", "document", "doc_id", "url")


@dataclass
class KBEnumerationResult:
    """KB 枚举结果。"""

    distinct_sources: list[str] = field(default_factory=list)
    estimated_doc_count: int = 0
    estimated_chunk_count: int = 0
    shard_hints: list[str] = field(default_factory=list)
    id_range: tuple[int, int] = (0, 0)
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict。"""
        return {
            "distinct_sources": self.distinct_sources,
            "estimated_doc_count": self.estimated_doc_count,
            "estimated_chunk_count": self.estimated_chunk_count,
            "shard_hints": self.shard_hints,
            "id_range": list(self.id_range),
            "success": self.success,
        }


def _source_of(chunk: Any) -> str | None:
    if not isinstance(chunk, dict):
        return None
    for k, v in chunk.items():
        if str(k).lower() in _SOURCE_ALIASES and v:
            return str(v)
    meta = chunk.get("metadata", {})
    if isinstance(meta, dict):
        for k, v in meta.items():
            if str(k).lower() in _SOURCE_ALIASES and v:
                return str(v)
    return None


def _id_int(chunk: Any) -> int | None:
    if not isinstance(chunk, dict):
        return None
    for k in ("chunk_id", "id", "index", "cid", "position"):
        v = chunk.get(k)
        if v is None and isinstance(chunk.get("metadata"), dict):
            v = chunk["metadata"].get(k)
        if v is not None:
            m = re.search(r"(\d+)", str(v))
            if m:
                return int(m.group(1))
    return None


def run_kb_enumeration(chunks_by_query: Any) -> KBEnumerationResult:
    """枚举 KB 结构。

    Args:
        chunks_by_query: list[list[dict]]，每轮查询返回的 chunks

    Returns:
        KBEnumerationResult
    """
    result = KBEnumerationResult()
    if not isinstance(chunks_by_query, list):
        chunks_by_query = [chunks_by_query]
    all_chunks: list[Any] = []
    for q in chunks_by_query:
        if isinstance(q, list):
            all_chunks.extend(q)
        elif isinstance(q, dict):
            all_chunks.append(q)

    sources: set[str] = set()
    ids: list[int] = []
    shards: set[str] = set()
    for c in all_chunks:
        s = _source_of(c)
        if s:
            sources.add(s)
            m = re.search(r"(shard|part|vol)[-_ ]?(\d+)", s, re.IGNORECASE)
            if m:
                shards.add(m.group(0).lower())
        i = _id_int(c)
        if i is not None:
            ids.append(i)

    result.distinct_sources = sorted(sources)
    result.shard_hints = sorted(shards)
    result.estimated_chunk_count = len(all_chunks)
    result.estimated_doc_count = max(len(sources), 1)
    if ids:
        result.id_range = (min(ids), max(ids))
        span = max(ids) - min(ids)
        # 若 chunk id 跨度远大于观测数，说明索引规模更大
        if span > len(ids) * 2:
            result.estimated_chunk_count = span + 1
    result.success = bool(sources) or bool(ids)
    return result
