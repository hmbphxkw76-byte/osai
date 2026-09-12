# -*- coding: utf-8 -*-
"""RAG metadata data structures, field-schema constants, and leaf helpers.

SRP split from `metadata_parser.py` (R-DELIVERY-1 / REQ): this module owns the
*definitions* — dataclasses, alias/path schemas, and pure nested/alias access
helpers — with no parsing or I/O logic of its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RetrievedChunk:
    """Single retrieved passage/chunk with full metadata.

    Attacker value:
        chunk_id: Reveals document structure and chunking strategy
        text: Raw content bypassing LLM summarization/redaction
        score fields: Enable threshold inference and ranking analysis
        source/doc_id: Knowledge base mapping across queries
    """

    chunk_id: str = ""
    source_title: str = ""
    source_path: str = ""
    text: str = ""
    text_length: int = 0
    vector_score: float | None = None
    bm25_score: float | None = None
    combined_score: float | None = None
    rank: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "source_title": self.source_title,
            "source_path": self.source_path,
            "text": self.text[:200],  # Truncate for storage
            "text_length": self.text_length,
            "vector_score": self.vector_score,
            "bm25_score": self.bm25_score,
            "combined_score": self.combined_score,
            "rank": self.rank,
        }


@dataclass
class RetrievalTiming:
    """Timing decomposition for RAG response analysis.

    Attacker value:
        retrieval_time <> generation_time: reveals caching behavior
        total_time: overall latency baseline
    """

    retrieval_time_ms: float | None = None
    generation_time_ms: float | None = None
    total_time_ms: float | None = None

    @property
    def cache_hit_probability(self) -> float:
        """Estimate cache hit probability based on retrieval timing.

        Academic basis:
            - Pessl et al. (arXiv:1901.01322) — Cache timing side-channels
            - Gao et al. (arXiv:2311.10536 §4.3) — RAG latency profiling

        Heuristic:
            - retrieval_time < 5ms → high probability cache hit (>0.8)
            - retrieval_time > 100ms → low probability cache hit (<0.3)
            - Linear interpolation in between
        """
        if self.retrieval_time_ms <= 0:
            return 0.5  # Unknown
        if self.retrieval_time_ms < 5.0:
            return 0.9  # Almost certainly cached
        if self.retrieval_time_ms > 100.0:
            return 0.1  # Almost certainly not cached
        # Linear interpolation: 5ms→0.8, 100ms→0.2
        return max(0.1, min(0.9, 0.8 - (self.retrieval_time_ms - 5) * (0.6 / 95)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "retrieval_time_ms": self.retrieval_time_ms,
            "generation_time_ms": self.generation_time_ms,
            "total_time_ms": self.total_time_ms,
        }


@dataclass
class RAGResponseMetadata:
    """Complete parsed metadata from a single RAG response.

    This is the primary data structure returned by the parser.
    It contains all extractable intelligence from one RAG API call.
    """

    # Core retrieval data
    chunks: list[RetrievedChunk] = field(default_factory=list)
    num_chunks: int = 0

    # Timing analysis
    timing: RetrievalTiming = field(default_factory=RetrievalTiming)

    # Knowledge base mapping (aggregated from chunks)
    unique_sources: list[str] = field(default_factory=list)
    unique_chunk_ids: list[str] = field(default_factory=list)

    # Score analysis
    score_range_vector: tuple[float, float] | None = None
    score_range_bm25: tuple[float, float] | None = None
    score_range_combined: tuple[float, float] | None = None

    # Response metadata
    has_structured_sources: bool = False
    raw_response_keys: list[str] = field(default_factory=list)
    format_type: str = "unknown"  # openai_rag, cohere, anthropic, custom

    def to_dict(self) -> dict[str, Any]:
        return {
            "num_chunks": self.num_chunks,
            "chunks": [c.to_dict() for c in self.chunks[:10]],  # Limit storage
            "timing": self.timing.to_dict(),
            "unique_sources": self.unique_sources[:50],
            "unique_chunk_ids": self.unique_chunk_ids[:50],
            "score_range_vector": self.score_range_vector,
            "score_range_bm25": self.score_range_bm25,
            "score_range_combined": self.score_range_combined,
            "has_structured_sources": self.has_structured_sources,
            "format_type": self.format_type,
        }


@dataclass
class KnowledgeBaseMap:
    """Aggregated knowledge base structure from multiple RAG queries.

    Built by combining results from multiple queries to map the entire KB.

    Academic basis:
        - Iterative knowledge base probing (Greshake et al., arXiv:2302.12173)
        - Document enumeration attacks (Kandpal et al., arXiv:2308.14032)

    Attacker value:
        - Complete document inventory: all indexed documents
        - Chunk count estimation: per-document size inference
        - Sensitivity scoring: which documents contain sensitive content
    """

    total_queries: int = 0
    total_chunks_observed: int = 0
    unique_documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    chunk_id_patterns: dict[str, int] = field(default_factory=dict)
    score_statistics: dict[str, dict[str, float]] = field(default_factory=dict)
    inferred_chunk_size: int | None = None
    inferred_chunk_overlap: int | None = None
    inferred_retrieval_formula: str = "unknown"

    @property
    def document_count(self) -> int:
        return len(self.unique_documents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "total_chunks_observed": self.total_chunks_observed,
            "document_count": self.document_count,
            "documents": {k: v for k, v in list(self.unique_documents.items())[:100]},
            "chunk_id_patterns": dict(sorted(self.chunk_id_patterns.items(), key=lambda x: -x[1])[:20]),
            "score_statistics": self.score_statistics,
            "inferred_chunk_size": self.inferred_chunk_size,
            "inferred_chunk_overlap": self.inferred_chunk_overlap,
            "inferred_retrieval_formula": self.inferred_retrieval_formula,
        }


# ====================================================================
# Field-schema constants — format-agnostic alias/path discovery
# ====================================================================

# Known RAG response field path patterns (ordered by specificity)
# Each tuple: (path_patterns, format_name)
# path_patterns: list of possible JSON paths to find sources/chunks

_SOURCE_PATH_PATTERNS = [
    # OpenAI-compatible with RAG extensions
    (["sources"], "openai_rag"),
    (["source_documents"], "langchain_style"),
    (["contexts"], "Generic_rag"),
    (["retrieval_results"], "retrieval_api"),
    (["passages", "documents"], "cohere_style"),
    (["citations"], "anthropic_style"),
    (["results"], "generic_results"),
    (["data", "sources"], "nested_data"),
    (["response", "sources"], "nested_response"),
]

_CHUNK_ID_ALIASES = [
    "chunk_id",
    "chunk_index",
    "passage_id",
    "doc_chunk_id",
    "id",
    "chunkId",
    "chunk_i",
    "segment_id",
    "block_id",
]

_SOURCE_TITLE_ALIASES = [
    "title",
    "source",
    "document_name",
    "file_name",
    "doc_title",
    "source_title",
    "name",
    "source_document",
    "filename",
]

_SOURCE_PATH_ALIASES = [
    "path",
    "source_path",
    "file_path",
    "doc_path",
    "url",
    "uri",
]

_TEXT_ALIASES = [
    "text",
    "content",
    "snippet",
    "passage",
    "context",
    "body",
    "chunk_text",
    "document_text",
    "page_content",
]

_VECTOR_SCORE_ALIASES = [
    "vector_score",
    "semantic_score",
    "similarity",
    "cosine_score",
    "embedding_score",
    "dense_score",
    "score",
]

_BM25_SCORE_ALIASES = [
    "bm25_score",
    "keyword_score",
    "sparse_score",
    "tfidf_score",
    "lexical_score",
]

_COMBINED_SCORE_ALIASES = [
    "combined_score",
    "final_score",
    "relevance_score",
    "rank_score",
    "weighted_score",
    "hybrid_score",
]

_TIMING_PATHS = [
    ["retrieval_info"],
    ["metadata", "timing"],
    ["debug", "retrieval"],
    ["_timing"],
    ["perf"],
]


def _safe_get_nested(data: dict[str, Any], path: list[str]) -> Any | None:
    """Safely traverse nested dict by path list."""
    current = data
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


def _find_field_by_aliases(data: dict[str, Any], aliases: list[str]) -> tuple[str, Any] | None:
    """Find first matching field in dict by aliases (case-insensitive).

    Returns (matched_key, value) or None.
    """
    if not isinstance(data, dict):
        return None
    # Build case-insensitive lookup
    ci_map = {k.lower().strip(): k for k in data.keys() if isinstance(k, str)}
    for alias in aliases:
        if alias.lower() in ci_map:
            original_key = ci_map[alias.lower()]
            return (original_key, data[original_key])
    return None
