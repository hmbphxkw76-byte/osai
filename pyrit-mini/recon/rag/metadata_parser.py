# -*- coding: utf-8 -*-
"""RAG Metadata Auto-Parser — facade re-exporting the SRP-split submodules.

The implementation was split (R-DELIVERY-1) into focused single-responsibility
modules under `recon/rag/`:
    - _metadata_models       : dataclasses + field-schema constants + leaf helpers
    - _metadata_field_detect : source-path auto-detection (format discovery)
    - rag_response_parser    : single-response parsing
    - rag_query_stealth      : query diversification & lognormal timing
    - rag_collection         : high-level KB-mapping orchestrator

This module re-exports the original public + private API so every existing
importer (`from recon.rag.metadata_parser import ...`) keeps working unchanged.
"""

from recon.rag._metadata_field_detect import (
    _auto_detect_source_path,
    _recursive_find_chunks,
)
from recon.rag._metadata_models import (
    _BM25_SCORE_ALIASES,
    _CHUNK_ID_ALIASES,
    _COMBINED_SCORE_ALIASES,
    _SOURCE_PATH_ALIASES,
    _SOURCE_PATH_PATTERNS,
    _SOURCE_TITLE_ALIASES,
    _TEXT_ALIASES,
    _TIMING_PATHS,
    _VECTOR_SCORE_ALIASES,
    KnowledgeBaseMap,
    RAGResponseMetadata,
    RetrievalTiming,
    RetrievedChunk,
    _find_field_by_aliases,
    _safe_get_nested,
)
from recon.rag.rag_collection import (
    _build_probe_body,
    _send_and_parse,
    run_rag_metadata_collection,
)
from recon.rag.rag_query_stealth import (
    _QUERY_DIVERSIFIER_TEMPLATES,
    _TOPIC_CATEGORIES,
    _cluster_queries_by_topic,
    _compute_lognormal_delay,
    _diversify_query,
)
from recon.rag.rag_response_parser import (
    _compute_score_range,
    _extract_timing,
    _parse_single_chunk,
    parse_rag_response,
)

__all__ = [
    "RetrievedChunk",
    "RetrievalTiming",
    "RAGResponseMetadata",
    "KnowledgeBaseMap",
    "parse_rag_response",
    "run_rag_metadata_collection",
    "_safe_get_nested",
    "_find_field_by_aliases",
    "_auto_detect_source_path",
    "_recursive_find_chunks",
    "_parse_single_chunk",
    "_extract_timing",
    "_compute_score_range",
    "_diversify_query",
    "_cluster_queries_by_topic",
    "_compute_lognormal_delay",
    "_send_and_parse",
    "_build_probe_body",
    "_SOURCE_PATH_PATTERNS",
    "_CHUNK_ID_ALIASES",
    "_SOURCE_TITLE_ALIASES",
    "_SOURCE_PATH_ALIASES",
    "_TEXT_ALIASES",
    "_VECTOR_SCORE_ALIASES",
    "_BM25_SCORE_ALIASES",
    "_COMBINED_SCORE_ALIASES",
    "_TIMING_PATHS",
    "_QUERY_DIVERSIFIER_TEMPLATES",
    "_TOPIC_CATEGORIES",
]
