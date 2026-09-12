# -*- coding: utf-8 -*-
"""Core RAG response parser — extract structured metadata from a single response.

SRP split from `metadata_parser.py` (R-DELIVERY-1): owns single-response
parsing logic, building `RAGResponseMetadata` from discovered chunks/timing/scores.
"""

from __future__ import annotations

import logging
from typing import Any

from recon.rag._metadata_field_detect import _auto_detect_source_path
from recon.rag._metadata_models import (
    _BM25_SCORE_ALIASES,
    _CHUNK_ID_ALIASES,
    _COMBINED_SCORE_ALIASES,
    _SOURCE_PATH_ALIASES,
    _SOURCE_TITLE_ALIASES,
    _TEXT_ALIASES,
    _TIMING_PATHS,
    _VECTOR_SCORE_ALIASES,
    RAGResponseMetadata,
    RetrievalTiming,
    RetrievedChunk,
    _find_field_by_aliases,
    _safe_get_nested,
)

logger = logging.getLogger(__name__)


def parse_rag_response(response_data: dict[str, Any]) -> RAGResponseMetadata:
    """Parse arbitrary RAG response and extract all structured metadata.

    This is the MAIN ENTRY POINT for single-response parsing.
    Handles any RAG response format automatically.

    Algorithm:
        1. Auto-detect sources/chunk array path
        2. Parse each chunk into RetrievedChunk
        3. Extract timing information
        4. Compute aggregated statistics

    Academic basis:
        - Response structure taxonomy (Gao et al., arXiv:2311.10536 §3)
        - Multi-strategy extraction (defense-in-depth)
    """
    metadata = RAGResponseMetadata()
    metadata.raw_response_keys = list(response_data.keys())[:50] if isinstance(response_data, dict) else []

    # Step 1: Auto-detect source path
    source_info = _auto_detect_source_path(response_data)
    if not source_info:
        logger.debug("No structured sources found in RAG response")
        # Still try to extract timing
        metadata.timing = _extract_timing(response_data)
        return metadata

    source_path, format_type = source_info
    metadata.format_type = format_type
    metadata.has_structured_sources = True

    # Step 2: Parse chunks
    raw_chunks = _safe_get_nested(response_data, source_path)
    if not raw_chunks or not isinstance(raw_chunks, list):
        return metadata

    for rank, raw_chunk in enumerate(raw_chunks, start=1):
        if not isinstance(raw_chunk, dict):
            continue
        chunk = _parse_single_chunk(raw_chunk, rank)
        metadata.chunks.append(chunk)

    metadata.num_chunks = len(metadata.chunks)

    # Step 3: Aggregate unique sources and chunk IDs
    metadata.unique_sources = list(dict.fromkeys(c.source_title for c in metadata.chunks if c.source_title))
    metadata.unique_chunk_ids = list(dict.fromkeys(c.chunk_id for c in metadata.chunks if c.chunk_id))

    # Step 4: Extract timing
    metadata.timing = _extract_timing(response_data)

    # Step 5: Compute score ranges
    metadata.score_range_vector = _compute_score_range(
        [c.vector_score for c in metadata.chunks if c.vector_score is not None]
    )
    metadata.score_range_bm25 = _compute_score_range(
        [c.bm25_score for c in metadata.chunks if c.bm25_score is not None]
    )
    metadata.score_range_combined = _compute_score_range(
        [c.combined_score for c in metadata.chunks if c.combined_score is not None]
    )

    return metadata


def _parse_single_chunk(raw_chunk: dict[str, Any], rank: int) -> RetrievedChunk:
    """Parse a single chunk dict into structured RetrievedChunk.

    Uses alias-based field matching for format-agnostic extraction.
    """
    chunk = RetrievedChunk()
    chunk.rank = rank

    # chunk_id
    key_val = _find_field_by_aliases(raw_chunk, _CHUNK_ID_ALIASES)
    if key_val:
        chunk.chunk_id = str(key_val[1])

    # source_title
    key_val = _find_field_by_aliases(raw_chunk, _SOURCE_TITLE_ALIASES)
    if key_val:
        chunk.source_title = str(key_val[1])

    # source_path
    key_val = _find_field_by_aliases(raw_chunk, _SOURCE_PATH_ALIASES)
    if key_val:
        chunk.source_path = str(key_val[1])

    # text content
    key_val = _find_field_by_aliases(raw_chunk, _TEXT_ALIASES)
    if key_val:
        text = str(key_val[1])
        chunk.text = text
        chunk.text_length = len(text)

    # vector_score
    key_val = _find_field_by_aliases(raw_chunk, _VECTOR_SCORE_ALIASES)
    if key_val:
        try:
            chunk.vector_score = float(key_val[1])
        except (ValueError, TypeError):
            pass

    # bm25_score
    key_val = _find_field_by_aliases(raw_chunk, _BM25_SCORE_ALIASES)
    if key_val:
        try:
            chunk.bm25_score = float(key_val[1])
        except (ValueError, TypeError):
            pass

    # combined_score
    key_val = _find_field_by_aliases(raw_chunk, _COMBINED_SCORE_ALIASES)
    if key_val:
        try:
            chunk.combined_score = float(key_val[1])
        except (ValueError, TypeError):
            pass

    # Store any extra metadata fields
    known_aliases = set(
        _CHUNK_ID_ALIASES
        + _SOURCE_TITLE_ALIASES
        + _SOURCE_PATH_ALIASES
        + _TEXT_ALIASES
        + _VECTOR_SCORE_ALIASES
        + _BM25_SCORE_ALIASES
        + _COMBINED_SCORE_ALIASES
    )
    ci_known = {a.lower() for a in known_aliases}
    for key, value in raw_chunk.items():
        if isinstance(key, str) and key.lower().strip() not in ci_known:
            if len(chunk.metadata) < 10:  # Limit stored extras
                chunk.metadata[key] = value

    return chunk


def _extract_timing(response_data: dict[str, Any]) -> RetrievalTiming:
    """Extract timing information from RAG response.

    Handles various timing field formats:
        - retrieval_time_ms / generation_time_ms / total_time_ms
        - retrievalDuration / generationDuration
        - Nested timing objects
    """
    timing = RetrievalTiming()

    # Try known timing paths
    for timing_path in _TIMING_PATHS:
        timing_data = _safe_get_nested(response_data, timing_path)
        if timing_data and isinstance(timing_data, dict):
            # Try to extract fields
            for key, val in timing_data.items():
                if isinstance(val, (int, float)):
                    kl = key.lower()
                    if "retrieval" in kl and "time" in kl:
                        timing.retrieval_time_ms = float(val)
                    elif "generation" in kl and "time" in kl:
                        timing.generation_time_ms = float(val)
                    elif "total" in kl and "time" in kl:
                        timing.total_time_ms = float(val)

            if timing.retrieval_time_ms is not None:
                break

    # Also check top-level for timing fields
    if timing.retrieval_time_ms is None:
        ci_map = {k.lower().strip(): (k, v) for k, v in response_data.items() if isinstance(k, str)}
        for lookup_key, field_name in [
            ("retrieval_time_ms", "retrieval_time_ms"),
            ("retrieval_time", "retrieval_time_ms"),
            ("search_time", "retrieval_time_ms"),
        ]:
            if lookup_key in ci_map:
                try:
                    timing.retrieval_time_ms = float(ci_map[lookup_key][1])
                    break
                except (ValueError, TypeError):
                    pass

    return timing


def _compute_score_range(scores: list[float]) -> tuple[float, float] | None:
    """Compute (min, max) of score list."""
    if not scores:
        return None
    return (min(scores), max(scores))
