# -*- coding: utf-8 -*-
"""RAG response source-path auto-detection (format-agnostic discovery).

SRP split from `metadata_parser.py` (R-DELIVERY-1): owns the strategy for
locating the chunks/sources array within an arbitrary RAG response.
"""

from __future__ import annotations

from typing import Any

from recon.rag._metadata_models import (
    _CHUNK_ID_ALIASES,
    _COMBINED_SCORE_ALIASES,
    _SOURCE_PATH_PATTERNS,
    _SOURCE_TITLE_ALIASES,
    _TEXT_ALIASES,
    _VECTOR_SCORE_ALIASES,
    _safe_get_nested,
)


def _auto_detect_source_path(response_data: dict[str, Any]) -> tuple[list[str], str] | None:
    """Auto-detect the JSON path to sources/chunks in a RAG response.

    Returns (path, format_type) or None if no sources found.
    Strategy:
        1. Try known path patterns
        2. Recursive search for arrays with chunk-like objects
    """
    # Strategy 1: Known patterns
    for path, fmt in _SOURCE_PATH_PATTERNS:
        result = _safe_get_nested(response_data, path)
        if result and isinstance(result, list) and len(result) > 0:
            if isinstance(result[0], dict):
                return (path, fmt)

    # Strategy 2: Recursive search for chunk arrays
    found_path = _recursive_find_chunks(response_data, max_depth=4)
    if found_path:
        return (found_path, "auto_detected")

    return None


def _recursive_find_chunks(
    data: Any, max_depth: int = 4, current_path: list[str] | None = None
) -> list[str] | None:
    """Recursively search for arrays containing chunk-like dicts.

    A chunk-like dict has at least 2 of: id-like, text-like, score-like fields.
    """
    if current_path is None:
        current_path = []

    if max_depth <= 0:
        return None

    if isinstance(data, dict):
        for key, value in data.items():
            new_path = current_path + [key]
            if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                # Check if first item looks like a chunk
                item = value[0]
                ci_keys = {k.lower().strip() for k in item.keys() if isinstance(k, str)}
                chunk_indicators = sum(
                    [
                        bool(ci_keys & {a.lower() for a in _CHUNK_ID_ALIASES}),
                        bool(ci_keys & {a.lower() for a in _TEXT_ALIASES}),
                        bool(ci_keys & {a.lower() for a in _SOURCE_TITLE_ALIASES}),
                        bool(ci_keys & {a.lower() for a in _VECTOR_SCORE_ALIASES + _COMBINED_SCORE_ALIASES}),
                    ]
                )
                if chunk_indicators >= 2:
                    return new_path
            # Recurse
            result = _recursive_find_chunks(value, max_depth - 1, new_path)
            if result:
                return result

    return None
