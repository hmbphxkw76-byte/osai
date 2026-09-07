"""ContentFilterExt — Extends PyRIT native Content filter markers.

Aligned with PyRIT 1.0.1 architecture:
    In PyRIT 1.0.1, ``CONTENT_FILTER_MARKERS`` is defined in
    ``pyrit.exceptions.exception_classes`` module (frozenset).

    ``_is_content_filter_error`` function (in ``openai_error_handling`` module)
    imports ``exception_classes`` from ``CONTENT_FILTER_MARKERS`` and performs
    substring scanning to determine if it is a content filter error.

    This module directly extends ``exception_classes.CONTENT_FILTER_MARKERS``
    frozenset to enhance PyRIT native content filter detection, no wrapper function needed.

Three-layer defense mechanism:
    L1: Static markers (YAML configuration file)
    L2: Default extended markers (covers third-party API Chinese security markers)
    L3: Heuristic dynamic discovery (discover new markers from error messages, persistent cache)

Academic basis:
    - PyRIT (arXiv:2407.01232) — Content filtering target 
    - Greshake et al. (arXiv:2302.12173) — 
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# L2:  ( API,  LLM )
# PyRIT  CONTENT_FILTER_MARKERS :
#   content_filter, content_safety_violation, policy_violation, moderation_blocked
#  API Content filtering
_DEFAULT_EXTRA_MARKERS = frozenset(
    {
        # 
        "security_audit_fail",
        "security_error",
        "sensitive_content",
        "risk_content_detected",
        "review_blocked",
        "safety_system",
        "safety_system_triggered",
        # Content filtering ( LLM )
        "",
        "",
        "",
        "",
        "AI",
        "",
        "",
        "",
        "",
    }
)

# heuristic 
_CACHE_PATH = Path("outputs/cache/content_filter_markers.json")

# heuristic : 
_HEURISTIC_PATTERNS = [
    re.compile(r'"(block\w*|filter\w*|reject\w*|deny\w*)":\s*"([^"]+)"', re.IGNORECASE),
    re.compile(r'"(reason|message)":\s*"([^"]*(?:block|filter|reject|denied|violation)[^"]*)"', re.IGNORECASE),
]


def extend_content_filter_markers(
    config_path: str | Path | None = None,
) -> frozenset[str]:
    """Extends PyRIT native ``CONTENT_FILTER_MARKERS`` (three-layer defense).

    Aligned with PyRIT 1.0.1:
        PyRIT 1.0.1's ``CONTENT_FILTER_MARKERS`` is defined in
        ``pyrit.exceptions.exception_classes`` 
        ``_is_content_filter_error`` ( ``openai_error_handling`` ) imports
        ``exception_classes`` from frozenset
        Extend frozenset all

    Execution flow:
        1. Load YAML static configuration (L1)
        2. Merge default extended markers (L2)
        3. Load cached markers discovered in last run (L3)
        4. Extend ``exception_classes.CONTENT_FILTER_MARKERS`` frozenset
        5. Functional verification - ensure extended markers are recognized by PyRIT

    Args:
        config_path: YAML configuration file path (optional).

    Returns:
        Frozenset of all extended markers.
    """
    # L1: 
    static_markers: set[str] = set()
    if config_path:
        path = Path(config_path)
        if path.exists():
            import yaml

            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and isinstance(data.get("markers"), list):
                static_markers.update(data["markers"])
            logger.info("L1: Loaded %d static markers from %s", len(static_markers), config_path)

    # L2: 
    all_markers = static_markers | _DEFAULT_EXTRA_MARKERS
    logger.info("L2: %d default extra markers", len(_DEFAULT_EXTRA_MARKERS))

    # L3: heuristic 
    cached_markers = _load_discovered_markers()
    all_markers |= cached_markers
    logger.info("L3: %d cached discovered markers", len(cached_markers))

    #  PyRIT  CONTENT_FILTER_MARKERS
    _patch_content_filter_markers(all_markers)

    # 
    _verify_patch(all_markers)

    logger.info("Content filter extended with %d total markers", len(all_markers))
    return frozenset(all_markers)


def _patch_content_filter_markers(markers: set[str]) -> None:
    """Extends PyRIT native ``CONTENT_FILTER_MARKERS`` frozenset

    Aligned with PyRIT 1.0.1:
        ``CONTENT_FILTER_MARKERS`` is defined in
        ``pyrit.exceptions.exception_classes`` 
         frozenset

        ``openai_error_handling._is_content_filter_error`` 
        ``from pyrit.exceptions.exception_classes import CONTENT_FILTER_MARKERS``
        fromTherefore,
    """
    try:
        from pyrit.exceptions import exception_classes

        existing = getattr(exception_classes, "CONTENT_FILTER_MARKERS", frozenset())
        combined = frozenset(existing) | frozenset(markers)
        exception_classes.CONTENT_FILTER_MARKERS = combined
        logger.debug("Patched CONTENT_FILTER_MARKERS: %d total", len(combined))
    except ImportError:
        logger.warning("Could not import exception_classes for patching")

    #  handle_bad_request_exception  ()
    # handle_bad_request_exception  exception_classes ,
    #  CONTENT_FILTER_MARKERS ,
    # 


def _verify_patch(markers: set[str]) -> None:
    """Functional verification - ensure extended markers are recognized by PyRIT.

    Aligned with PyRIT 1.0.1:  ``exception_classes.CONTENT_FILTER_MARKERS``
    allExtend
    """
    try:
        from pyrit.exceptions import exception_classes

        current = getattr(exception_classes, "CONTENT_FILTER_MARKERS", frozenset())
        missing = markers - set(current)
        if missing:
            logger.error("Content filter verification FAILED: %d markers missing", len(missing))
            raise RuntimeError(f"Content filter markers not properly patched: {missing}")
        logger.debug("Content filter verification passed: all markers present")
    except ImportError:
        logger.warning("Could not verify content filter patch (module not found)")


def persist_discovered_markers() -> None:
    """Persist dynamically discovered markers to JSON file."""
    try:
        from pyrit.exceptions import exception_classes

        current = getattr(exception_classes, "CONTENT_FILTER_MARKERS", frozenset())
        discovered = set(current) - _DEFAULT_EXTRA_MARKERS
        #  PyRIT 
        _native_markers = frozenset(
            {
                "content_filter",
                "content_safety_violation",
                "policy_violation",
                "moderation_blocked",
            }
        )
        discovered -= _native_markers
        if not discovered:
            return

        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(
            json.dumps(list(discovered), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("Persisted %d discovered markers to %s", len(discovered), _CACHE_PATH)
    except ImportError:
        pass


def _load_discovered_markers() -> set[str]:
    """Load cached markers discovered in last run."""
    if not _CACHE_PATH.exists():
        return set()
    try:
        data = json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return set(data)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning("Failed to load discovered markers: %s", e)
    return set()


def discover_markers_from_error(error_str: str) -> set[str]:
    """Heuristic discovery of new content filter markers from error messages.

    Args:
        error_str: Error message string.

    Returns:
        Set of newly discovered markers.
    """
    discovered: set[str] = set()
    for pattern in _HEURISTIC_PATTERNS:
        for match in pattern.finditer(error_str):
            marker = match.group(2).strip()
            if marker and len(marker) < 100:
                discovered.add(marker)
    if discovered:
        logger.info("Heuristic discovered %d new markers: %s", len(discovered), discovered)
    return discovered
