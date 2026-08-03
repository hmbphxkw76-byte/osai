# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Response fingerprinting — SHA256-based dedup & change detection for agent tool outputs.

Aligns with RedAmon agentic/orchestrator_helpers/productivity.py:
  - _output_fingerprint(step) → SHA256
  - _normalize_args_pattern(tool_name, args) → canonical string

Purposes:
  1. Deduplication: detect identical tool responses across sessions/rounds
  2. Change detection: identify when agent tool behavior changes (e.g. patched tool)
  3. Noise normalization: strip timestamps, UUIDs, nonces before hashing

Non-LLM guarantee: pure SHA256 + regex, zero ML dependencies.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any


# ── Noise patterns: values that should be normalized before hashing ──

_NOISE_PATTERNS: list[re.Pattern[str]] = [
    # UUID v4
    re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        re.I,
    ),
    # ISO 8601 timestamps
    re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    ),
    # Unix timestamps (10+ digits)
    re.compile(r"\b1[3-9]\d{8,12}\b"),
    # Random nonce/request-id patterns (hex 32/64 char)
    re.compile(r"\b[0-9a-f]{32,64}\b", re.I),
    # JWT tokens (header.payload.signature)
    re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    # Session IDs
    re.compile(r"\b(sess|sid|session)[-_]?[0-9a-f]{16,}\b", re.I),
]

# Placeholder replacements (deterministic)
_NOISE_PLACEHOLDERS = [
    "<<UUID>>",
    "<<TIMESTAMP>>",
    "<<UNIX_TS>>",
    "<<HEX_ID>>",
    "<<JWT>>",
    "<<SESSION>>",
]


def normalize_text(text: str) -> str:
    """Strip noise patterns (timestamps, UUIDs, nonces) from text.

    Returns copy with all noise replaced by deterministic placeholders,
    so identical responses with different timestamps produce same hash.
    """
    result = text
    for pattern, placeholder in zip(_NOISE_PATTERNS, _NOISE_PLACEHOLDERS):
        result = pattern.sub(placeholder, result)
    return result


def fingerprint_text(text: str) -> str:
    """Compute SHA256 fingerprint of normalized text.

    Args:
        text: Raw response/output text.

    Returns:
        16-char hex SHA256 prefix (compatible with MCPProbe._hash_tool).
    """
    normalized = normalize_text(text)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def fingerprint_dict(data: dict[str, Any]) -> str:
    """Compute SHA256 fingerprint of a dict (sorted keys, JSON canonical).

    Args:
        data: Arbitrary dict (tool args, response JSON, etc.).

    Returns:
        16-char hex SHA256 prefix.
    """
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=True, default=str)
    normalized = normalize_text(canonical)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def fingerprint_response(
    body: str = "",
    status_code: int | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    """Compute composite fingerprint of an HTTP response.

    Combines normalized body + status code + selected headers (stripped of
    noise-sensitive values like Date/Set-Cookie).

    Args:
        body: Response body text.
        status_code: HTTP status code.
        headers: Response headers dict.

    Returns:
        16-char hex SHA256 prefix.
    """
    # Select stable headers (exclude Date, Set-Cookie, X-Request-Id, etc.)
    _STABLE_HEADERS = {"content-type", "content-length", "server", "cache-control", "etag"}
    stable: dict[str, str] = {}
    if headers:
        for key, value in headers.items():
            if key.lower() in _STABLE_HEADERS:
                stable[key] = value

    payload = {
        "body": normalize_text(body[:2000]),  # First 2KB is enough
        "status_code": status_code or 0,
        "headers": stable,
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class FingerprintSet:
    """Collection of fingerprints for deduplication tracking.

    Tracks seen fingerprints to detect:
      - Duplicate responses (same output for different inputs)
      - Tool behavior changes (new fingerprint != baseline)
    """

    fingerprints: dict[str, str] = field(default_factory=dict)
    # key → fingerprint hex

    def add(self, key: str, body: str, status_code: int | None = None) -> str:
        """Fingerprint and store a response by key.

        Returns the computed fingerprint hex string.
        """
        fp = fingerprint_response(body=body, status_code=status_code)
        self.fingerprints[key] = fp
        return fp

    def is_duplicate(self, key: str, fp: str) -> bool:
        """Check if fingerprint already seen."""
        return self.fingerprints.get(key) == fp

    def has_changed(self, key: str, fp: str) -> bool:
        """Check if fingerprint changed from previous (behavior drift)."""
        existing = self.fingerprints.get(key)
        if existing is None:
            return False
        return existing != fp and existing != ""

    def to_dict(self) -> dict[str, str]:
        return dict(self.fingerprints)
