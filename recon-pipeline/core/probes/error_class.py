# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Error Class diagnostic classifier — non-LLM response error taxonomy.

Aligns with RedAmon agentic/orchestrator_helpers/error_class.py (210 lines),
classifying HTTP + tool-call responses into 8 error categories for
agentic tool health scoring and diagnostic fingerprinting.

Categories:
  1. success                  — 2xx status, no error message
  2. shell_parser_error       — 400-level parse/syntax errors from tool args
  3. transport_error           — connection refused, timeout, DNS failure
  4. tool_internal_error       — 500 with "internal" / "unexpected" in body
  5. application_4xx           — generic 4xx (auth, not-found, bad request)
  6. application_5xx_fast      — 500-level, < 50ms (deterministic guardrail / WAF)
  7. application_5xx_networked_fast — 500-level, 50–200ms (fast fail, no backend)
  8. application_5xx_normal    — 500-level, >= 200ms (likely backend error)

Key design decisions (non-LLM guarantee):
  - Pure regex + numeric comparison; zero ML/model dependencies
  - Compatible with both HTTP responses and MCP/Agent tool results
  - 3-tier 5xx latency classification surfaces WAF vs backend failures
"""

from __future__ import annotations

import re
from enum import Enum


class ErrorClass(str, Enum):
    """Standardized error classification labels (RedAmon-aligned)."""

    SUCCESS = "success"
    SHELL_PARSER = "shell_parser_error"
    TRANSPORT = "transport_error"
    TOOL_INTERNAL = "tool_internal_error"
    APPLICATION_4XX = "application_4xx"
    APPLICATION_5XX_FAST = "application_5xx_fast"           # < 50ms
    APPLICATION_5XX_NETWORKED_FAST = "application_5xx_networked_fast"  # 50–200ms
    APPLICATION_5XX_NORMAL = "application_5xx_normal"        # >= 200ms


# ── Regex patterns ──

_SHELL_PARSER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(invalid|unexpected|unrecognized)\s+(argument|option|flag|syntax|token)", re.I),
    re.compile(r"(parse|parsing|syntax)\s+error", re.I),
    re.compile(r"missing\s+(required\s+)?(argument|parameter|field|option)", re.I),
    re.compile(r"unexpected\s+(end\s+of\s+input|token|character)", re.I),
    re.compile(r"bash:\s.*(syntax\s+error|command\s+not\s+found)", re.I),
]

_TRANSPORT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(connection\s+(refused|reset|timed?\s*out))", re.I),
    re.compile(r"(dns\s+(resolution|lookup|failure|error))", re.I),
    re.compile(r"(timeout|timed\s+out)\s+(error|exceeded)", re.I),
    re.compile(r"(could\s+not|unable\s+to)\s+(connect|resolve|reach)", re.I),
    re.compile(r"(ssl|tls|handshake|certificate)\s+(error|failed|expired)", re.I),
]

_TOOL_INTERNAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(internal\s+(server\s+)?error|unexpected\s+(error|exception))", re.I),
    re.compile(r"(null\s+pointer|stack\s+overflow|segmentation\s+fault)", re.I),
    re.compile(r"(panic|fatal|abort|crashed)", re.I),
    re.compile(r"traceback\s+\(most\s+recent\s+call\s+last\)", re.I),
]

_SUCCESS_BODY_PATTERNS: list[re.Pattern[str]] = [
    # Response bodies that are normal even with non-2xx codes
    re.compile(r'"error"\s*:\s*\{[^}]*"message"', re.I),  # structured errors are still application errors
]


def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    """Check if text matches any compiled pattern."""
    if not text:
        return False
    return any(p.search(text) for p in patterns)


def classify_error_class(
    *,
    success: bool = False,
    status_code: int | None = None,
    error_message: str = "",
    body: str = "",
    duration_ms: int = 0,
) -> str:
    """Classify a response into one of 8 error classes.

    Args:
        success: Whether the caller considers this a success (e.g. result parsed).
        status_code: HTTP status code (or None for non-HTTP calls).
        error_message: Error message from exception or tool output.
        body: Full response body text for pattern matching.
        duration_ms: Round-trip duration in milliseconds (used for 3-tier 5xx).

    Returns:
        ErrorClass value string.

    Examples:
        >>> classify_error_class(success=True, status_code=200)
        'success'
        >>> classify_error_class(status_code=500, body="internal error", duration_ms=30)
        'application_5xx_fast'
        >>> classify_error_class(status_code=400, body="invalid argument --foo")
        'shell_parser_error'
    """
    combined = f"{error_message}\n{body}".strip()

    # 1. Explicit success
    if success and (status_code is None or 200 <= status_code < 300):
        return ErrorClass.SUCCESS.value

    # 2. Transport errors (before status_code checks — can happen at any layer)
    if _matches_any(combined, _TRANSPORT_PATTERNS):
        return ErrorClass.TRANSPORT.value

    # 3. Status-code driven classification
    if status_code is not None:
        # 4xx
        if 400 <= status_code < 500:
            # Distinguish shell/parser errors from generic 4xx
            if _matches_any(combined, _SHELL_PARSER_PATTERNS):
                return ErrorClass.SHELL_PARSER.value
            return ErrorClass.APPLICATION_4XX.value

        # 5xx — triage by latency
        if 500 <= status_code < 600:
            # Detect tool internal errors by body pattern
            if _matches_any(combined, _TOOL_INTERNAL_PATTERNS):
                return ErrorClass.TOOL_INTERNAL.value

            # 3-tier latency classification
            if duration_ms < 50:
                return ErrorClass.APPLICATION_5XX_FAST.value
            elif duration_ms < 200:
                return ErrorClass.APPLICATION_5XX_NETWORKED_FAST.value
            else:
                return ErrorClass.APPLICATION_5XX_NORMAL.value

    # 4. Non-HTTP tool internal error detection
    if _matches_any(combined, _TOOL_INTERNAL_PATTERNS):
        return ErrorClass.TOOL_INTERNAL.value

    if _matches_any(combined, _SHELL_PARSER_PATTERNS):
        return ErrorClass.SHELL_PARSER.value

    # 5. Successful but non-2xx (e.g. MCP JSON-RPC result)
    if success:
        return ErrorClass.SUCCESS.value

    # 6. Fallback
    return ErrorClass.APPLICATION_4XX.value if status_code and status_code < 500 else ErrorClass.TOOL_INTERNAL.value


def classify_http_response(
    status_code: int,
    body: str = "",
    duration_ms: int = 0,
) -> str:
    """Convenience: classify a standard HTTP response.

    Args:
        status_code: HTTP status code.
        body: Response body text.
        duration_ms: Round-trip latency.

    Returns:
        ErrorClass value.
    """
    success = 200 <= status_code < 300
    return classify_error_class(
        success=success,
        status_code=status_code,
        body=body,
        duration_ms=duration_ms,
    )


def is_recoverable_error(error_class: str) -> bool:
    """Check if an error class is likely recoverable (retry safe).

    Recoverable: shell_parser, transport, tool_internal (may self-heal).
    Non-recoverable: application_4xx (auth/permission), 5xx_fast (WAF).
    """
    return error_class in (
        ErrorClass.SHELL_PARSER.value,
        ErrorClass.TRANSPORT.value,
        ErrorClass.TOOL_INTERNAL.value,
    )


def error_class_severity(error_class: str) -> int:
    """Return severity score 0-10 (higher = worse).

    Scores:
        success=0, shell_parser=2, transport=5, 4xx=3,
        tool_internal=7, 5xx_netslow=6, 5xx_normal=5, 5xx_fast=8 (likely WAF/block)
    """
    _map = {
        ErrorClass.SUCCESS.value: 0,
        ErrorClass.SHELL_PARSER.value: 2,
        ErrorClass.TRANSPORT.value: 5,
        ErrorClass.TOOL_INTERNAL.value: 7,
        ErrorClass.APPLICATION_4XX.value: 3,
        ErrorClass.APPLICATION_5XX_FAST.value: 8,
        ErrorClass.APPLICATION_5XX_NETWORKED_FAST.value: 6,
        ErrorClass.APPLICATION_5XX_NORMAL.value: 5,
    }
    return _map.get(error_class, 5)
