"""core/object_taxonomy — SSOT for the attack-object axis (ADR: directory-consistency).

Single source of truth for the *object* (attack surface) taxonomy that threads
through every layer of the pipeline, enabling a consistent object-first CLI:

    python -m target  <object> --strike <object> --converters <object> --data <object>

The object key is stable across layers:
    target(obj) -> strike(obj) -> converters(obj) -> data(obj) -> assess(obj) -> report(obj)

This module is intentionally dependency-free (no project imports) so it can be
imported from anywhere (CLI, arm/, assess/, report/, data loader) without
circular-import risk.

Object set (canonical):
    a2a, mcp, rag, model, web, memory, session, evasion, injection, embedding, api

Non-object (cross-cutting) layers keep their own structure and MUST NOT be
object-ified: core/ (phases/contracts), utils/, tools/.
"""

from __future__ import annotations

from typing import Iterable

# Canonical ordered object axis. Order matters only for stable display.
OBJECTS: tuple[str, ...] = (
    "a2a",
    "mcp",
    "rag",
    "model",
    "web",
    "memory",
    "session",
    "evasion",
    "injection",
    "embedding",
    "api",
)

# Aliases accepted on the CLI but normalized to OBJECTS.
OBJECT_ALIASES: dict[str, str] = {
    "agent": "a2a",
    "agent2agent": "a2a",
    "mcpsec": "mcp",
    "model_context_protocol": "mcp",
    "rag_pipeline": "rag",
    "retrieval": "rag",
    "llm": "model",
    "chat": "model",
    "web_api": "web",
    "api_security": "web",
    "mem": "memory",
    "sess": "session",
}

# Mapping: object -> assess/report component_type key (the legacy component
# classification used by assess.component_scorers / report.component_reports).
OBJECT_TO_COMPONENT: dict[str, str] = {
    "mcp": "mcp_tool_poisoning",
    "a2a": "a2a_agent_integrity",
    "model": "model_behavior_shift",
    "rag": "rag_pipeline",
    "web": "web_api",
    "memory": "session_memory",
    "session": "session_memory",
    "evasion": "web_api",          # evasion techniques surface via web/encoding layers
    "injection": "model_behavior_shift",  # indirect prompt injection -> model layer
    "embedding": "rag_pipeline",
    "api": "web_api",
}

# Reverse mapping: component_type -> object (first match wins).
COMPONENT_TO_OBJECT: dict[str, str] = {v: k for k, v in OBJECT_TO_COMPONENT.items()}


def normalize_object(key: str) -> str | None:
    """Normalize a raw CLI/object token to a canonical object key.

    Returns the canonical object string, or None if not recognized.
    """
    if not key:
        return None
    k = key.strip().lower()
    if k in OBJECTS:
        return k
    return OBJECT_ALIASES.get(k)


def component_for_object(key: str) -> str | None:
    """Return the component_type key for an object (or None)."""
    norm = normalize_object(key)
    return OBJECT_TO_COMPONENT.get(norm) if norm else None


def object_for_component(component: str) -> str | None:
    """Return the object key for a component_type key (or None)."""
    return COMPONENT_TO_OBJECT.get(component)


def all_objects() -> tuple[str, ...]:
    """Return the canonical object tuple."""
    return OBJECTS


def is_object(key: str) -> bool:
    """True if key is a canonical object or a known alias."""
    return normalize_object(key) is not None


def validate_object_list(keys: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split an iterable of raw tokens into (normalized_objects, unknown)."""
    normalized: list[str] = []
    unknown: list[str] = []
    for k in keys:
        n = normalize_object(k)
        if n is None:
            unknown.append(k)
        elif n not in normalized:
            normalized.append(n)
    return normalized, unknown
