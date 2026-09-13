"""report/component_reports.py - Component-Specific Report Section Builders.

This module is now the **object-axis registry / public API** for component
report sections. The actual per-component section builders live in their
object-local packages (report/<object>/sections.py) so the directory layout
mirrors strike/<object>/ (one directory per attack surface). This file:

  - keeps the stable public API (generate_component_sections,
    format_component_sections_for_report, register_component_builder, ...)
  - imports each object builder and registers it under its component_type key
  - re-exports the shared _assess_replay_complexity helper for backward compat

Design principles:
    - PyRIT Native First: All outputs compatible with PyRIT native scorers
    - Component-aware: Each report builder tailors sections to attack type
    - Token-minimal: Reuses existing evidence fields, no redundant LLM calls

Academic basis:
    - OWASP LLM 2025: AI-specific category coverage
    - OWASP ASI 2025: Agent-specific threat modeling
    - arXiv:2402.07867: RAG retrieval poisoning taxonomy
    - OWASP API Security Top 2023: API attack coverage
"""

from __future__ import annotations

import logging
from typing import Any

# Object-axis section builders (real logic in report/<object>/sections.py)
from report.a2a.sections import _build_a2a_agent_integrity_sections  # noqa: F401
from report.agent.sections import _build_agent_sections  # noqa: F401

# Backward-compat re-export: helper now lives in report/common/replay.py
from report.common.replay import _assess_replay_complexity  # noqa: F401
from report.evidence import EvidenceCollection
from report.mcp.sections import _build_mcp_tool_poisoning_sections  # noqa: F401
from report.model.sections import _build_model_behavior_shift_sections  # noqa: F401
from report.multimodal_upload.sections import _build_multimodal_upload_sections  # noqa: F401
from report.rag.sections import _build_rag_pipeline_sections  # noqa: F401
from report.session.sections import _build_session_memory_sections  # noqa: F401
from report.web.sections import _build_web_api_sections  # noqa: F401

logger = logging.getLogger(__name__)

# =============================================================================
# Component Type Registry
# =============================================================================

# Maps component types to their specialized report builders
_COMPONENT_BUILDERS: dict[str, Any] = {}


def register_component_builder(component_type: str, builder: Any) -> None:
    """Register a report builder for a component type.

    Args:
        component_type: Component type key (e.g., "mcp_tool_poisoning")
        builder: Builder function that takes EvidenceCollection and returns markdown str
    """
    _COMPONENT_BUILDERS[component_type] = builder


def get_component_builder(component_type: str) -> Any:
    """Get the report builder for a component type.

    Returns:
        Builder function or None if no specialized builder exists
    """
    return _COMPONENT_BUILDERS.get(component_type)


def list_supported_component_types() -> list[str]:
    """List all component types with specialized report builders."""
    return list(_COMPONENT_BUILDERS.keys())


# =============================================================================
# Helper Functions
# =============================================================================


def _determine_dominant_component(evidence: EvidenceCollection) -> str | None:
    """Determine the dominant component type from evidence collection.

    Uses metadata component_type or category to determine which component
    has the most evidence entries.

    Returns:
        Dominant component type or None
    """
    component_counts: dict[str, int] = {}

    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        comp = meta.get("component_type")
        if comp:
            component_counts[comp] = component_counts.get(comp, 0) + 1
            continue

        # Fallback to category inference
        cat = meta.get("category", "")
        if "mcp_" in cat.lower():
            component_counts["mcp_tool_poisoning"] = component_counts.get("mcp_tool_poisoning", 0) + 1
        elif "tool_use" in cat.lower() or "rogue_tool" in cat.lower():
            component_counts["agent"] = component_counts.get("agent", 0) + 1
        elif "a2a_" in cat.lower() or "agent_" in cat.lower():
            component_counts["a2a_agent_integrity"] = component_counts.get("a2a_agent_integrity", 0) + 1
        elif "model_" in cat.lower() or "backdoor" in cat.lower() or "filter" in cat.lower():
            component_counts["model_behavior_shift"] = component_counts.get("model_behavior_shift", 0) + 1
        elif "rag_" in cat.lower() or "retrieval" in cat.lower():
            component_counts["rag_pipeline"] = component_counts.get("rag_pipeline", 0) + 1
        elif "session_" in cat.lower() or "memory" in cat.lower():
            component_counts["session_memory"] = component_counts.get("session_memory", 0) + 1
        elif "web_" in cat.lower() or "auth_" in cat.lower() or "jwt" in cat.lower():
            component_counts["web_api"] = component_counts.get("web_api", 0) + 1

    if not component_counts:
        return None

    return max(component_counts, key=component_counts.get)


# =============================================================================
# Public API
# =============================================================================


def generate_component_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Generate component-specific report sections if applicable.

    This is the public entry point called by report/generator.py to inject
    component-specific sections into the report.

    Returns:
        Dict mapping section names to markdown content (empty if no component match)
    """
    dominant = _determine_dominant_component(evidence)
    if not dominant:
        return {}

    builder = get_component_builder(dominant)
    if builder:
        logger.info("Generating component-specific report sections for: %s", dominant)
        try:
            return builder(evidence)
        except Exception as e:
            logger.warning("Component report builder failed for %s: %s", dominant, e)
            return {}

    return {}


def format_component_sections_for_report(evidence: EvidenceCollection) -> str:
    """Format component sections as a markdown block for report insertion.

    Returns:
        Markdown string with component-specific sections
    """
    sections = generate_component_sections(evidence)
    if not sections:
        return ""

    # Order sections by importance
    priority_order = [
        "tool_inventory",
        "trust_chain",
        "persona_shift",
        "schema_manipulation",
        "routing_hijack",
        "trigger_patterns",
        "side_effects",
        "workflow_integrity",
        "filter_bypass",
        "compliance_shift",
        "retrieval_manipulation",
        "context_leakage",
        "auth_bypass",
        "vector_contamination",
        "memory_poisoning",
        "rate_evasion",
        "session_boundary",
        "context_injection",
        "smuggling",
        "gateway_bypass",
        "replay_complexity",
    ]

    parts: list[str] = []
    parts.append("\n---\n")
    parts.append("## Component-Specific Analysis\n")

    for key in priority_order:
        if key in sections:
            parts.append(sections[key])

    # Add any remaining sections not in priority list
    for key, content in sections.items():
        if key not in priority_order:
            parts.append(content)

    return "\n".join(parts)


# =============================================================================
# Module Initialization: Register Default Builders
# =============================================================================


def _register_default_builders() -> None:
    """Register the built-in component report builders."""
    register_component_builder("mcp_tool_poisoning", _build_mcp_tool_poisoning_sections)
    register_component_builder("a2a_agent_integrity", _build_a2a_agent_integrity_sections)
    register_component_builder("model_behavior_shift", _build_model_behavior_shift_sections)
    register_component_builder("rag_pipeline", _build_rag_pipeline_sections)
    register_component_builder("multimodal_upload", _build_multimodal_upload_sections)
    register_component_builder("session_memory", _build_session_memory_sections)
    register_component_builder("web_api", _build_web_api_sections)
    register_component_builder("agent", _build_agent_sections)


# Auto-register on module import
_register_default_builders()
