"""report/component_poc.py - Component-Specific PoC Script Generators.

This module is now the **object-axis registry / public API** for component
PoC generators. The actual per-component generators live in their object-local
packages (report/<object>/poc.py) so the directory layout mirrors strike/<object>/.

Design principles:
    - PyRIT Native First: All PoCs use PyRIT native converters/attacks
    - Replay-ready: Generated scripts are immediately executable
    - Component-aware: Templates include component-specific setup code
"""

from __future__ import annotations

import logging
from typing import Any

# Object-axis PoC generators (real logic in report/<object>/poc.py)
from report.a2a.poc import _generate_a2a_poc  # noqa: F401
from report.agent.poc import _generate_agent_poc  # noqa: F401
from report.mcp.poc import _generate_mcp_poc  # noqa: F401
from report.model.poc import _generate_model_poc  # noqa: F401
from report.rag.poc import _generate_rag_poc  # noqa: F401
from report.session.poc import _generate_session_poc  # noqa: F401
from report.web.poc import _generate_web_poc  # noqa: F401

logger = logging.getLogger(__name__)

# =============================================================================
# PoC Template Registry
# =============================================================================

_POC_TEMPLATES: dict[str, Any] = {}


def register_poc_template(component_type: str, template_fn: Any) -> None:
    """Register a PoC generator for a component type.

    Args:
        component_type: Component type key (e.g., "mcp_tool_poisoning")
        template_fn: Function that takes evidence dict and returns PoC script str
    """
    _POC_TEMPLATES[component_type] = template_fn


def get_poc_template(component_type: str) -> Any:
    """Get the PoC generator for a component type.

    Returns:
        Template function or None
    """
    return _POC_TEMPLATES.get(component_type)


# =============================================================================
# Public API
# =============================================================================


def generate_component_poc(evidence: dict[str, Any]) -> str | None:
    """Generate component-specific PoC script if applicable.

    This is the public entry point that selects the appropriate PoC template
    based on the evidence metadata.

    Returns:
        Python script string or None if no component-specific PoC available
    """
    metadata = evidence.get("metadata", {}) or {}
    component_type = metadata.get("component_type")

    if not component_type:
        # Infer from category
        cat = metadata.get("category", "")
        cat_lower = cat.lower()
        if "mcp_" in cat_lower:
            component_type = "mcp_tool_poisoning"
        elif "tool_use" in cat_lower or "rogue_tool" in cat_lower:
            component_type = "agent"
        elif "a2a_" in cat_lower or "agent_" in cat_lower:
            component_type = "a2a_agent_integrity"
        elif "model_" in cat_lower or "backdoor" in cat_lower or "filter" in cat_lower:
            component_type = "model_behavior_shift"

    if not component_type:
        # Infer from additional component categories
        if "rag_" in cat_lower or "retrieval" in cat_lower:
            component_type = "rag_pipeline"
        elif "session_" in cat_lower or "memory" in cat_lower:
            component_type = "session_memory"
        elif "web_" in cat_lower or "auth_" in cat_lower or "jwt" in cat_lower:
            component_type = "web_api"

    if not component_type:
        return None

    template_fn = get_poc_template(component_type)
    if template_fn:
        try:
            return template_fn(evidence)
        except Exception as e:
            logger.warning("Component PoC generation failed for %s: %s", component_type, e)
            return None

    return None


def list_available_poc_templates() -> list[str]:
    """List all component types with PoC templates."""
    return list(_POC_TEMPLATES.keys())


# =============================================================================
# Module Initialization: Register Default Templates
# =============================================================================


def _register_default_templates() -> None:
    """Register the built-in PoC templates."""
    register_poc_template("mcp_tool_poisoning", _generate_mcp_poc)
    register_poc_template("a2a_agent_integrity", _generate_a2a_poc)
    register_poc_template("model_behavior_shift", _generate_model_poc)
    register_poc_template("rag_pipeline", _generate_rag_poc)
    register_poc_template("session_memory", _generate_session_poc)
    register_poc_template("web_api", _generate_web_poc)
    register_poc_template("agent", _generate_agent_poc)


# Auto-register on module import
_register_default_templates()
