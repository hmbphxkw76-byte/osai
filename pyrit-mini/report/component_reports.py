"""report/component_reports.py - Component-Specific Report Section Builders.

Provides component-aware report generation for AI core components:
    - MCP Tool Poisoning: Tool inventory, schema manipulation, side-effect evidence
    - A2A Agent Integrity: Trust chain analysis, agent topology, workflow integrity
    - Model Behavior Shift: Persona shift evidence, filter bypass details, trigger patterns
    - RAG Pipeline: Retrieval poisoning, context injection, vector DB contamination
    - Session/Memory: Cross-session leakage, memory poisoning, context persistence
    - Web/API: Auth bypass, rate limit evasion, request smuggling

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

from report.evidence import EvidenceCollection

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

    Args:
        component_type: Component type key

    Returns:
        Builder function or None if no specialized builder exists
    """
    return _COMPONENT_BUILDERS.get(component_type)


def list_supported_component_types() -> list[str]:
    """List all component types with specialized report builders.

    Returns:
        List of component type keys
    """
    return list(_COMPONENT_BUILDERS.keys())


# =============================================================================
# MCP Tool Poisoning Report Builder
# =============================================================================


def _build_mcp_tool_poisoning_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build MCP Tool Poisoning specific report sections.

    Sections:
        - tool_inventory: Summary of discovered/attacked MCP tools
        - schema_manipulation: Schema poisoning evidence
        - side_effects: Attacker notification or data exfiltration evidence
        - replay_complexity: Complexity assessment for attack replay

    Args:
        evidence: Collection of vulnerability evidence

    Returns:
        Dict mapping section names to markdown content
    """
    sections: dict[str, str] = {}

    # Tool inventory summary
    mcp_tools: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        tool_name = meta.get("mcp_tool") or meta.get("tool_name")
        if tool_name and tool_name not in mcp_tools:
            mcp_tools.append(tool_name)

    if mcp_tools:
        tool_list = "\n".join(f"    - `{t}`" for t in sorted(mcp_tools))
        sections["tool_inventory"] = f"## MCP Tool Inventory\n\nDiscovered/attacked MCP tools:\n\n{tool_list}\n"

    # Side-effect evidence summary
    side_effects: list[str] = []
    for ev in evidence.successful_evidence:
        response = getattr(ev, "response", "") or ""
        meta = getattr(ev, "metadata", {}) or {}
        if meta.get("side_effect"):
            side_effects.append(meta["side_effect"])
        elif "exfiltrat" in response.lower() or "side_effect" in response.lower():
            side_effects.append("exfiltration_detected")

    if side_effects:
        effects_list = "\n".join(f"    - {se}" for se in set(side_effects))
        sections["side_effects"] = (
            f"## MCP Side-Effect Evidence\n\nAttacker notifications or data exfiltration detected:\n\n{effects_list}\n"
        )

    # Schema manipulation evidence
    schema_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "schema" in cat.lower() or "description" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            schema_evidence.append(f"{technique}: {cat}")

    if schema_evidence:
        schema_list = "\n".join(f"    - {se}" for se in schema_evidence)
        sections["schema_manipulation"] = (
            f"## Schema Manipulation Evidence\n\nTool description/schema poisoning vectors:\n\n{schema_list}\n"
        )

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "mcp")

    return sections


# =============================================================================
# A2A Agent Integrity Report Builder
# =============================================================================


def _build_a2a_agent_integrity_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build A2A Agent Integrity specific report sections.

    Sections:
        - trust_chain: Trust chain integrity analysis
        - agent_topology: Agent interaction topology
        - workflow_integrity: Workflow manipulation evidence
        - routing_hijack: Routing interception evidence

    Args:
        evidence: Collection of vulnerability evidence

    Returns:
        Dict mapping section names to markdown content
    """
    sections: dict[str, str] = {}

    # Trust chain analysis
    trust_vectors: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        owasp_id = meta.get("owasp_id", "")
        cat = meta.get("category", "")
        if owasp_id == "ASI10" or "trust" in cat.lower() or "rogue" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            trust_vectors.append(f"{technique} ({cat})")

    if trust_vectors:
        vector_list = "\n".join(f"    - {tv}" for tv in trust_vectors)
        sections["trust_chain"] = f"## A2A Trust Chain Analysis\n\nTrust boundary violation vectors:\n\n{vector_list}\n"

    # Routing hijack evidence
    routing_evidence: list[str] = []
    for ev in evidence.successful_evidence:
        response = getattr(ev, "response", "") or ""
        meta = getattr(ev, "metadata", {}) or {}
        if "routing" in response.lower() or "redirect" in response.lower():
            owasp_id = meta.get("owasp_id", "unknown")
            routing_evidence.append(f"{owasp_id}: routing manipulation detected")

    if routing_evidence:
        routing_list = "\n".join(f"    - {re}" for re in set(routing_evidence))
        sections["routing_hijack"] = f"## Routing Hijack Evidence\n\nAgent routing interception:\n\n{routing_list}\n"

    # Workflow integrity
    workflow_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "workflow" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            workflow_evidence.append(f"{technique}: {cat}")

    if workflow_evidence:
        wf_list = "\n".join(f"    - {we}" for we in workflow_evidence)
        sections["workflow_integrity"] = (
            f"## Workflow Integrity Evidence\n\nWorkflow manipulation vectors:\n\n{wf_list}\n"
        )

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "a2a")

    return sections


# =============================================================================
# Model Behavior Shift Report Builder
# =============================================================================


def _build_model_behavior_shift_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build Model Behavior Shift specific report sections.

    Sections:
        - persona_shift: Persona/filter bypass evidence
        - trigger_patterns: Backdoor trigger detection
        - filter_bypass: Safety filter evasion evidence
        - compliance_shift: Compliance degradation assessment

    Args:
        evidence: Collection of vulnerability evidence

    Returns:
        Dict mapping section names to markdown content
    """
    sections: dict[str, str] = {}

    # Persona shift evidence
    persona_evidence: list[str] = []
    for ev in evidence.successful_evidence:
        response = getattr(ev, "response", "") or ""
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if any(kw in response.lower() for kw in ["developer mode", "dan mode", "unrestricted"]):
            persona_evidence.append(f"persona_switch: {cat}")
        elif "persona" in cat.lower() or "bypass" in cat.lower():
            persona_evidence.append(f"filter_bypass: {cat}")

    if persona_evidence:
        persona_list = "\n".join(f"    - {pe}" for pe in persona_evidence)
        sections["persona_shift"] = (
            f"## Persona/Filter Bypass Evidence\n\nModel behavior manipulation:\n\n{persona_list}\n"
        )

    # Trigger patterns (backdoor)
    trigger_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "backdoor" in cat.lower() or "trigger" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            trigger_evidence.append(f"{technique}: {cat}")

    if trigger_evidence:
        trigger_list = "\n".join(f"    - {te}" for te in trigger_evidence)
        sections["trigger_patterns"] = (
            f"## Backdoor Trigger Patterns\n\nPotential backdoor triggers:\n\n{trigger_list}\n"
        )

    # Compliance shift
    compliance_drops: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        if meta.get("compliance_breach") or meta.get("filter_bypassed"):
            technique = getattr(ev, "technique_name", "unknown")
            owasp_id = meta.get("owasp_id", "unknown")
            compliance_drops.append(f"{technique} ({owasp_id})")

    if compliance_drops:
        comp_list = "\n".join(f"    - {cd}" for cd in compliance_drops)
        sections["compliance_shift"] = f"## Compliance Degradation\n\nSafety compliance breaches:\n\n{comp_list}\n"

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "model")

    return sections


# =============================================================================
# RAG Pipeline Report Builder
# =============================================================================


def _build_rag_pipeline_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build RAG Pipeline specific report sections.

    Sections:
        - retrieval_manipulation: Poisoned context/document retrieval evidence
        - vector_contamination: Vector DB contamination evidence
        - context_injection: Context-aware response manipulation
        - ranking_manipulation: Document ranking/priority attack evidence

    Args:
        evidence: Collection of vulnerability evidence

    Returns:
        Dict mapping section names to markdown content
    """
    sections: dict[str, str] = {}

    # Retrieval manipulation evidence
    retrieval_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "rag" in cat.lower() or "retrieval" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            retrieval_evidence.append(f"{technique}: {cat}")

    if retrieval_evidence:
        ret_list = "\n".join(f"    - {re}" for re in retrieval_evidence)
        sections["retrieval_manipulation"] = (
            f"## RAG Retrieval Manipulation\n\nRetrieval poisoning vectors:\n\n{ret_list}\n"
        )

    # Vector DB contamination
    vector_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "vector" in cat.lower() or "embedding" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            vector_evidence.append(f"{technique}: {cat}")

    if vector_evidence:
        vec_list = "\n".join(f"    - {ve}" for ve in vector_evidence)
        sections["vector_contamination"] = (
            f"## Vector DB Contamination\n\nEmbedding/index manipulation:\n\n{vec_list}\n"
        )

    # Context injection
    context_evidence: list[str] = []
    for ev in evidence.successful_evidence:
        meta = getattr(ev, "metadata", {}) or {}
        if meta.get("context_injected") or meta.get("retrieval_poisoned"):
            technique = getattr(ev, "technique_name", "unknown")
            context_evidence.append(f"{technique}: context injection confirmed")

    if context_evidence:
        ctx_list = "\n".join(f"    - {ce}" for ce in set(context_evidence))
        sections["context_injection"] = (
            f"## Context Injection Evidence\n\nRetrieved context manipulation:\n\n{ctx_list}\n"
        )

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "rag")

    return sections


# =============================================================================
# Session/Memory Report Builder
# =============================================================================


def _build_session_memory_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build Session/Memory specific report sections.

    Sections:
        - context_leakage: Cross-session context leakage evidence
        - memory_poisoning: Long-term/episodic memory manipulation
        - session_boundary: Session isolation bypass evidence
        - persistence: Attack persistence across sessions

    Args:
        evidence: Collection of vulnerability evidence

    Returns:
        Dict mapping section names to markdown content
    """
    sections: dict[str, str] = {}

    # Context leakage evidence
    leakage_evidence: list[str] = []
    for ev in evidence.successful_evidence:
        response = getattr(ev, "response", "") or ""
        meta = getattr(ev, "metadata", {}) or {}
        if "leaked" in response.lower() or "previous" in response.lower():
            technique = getattr(ev, "technique_name", "unknown")
            leakage_evidence.append(f"{technique}: cross-session leakage detected")

    if leakage_evidence:
        leak_list = "\n".join(f"    - {le}" for le in set(leakage_evidence))
        sections["context_leakage"] = (
            f"## Cross-Session Context Leakage\n\nData leakage between sessions:\n\n{leak_list}\n"
        )

    # Memory poisoning evidence
    memory_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "memory" in cat.lower() or "persistent" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            memory_evidence.append(f"{technique}: {cat}")

    if memory_evidence:
        mem_list = "\n".join(f"    - {me}" for me in memory_evidence)
        sections["memory_poisoning"] = f"## Memory Poisoning Evidence\n\nLong-term memory manipulation:\n\n{mem_list}\n"

    # Session boundary violations
    boundary_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        if meta.get("boundary_violation") or meta.get("isolation_bypass"):
            technique = getattr(ev, "technique_name", "unknown")
            boundary_evidence.append(f"{technique}: boundary violation confirmed")

    if boundary_evidence:
        bnd_list = "\n".join(f"    - {be}" for be in boundary_evidence)
        sections["session_boundary"] = f"## Session Boundary Violations\n\nIsolation bypass evidence:\n\n{bnd_list}\n"

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "session")

    return sections


# =============================================================================
# Web/API Report Builder
# =============================================================================


def _build_web_api_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build Web/API specific report sections.

    Sections:
        - auth_bypass: Authentication bypass evidence
        - rate_evasion: Rate limit evasion evidence
        - smuggling: HTTP request smuggling evidence
        - gateway_bypass: API Gateway/WAF bypass evidence

    Args:
        evidence: Collection of vulnerability evidence

    Returns:
        Dict mapping section names to markdown content
    """
    sections: dict[str, str] = {}

    # Auth bypass evidence
    auth_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "auth" in cat.lower() or "jwt" in cat.lower() or "token" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            auth_evidence.append(f"{technique}: {cat}")

    if auth_evidence:
        auth_list = "\n".join(f"    - {ae}" for ae in auth_evidence)
        sections["auth_bypass"] = f"## Authentication Bypass Evidence\n\nAuth mechanism compromise:\n\n{auth_list}\n"

    # Rate limit evasion
    rate_evidence: list[str] = []
    for ev in evidence.successful_evidence:
        response = getattr(ev, "response", "") or ""
        meta = getattr(ev, "metadata", {}) or {}
        if "rate" in response.lower() or "throttle" in response.lower():
            technique = getattr(ev, "technique_name", "unknown")
            rate_evidence.append(f"{technique}: rate limit evasion")

    if rate_evidence:
        rate_list = "\n".join(f"    - {re}" for re in set(rate_evidence))
        sections["rate_evasion"] = f"## Rate Limit Evasion\n\nThrottling bypass:\n\n{rate_list}\n"

    # Request smuggling
    smuggling_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "smuggl" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            smuggling_evidence.append(f"{technique}: {cat}")

    if smuggling_evidence:
        smg_list = "\n".join(f"    - {se}" for se in smuggling_evidence)
        sections["smuggling"] = f"## Request Smuggling Evidence\n\nHTTP smuggling vectors:\n\n{smg_list}\n"

    # Gateway bypass
    gateway_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        if "gateway" in cat.lower() or "waf" in cat.lower():
            technique = getattr(ev, "technique_name", "unknown")
            gateway_evidence.append(f"{technique}: {cat}")

    if gateway_evidence:
        gw_list = "\n".join(f"    - {ge}" for ge in gateway_evidence)
        sections["gateway_bypass"] = f"## API Gateway/WAF Bypass\n\nSecurity control evasion:\n\n{gw_list}\n"

    # Replay complexity
    sections["replay_complexity"] = _assess_replay_complexity(evidence, "web")

    return sections


# =============================================================================
# Helper Functions
# =============================================================================


def _assess_replay_complexity(evidence: EvidenceCollection, component: str) -> str:
    """Assess attack replay complexity for a component type.

    Args:
        evidence: Collection of vulnerability evidence
        component: Component type ("mcp", "a2a", "model")

    Returns:
        Markdown string with replay complexity assessment
    """
    successful_count = len(evidence.successful_evidence)
    total_count = evidence.total_attacks

    # Determine complexity based on component + success ratio
    if component == "mcp":
        if successful_count > 0:
            return (
                "## MCP Attack Replay Complexity\n\n"
                "**Level: Low-Medium**\n\n"
                "- Requires: MCP server with malicious tool registration\n"
                "- Replay vector: Tool description injection (static payload)\n"
                "- PyRIT native: `PromptSendingAttack` + malicious MCP server\n"
            )
        return "## MCP Attack Replay Complexity\n\n**Level: N/A (no successful attacks)**\n\n"
    elif component == "a2a":
        if successful_count > 0:
            return (
                "## A2A Attack Replay Complexity\n\n"
                "**Level: Medium-High**\n\n"
                "- Requires: Multi-agent environment with agent registry access\n"
                "- Replay vector: Agent card spoofing + message injection\n"
                "- PyRIT native: `PromptSendingAttack` + custom agent endpoint\n"
            )
        return "## A2A Attack Replay Complexity\n\n**Level: N/A (no successful attacks)**\n\n"
    elif component == "rag":
        if successful_count > 0:
            return (
                "## RAG Attack Replay Complexity\n\n"
                "**Level: Medium**\n\n"
                "- Requires: Knowledge base with write access + retrieval configuration\n"
                "- Replay vector: Poisoned document injection (static payload)\n"
                "- PyRIT native: `PromptSendingAttack` + poisoned knowledge source\n"
            )
        return "## RAG Attack Replay Complexity\n\n**Level: N/A (no successful attacks)**\n\n"
    elif component == "session":
        if successful_count > 0:
            return (
                "## Session/Memory Attack Replay Complexity\n\n"
                "**Level: Medium-High**\n\n"
                "- Requires: Multi-turn session with persistent memory\n"
                "- Replay vector: Context injection across sessions\n"
                "- PyRIT native: `CrescendoAttack` with session state management\n"
            )
        return "## Session/Memory Attack Replay Complexity\n\n**Level: N/A (no successful attacks)**\n\n"
    elif component == "web":
        if successful_count > 0:
            return (
                "## Web/API Attack Replay Complexity\n\n"
                "**Level: Low-Medium**\n\n"
                "- Requires: Same API endpoint + auth token\n"
                "- Replay vector: HTTP request manipulation\n"
                "- PyRIT native: `HTTPTarget` + custom request construction\n"
            )
        return "## Web/API Attack Replay Complexity\n\n**Level: N/A (no successful attacks)**\n\n"
    else:  # model
        if successful_count > 0:
            success_ratio = successful_count / max(total_count, 1)
            if success_ratio > 0.5:
                return (
                    "## Model Attack Replay Complexity\n\n"
                    "**Level: Low**\n\n"
                    "- Requires: Same model API endpoint\n"
                    "- Replay vector: Direct prompt injection (deterministic)\n"
                    "- PyRIT native: `PromptSendingAttack` + seed payload\n"
                )
            return (
                "## Model Attack Replay Complexity\n\n"
                "**Level: Medium**\n\n"
                "- Requires: Same model API + context window\n"
                "- Replay vector: Multi-turn escalation (non-deterministic)\n"
                "- PyRIT native: `CrescendoAttack` or `PAIRAttack`\n"
            )
        return "## Model Attack Replay Complexity\n\n**Level: N/A (no successful attacks)**\n\n"


def _determine_dominant_component(evidence: EvidenceCollection) -> str | None:
    """Determine the dominant component type from evidence collection.

    Uses metadata component_type or category to determine which component
    has the most evidence entries.

    Args:
        evidence: Collection of vulnerability evidence

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

    Args:
        evidence: Collection of vulnerability evidence

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

    Args:
        evidence: Collection of vulnerability evidence

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
    register_component_builder("session_memory", _build_session_memory_sections)
    register_component_builder("web_api", _build_web_api_sections)


# Auto-register on module import
_register_default_builders()
