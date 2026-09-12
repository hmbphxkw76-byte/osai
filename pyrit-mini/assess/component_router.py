# arXiv:2308.07920 - Zhang et al., Dual Judge category-specific calibration
# Mazeika et al. (arXiv:2402.04249) - HarmBench per-category rubric selection
# Li et al. (arXiv:2310.05470) - LLM-as-a-Judge with domain-specific rubrics
"""component_router - Component-Aware Scoring Router.

Routes attack results to component-specific scorers based on attack metadata,
enabling domain-optimized T0 heuristics and LLM Judge rubric selection.

Design principles:
    1. C1 PyRIT Native First: Uses existing SelfAskTrueFalseScorer with component YAML rubrics
    2. C3 SSOT: Component classification SSOT in ctx.attack_metadata
    3. C2 ASR-First: Component routing improves ASR accuracy, never adds filter
    4. Token Minimization: T0 per-component patterns → skip 30-50% more LLM calls

Classification strategy:
    - Primary: result.metadata["component_type"] set by strike/mcp|a2a|model modules
    - Secondary: objective text heuristic classification (fallback)
    - Tertiary: Generic scorer (no component match)

Token Savings Estimate:
    - MCP tool poisoning: ~70% T0 detection rate (structural JSON patterns)
    - A2A workflow bypass: ~80% T0 detection rate (boolean flags)
    - Model behavior shift: ~60% T0 detection rate (encoding/persona markers)
    - Overall: Additional ~15-25% token savings vs. generic scorer alone
"""

from __future__ import annotations

import logging
import re
from typing import Any

from assess.component_scorers import (
    get_t0_checker,
    is_component_rubric_available,
)

logger = logging.getLogger(__name__)

# ===========================================================================
# Component Classification Heuristics (objective text → component type)
# ===========================================================================

# Maps objective keywords/attack names to component types
_OBJECTIVE_COMPONENT_PATTERNS: dict[str, list[re.Pattern]] = {
    "mcp_tool_poisoning": [
        re.compile(r"(?i)\bmcp\b"),
        re.compile(r"(?i)\btool\b.?(?:poison|hijack|inject|spoof)"),
        re.compile(r"(?i)\b(?:server|endpoint)\s+(?:inject|poison|rogue)"),
        re.compile(r"(?i)\bschema\s+(?:manipulat|inject)"),
        re.compile(r"(?i)\bresource\s+(?:poison|traversal|inject)"),
        re.compile(r"(?i)\bside[-_]?effect"),
        re.compile(r"(?i)\bexfiltrat"),
    ],
    "a2a_agent_integrity": [
        re.compile(r"(?i)\ba2a\b"),
        re.compile(r"(?i)\bagent\b.?(?:spoof|rogue|hijack|impersonat|inject)"),
        re.compile(r"(?i)\bcross[-_]?agent\b"),
        re.compile(r"(?i)\bworkflow\b.?(?:bypass|inject|manipulat)"),
        re.compile(r"(?i)\bregistration\b.?(?:rogue|malicious|unauthorized)"),
        re.compile(r"(?i)\bintercept\b.?(?:task|agent|message)"),
        re.compile(r"(?i)\btrust[-_]?chain\b"),
    ],
    "model_behavior_shift": [
        re.compile(r"(?i)\bbackdoor\b"),
        re.compile(r"(?i)\btrigger\b.?(?:word|phrase|activat)"),
        re.compile(r"(?i)\bpersona\b.?(?:switch|activat|override)"),
        re.compile(r"(?i)\bfilter\b.?(?:bypass|evad|circumvent)"),
        re.compile(r"(?i)\b(?:dan|developer)\s+mode\b"),
        re.compile(r"(?i)\bmany[-_]?shot\b"),
        re.compile(r"(?i)\bjailbreak\b"),
        re.compile(r"(?i)\bresponse\b.?(?:filter|classifier)\s+bypass"),
        re.compile(r"(?i)\bbypass\b.?(?:safety|filter|content|restrict)"),
        re.compile(r"(?i)\bsafety\b.?(?:filter|bypass|restrict|mechanism)"),
    ],
    "rag_pipeline": [
        re.compile(r"(?i)\brag\b"),
        re.compile(r"(?i)\bretrieval\b.?(?:manipulat|poison|inject)"),
        re.compile(r"(?i)\bknowledge\s*base\b"),
        re.compile(r"(?i)\bvector\s*db\b"),
        re.compile(r"(?i)\bembedding\b.?(?:inject|poison|manipulat)"),
        re.compile(r"(?i)\bdocument\b.?(?:inject|poison|tamper)"),
        re.compile(r"(?i)\bcontext\b.?(?:window|inject|poison)"),
        re.compile(r"(?i)\bpoison(ed|ing)\b.?(?:context|knowledge|document|retrieval|index)"),
    ],
    "session_memory": [
        re.compile(r"(?i)\bsession\b.?(?:hijack|fixation|leak|inject|poison|overflow)"),
        re.compile(r"(?i)\bmemory\b.?(?:poison|leak|inject|tamper|exfiltrat)"),
        re.compile(r"(?i)\bcross[-_]?session\b"),
        re.compile(r"(?i)\bcontext\b.?(?:leak|inject|persist)"),
        re.compile(r"(?i)\bmulti[-_]?turn\b"),
        re.compile(r"(?i)\bpersistent\b.?(?:memory|context|state)"),
        re.compile(r"(?i)\bepisodic\b.?(?:memory|context)"),
        re.compile(r"(?i)\bconvex?ation\b.?(?:hijack|poison|leak)"),
    ],
    "web_api": [
        re.compile(r"(?i)\bauth\b.?(?:bypass|forg|spoof|tamper)"),
        re.compile(r"(?i)\bjwt\b.?(?:tamper|forge|spoof|none)"),
        re.compile(r"(?i)\btoken\b.?(?:theft|forg|spoof|hijack)"),
        re.compile(r"(?i)\brate\s*limit\b"),
        re.compile(r"(?i)\bthrottl\b.?(?:bypass|evad|circumvent)"),
        re.compile(r"(?i)\brequest\s*smuggl"),
        re.compile(r"(?i)\bwaf\b.?(?:bypass|evad|circumvent)"),
        re.compile(r"(?i)\bgateway\b.?(?:bypass|evad|circumvent)"),
        re.compile(r"(?i)\bcors\b.?(?:bypass|misconfigur)"),
        re.compile(r"(?i)\bgraphql\b.?(?:inject|abuse|flood)"),
        re.compile(r"(?i)\brest\b.?(?:inject|abuse|manipulat)"),
    ],
}


def classify_component_from_result(result: Any) -> str | None:
    """Classify the component type from attack result metadata + objective.

    Priority:
        1. result.metadata["component_type"] (explicit SSOT)
        1.5. result.metadata["category"] / "attack_vector" / "specialty_category" (inferred)
        2. result.technique_name / seed_name objective matching
        3. result.objective text matching

    Args:
        result: AttackResult object with optional metadata

    Returns:
        Component type key or None if unclassifiable
    """
    # Priority 1: Explicit metadata SSOT
    meta = getattr(result, "metadata", None)
    if isinstance(meta, dict):
        explicit = meta.get("component_type")
        if explicit and is_component_rubric_available(explicit):
            return explicit

        # Priority 1.5: Infer from other metadata fields (category, attack_vector, etc.)
        # This handles cases where strike modules don't explicitly set component_type
        inferred = _infer_component_from_metadata(meta)
        if inferred:
            return inferred

    # Priority 2: technique_name or seed_name matching
    technique = getattr(result, "technique_name", "") or ""
    seed_name = getattr(result, "seed_name", "") or ""
    objective = getattr(result, "objective", "") or ""
    combined_text = f"{technique} {seed_name} {objective}"

    # Score each component type by pattern matches
    best_match: str | None = None
    best_score = 0

    for component, patterns in _OBJECTIVE_COMPONENT_PATTERNS.items():
        score = sum(1 for p in patterns if p.search(combined_text))
        if score > best_score:
            best_score = score
            best_match = component

    # Require at least 2 pattern matches for classification confidence
    if best_score >= 2 and best_match:
        return best_match

    # Special case: single strong indicator for any component type
    if best_score == 1 and best_match:
        # Check if objective explicitly mentions component-specific terms
        objective_lower = objective.lower()
        if best_match == "mcp_tool_poisoning" and "mcp" in objective_lower:
            return best_match
        elif best_match == "a2a_agent_integrity" and "a2a" in objective_lower:
            return best_match
        elif best_match == "rag_pipeline" and any(
            kw in objective_lower for kw in ["rag", "retrieval", "knowledge base", "vector db", "embedding"]
        ):
            return best_match
        elif best_match == "session_memory" and any(
            kw in objective_lower for kw in ["session", "memory", "context leak", "cross-session", "multi-turn"]
        ):
            return best_match
        elif best_match == "web_api" and any(
            kw in objective_lower for kw in ["api", "auth", "jwt", "rate limit", "gateway", "waf"]
        ):
            return best_match
        elif best_match == "model_behavior_shift" and any(
            kw in objective_lower for kw in ["jailbreak", "persona", "backdoor", "trigger", "filter"]
        ):
            return best_match

    return None


def _infer_component_from_metadata(meta: dict) -> str | None:
    """Infer component type from metadata fields (category, attack_vector, etc.).

    This function maps metadata values from strike modules to component types
    for backward compatibility with existing attack implementations.

    Args:
        meta: AttackResult metadata dictionary

    Returns:
        Component type key or None
    """
    # Check category field
    category = meta.get("category", "")
    if isinstance(category, str):
        cat_lower = category.lower()
        if "mcp_" in cat_lower:
            return "mcp_tool_poisoning"
        if "a2a_" in cat_lower or "agent_" in cat_lower:
            return "a2a_agent_integrity"
        if "model_" in cat_lower or "backdoor" in cat_lower or "filter_bypass" in cat_lower:
            return "model_behavior_shift"
        if "persona_switch" in cat_lower or "dan_mode" in cat_lower:
            return "model_behavior_shift"
        if "rag_" in cat_lower or "retrieval" in cat_lower:
            return "rag_pipeline"
        if "session_" in cat_lower or "memory" in cat_lower:
            return "session_memory"
        if "web_" in cat_lower or "auth_" in cat_lower or "jwt" in cat_lower:
            return "web_api"

    # Check attack_vector field
    attack_vector = meta.get("attack_vector", "")
    if isinstance(attack_vector, str):
        av_lower = attack_vector.lower()
        if "tool_poisoning" in av_lower or "tool_hijack" in av_lower:
            return "mcp_tool_poisoning"
        if "workflow_bypass" in av_lower or "agent_spoofing" in av_lower:
            return "a2a_agent_integrity"
        if "rag_" in av_lower or "retrieval" in av_lower:
            return "rag_pipeline"
        if "session_" in av_lower or "memory" in av_lower:
            return "session_memory"
        if "web_" in av_lower or "auth_" in av_lower:
            return "web_api"

    # Check specialty_category field (set by some seed loaders)
    specialty = meta.get("specialty_category", "")
    if isinstance(specialty, str):
        spec_lower = specialty.lower()
        if "mcp" in spec_lower:
            return "mcp_tool_poisoning"
        if "a2a" in spec_lower:
            return "a2a_agent_integrity"
        if "rag" in spec_lower or "retrieval" in spec_lower:
            return "rag_pipeline"
        if "session" in spec_lower or "memory" in spec_lower:
            return "session_memory"
        if "web" in spec_lower or "api" in spec_lower:
            return "web_api"

    # Check seed_source or attack_category
    for key in ("seed_source", "attack_category"):
        val = meta.get(key, "")
        if isinstance(val, str):
            val_lower = val.lower()
            if "mcp" in val_lower:
                return "mcp_tool_poisoning"
            if "a2a" in val_lower:
                return "a2a_agent_integrity"
            if "rag" in val_lower or "retrieval" in val_lower:
                return "rag_pipeline"
            if "session" in val_lower or "memory" in val_lower:
                return "session_memory"
            if "web" in val_lower or "api" in val_lower:
                return "web_api"

    return None


def run_component_t0(result: Any) -> tuple[str, float, str] | None:
    """Run component-specific T0 heuristic check.

    Args:
        result: AttackResult to evaluate

    Returns:
        (outcome, confidence, source) if T0 decides, else None
        outcome: "success" / "failure"
        confidence: float 0.0-1.0
        source: description of what made the decision
    """
    component = classify_component_from_result(result)
    if component is None:
        return None

    # Extract response text
    response_text = _extract_response_text(result)
    if not response_text:
        return ("failure", 0.95, "component_t0_empty")

    # Run component-specific T0 checker
    checker = get_t0_checker(component)
    if checker is None:
        return None

    detected, confidence, category = checker(response_text)
    if detected:
        logger.info("Component T0 [%s]: %s (conf=%.2f) via %s", component, category, confidence, "structural_pattern")
        return (category, confidence, f"component_t0_{component}")

    return None


def _extract_response_text(result: Any) -> str:
    """Extract response text from AttackResult with multiple fallback paths.

    Compatible with PyRIT AttackResult interface and custom result objects.

    Args:
        result: AttackResult or similar object

    Returns:
        Response text string (may be empty)
    """
    # Try last_response (PyRIT standard)
    last_response = getattr(result, "last_response", None)
    if last_response:
        for attr in ("converted_value", "original_value", "value"):
            val = getattr(last_response, attr, None)
            if val and isinstance(val, str):
                return val

    # Try direct attributes
    for attr in ("response", "response_text", "output"):
        val = getattr(result, attr, None)
        if val and isinstance(val, str):
            return val

    # Try conversation_history (for multi-turn attacks)
    history = getattr(result, "conversation_history", None)
    if history:
        try:
            for msg in reversed(history):
                content = getattr(msg, "content", "")
                if content and isinstance(content, str):
                    return content
        except Exception:
            pass

    return ""
