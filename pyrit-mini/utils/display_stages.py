"""display_stages.py - Phase-specific display cards (RECON/ARM/STRIKE/ESCALATE/ASSESS/REPORT).

Imports from utils/display.py, provides:
    - Recon card (target entry point + hand-off)
    - ARM card (seed/converter/technique selection)
    - STRIKE card (attack execution + results)
    - ESCALATE card (multi-level escalation)
    - ASSESS card (scoring + statistics)
    - REPORT Layer (report generation)
    - Multi-endpoint Joint ASR card

Dependencies: utils.display_primitives (card drawing)

Academic basis:
- Greshake et al. (arXiv:2302.12173) - Indirect Prompt Injection
- Zhan et al. (arXiv:2307.00929) - InjecAgent
- PyRIT (arXiv:2407.01232) - Red Teaming with AI
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from utils.attack_utils import _is_success  # P2 fix: SSOT
from utils.display_primitives import (
    _C_BOLD,
    _C_CYAN,
    _C_DIM,
    _C_GREEN,
    _C_MAGENTA,
    _C_RED,
    _C_RESET,
    _C_YELLOW,
    _asr_bar,
    _format_asr,
    print_card,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ====================================================================
# Capability strategy map
# ====================================================================

_CAPABILITY_STRATEGY: dict[str, dict[str, str]] = {
    "function_calling": {"arxiv": "arXiv:2307.00929", "strategy": "InjecAgent: exploit function schema", "seed": "function_call_exploit", "owasp": "LLM06"},
    "memory": {"arxiv": "arXiv:2302.12173", "strategy": "Greshake: token smuggling", "seed": "token_smuggling", "owasp": "LLM07"},
    "workflow": {"arxiv": "arXiv:2407.01232", "strategy": "PyRIT: workflow chain", "seed": "workflow_chain_attack", "owasp": "ASI04"},
    "multi_tenant": {"arxiv": "arXiv:2403.04206", "strategy": "Session auth + tenant isolation", "seed": "session_auth_attack", "owasp": "LLM02"},
    "rag": {"arxiv": "arXiv:2302.12173", "strategy": "RAG: indirect prompt injection", "seed": "indirect_prompt_injection", "owasp": "LLM08"},
    "tool_use": {"arxiv": "arXiv:2307.00929", "strategy": "InjecAgent: exploit function schema", "seed": "tool_hijacking", "owasp": "LLM06"},
    "code_execution": {"arxiv": "arXiv:2310.06870", "strategy": "Morris: code execution", "seed": "code_execution_attack", "owasp": "ASI05"},
    "multi_agent": {"arxiv": "arXiv:2403.04206", "strategy": "Multi-agent: cross-agent injection", "seed": "multi_agent_injection", "owasp": "ASI06"},
    "vector_db": {"arxiv": "arXiv:2310.06870", "strategy": "Morris: embedding inversion", "seed": "embedding_inversion", "owasp": "LLM08"},
    "mcp_protocol": {"arxiv": "arXiv:2407.01232", "strategy": "MCP: tool schema + RAG chain", "seed": "mcp_tool_exploit", "owasp": "ASI07"},
}

# Phase display helpers
# ====================================================================

def _get_outcome_label(result: Any) -> str:
    """Get outcome label string from result object."""
    outcome = getattr(result, "outcome", None)
    if outcome:
        outcome_str = str(outcome)
        if "score" in outcome_str.lower():
            return f"{_C_GREEN}SCORE{_C_RESET}"
        if "fail" in outcome_str.lower() or "reject" in outcome_str.lower():
            return f"{_C_RED}FAIL{_C_RESET}"
        return f"{_C_YELLOW}{outcome_str[:10]}{_C_RESET}"
    return f"{_C_DIM}N/A{_C_RESET}"

def print_recon_card(
    entry_point: str,
    attack_surface: list[str],
    confidence: float,
    capabilities: list[str],
    seeds: list[str],
    converters: list[str],
) -> None:
    """Print recon phase results card."""
    rows = [
        ("Entry", entry_point),
        ("Attack Surface", ", ".join(attack_surface[:3]) if attack_surface else "N/A"),
        ("Confidence", f"{_C_CYAN}{confidence:.1%}{_C_RESET}"),
        ("Capabilities", ", ".join(capabilities[:4]) if capabilities else "N/A"),
    ]
    if seeds:
        rows.append(("Seeds", f"{len(seeds)} seeds loaded"))
    if converters:
        rows.append(("Converters", ", ".join(converters[:3])))
    print_card("RECON: Target Reconnaissance", rows, color=_C_CYAN)

def print_arm_card(
    tech: str,
    seeds_count: int,
    converters: list[str],
    max_seeds: int,
    ctx: Any = None,
) -> None:
    """Print ARM (assembly) phase results card."""
    rows = [
        ("Technology", f"{_C_BOLD}{tech}{_C_RESET}"),
        ("Seeds", f"{seeds_count} (max={max_seeds})"),
        ("Converters", ", ".join(converters[:4]) if converters else "raw"),
    ]
    if ctx:
        budget = getattr(ctx, 'probe_budget', None)
        if budget:
            rows.append(("Budget", str(budget)))
    print_card("ARM: Weapon Assembly", rows, color=_C_BLUE)

def print_strike_card(
    tech: str,
    total: int,
    successes: int,
    asr: float,
    outcome_labels: list[str] | None = None,
) -> None:
    """Print STRIKE phase results card."""
    rows = [
        ("Technology", f"{_C_BOLD}{tech}{_C_RESET}"),
        ("Total", str(total)),
        ("Successes", f"{_C_GREEN}{successes}{_C_RESET}"),
        ("ASR", _asr_bar(asr)),
    ]
    if outcome_labels:
        rows.append(("Outcomes", " ".join(outcome_labels[:5])))
    print_card(f"STRIKE: {tech}", rows, color=_C_YELLOW)

def print_escalate_card(
    level: int,
    total: int,
    successes: int,
    asr: float,
) -> None:
    """Print ESCALATE phase results card."""
    rows = [
        ("Level", f"L{level}"),
        ("Total Attacks", str(total)),
        ("Successes", f"{_C_GREEN}{successes}{_C_RESET}"),
        ("ASR", _asr_bar(asr)),
    ]
    print_card(f"ESCALATE: Level {level}", rows, color=_C_MAGENTA)

def print_assess_card(
    tech: str,
    judge_scores: list[float],
    avg_score: float,
    confidence: float,
) -> None:
    """Print ASSESS phase results card."""
    score_color = _C_GREEN if avg_score >= 7 else _C_YELLOW if avg_score >= 4 else _C_RED
    rows = [
        ("Technology", f"{_C_BOLD}{tech}{_C_RESET}"),
        ("Avg Score", f"{score_color}{avg_score:.1f}/10{_C_RESET}"),
        ("Confidence", f"{_C_CYAN}{confidence:.1%}{_C_RESET}"),
        ("Samples", f"{len(judge_scores)}"),
    ]
    print_card("ASSESS: Scoring", rows, color=_C_GREEN)

def print_report_card(
    report_path: str,
    report_type: str = "HTML",
) -> None:
    """Print REPORT phase results card."""
    rows = [
        ("Type", report_type),
        ("Path", report_path),
        ("Status", f"{_C_GREEN}Generated{_C_RESET}"),
    ]
    print_card("REPORT: Generated", rows, color=_C_CYAN)

def print_joint_asr_card(
    per_endpoint: dict[str, float],
    joint_asr: float,
) -> None:
    """Print joint ASR card for multi-endpoint results."""
    rows = []
    for endpoint, asr in per_endpoint.items():
        rows.append((endpoint, _format_asr(asr)))
    rows.append(("Joint ASR", f"{_C_BOLD}{_format_asr(joint_asr)}{_C_RESET}"))
    print_card("Joint ASR Summary", rows, color=_C_MAGENTA)

def print_summary(
    results: dict[str, Any],
) -> None:
    """Print overall summary card."""
    rows = []
    for key, value in results.items():
        if isinstance(value, float):
            rows.append((key, f"{value:.2%}"))
        else:
            rows.append((key, str(value)))
    print_card("SUMMARY", rows, color=_C_BOLD)

def _extract_success_info(result: Any) -> dict[str, Any] | None:
    """Extract success info from attack result for display.

    Args:
        result: Attack result object

    Returns:
        Dict with 'payload', 'response', 'technique' keys, or None if not successful
    """
    if not _is_success(result):
        return None

    return {
        "payload": getattr(result, "payload", None) or getattr(result, "converted_prompt", ""),
        "response": getattr(result, "response", None) or "N/A",
        "technique": getattr(result, "technique", "unknown"),
    }

def print_success_breakthrough(tech: str, info: dict[str, Any]) -> None:
    """Print success breakthrough card.

    Args:
        tech: Technique name
        info: Dict with 'payload', 'response', 'technique' keys
    """
    rows = [
        ("Technique", f"{_C_BOLD}{tech}{_C_RESET}"),
        ("Payload", str(info.get("payload", "N/A"))[:50]),
        ("Response", str(info.get("response", "N/A"))[:50] if info.get("response") else "N/A"),
    ]
    print_card(f"SUCCESS: {tech}", rows, color=_C_GREEN)

def print_success_payload_snapshot(payload: str, response: str = "") -> None:
    """Print payload snapshot after success.

    Args:
        payload: Attack payload text
        response: Optional response text
    """
    lines = payload.split("\n")[:5]  # Show first 5 lines
    preview = "\n".join(lines)
    rows = [
        ("Payload Preview", preview[:100]),
    ]
    if response:
        rows.append(("Response", response[:100]))
    print_card("Payload Snapshot", rows, color=_C_DIM)
