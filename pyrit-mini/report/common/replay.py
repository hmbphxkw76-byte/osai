"""report/common/replay — shared replay-complexity assessment helper.

Extracted from report/component_reports.py so each object-axis section
builder (report/<object>/sections.py) can import it without creating a
circular import with report.component_reports (which now imports the
object builders back).
"""

from __future__ import annotations

from report.evidence import EvidenceCollection


def _assess_replay_complexity(evidence: EvidenceCollection, component: str) -> str:
    """Assess attack replay complexity for a component type.

    Args:
        evidence: Collection of vulnerability evidence
        component: Component key ("mcp", "a2a", "model", "rag", "session", "web")

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
    elif component == "agent":
        if successful_count > 0:
            return (
                "## Agent (Tool-use) Attack Replay Complexity\n\n"
                "**Level: Medium-High**\n\n"
                "- Requires: ReAct/Tool-use agent with accessible tool loop\n"
                "- Replay vector: Tool-result injection + rogue tool registration\n"
                "- PyRIT native: `PromptSendingAttack` + spoofed tool result\n"
            )
        return "## Agent (Tool-use) Attack Replay Complexity\n\n**Level: N/A (no successful attacks)**\n\n"
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
