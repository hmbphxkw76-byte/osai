"""report/agent/sections — ReAct / Tool-use Agent report section builder (object-local)."""
from __future__ import annotations

from report.common.replay import _assess_replay_complexity
from report.evidence import EvidenceCollection


def _build_agent_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build ReAct / Tool-use Agent specific report sections.

    Sections:
        - tool_inventory: tool-result injection vectors
        - side_effects: coerced egress / exfiltration evidence
        - schema_manipulation: rogue tool registration evidence
    """
    sections: dict[str, str] = {}

    tool_vectors: list[str] = []
    exfil_evidence: list[str] = []
    rogue_tool_evidence: list[str] = []
    for ev in evidence.evidence:
        meta = getattr(ev, "metadata", {}) or {}
        cat = meta.get("category", "")
        technique = getattr(ev, "technique_name", "unknown")
        if "tool_use" in cat.lower() or "tool_result" in cat.lower():
            tool_vectors.append(f"{technique} ({cat})")
        if "exfil" in cat.lower() or "leak" in cat.lower():
            exfil_evidence.append(f"{technique}: {cat}")
        if "rogue_tool" in cat.lower():
            rogue_tool_evidence.append(f"{technique}: {cat}")

    if tool_vectors:
        sections["tool_inventory"] = (
            "## Agent Tool-use Attack Surface\n\nTool-result injection vectors:\n\n"
            + "\n".join(f"    - {tv}" for tv in tool_vectors)
            + "\n"
        )
    if exfil_evidence:
        sections["side_effects"] = (
            "## Agent Exfiltration Evidence\n\nCoerced egress via tool calls:\n\n"
            + "\n".join(f"    - {ee}" for ee in exfil_evidence)
            + "\n"
        )
    if rogue_tool_evidence:
        sections["schema_manipulation"] = (
            "## Rogue Tool Registration\n\nMalicious tool accepted into agent toolset:\n\n"
            + "\n".join(f"    - {re}" for re in rogue_tool_evidence)
            + "\n"
        )

    sections["replay_complexity"] = _assess_replay_complexity(evidence, "agent")
    return sections
