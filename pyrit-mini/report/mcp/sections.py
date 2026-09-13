"""report/mcp/sections — MCP Tool Poisoning report section builder (object-local).

Moved verbatim from report/component_reports.py to realize the object-axis:
the MCP converter/config lives under report/mcp/, matching strike/mcp/.
"""
from __future__ import annotations

from report.common.replay import _assess_replay_complexity
from report.evidence import EvidenceCollection


def _build_mcp_tool_poisoning_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build MCP Tool Poisoning specific report sections.

    Sections:
        - tool_inventory: Summary of discovered/attacked MCP tools
        - schema_manipulation: Schema poisoning evidence
        - side_effects: Attacker notification or data exfiltration evidence
        - replay_complexity: Complexity assessment for attack replay
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
