"""report/a2a/sections — A2A Agent Integrity report section builder (object-local)."""
from __future__ import annotations

from report.common.replay import _assess_replay_complexity
from report.evidence import EvidenceCollection


def _build_a2a_agent_integrity_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build A2A Agent Integrity specific report sections.

    Sections:
        - trust_chain: Trust chain integrity analysis
        - agent_topology: Agent interaction topology
        - workflow_integrity: Workflow manipulation evidence
        - routing_hijack: Routing interception evidence
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
