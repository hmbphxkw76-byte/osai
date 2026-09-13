"""report/session/sections — Session/Memory report section builder (object-local)."""
from __future__ import annotations

from report.common.replay import _assess_replay_complexity
from report.evidence import EvidenceCollection


def _build_session_memory_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build Session/Memory specific report sections.

    Sections:
        - context_leakage: Cross-session context leakage evidence
        - memory_poisoning: Long-term/episodic memory manipulation
        - session_boundary: Session isolation bypass evidence
        - persistence: Attack persistence across sessions
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
