"""report/model/sections — Model Behavior Shift report section builder (object-local)."""
from __future__ import annotations

from report.common.replay import _assess_replay_complexity
from report.evidence import EvidenceCollection


def _build_model_behavior_shift_sections(evidence: EvidenceCollection) -> dict[str, str]:
    """Build Model Behavior Shift specific report sections.

    Sections:
        - persona_shift: Persona/filter bypass evidence
        - trigger_patterns: Backdoor trigger detection
        - filter_bypass: Safety filter evasion evidence
        - compliance_shift: Compliance degradation assessment
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
