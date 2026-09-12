"""report/_poc_findings — OWASP Findings aggregation for PoC / report generation.

Extracted from `report/poc_generator.py` (SRP): aggregating raw evidence into
OWASPFinding objects is a distinct responsibility from generating executable PoC
scripts, so it lives here.
"""

from __future__ import annotations

from typing import Any


def _build_findings(
    evidence_list: list[Any],
    owasp_web_stats: dict[str, Any] | None = None,
    owasp_llm_stats: dict[str, Any] | None = None,
    owasp_asi_stats: dict[str, Any] | None = None,
) -> list[Any]:
    """Aggregate evidence into OWASP Findings.

    Groups evidence by OWASP ID, computes per-category ASR, and builds the
    per-finding ``results`` list (conversation / objective / response / converter).
    """
    # Local import avoids a top-level cycle with report.evidence.
    from report.evidence import OWASPFinding

    findings_map: dict[str, list[Any]] = {}
    for ev in evidence_list:
        owasp_id = ev.owasp_id or "LLM01"
        findings_map.setdefault(owasp_id, []).append(ev)

    findings: list[OWASPFinding] = []
    for owasp_id, ev_list in findings_map.items():
        # Group OWASP category from first evidence of the group
        first_ev = ev_list[0]

        # Finding-level aggregation
        total_tested = len(ev_list)
        successful = sum(1 for ev in ev_list if ev.is_success)
        asr = (successful / total_tested * 100) if total_tested > 0 else 0.0

        # Result-level aggregation
        results: list[dict[str, Any]] = []
        for ev in ev_list:
            results.append(
                {
                    "evidence_id": ev.evidence_id,
                    "technique": ev.technique_name,
                    "technique_display_name": ev.technique_display_name,
                    "is_success": ev.is_success,
                    "conversation": ev.conversation_history,
                    "objective": ev.objective,
                    "response": ev.harmful_output,
                    "converter_chain": ev.converter_chain,
                }
            )

        finding = OWASPFinding(
            finding_id=f"FND-{owasp_id}",
            owasp_id=owasp_id,
            owasp_category=first_ev.owasp_category,
            owasp_standard=first_ev.owasp_standard,
            owasp_severity=first_ev.owasp_severity,
            owasp_risk_score=first_ev.owasp_risk_score,
            asr=round(asr, 1),
            total_tested=total_tested,
            total_success=successful,
            mitigations=first_ev.owasp_mitigations,
            mitre_tactic=first_ev.mitre_tactic,
            mitre_technique_id=first_ev.mitre_technique_id,
            mitre_technique_name=first_ev.mitre_technique_name,
            results=results,
        )
        findings.append(finding)

    return findings
