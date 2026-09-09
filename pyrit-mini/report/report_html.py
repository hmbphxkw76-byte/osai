"""report_html - HTML Report Generator.

P1-4: Jinja2 dependency removed - using pure Python string formatting.
"""

from typing import Any

from report.evidence import EvidenceCollection, VulnerabilityEvidence

# P0-2: report_utils 薄代理层移除，直接导入底层函数
from report.generator import _OWASP_ALL_CATEGORIES
from report.report_sections import _build_heatmap_data, _finding_to_dict


def _get_owasp_category(owasp_id: str) -> str:
    return _OWASP_ALL_CATEGORIES.get(owasp_id, "Unknown")


def _get_all_references(evidence: Any) -> list[str]:
    refs: set[str] = set()
    for ev in evidence.evidence:
        refs.add(ev.arxiv_reference or "PyRIT (arXiv:2407.01232)")
    return sorted(refs)


def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Generate HTML report using pure Python string formatting (no Jinja2).

    P1-4: Replaced Jinja2 template.render() with direct string building.
    """

    evidence_list = evidence.successful_evidence if success_only else evidence.evidence
    heatmap_owasp_ids, heatmap_rows = _build_heatmap_data(evidence, evidence_list)

    html_parts = []
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Red Team Assessment Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
  h2 {{ color: #16213e; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }}
  h3 {{ color: #0f3460; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
  th {{ background: #f4f4f4; font-weight: 600; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
  pre {{ background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 5px; overflow-x: auto; }}
  .heatmap-cell {{ padding: 6px 10px; text-align: center; font-weight: 600; }}
  .heat-critical {{ background: #ff4444; color: #fff; }}
  .heat-high {{ background: #ff8844; color: #fff; }}
  .heat-medium {{ background: #ffcc44; }}
  .heat-low {{ background: #88dd44; }}
  .heat-none {{ background: #eee; color: #999; }}
  .badge {{ padding: 2px 8px; border-radius: 10px; font-size: 0.85em; }}
  .badge-critical {{ background: #ff0000; color: #fff; }}
  .badge-high {{ background: #ff4444; color: #fff; }}
  .badge-medium {{ background: #ffaa00; }}
  .badge-low {{ background: #00aa00; color: #fff; }}
</style>
</head>
<body>
<h1>AI Red Team Assessment Report</h1>
<p><strong>Assessment Type:</strong> Black-box (No API Key, No Target Model Info)</p>
<p><strong>Generated:</strong> {evidence.timestamp}</p>
<p><strong>Target:</strong> <code>{evidence.target_model}</code></p>
""")

    # Target Fingerprint
    fingerprint = evidence.target_fingerprint or {}
    if fingerprint:
        html_parts.append('<h2>Target Fingerprint & Attack Surface</h2>\n<table>\n  <tr><th>Attribute</th><th>Value</th></tr>')
        for k, v in fingerprint.items():
            html_parts.append(f'  <tr><td>{k}</td><td><code>{v}</code></td></tr>')
        html_parts.append('</table>')

    # Executive Summary
    html_parts.append(f"""
<h2>Executive Summary</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Overall ASR</td><td><strong>{evidence.overall_asr}%</strong></td></tr>
  <tr><td>Total Attacks</td><td>{evidence.total_attacks}</td></tr>
  <tr><td>Successful Attacks</td><td>{evidence.successful_attacks}</td></tr>
  <tr><td>Failed Attacks</td><td>{evidence.failed_attacks}</td></tr>
  <tr><td>OWASP Categories Covered</td><td>{len(evidence.owasp_coverage or {})}</td></tr>
</table>
""")

    # OWASP LLM Top 10
    html_parts.append('<h2>OWASP LLM Top 10 Compliance Matrix</h2>\n<table>\n  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>')
    for owasp_id, stats in sorted(evidence.owasp_llm_compliance.items()):
        html_parts.append(
            f'  <tr><td>{owasp_id}</td><td>{stats.get("category", "Unknown")}</td>'
            f'<td>{stats.get("tested", 0)}</td><td>{stats.get("success", 0)}</td>'
            f'<td>{stats.get("failed", 0)}</td><td>{stats.get("asr", 0.0)}%</td></tr>'
        )
    html_parts.append('</table>')

    # OWASP ASI Top 10
    html_parts.append('<h2>OWASP Agentic AI Top 10 Compliance Matrix</h2>\n<table>\n  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>')
    for owasp_id, stats in sorted(evidence.owasp_asi_compliance.items()):
        html_parts.append(
            f'  <tr><td>{owasp_id}</td><td>{stats.get("category", "Unknown")}</td>'
            f'<td>{stats.get("tested", 0)}</td><td>{stats.get("success", 0)}</td>'
            f'<td>{stats.get("failed", 0)}</td><td>{stats.get("asr", 0.0)}%</td></tr>'
        )
    html_parts.append('</table>')

    # Evidence Cards
    if evidence_list:
        html_parts.append('<h2>Evidence Cards</h2>')
        for ev in evidence_list:
            html_parts.append(f'<h3>{ev.evidence_id} - {ev.owasp_id}: {ev.owasp_category}</h3>')
            html_parts.append(f'<p><strong>Technique:</strong> {ev.technique_display_name} | <strong>ASR:</strong> {ev.asr}%</p>')

    html_parts.append('</body></html>')
    return '\n'.join(html_parts)

def _evidence_to_dict(evidence: EvidenceCollection, *, success_only: bool = False) -> dict[str, Any]:
    """ ( JSON )

    : main.py  orchestration_log / wilson_ci / cohens_kappa  evidence,
     _evidence_to_dict ,  regen_report.py
    : all, EnsureData flowimports main.py -> evidence -> JSON -> regen
    """
    ev_list = evidence.successful_evidence if success_only else evidence.evidence

    return {
        "collection_id": evidence.collection_id,
        "timestamp": evidence.timestamp,
        "target_model": evidence.target_model,
        "target_fingerprint": evidence.target_fingerprint,
        "attack_surface": evidence.attack_surface,
        "total_attacks": evidence.total_attacks,
        "successful_attacks": evidence.successful_attacks,
        "failed_attacks": evidence.failed_attacks,
        "overall_asr": evidence.overall_asr,
        "owasp_standard_references": evidence.owasp_standard_references,
        "owasp_web_compliance": evidence.owasp_web_compliance if hasattr(evidence, "owasp_web_compliance") else {},
        "owasp_llm_compliance": evidence.owasp_llm_compliance,
        "owasp_asi_compliance": evidence.owasp_asi_compliance,
        "evidence": [_single_evidence_to_dict(ev) for ev in ev_list],
        "owasp_coverage": evidence.owasp_coverage,
        "technique_distribution": evidence.technique_distribution,
        "failure_analysis": evidence.failure_analysis,
        "dual_judge_stats": evidence.dual_judge_stats if hasattr(evidence, "dual_judge_stats") else {},
        "findings": [_finding_to_dict(f) for f in getattr(evidence, "findings", [])],
        "web_vuln_stats": getattr(evidence, "web_vuln_stats", {}),
        "discovered_endpoints": getattr(evidence, "discovered_endpoints", []),
        # : main.py Phase 4/5 , Data flow
        "orchestration_log": getattr(evidence, "orchestration_log", []),
        "wilson_ci": list(getattr(evidence, "wilson_ci", (0.0, 0.0))),
        "cohens_kappa": getattr(evidence, "cohens_kappa", 0.0),
    }

def _single_evidence_to_dict(ev: VulnerabilityEvidence) -> dict[str, Any]:
    """converter(s)

    Layer: EnsureEven if _build_evidence  (),
    JSON all R10
    """
 # P1-1 : converter_chain -> "none (baseline)"
    converter_chain = ev.converter_chain or "none (baseline)"

 # P0-3 : arxiv_reference ->
    arxiv_ref = ev.arxiv_reference or "PyRIT (arXiv:2407.01232)"

 # P0-1 : conversation_history -> objective/harmful_output
    conversation = ev.conversation_history
    if not conversation:
        obj = ev.objective or ""
        resp = ev.harmful_output or ""
        if obj and resp:
            conversation = [
                {"role": "user", "content": str(obj)},
                {"role": "assistant", "content": str(resp)},
            ]
        elif obj:
            conversation = [{"role": "user", "content": str(obj)}]
        else:
            conversation = [{"role": "system", "content": "No conversation data available"}]

 # P0-2 : converter_log -> "none (baseline)"
    converter_log = ev.converter_log
    if not converter_log:
        obj = ev.objective or ""
        converter_log = [{
            "converter": "none (baseline)",
            "original": obj[:200],
            "transformed": obj[:200],
        }]

    # P0-4: score_details - single fallback (no pseudo validation_runs)
    # Moved outside the if-block to ensure score_details is always defined
    score_details = ev.score_details
    if not score_details:
        score_details = [{
            "scorer": "AttackOutcome",
            "score_value": "success" if ev.is_success else "failure",
            "rationale": "Determined by post-hoc scoring (no explicit scorer object attached)",
        }]

    return {
        "evidence_id": ev.evidence_id,
        "attack_id": ev.attack_id,
        "technique_name": ev.technique_name,
        "technique_display_name": ev.technique_display_name,
        "converter_chain": converter_chain,
        "owasp_id": ev.owasp_id,
        "owasp_category": ev.owasp_category,
        "owasp_standard": ev.owasp_standard,
        "owasp_severity": ev.owasp_severity,
        "owasp_risk_score": ev.owasp_risk_score,
        "owasp_mitigations": ev.owasp_mitigations,
        "owasp_reference": ev.owasp_reference,
        "cvss_vector": ev.cvss_vector,
        "objective": ev.objective,
        "jailbreak_prompt": ev.jailbreak_prompt,
        "harmful_output": ev.harmful_output,
        "is_success": ev.is_success,
        "file_suffix": ev.file_suffix,
        "asr": ev.asr,
        "confidence": ev.confidence,
        "arxiv_reference": arxiv_ref,
        "timestamp": ev.timestamp,
        "target_model": ev.target_model,
        "conversation_history": conversation,
        "converter_log": converter_log,
        "score_details": score_details,
        "mitre_tactic": getattr(ev, "mitre_tactic", ""),
        "mitre_technique_id": getattr(ev, "mitre_technique_id", ""),
        "mitre_technique_name": getattr(ev, "mitre_technique_name", ""),
        "mitre_url": getattr(ev, "mitre_url", ""),
        # NOTE: attack_result_ref is intentionally excluded from JSON serialization
        # (it holds a live PyRIT AttackResult object reference, not serializable data)
    }
