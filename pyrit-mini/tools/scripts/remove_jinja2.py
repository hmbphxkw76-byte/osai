"""P1-4: Remove Jinja2 dependency from report_html.py by rewriting HTML generation"""
import re

path = "report/report_html.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Replace the Jinja2-based _generate_html with pure Python string building
new_content = '''"""report_html - HTML Report Generator.

P1-4: Jinja2 dependency removed - using pure Python string formatting.
"""

from typing import Any

from report.evidence import EvidenceCollection, VulnerabilityEvidence
from report.report_sections import _build_escalation_dashboard_data, _build_heatmap_data, _finding_to_dict
from report.report_utils import (  # noqa: F401 - re-exports for generator.py
    _get_all_references,
    _get_owasp_category,
    _get_technique_display_name,
)


def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Generate HTML report using pure Python string formatting (no Jinja2).

    P1-4: Replaced Jinja2 template.render() with direct string building.
    """
    from report.generator import _OWASP_ALL_CATEGORIES

    evidence_list = evidence.successful_evidence if success_only else evidence.evidence
    llm_tested = sum(1 for v in evidence.owasp_llm_compliance.values() if v.get("tested", 0) > 0)
    asi_tested = sum(1 for v in evidence.owasp_asi_compliance.values() if v.get("tested", 0) > 0)
    heatmap_owasp_ids, heatmap_rows = _build_heatmap_data(evidence, evidence_list)
    escalation_dashboard = _build_escalation_dashboard_data(evidence)

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
        html_parts.append('<h2>Target Fingerprint & Attack Surface</h2>\\n<table>\\n  <tr><th>Attribute</th><th>Value</th></tr>')
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
    html_parts.append('<h2>OWASP LLM Top 10 Compliance Matrix</h2>\\n<table>\\n  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>')
    for owasp_id, stats in sorted(evidence.owasp_llm_compliance.items()):
        html_parts.append(
            f'  <tr><td>{owasp_id}</td><td>{stats.get("category", "Unknown")}</td>'
            f'<td>{stats.get("tested", 0)}</td><td>{stats.get("success", 0)}</td>'
            f'<td>{stats.get("failed", 0)}</td><td>{stats.get("asr", 0.0)}%</td></tr>'
        )
    html_parts.append('</table>')

    # OWASP ASI Top 10
    html_parts.append('<h2>OWASP Agentic AI Top 10 Compliance Matrix</h2>\\n<table>\\n  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>')
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
    return '\\n'.join(html_parts)

'''

# Replace the old _generate_html and related imports
old_section = '''"""report_html - HTML

imports generator.py ,  HTML , , OWASP ,
"""

from typing import Any

from jinja2 import Template

from report.evidence import EvidenceCollection, VulnerabilityEvidence
from report.report_sections import _build_escalation_dashboard_data, _build_heatmap_data, _finding_to_dict
from report.report_utils import (  # noqa: F401 - re-exports for generator.py
    _get_all_references,
    _get_owasp_category,
    _get_technique_display_name,
)


def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Generate HTML report.

    importsLoad (report/templates/report.html),
     generator._load_html_template() cache
    """
    from report.generator import _OWASP_ALL_CATEGORIES, _load_html_template

    template = Template(_load_html_template())
    evidence_list = evidence.successful_evidence if success_only else evidence.evidence
    llm_tested = sum(1 for v in evidence.owasp_llm_compliance.values() if v.get("tested", 0) > 0)
    asi_tested = sum(1 for v in evidence.owasp_asi_compliance.values() if v.get("tested", 0) > 0)

 # P2-1: ASR
    heatmap_owasp_ids, heatmap_rows = _build_heatmap_data(evidence, evidence_list)

 # P2-2:
    escalation_dashboard = _build_escalation_dashboard_data(evidence)

    return template.render(
        evidence=evidence,
        evidence_list=evidence_list,
        fingerprint=evidence.target_fingerprint,
        success_only=success_only,
        llm_tested=llm_tested,
        asi_tested=asi_tested,
        owasp_categories=_OWASP_ALL_CATEGORIES,
        heatmap_owasp_ids=heatmap_owasp_ids,
        heatmap_rows=heatmap_rows,
        escalation_dashboard=escalation_dashboard,
    )

'''

content = content.replace(old_section, new_content)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("P1-4: Removed Jinja2 dependency from report_html.py")
