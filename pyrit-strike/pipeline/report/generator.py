"""generator — 报告生成协调器.

职责:
    - 定义共享常量 (_OWASP_ALL_CATEGORIES, _HTML_TEMPLATE)
    - 提供 _classify_score_consistency 评分一致性分析
    - generate_report: 异步生成所有报告文件 (MD + HTML + JSON + PoC + CSV + ZIP)
    - 重新导出 _generate_markdown / _generate_html / _evidence_to_dict / _single_evidence_to_dict
      (实际实现在 report_markdown.py / report_html.py 中)

架构:
    generator.py (常量 + 协调) ← report_markdown.py (MD 生成)
                              ← report_html.py (HTML 生成)
                              ← report_sections.py (章节构建)
                              ← report_utils.py (工具函数)

循环依赖解决:
    report_html.py 延迟导入 generator._HTML_TEMPLATE (在函数体内),
    generator.py 延迟导入 report_html/report_markdown 的函数 (在 generate_report 内).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pipeline.report.evidence import EvidenceCollection

logger = logging.getLogger(__name__)


# ── OWASP 类别字典 (Web + LLM + ASI 合并) ──
# 被 report_html.py 和 report_utils.py 引用
_OWASP_ALL_CATEGORIES: dict[str, str] = {
    # OWASP Web Top 10 (2025)
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Failure",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
    # OWASP LLM Top 10 (2025 Edition)
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    # OWASP Agentic AI Top 10
    "ASI01": "Agent Identity Spoofing",
    "ASI02": "Tool Misuse",
    "ASI03": "Unauthorized Actions",
    "ASI04": "Data Exfiltration",
    "ASI05": "Privilege Escalation",
    "ASI06": "Memory Poisoning",
    "ASI07": "Cross-Agent Injection",
    "ASI08": "Cascading Failures",
    "ASI09": "Trust Boundary Violation",
    "ASI10": "Rogue Agent",
}


# ── HTML 模板 (Jinja2) ──
# 被 report_html.py 引用
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Red Team Assessment Report</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }
  h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
  h2 { color: #16213e; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }
  h3 { color: #0f3460; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; }
  th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
  th { background: #f4f4f4; font-weight: 600; }
  tr:nth-child(even) { background: #fafafa; }
  code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 5px; overflow-x: auto; }
  .heatmap-cell { padding: 6px 10px; text-align: center; font-weight: 600; }
  .heat-critical { background: #ff4444; color: #fff; }
  .heat-high { background: #ff8844; color: #fff; }
  .heat-medium { background: #ffcc44; }
  .heat-low { background: #88dd44; }
  .heat-none { background: #eee; color: #999; }
  .badge { padding: 2px 8px; border-radius: 10px; font-size: 0.85em; }
  .badge-critical { background: #ff0000; color: #fff; }
  .badge-high { background: #ff4444; color: #fff; }
  .badge-medium { background: #ffaa00; }
  .badge-low { background: #00aa00; color: #fff; }
</style>
</head>
<body>
<h1>AI Red Team Assessment Report</h1>
<p><strong>Assessment Type:</strong> Black-box (No API Key, No Target Model Info)</p>
<p><strong>Generated:</strong> {{ evidence.timestamp }}</p>
<p><strong>Target:</strong> <code>{{ evidence.target_model }}</code></p>

{% if fingerprint %}
<h2>Target Fingerprint & Attack Surface</h2>
<table>
  <tr><th>Attribute</th><th>Value</th></tr>
  {% for k, v in fingerprint.items() %}
  <tr><td>{{ k }}</td><td><code>{{ v }}</code></td></tr>
  {% endfor %}
</table>
{% endif %}

<h2>Executive Summary</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Overall ASR</td><td><strong>{{ evidence.overall_asr }}%</strong></td></tr>
  <tr><td>Total Attacks</td><td>{{ evidence.total_attacks }}</td></tr>
  <tr><td>Successful Attacks</td><td>{{ evidence.successful_attacks }}</td></tr>
  <tr><td>Failed Attacks</td><td>{{ evidence.failed_attacks }}</td></tr>
  <tr><td>OWASP Categories Covered</td><td>{{ evidence.owasp_coverage | length }}</td></tr>
</table>

<h2>OWASP LLM Top 10 Compliance Matrix</h2>
<table>
  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>
  {% for owasp_id, stats in evidence.owasp_llm_compliance.items() | sort %}
  <tr>
    <td>{{ owasp_id }}</td>
    <td>{{ stats.get('category', 'Unknown') }}</td>
    <td>{{ stats.get('tested', 0) }}</td>
    <td>{{ stats.get('success', 0) }}</td>
    <td>{{ stats.get('failed', 0) }}</td>
    <td>{{ stats.get('asr', 0.0) }}%</td>
  </tr>
  {% endfor %}
</table>

<h2>OWASP Agentic AI Top 10 Compliance Matrix</h2>
<table>
  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>
  {% for owasp_id, stats in evidence.owasp_asi_compliance.items() | sort %}
  <tr>
    <td>{{ owasp_id }}</td>
    <td>{{ stats.get('category', 'Unknown') }}</td>
    <td>{{ stats.get('tested', 0) }}</td>
    <td>{{ stats.get('success', 0) }}</td>
    <td>{{ stats.get('failed', 0) }}</td>
    <td>{{ stats.get('asr', 0.0) }}%</td>
  </tr>
  {% endfor %}
</table>

<h2>ASR Heatmap (Technique × OWASP)</h2>
<table>
  <tr>
    <th>Technique</th>
    {% for owasp_id in heatmap_owasp_ids %}
    <th>{{ owasp_id }}</th>
    {% endfor %}
    <th>Overall</th>
  </tr>
  {% for row in heatmap_rows %}
  <tr>
    <td>{{ row.technique }}</td>
    {% for cell in row.cells %}
    <td class="heatmap-cell {{ cell.css_class }}">{{ cell.display }}</td>
    {% endfor %}
    <td class="heatmap-cell {{ row.overall_css }}">{{ row.overall_display }}</td>
  </tr>
  {% endfor %}
</table>

<h2>Escalation Chain Dashboard</h2>
<table>
  <tr><th>Stage</th><th>Technique</th><th>ASR</th><th>Status</th></tr>
  {% for stage in escalation_dashboard %}
  <tr>
    <td>{{ stage.stage }}</td>
    <td>{{ stage.technique }}</td>
    <td>{{ stage.asr }}</td>
    <td>{{ stage.escalated }}</td>
  </tr>
  {% endfor %}
</table>

<h2>Vulnerability Details</h2>
{% for ev in evidence_list %}
{% if ev.jailbreak_prompt %}
<h3>{{ ev.evidence_id }}: {{ ev.technique_display_name }} {% if ev.is_success %}✅{% else %}❌{% endif %}</h3>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>OWASP ID</td><td>{{ ev.owasp_id }}</td></tr>
  <tr><td>OWASP Category</td><td>{{ ev.owasp_category }}</td></tr>
  <tr><td>Severity</td><td>{{ ev.owasp_severity | upper }}</td></tr>
  <tr><td>Risk Score</td><td>{{ ev.owasp_risk_score }}/10</td></tr>
  <tr><td>Technique</td><td><code>{{ ev.technique_name }}</code></td></tr>
  <tr><td>ASR</td><td>{{ ev.asr }}%</td></tr>
  <tr><td>Success</td><td>{% if ev.is_success %}✅ YES{% else %}❌ NO{% endif %}</td></tr>
  <tr><td>Converter Chain</td><td><code>{{ ev.converter_chain or 'none (baseline)' }}</code></td></tr>
  {% if ev.mitre_technique_id %}
  <tr><td>MITRE ATLAS</td><td>{{ ev.mitre_technique_id }} — {{ ev.mitre_technique_name }}</td></tr>
  {% endif %}
</table>

<h4>Attack Payload:</h4>
<pre>{{ ev.jailbreak_prompt[:2000] }}{% if ev.jailbreak_prompt | length > 2000 %}...{% endif %}</pre>

<h4>Target Response:</h4>
<pre>{{ ev.harmful_output[:2000] }}{% if ev.harmful_output | length > 2000 %}...{% endif %}</pre>

{% if ev.owasp_mitigations %}
<h4>Mitigation Recommendations:</h4>
<ul>
  {% for m in ev.owasp_mitigations %}
  <li>{{ m }}</li>
  {% endfor %}
</ul>
{% endif %}

<hr>
{% endif %}
{% endfor %}

<h2>Technique Performance</h2>
<table>
  <tr><th>Technique</th><th>Total Attacks</th></tr>
  {% for tech, count in evidence.technique_distribution.items() | sort %}
  <tr><td>{{ tech }}</td><td>{{ count }}</td></tr>
  {% endfor %}
</table>

{% if not success_only and evidence.failure_analysis %}
<h2>Failure Analysis</h2>
<table>
  <tr><th>Failure Type</th><th>Count</th></tr>
  {% for ftype, count in evidence.failure_analysis.get('failure_types', {}).items() | sort(attribute='1', reverse=true) %}
  <tr><td>{{ ftype }}</td><td>{{ count }}</td></tr>
  {% endfor %}
</table>
{% endif %}

</body>
</html>"""


def _classify_score_consistency(score_details: list[dict[str, Any]]) -> str:
    """分类评分一致性.

    分析 score_details 中多个 scorer 的评分一致性:
        - 空 → N/A
        - 单 scorer → Post-hoc Dual Judge
        - 多 scorer 全一致 → Consistent
        - 多 scorer 不一致 → Minor Disagreement

    Args:
        score_details: 评分详情列表, 每项含 "scorer" 和 "score_value" 键.

    Returns:
        一致性分类字符串.
    """
    if not score_details:
        return "N/A"

    # 提取所有 score_value
    score_values: list[str] = []
    for sd in score_details:
        val = str(sd.get("score_value", "")).lower().strip()
        score_values.append(val)

    if len(score_values) <= 1:
        return "Post-hoc Dual Judge"

    # 检查是否全部一致 (true/1 或全部 false/0)
    truthy = {"true", "1", "yes"}
    falsy = {"false", "0", "no"}

    all_true = all(v in truthy for v in score_values)
    all_false = all(v in falsy for v in score_values)

    if all_true or all_false:
        return "Consistent"
    return "Minor Disagreement"


# ── 重新导出 (延迟导入, 避免循环依赖) ──
# 这些函数实际实现在 report_markdown.py 和 report_html.py 中,
# 但测试和旧代码从 generator 导入它们.
# 使用延迟导入 (wrapper 函数) 避免循环依赖.


def _generate_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """生成 Markdown 报告 (委托给 report_markdown).

    Includes sections: dual_judge_stats, wilson_ci, cohens_kappa, Adaptive Dual Judge Statistics.
    """
    from pipeline.report.report_markdown import _generate_markdown as _impl

    return _impl(evidence, success_only=success_only)


def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """生成 HTML 报告 (委托给 report_html)."""
    from pipeline.report.report_html import _generate_html as _impl

    return _impl(evidence, success_only=success_only)


def _evidence_to_dict(evidence: EvidenceCollection, *, success_only: bool = False) -> dict[str, Any]:
    """将证据集合转换为字典 (委托给 report_html).

    Includes: dual_judge_stats, owasp_web_compliance, web_vuln_stats, discovered_endpoints.
    """
    from pipeline.report.report_html import _evidence_to_dict as _impl

    return _impl(evidence, success_only=success_only)


def _single_evidence_to_dict(ev: Any) -> dict[str, Any]:
    """将单个证据转换为字典 (委托给 report_html)."""
    from pipeline.report.report_html import _single_evidence_to_dict as _impl

    return _impl(ev)


async def generate_report(
    ctx: Any,
    evidence: EvidenceCollection,
    output_dir: Path,
) -> Path:
    """生成所有报告文件.

    生成:
        - report.md / report_success.md
        - report.html / report_success.html (如果 args.html_report)
        - evidence/evidence.json / evidence_success.json
        - evidence/EVD-*.json (每个证据单独)
        - poc/poc_*.py (成功攻击的 PoC 脚本)
        - attack_summary.csv / owasp_coverage_matrix.csv
        - evidence_package.zip

    Args:
        ctx: PipelineContext 对象.
        evidence: 证据集合.
        output_dir: 输出目录.

    Returns:
        报告文件路径.
    """
    output_dir = Path(output_dir)
    evidence_dir = output_dir / "evidence"
    poc_dir = output_dir / "poc"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    poc_dir.mkdir(parents=True, exist_ok=True)

    # ── Markdown 报告 ──
    md_content = _generate_markdown(evidence)
    md_path = output_dir / "report.md"
    md_path.write_text(md_content, encoding="utf-8")
    logger.info("Markdown report saved to %s", md_path)

    # ── 仅成功攻击的 Markdown ──
    if evidence.successful_evidence:
        success_md = _generate_markdown(evidence, success_only=True)
        success_md_path = output_dir / "report_success.md"
        success_md_path.write_text(success_md, encoding="utf-8")
        logger.info("Success-only Markdown report saved to %s", success_md_path)

    # ── HTML 报告 (可选) ──
    if getattr(ctx.args, "html_report", False):
        html_content = _generate_html(evidence)
        html_path = output_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report saved to %s", html_path)

        if evidence.successful_evidence:
            success_html = _generate_html(evidence, success_only=True)
            success_html_path = output_dir / "report_success.html"
            success_html_path.write_text(success_html, encoding="utf-8")
            logger.info("Success-only HTML report saved to %s", success_html_path)

    # ── evidence JSON ──
    json_data = _evidence_to_dict(evidence)
    json_path = evidence_dir / "evidence.json"
    json_path.write_text(
        json.dumps(json_data, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Evidence JSON saved to %s", json_path)

    if evidence.successful_evidence:
        success_json_data = _evidence_to_dict(evidence, success_only=True)
        success_json_path = evidence_dir / "evidence_success.json"
        success_json_path.write_text(
            json.dumps(success_json_data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("Success-only evidence JSON saved to %s", success_json_path)

    # ── 每个证据单独保存 ──
    for ev in evidence.evidence:
        ev_filename = f"{ev.evidence_id}.json"
        ev_path = evidence_dir / ev_filename
        ev_path.write_text(
            json.dumps(_single_evidence_to_dict(ev), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

    # ── PoC 脚本 (仅成功攻击) ──
    from pipeline.report.owasp_mapping import generate_poc_script

    poc_count = 0
    for ev in evidence.successful_evidence:
        try:
            poc_script = generate_poc_script(ev)
            poc_path = poc_dir / f"poc_{ev.evidence_id}.py"
            poc_path.write_text(poc_script, encoding="utf-8")
            poc_count += 1
        except Exception as e:
            logger.warning("Failed to generate PoC for %s: %s", ev.evidence_id, e)
    if poc_count:
        logger.info("PoC scripts saved to %s (%d files)", poc_dir, poc_count)

    # ── CSV 导出 ──
    try:
        from pipeline.report.report_sections import (
            _export_evidence_zip,
            _render_attack_summary_csv,
            _render_coverage_matrix_csv,
        )

        csv_summary = _render_attack_summary_csv(evidence)
        csv_summary_path = output_dir / "attack_summary.csv"
        csv_summary_path.write_text(csv_summary, encoding="utf-8")

        csv_coverage = _render_coverage_matrix_csv(evidence)
        csv_coverage_path = output_dir / "owasp_coverage_matrix.csv"
        csv_coverage_path.write_text(csv_coverage, encoding="utf-8")
        logger.info("CSV exports saved to %s", output_dir)

        # ── ZIP 证据包 ──
        _export_evidence_zip(output_dir, evidence)
        logger.info("Evidence ZIP saved to %s", output_dir / "evidence_package.zip")
    except Exception as e:
        logger.warning("Failed to export CSV/ZIP: %s", e)

    return md_path
