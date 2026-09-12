"""report_html - HTML Report Generator.

P1-4: Jinja2 dependency removed - using pure Python string formatting.
"""

import dataclasses
import logging
from typing import Any

from report.evidence import EvidenceCollection, VulnerabilityEvidence

# P0-2: report_utils 薄代理层移除，直接导入底层函数
from report.generator import _OWASP_ALL_CATEGORIES
from report.report_sections import _build_heatmap_data, _finding_to_dict

logger = logging.getLogger(__name__)


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
<p><strong>Target:</strong> <code>{_esc(evidence.target_model)}</code></p>
""")

    # Target Fingerprint
    # W0 类型错配修复：`evidence.target_fingerprint` 在真实链路上是
    # `recon.burp_parser.TargetFingerprint` **dataclass 实例**（非 dict），
    # 直接 `.items()` → AttributeError，报告在 HTML 渲染第一步即失败。
    # 这里统一归一化为 dict（dataclass 走 asdict/to_dict，dict 原样使用）。
    fingerprint = _as_mapping(evidence.target_fingerprint)
    if fingerprint:
        html_parts.append(
            "<h2>Target Fingerprint & Attack Surface</h2>\n<table>\n  <tr><th>Attribute</th><th>Value</th></tr>"
        )
        for k, v in fingerprint.items():
            html_parts.append(f"  <tr><td>{_esc(k)}</td><td><code>{_esc(v)}</code></td></tr>")
        html_parts.append("</table>")

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
    html_parts.append(
        "<h2>OWASP LLM Top 10 Compliance Matrix</h2>\n<table>\n  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>"
    )
    for owasp_id, stats in sorted(evidence.owasp_llm_compliance.items()):
        html_parts.append(
            f"  <tr><td>{owasp_id}</td><td>{stats.get('category', 'Unknown')}</td>"
            f"<td>{stats.get('tested', 0)}</td><td>{stats.get('success', 0)}</td>"
            f"<td>{stats.get('failed', 0)}</td><td>{stats.get('asr', 0.0)}%</td></tr>"
        )
    html_parts.append("</table>")

    # OWASP ASI Top 10
    html_parts.append(
        "<h2>OWASP Agentic AI Top 10 Compliance Matrix</h2>\n<table>\n  <tr><th>OWASP ID</th><th>Category</th><th>Tested</th><th>Success</th><th>Failed</th><th>ASR</th></tr>"
    )
    for owasp_id, stats in sorted(evidence.owasp_asi_compliance.items()):
        html_parts.append(
            f"  <tr><td>{owasp_id}</td><td>{stats.get('category', 'Unknown')}</td>"
            f"<td>{stats.get('tested', 0)}</td><td>{stats.get('success', 0)}</td>"
            f"<td>{stats.get('failed', 0)}</td><td>{stats.get('asr', 0.0)}%</td></tr>"
        )
    html_parts.append("</table>")

    # == plan Wave 6：组件专属分析章节（此前 HTML 从不消费 component_reports）==
    # `component_reports` 已能产出 MCP 工具清单 / A2A 信任链 / 模型人格偏移等章节，
    # 但只有 Markdown 链路在用；HTML 报告（交付主格式）一直缺失，构成 §9 交付缺口。
    component_html = _render_component_sections(evidence)
    if component_html:
        html_parts.append(component_html)

    # == plan Wave 6：影响链举证 / 攻击链 / 组件拓扑 / 预算 ==
    combo_html = _render_combo_artifacts(evidence)
    if combo_html:
        html_parts.append(combo_html)

    # Evidence Cards
    if evidence_list:
        html_parts.append("<h2>Evidence Cards</h2>")
        for ev in evidence_list:
            html_parts.append(
                f"<h3>{_esc(ev.evidence_id)} - {_esc(ev.owasp_id)}: {_esc(ev.owasp_category)}</h3>"
            )
            html_parts.append(
                f"<p><strong>Technique:</strong> {_esc(ev.technique_display_name)} | "
                f"<strong>ASR:</strong> {ev.asr}%</p>"
            )
            component_type = (getattr(ev, "metadata", None) or {}).get("component_type")
            if component_type:
                html_parts.append(f"<p><strong>Component:</strong> <code>{_esc(component_type)}</code></p>")
            if ev.objective:
                html_parts.append(
                    f"<p><strong>Objective:</strong> {_esc(ev.objective)}</p>"
                )
            if ev.harmful_output:
                html_parts.append(
                    f"<pre>{_esc(str(ev.harmful_output)[:4000])}</pre>"
                )

    html_parts.append("</body></html>")
    return "\n".join(html_parts)


def _as_mapping(value: Any) -> dict[str, Any]:
    """把 dict / dataclass / 带 to_dict() 的对象统一归一化为 dict。

    消除「同一字段在不同链路是 dict、另一处是 dataclass」的类型错配，
    例如 `evidence.target_fingerprint`（`TargetFingerprint` dataclass）
    却被当作 dict 调用 `.items()`。空值/不可转换对象返回 {}（IA-6：不崩溃）。
    """
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            result = to_dict()
            if isinstance(result, dict):
                return result
        except Exception as e:
            logger.debug("[HTML] to_dict() 失败，尝试 dataclass 转换: %s", e)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return dataclasses.asdict(value)
        except Exception as e:
            logger.debug("[HTML] asdict() 失败: %s", e)
    return {}


def _esc(value: Any) -> str:
    """HTML 转义（Wave 6：目标响应是攻击者可控内容，直接插值会破坏报告结构）。"""
    if value is None:
        return ""
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _render_combo_artifacts(evidence: EvidenceCollection) -> str:
    """渲染「入口组件 → 业务影响」的影响链举证 + 攻击链 + 预算（plan Wave 6）。

    举证不完整的缺口会**显式渲染出来**（而不是静默省略），满足「举证而非断言」。
    """
    chains = list(getattr(evidence, "impact_chains", []) or [])
    gaps = list(getattr(evidence, "impact_gaps", []) or [])
    graph = getattr(evidence, "component_graph", None) or {}
    budget = getattr(evidence, "budget_report", None) or {}
    manifest = getattr(evidence, "score_manifest", None) or {}

    if not (chains or gaps or graph or budget):
        return ""

    parts = ['<h2>Impact Chain &amp; Combo Artifacts</h2>']

    # 组件拓扑
    if graph:
        nodes = graph.get("nodes") or []
        parts.append("<h3>Component Graph</h3>")
        parts.append("<table>\n  <tr><th>Component</th><th>Confidence</th><th>Inferred</th></tr>")
        for n in nodes:
            attrs = n.get("attributes") or {}
            parts.append(
                f"  <tr><td><code>{_esc(n.get('component_key'))}</code></td>"
                f"<td>{n.get('confidence', 0)}</td>"
                f"<td>{'yes' if attrs.get('inferred') else 'no'}</td></tr>"
            )
        parts.append("</table>")
        entries = graph.get("entry_points") or []
        if entries:
            parts.append(f"<p><strong>Entry points:</strong> <code>{_esc(', '.join(entries))}</code></p>")

    # 影响链
    if chains:
        parts.append("<h3>Impact Chains</h3>")
        for idx, c in enumerate(chains, 1):
            nodes = c.get("nodes") or []
            parts.append(f"<h4>Chain {idx} — severity: {_esc(c.get('max_severity', 'n/a'))}</h4>")
            parts.append("<table>\n  <tr><th>Step</th><th>Component</th><th>Severity</th><th>Evidence</th></tr>")
            for n in nodes:
                parts.append(
                    f"  <tr><td>{_esc(n.get('step_id'))}</td>"
                    f"<td><code>{_esc(n.get('component_key'))}</code></td>"
                    f"<td>{_esc(n.get('severity'))}</td>"
                    f"<td>{_esc(', '.join(n.get('evidence_ids') or []) or '—')}</td></tr>"
                )
            parts.append("</table>")
            if c.get("terminal_impact"):
                parts.append(f"<p><strong>Business impact:</strong> {_esc(c['terminal_impact'])}</p>")

    # 举证缺口（反静默）
    if gaps:
        parts.append('<h3 style="color:#b00">Causality Gaps (evidence incomplete)</h3>')
        parts.append("<table>\n  <tr><th>Kind</th><th>Target</th><th>Detail</th></tr>")
        for g in gaps:
            parts.append(
                f"  <tr><td>{_esc(g.get('kind'))}</td><td>{_esc(g.get('target'))}</td>"
                f"<td>{_esc(g.get('detail'))}</td></tr>"
            )
        parts.append("</table>")

    # 预算
    if budget:
        snap = budget.get("snapshot") or {}
        parts.append("<h3>Budget</h3>")
        parts.append(
            "<table>\n  <tr><th>Metric</th><th>Value</th></tr>"
            f"  <tr><td>Attacks used / remaining</td><td>{snap.get('attacks_used', 0)} / {snap.get('attacks_remaining', 0)}</td></tr>"
            f"  <tr><td>Elapsed (s)</td><td>{snap.get('elapsed_seconds', 0)}</td></tr>"
            f"  <tr><td>Exhausted reasons</td><td>{_esc(', '.join(snap.get('exhausted_reasons') or []) or 'none')}</td></tr>"
            "</table>"
        )
        trims = budget.get("trims") or []
        if trims:
            parts.append("<p><strong>Trimmed (low ASR prior, budget exhausted):</strong></p><ul>")
            for t in trims:
                parts.append(f"  <li>{_esc(', '.join(t.get('dropped') or []))}</li>")
            parts.append("</ul>")

    # 可复现指纹
    if manifest:
        parts.append("<h3>Scoring Reproducibility</h3>")
        parts.append(
            "<table>\n  <tr><th>Item</th><th>Value</th></tr>"
            f"  <tr><td>Random seed</td><td>{_esc(manifest.get('random_seed'))}</td></tr>"
            f"  <tr><td>Judge models</td><td>{_esc(', '.join(manifest.get('judge_models') or []) or 'n/a')}</td></tr>"
            f"  <tr><td>Aggregation</td><td>{_esc(manifest.get('aggregation'))}</td></tr>"
            f"  <tr><td>Rubrics</td><td>{_esc(', '.join(manifest.get('rubric_paths') or []) or 'n/a')}</td></tr>"
            "</table>"
        )
    return "\n".join(parts)


def _render_component_sections(evidence: EvidenceCollection) -> str:
    """渲染组件专属报告章节为 HTML 片段；无组件归属时返回空串（IA-6：不崩溃）。"""
    try:
        from report.component_reports import generate_component_sections

        sections = generate_component_sections(evidence)
    except Exception as e:
        logger.warning("[HTML] 组件专属章节生成失败（已降级）: %s", e)
        return ""

    if not sections:
        return ""

    parts = ['<h2>Component-Specific Analysis</h2>']
    for name, body in sections.items():
        title = str(name).replace("_", " ").title()
        parts.append(f"<h3>{_esc(title)}</h3>")
        # 章节正文是 Markdown；以 <pre> 原样呈现，避免 Markdown→HTML 转换失真
        parts.append(f"<pre>{_esc(body)}</pre>")
    return "\n".join(parts)


def _evidence_to_dict(evidence: EvidenceCollection, *, success_only: bool = False) -> dict[str, Any]:
    """Convert evidence collection to dictionary (for JSON serialization).

    Used by: main.py (orchestration_log / wilson_ci / cohens_kappa evidence),
    _evidence_to_dict, and regen_report.py.

    Data flow: main.py -> evidence -> JSON -> regen_report.py
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
        # NOTE: web_vuln_stats and discovered_endpoints were removed from EvidenceCollection
        # during P0 audit (never populated). Kept here for backward compatibility with
        # external consumers that may expect these keys in JSON output.
        "web_vuln_stats": getattr(evidence, "web_vuln_stats", {}),
        "discovered_endpoints": getattr(evidence, "discovered_endpoints", []),
        # : main.py Phase 4/5 , Data flow
        "orchestration_log": getattr(evidence, "orchestration_log", []),
        "wilson_ci": list(getattr(evidence, "wilson_ci", (0.0, 0.0))),
        "cohens_kappa": getattr(evidence, "cohens_kappa", 0.0),
    }


def _single_evidence_to_dict(ev: VulnerabilityEvidence) -> dict[str, Any]:
    """Convert single evidence to dictionary, handling converter(s) fallback.

    Layer: Ensure JSON serialization works even if _build_evidence fails to populate
    optional fields. Applies R10 fallback defaults for converter_chain, arxiv_reference,
    conversation_history, converter_log, and score_details.
    """
    # P1-1 fix: Ensure converter_chain -> "none (baseline)" instead of null
    converter_chain = ev.converter_chain or "none (baseline)"

    # P0-3 fix: Ensure arxiv_reference has fallback value
    arxiv_ref = ev.arxiv_reference or "PyRIT (arXiv:2407.01232)"

    # P0-1 fix: Ensure conversation_history falls back to objective/harmful_output
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

    # P0-2 fix: Ensure converter_log falls back to "none (baseline)"
    converter_log = ev.converter_log
    if not converter_log:
        obj = ev.objective or ""
        converter_log = [
            {
                "converter": "none (baseline)",
                "original": obj[:200],
                "transformed": obj[:200],
            }
        ]

    # P0-4: score_details - single fallback (no pseudo validation_runs)
    # Moved outside the if-block to ensure score_details is always defined
    score_details = ev.score_details
    if not score_details:
        score_details = [
            {
                "scorer": "AttackOutcome",
                "score_value": "success" if ev.is_success else "failure",
                "rationale": "Determined by post-hoc scoring (no explicit scorer object attached)",
            }
        ]

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
