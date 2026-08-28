"""report_markdown — Markdown 报告生成.

从 generator.py 拆分出来, 包含 _generate_markdown 函数。
"""

from __future__ import annotations

import logging

from pipeline.report.evidence import EvidenceCollection, VulnerabilityEvidence
from pipeline.report.owasp_mapping import generate_poc_script
from pipeline.report.report_sections import (
    _build_escalation_dashboard_data,
    _build_score_consistency_section,
    _build_technique_effectiveness_matrix,
)
from pipeline.report.report_utils import (
    _get_all_references,
    _get_technique_display_name,
)

logger = logging.getLogger(__name__)


def _generate_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """生成完整的 Markdown 安全报告。

    Args:
        evidence: 证据集合。
        success_only: 仅包含成功攻击的证据。

    Returns:
        Markdown 报告字符串。
    """
    lines: list[str] = []
    evidence_list = evidence.successful_evidence if success_only else evidence.evidence

    # ── 标题 ──
    lines.append("# AI Red Team Assessment Report")
    lines.append("")
    lines.append(f"**Target Model:** {evidence.target_model}")
    lines.append(f"**Assessment Date:** {evidence.timestamp}")
    lines.append(f"**Total Attacks:** {evidence.total_attacks}")
    lines.append(f"**Successful Attacks:** {evidence.successful_attacks}")
    lines.append(f"**Failed Attacks:** {evidence.failed_attacks}")
    lines.append(f"**Overall ASR:** {evidence.overall_asr:.1f}%")
    lines.append("")

    # ── Executive Summary ──
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"This report presents the findings of an AI Red Team assessment "
        f"conducted on **{evidence.target_model}**. "
        f"A total of **{evidence.total_attacks}** attacks were executed "
        f"across multiple techniques, achieving an overall Attack Success Rate (ASR) "
        f"of **{evidence.overall_asr:.1f}%**.",
    )
    lines.append("")

    # ── Findings Summary ──
    lines.append("## Findings Summary")
    lines.append("")
    if hasattr(evidence, "findings") and evidence.findings:
        lines.append("| Finding ID | OWASP ID | Category | Severity | Risk Score | Tested | Success | ASR |")
        lines.append("|-----------|----------|----------|----------|------------|--------|---------|-----|")
        for finding in evidence.findings:
            lines.append(
                f"| {finding.finding_id} | {finding.owasp_id} | {finding.owasp_category} "
                f"| {finding.owasp_severity} | {finding.owasp_risk_score} "
                f"| {finding.total_tested} | {finding.total_success} | {finding.asr}% |",
            )
    else:
        lines.append("No findings generated.")
    lines.append("")

    # ── Vulnerability Details ──
    lines.append("## Vulnerability Details")
    lines.append("")
    for ev in evidence_list:
        lines.append(f"### {ev.evidence_id} — {ev.owasp_id}: {ev.owasp_category}")
        lines.append("")
        lines.append(f"**Technique:** {ev.technique_display_name}")
        lines.append(f"**Severity:** {ev.owasp_severity}")
        lines.append(f"**Risk Score:** {ev.owasp_risk_score}")
        lines.append(f"**Success:** {'Yes' if ev.is_success else 'No'}")
        lines.append(f"**Converter Chain:** {ev.converter_chain or 'none (baseline)'}")
        lines.append("")
        lines.append(f"**Objective:** {ev.objective}")
        lines.append("")
        lines.append(f"**Jailbreak Prompt:** {ev.jailbreak_prompt}")
        lines.append("")
        lines.append(f"**Harmful Output:** {ev.harmful_output}")
        lines.append("")
        lines.append("**Conversation History:**")
        lines.append("")
        for msg in ev.conversation_history:
            lines.append(f"  - **{msg.get('role', 'unknown')}:** {msg.get('content', '')}")
        lines.append("")

        # PoC Script
        lines.append("**PoC Script:**")
        lines.append("```python")
        lines.append(generate_poc_script(ev))
        lines.append("```")
        lines.append("")

        # Validation Runs
        lines.append("**Validation Runs:**")
        lines.append("")
        for run in getattr(ev, "validation_runs", []):
            lines.append(f"  - Run {run.get('run', '?')}: {'Success' if run.get('success') else 'Failed'}")
        lines.append("")

        # Testing Conditions
        lines.append("**Testing Conditions:**")
        lines.append("")
        for k, v in getattr(ev, "testing_conditions", {}).items():
            lines.append(f"  - **{k}:** {v}")
        lines.append("")

        # Remediation Priority
        lines.append("### Remediation Priority")
        lines.append("")
        lines.append("**OWASP Mitigations:**")
        for mitigation in ev.owasp_mitigations:
            lines.append(f"  - {mitigation}")
        lines.append("")

    # ── OWASP LLM Top 10 ──
    lines.append("## OWASP LLM Top 10")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | Failed | ASR |")
    lines.append("|----------|----------|--------|---------|--------|-----|")
    for owasp_id, info in sorted(evidence.owasp_llm_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |",
        )
    lines.append("")

    # ── OWASP ASI Top 10 ──
    lines.append("## OWASP ASI Top 10 (Agentic AI)")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | Failed | ASR |")
    lines.append("|----------|----------|--------|---------|--------|-----|")
    for owasp_id, info in sorted(evidence.owasp_asi_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |",
        )
    lines.append("")

    # ── Technique Performance ──
    lines.append("## Technique Performance")
    lines.append("")
    tech_map: dict[str, list[VulnerabilityEvidence]] = {}
    for ev in evidence_list:
        tech_map.setdefault(ev.technique_name, []).append(ev)
    lines.append("| Technique | Tested | Success | Failed | ASR |")
    lines.append("|-----------|--------|---------|--------|-----|")
    for tech, evs in sorted(tech_map.items()):
        tested = len(evs)
        success = sum(1 for ev in evs if ev.is_success)
        failed = tested - success
        asr = (success / tested * 100) if tested > 0 else 0
        lines.append(f"| {_get_technique_display_name(tech)} | {tested} | {success} | {failed} | {asr:.0f}% |")
    lines.append("")

    # ── Failure Analysis ──
    lines.append("## Failure Analysis")
    lines.append("")
    if evidence.failure_analysis:
        fa = evidence.failure_analysis
        lines.append("### Failure Types")
        lines.append("")
        for ftype, count in sorted(
            fa.get("failure_types", {}).items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            lines.append(f"- {ftype}: {count}")
        lines.append("")
        lines.append("### Technique Ranking")
        lines.append("")
        for rank in fa.get("technique_ranking", []):
            lines.append(
                f"- {rank.get('technique', '')}: "
                f"{rank.get('success_rate', 0)}% ({rank.get('total', 0)} attacks)",
            )
    lines.append("")

    # ── Attack Technique Effectiveness Matrix ──
    matrix_lines = _build_technique_effectiveness_matrix(evidence, evidence.evidence)
    lines.extend(matrix_lines)

    # ── MITRE ATLAS Mapping ──
    lines.append("## MITRE ATLAS Mapping")
    lines.append("")
    lines.append("| OWASP ID | MITRE Tactic | Technique ID | Technique Name |")
    lines.append("|----------|-------------|--------------|----------------|")
    for ev in evidence_list:
        lines.append(
            f"| {ev.owasp_id} | {ev.mitre_tactic} | {ev.mitre_technique_id} "
            f"| {ev.mitre_technique_name} |",
        )
    lines.append("")

    # ── MITRE ATLAS Reference ──
    lines.append("## MITRE ATLAS Reference")
    lines.append("")
    for ev in evidence_list:
        if ev.mitre_url:
            lines.append(f"- [{ev.mitre_technique_id}]({ev.mitre_url}): {ev.mitre_technique_name}")
    lines.append("")

    # ── Score Consistency Analysis ──
    score_lines = _build_score_consistency_section(evidence)
    lines.extend(score_lines)

    # ── Three-Tier Evidence Chain ──
    lines.append("## Three-Tier Evidence Chain")
    lines.append("")
    if hasattr(evidence, "findings") and evidence.findings:
        for finding in evidence.findings:
            lines.append(f"### {finding.finding_id}: {finding.owasp_id}")
            lines.append(f"**Severity:** {finding.owasp_severity} | **ASR:** {finding.asr}%")
            lines.append("")
            for result in finding.results:
                lines.append(
                    f"  - **Result:** {result.get('evidence_id', '')} "
                    f"({result.get('technique', '')}) — "
                    f"{'Success' if result.get('is_success') else 'Failed'}",
                )
            lines.append("")
    lines.append("")

    # ── Escalation Chain Report ──
    lines.append("## Escalation Chain Report")
    lines.append("")
    dashboard = _build_escalation_dashboard_data(evidence)
    lines.append("| Stage | Technique | ASR | Status |")
    lines.append("|-------|-----------|-----|--------|")
    for stage in dashboard:
        lines.append(
            f"| {stage['stage']} | {stage['technique']} | {stage['asr']} | {stage['escalated']} |",
        )
    lines.append("")

    # ── Adaptive Dual Judge Statistics ──
    # L5 v8: Dual Judge Statistics
    if hasattr(evidence, 'dual_judge_stats') and evidence.dual_judge_stats:
        stats = evidence.dual_judge_stats
        lines.append("## Adaptive Dual Judge Statistics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Scored | {stats.get('total_scored', 0)} |")
        lines.append(f"| Dual Judge Invoked | {stats.get('dual_judge_invoked', 0)} ({stats.get('dual_judge_rate', 0)}%) |")
        lines.append(f"| Agreements | {stats.get('agreements', 0)} |")
        lines.append(f"| Disagreements | {stats.get('disagreements', 0)} |")
        lines.append(f"| Agreement Rate | {stats.get('agreement_rate', 0)}% |")
        # L5 v29: Cohen's Kappa
        kappa = stats.get('cohens_kappa', 0.0)
        kappa_interp = (
            "almost perfect" if kappa > 0.80
            else "substantial" if kappa > 0.60
            else "moderate" if kappa > 0.40
            else "fair"
        )
        lines.append(f"| Cohen's Kappa | {kappa:.3f} ({kappa_interp}) |")
        lines.append(f"| Third Judge Invoked | {stats.get('third_judge_invoked', 0)} ({stats.get('third_judge_rate', 0)}%) |")
        lines.append(f"| Third Judge Arbitrated Success | {stats.get('third_arbitrated_success', 0)} |")
        lines.append(f"| Judge 1 Successes | {stats.get('judge1_successes', 0)} |")
        lines.append(f"| Judge 2 Successes | {stats.get('judge2_successes', 0)} |")
        lines.append(f"| High Confidence Threshold | {stats.get('high_confidence_threshold', 0)} |")
        lines.append("")

    # L5 v29: Wilson Score CI
    if hasattr(evidence, 'wilson_ci') and evidence.wilson_ci != (0.0, 0.0):
        lines.append(f"- **ASR 95% CI (Wilson)**: [{evidence.wilson_ci[0]}%, {evidence.wilson_ci[1]}%]")
    if hasattr(evidence, 'cohens_kappa') and evidence.cohens_kappa != 0.0:
        kappa = evidence.cohens_kappa
        interpretation = (
            "almost perfect" if kappa > 0.80
            else "substantial" if kappa > 0.60
            else "moderate" if kappa > 0.40
            else "fair"
        )
        lines.append(f"- **Cohen's Kappa**: {kappa:.3f} ({interpretation})")

    # ── References ──
    lines.append("## References")
    lines.append("")
    refs = _get_all_references(evidence)
    for ref in refs:
        lines.append(f"- {ref}")
    lines.append("")

    return "\n".join(lines)
