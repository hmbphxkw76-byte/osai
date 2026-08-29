"""report_markdown 鈥?Markdown 鎶ュ憡鐢熸垚.

浠?generator.py 鎷嗗垎鍑烘潵, 鍖呭惈 _generate_markdown 鍑芥暟銆?
"""

from __future__ import annotations

import logging

from report.evidence import EvidenceCollection, VulnerabilityEvidence
from report.owasp_mapping import generate_poc_script
from report.report_sections import (
    _build_escalation_dashboard_data,
    _build_score_consistency_section,
    _build_technique_effectiveness_matrix,
)
from report.report_utils import (
    _get_all_references,
    _get_technique_display_name,
)

logger = logging.getLogger(__name__)


def _generate_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """鐢熸垚瀹屾暣鐨?Markdown 瀹夊叏鎶ュ憡銆?

    Args:
        evidence: 璇佹嵁闆嗗悎銆?
        success_only: 浠呭寘鍚垚鍔熸敾鍑荤殑璇佹嵁銆?

    Returns:
        Markdown 鎶ュ憡瀛楃涓层€?
    """
    lines: list[str] = []
    evidence_list = evidence.successful_evidence if success_only else evidence.evidence

    # 鈹€鈹€ 鏍囬 鈹€鈹€
    lines.append("# AI Red Team Assessment Report")
    lines.append("")
    lines.append(f"**Target Model:** {evidence.target_model}")
    lines.append(f"**Assessment Date:** {evidence.timestamp}")
    lines.append(f"**Total Attacks:** {evidence.total_attacks}")
    lines.append(f"**Successful Attacks:** {evidence.successful_attacks}")
    lines.append(f"**Failed Attacks:** {evidence.failed_attacks}")
    lines.append(f"**Overall ASR:** {evidence.overall_asr:.1f}%")
    lines.append("")

    # 鈹€鈹€ Executive Summary 鈹€鈹€
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

    # 鈹€鈹€ Findings Summary 鈹€鈹€
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

    # 鈹€鈹€ Vulnerability Details 鈹€鈹€
    lines.append("## Vulnerability Details")
    lines.append("")
    for ev in evidence_list:
        lines.append(f"### {ev.evidence_id} 鈥?{ev.owasp_id}: {ev.owasp_category}")
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

        # PoC Script 鈥?寮傚父淇濇姢: PoC 鐢熸垚澶辫触涓嶅簲涓柇鏁翠釜鎶ュ憡
        # 鏂偣淇: report_markdown 涓?generate_poc_script 璋冪敤缂哄皯寮傚父淇濇姢,
        # 濡傛灉 PoC 鐢熸垚澶辫触 (濡傛ā鏉挎牸寮忛敊璇?, 鏁翠釜 Markdown 鎶ュ憡涔熶細澶辫触銆?
        # 淇: try/except 鍖呰９, 澶辫触鏃跺湪鎶ュ憡涓褰曢敊璇€岄潪涓柇銆?
        lines.append("**PoC Script:**")
        lines.append("```python")
        try:
            lines.append(generate_poc_script(ev))
        except Exception as e:
            logger.warning("PoC generation failed for %s: %s", ev.evidence_id, e)
            lines.append(f"# PoC generation failed: {e}")
            lines.append(f"# Evidence ID: {ev.evidence_id}")
            lines.append(f"# Technique: {ev.technique_name}")
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

    # 鈹€鈹€ OWASP LLM Top 10 鈹€鈹€
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

    # 鈹€鈹€ OWASP ASI Top 10 鈹€鈹€
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

    # 鈹€鈹€ Technique Performance 鈹€鈹€
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

    # 鈹€鈹€ Failure Analysis 鈹€鈹€
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

    # 鈹€鈹€ Attack Technique Effectiveness Matrix 鈹€鈹€
    matrix_lines = _build_technique_effectiveness_matrix(evidence, evidence.evidence)
    lines.extend(matrix_lines)

    # 鈹€鈹€ MITRE ATLAS Mapping 鈹€鈹€
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

    # 鈹€鈹€ MITRE ATLAS Reference 鈹€鈹€
    lines.append("## MITRE ATLAS Reference")
    lines.append("")
    for ev in evidence_list:
        if ev.mitre_url:
            lines.append(f"- [{ev.mitre_technique_id}]({ev.mitre_url}): {ev.mitre_technique_name}")
    lines.append("")

    # 鈹€鈹€ Score Consistency Analysis 鈹€鈹€
    score_lines = _build_score_consistency_section(evidence)
    lines.extend(score_lines)

    # 鈹€鈹€ Three-Tier Evidence Chain 鈹€鈹€
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
                    f"({result.get('technique', '')}) 鈥?"
                    f"{'Success' if result.get('is_success') else 'Failed'}",
                )
            lines.append("")
    lines.append("")

    # 鈹€鈹€ Escalation Chain Report 鈹€鈹€
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

    # 鈹€鈹€ Adaptive Dual Judge Statistics 鈹€鈹€
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

    # 鈹€鈹€ References 鈹€鈹€
    lines.append("## References")
    lines.append("")
    refs = _get_all_references(evidence)
    for ref in refs:
        lines.append(f"- {ref}")
    lines.append("")

    return "\n".join(lines)

