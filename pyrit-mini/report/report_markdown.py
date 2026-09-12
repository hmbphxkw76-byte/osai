# arXiv:2402.12109 - Russinovich et al., Crescendo
# arXiv:2310.08419 - Chao et al., PAIR
# arXiv:2312.02191 - Mehrotra et al., TAP (Tree of Attacks)
# arXiv:2307.08673 - Zou et al., GCG
# arXiv:2402.01135 - Chao et al., Best-of-N
"""report_markdown - Markdown (Layer v57).

v57 :
    - A: Layer -  executive / findings / technical converter(s)
    - C: Evidence  -  (Jailbreak Prompt = Objective, Conversation History = Harmful Output),
    - D:  -  + TechniquexOWASP
    - E:  - Pipeline
"""

from __future__ import annotations

from report.evidence import EvidenceCollection, VulnerabilityEvidence
from report.evidence_extract import _get_technique_display_name
from report.report_sections import (
    _build_escalation_dashboard_data,
    _build_score_consistency_section,
    _build_technique_effectiveness_matrix,
)

# Section builders were split out (SRP) into `report/_markdown_sections.py`; re-export
# them so the `_generate_*` converters keep calling them unchanged.
from report._markdown_sections import (
    _append_evidence_card,
    _append_orchestration_flowchart,
    _append_pipeline_flowchart,
    _append_risk_heatmap,
    _append_weapon_loadout,
)


def _get_all_references(evidence: EvidenceCollection) -> list[str]:
    """P0-2: 内联原本在 report_utils 的函数"""
    refs: set[str] = set()
    for ev in evidence.evidence:
        refs.add(ev.arxiv_reference or "PyRIT (arXiv:2407.01232)")
    return sorted(refs)


def _generate_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """v57: allconverter(s) report.md, ,
    converter(s)Layer:
        - report_executive.md  - Layer (1-2 )
        - report_findings.md   - + ()
        - report_technical.md  -

    : report.md , ++
    """
    lines: list[str] = []

    # == + ==
    lines.append("# AI Red Team Assessment Report")
    lines.append("")
    lines.append(f"**Target Model:** {evidence.target_model}")
    lines.append(f"**Assessment Date:** {evidence.timestamp}")
    lines.append(f"**Total Attacks:** {evidence.total_attacks}")
    lines.append(f"**Successful Attacks:** {evidence.successful_attacks}")
    lines.append(f"**Failed Attacks:** {evidence.failed_attacks}")
    lines.append(f"**Overall ASR:** {evidence.overall_asr:.1f}%")
    lines.append("")

    # == Wilson CI () ==
    _wilson_ci = getattr(evidence, "wilson_ci", None)
    if _wilson_ci and len(_wilson_ci) == 2 and (_wilson_ci[0] != 0.0 or _wilson_ci[1] != 0.0):
        lines.append("")

    # == Layer (A) ==
    lines.append("## [FOLDER] Report Structure")
    lines.append("")
    lines.append("| File | Description | Target Audience |")
    lines.append("|------|-------------|-----------------|")
    lines.append(
        "| [report_executive.md](report_executive.md) | Executive summary - key metrics, top risks, remediation priority | CISO / Security Lead |"
    )
    lines.append(
        "| [report_findings.md](report_findings.md) | Vulnerability details - per-evidence analysis, PoC links | Security Engineer |"
    )
    lines.append(
        "| [report_technical.md](report_technical.md) | Technical appendix - MITRE mapping, scoring, orchestration log | Technical Reviewer |"
    )
    lines.append(
        "| [native_output/](native_output/) | PyRIT native output (official format) | OffSec AI-300 Examiner |"
    )
    lines.append("| [evidence/](evidence/) | Per-evidence JSON files | Automation / CI/CD |")
    lines.append("| [poc/](poc/) | PoC scripts (Python) | Red Team Operator |")
    lines.append("")

    # == Findings Summary (D ) ==
    lines.append("## Findings Summary")
    lines.append("")
    if hasattr(evidence, "findings") and evidence.findings:
        lines.append("|-----------|----------|----------|----------|------------|--------|---------|-----|")
        for finding in evidence.findings:
            lines.append(
                f"| {finding.finding_id} | {finding.owasp_id} | {finding.owasp_category} "
                f"| {finding.owasp_severity} | {finding.owasp_risk_score} "
                f"| {finding.total_tested} | {finding.total_success} | {finding.asr}% |"
            )
    else:
        lines.append("")

    # == (D) ==
    _append_risk_heatmap(lines, evidence)

    # == Technique x OWASP (D) ==
    matrix_lines = _build_technique_effectiveness_matrix(evidence, evidence.evidence)
    lines.extend(matrix_lines)

    # == Pipeline (E) ==
    _append_pipeline_flowchart(lines, evidence)

    # == ==
    lines.append("## Detailed Sections")
    lines.append("")
    lines.append("-> See [report_executive.md](report_executive.md) for executive summary and remediation priority")
    lines.append(
        "-> See [report_findings.md](report_findings.md) for per-evidence vulnerability details and PoC scripts"
    )
    lines.append(
        "-> See [report_technical.md](report_technical.md) for MITRE ATLAS mapping, scoring analysis, and orchestration decision log"
    )
    lines.append("")

    # == References ==
    lines.append("## References")
    lines.append("")
    refs = _get_all_references(evidence)
    for ref in refs:
        lines.append("")

    return "\n".join(lines)


def _generate_executive_markdown(evidence: EvidenceCollection) -> str:
    """Docstring.
    : CISO /  30
    :  + Top-3  +  +
    """
    lines: list[str] = []

    lines.append("# Executive Summary - AI Red Team Assessment")
    lines.append("")
    lines.append(f"**Target:** {evidence.target_model}")
    lines.append(f"**Date:** {evidence.timestamp}")
    lines.append("")

    # == ==
    lines.append("## Key Metrics Dashboard")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Attacks | {evidence.total_attacks} |")
    lines.append(f"| Successful | {evidence.successful_attacks} |")
    lines.append(f"| Failed | {evidence.failed_attacks} |")
    lines.append(f"| Overall ASR | {evidence.overall_asr:.1f}% |")

    _wilson_ci = getattr(evidence, "wilson_ci", None)
    if _wilson_ci and len(_wilson_ci) == 2 and (_wilson_ci[0] != 0.0 or _wilson_ci[1] != 0.0):
        lines.append(f"| Wilson CI (95%) | {_wilson_ci[0]:.3f} - {_wilson_ci[1]:.3f} |")

    # OWASP coverage
    llm_covered = sum(1 for v in evidence.owasp_llm_compliance.values() if v.get("tested", 0) > 0)
    asi_covered = sum(1 for v in evidence.owasp_asi_compliance.values() if v.get("tested", 0) > 0)
    lines.append(f"| OWASP LLM Coverage | {llm_covered}/10 |")
    lines.append(f"| OWASP ASI Coverage | {asi_covered}/10 |")

    #
    if evidence.findings:
        max_risk = max(evidence.findings, key=lambda f: f.owasp_risk_score)
        lines.append(f"| Highest Risk Score | {max_risk.owasp_risk_score}/10 ({max_risk.owasp_id}) |")
    lines.append("")

    # == Top-3 ==
    lines.append("## Top-3 Risk Findings")
    lines.append("")
    if evidence.findings:
        sorted_findings = sorted(evidence.findings, key=lambda f: f.asr, reverse=True)
        for i, finding in enumerate(sorted_findings[:3], 1):
            lines.append("")
            lines.append(f"- **Severity:** {finding.owasp_severity}")
            lines.append(f"- **Risk Score:** {finding.owasp_risk_score}/10")
            lines.append(f"- **ASR:** {finding.asr}% ({finding.total_success}/{finding.total_tested})")
            lines.append(f"- **Techniques:** {', '.join(sorted({r.get('technique', '') for r in finding.results}))}")
            lines.append("")

    # == ==
    lines.append("## Remediation Priority Matrix")
    lines.append("")
    lines.append("| Priority | OWASP ID | Category | Risk Score | ASR |")
    lines.append("|----------|----------|----------|------------|-----|")
    if evidence.findings:
        sorted_by_risk = sorted(evidence.findings, key=lambda f: f.owasp_risk_score, reverse=True)
        for i, finding in enumerate(sorted_by_risk, 1):
            priority = "P0" if finding.owasp_risk_score >= 9 else "P1" if finding.owasp_risk_score >= 7 else "P2"
            lines.append(
                f"| {priority} | {finding.owasp_id} | {finding.owasp_category} "
                f"| {finding.owasp_risk_score} | {finding.asr}% |"
            )
    lines.append("")

    # == OWASP ==
    lines.append("## OWASP LLM Top 10 Compliance")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | ASR |")
    lines.append("|----------|----------|--------|---------|-----|")
    for owasp_id, info in sorted(evidence.owasp_llm_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('asr', 0)}% |"
        )
    lines.append("")

    # == OWASP ASI Top 10 (Agentic AI) ==
    lines.append("## OWASP ASI Top 10 (Agentic AI) Compliance")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | ASR |")
    lines.append("|----------|----------|--------|---------|-----|")
    for owasp_id, info in sorted(evidence.owasp_asi_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('asr', 0)}% |"
        )
    lines.append("")

    # == ==
    lines.append("## Conclusion")
    lines.append("")
    risk_level = "CRITICAL" if evidence.overall_asr >= 70 else "HIGH" if evidence.overall_asr >= 40 else "MODERATE"
    lines.append(
        f"The target **{evidence.target_model}** has an overall ASR of "
        f"**{evidence.overall_asr:.1f}%**, indicating a **{risk_level}** risk level. "
        f"Immediate remediation is required for the top findings listed above."
    )
    lines.append("")

    # == R-03: Attack Path Summary ==
    # - 3
    lines.append("## Attack Path Summary (Offensive Perspective)")
    lines.append("")
    lines.append("> This section describes how an attacker would exploit the identified vulnerabilities.")
    lines.append("")

    # findings
    if evidence.findings:
        sorted_for_attack = sorted(evidence.findings, key=lambda f: f.asr, reverse=True)
        top_paths = [f for f in sorted_for_attack if f.asr > 0][:3]
        if top_paths:
            for i, path in enumerate(top_paths, 1):
                techs = (
                    ", ".join(sorted({r.get("technique", "") for r in path.results if r.get("technique")}))
                    if path.results
                    else "N/A"
                )
                lines.append(
                    f"{i}. **[{path.owasp_id}] {path.owasp_category}** - ASR {path.asr}% via techniques: {techs}"
                )
        else:
            lines.append("- No successful attack paths identified")
    else:
        lines.append("- No findings available")
    lines.append("")

    # == R-04: Expected ASR Reduction Post-Remediation ==
    # ASR
    lines.append("## Expected ASR Reduction Post-Remediation")
    lines.append("")
    lines.append("| Remediation Action | Target OWASP ID | Current ASR | Expected ASR |")
    lines.append("|-------------------|-----------------|-------------|--------------|")

    if evidence.findings:
        for finding in sorted_findings[:5]:
            expected_asr = finding.asr * 0.1  # Expected 90% reduction after remediation
            lines.append(
                f"| Implement {finding.owasp_id} mitigations "
                f"| {finding.owasp_id} "
                f"| {finding.asr}% "
                f"| <={expected_asr:.0f}% |"
            )
    else:
        lines.append("- No findings available for remediation projection")

    lines.append("")

    return "\n".join(lines)


def _generate_findings_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Docstring.
    : converter(s) Evidence
    C:  - , ,
    """
    lines: list[str] = []
    evidence_list = evidence.successful_evidence if success_only else evidence.evidence

    lines.append("# Vulnerability Details - AI Red Team Assessment")
    lines.append("")
    lines.append(f"**Target:** {evidence.target_model}")
    lines.append(f"**Date:** {evidence.timestamp}")
    lines.append(f"**Total Evidence:** {len(evidence_list)}")
    lines.append("")

    # == Target Fingerprint () ==
    fp = evidence.target_fingerprint or {}
    if fp:
        lines.append("")
        lines.append("| Attribute | Value |")
        lines.append("|-----------|-------|")
        for key in ("app_type", "target_type", "auth_type", "capabilities", "model_family", "language"):
            val = fp.get(key, "")
            if val:
                lines.append(f"| {key} | {val} |")

    # == Evidence Cards (C: per-evidence detail) ==
    lines.append("## Evidence Cards")
    lines.append("")
    for ev in evidence_list:
        lines.append(f"### {ev.evidence_id} - {ev.owasp_id}: {ev.owasp_category}")
        lines.append("")
        lines.append("| Attribute | Value |")
        lines.append("|-----------|-------|")
        lines.append(f"| Technique | {ev.technique_display_name} |")
        lines.append(f"| OWASP | {ev.owasp_id} |")
        lines.append(f"| Severity | {ev.owasp_severity} |")
        lines.append(f"| Risk Score | {ev.owasp_risk_score}/10 |")
        lines.append(f"| Success | {'YES' if ev.is_success else 'NO'} |")
        lines.append(f"| ASR | {ev.asr}% |")
        lines.append(f"| Converter | {ev.converter_chain or 'none'} |")
        lines.append(f"| Confidence | {ev.confidence} |")
        lines.append("")
        lines.append(f"**Objective:** {ev.objective[:200]}")
        lines.append("")
        if ev.jailbreak_prompt:
            lines.append(f"**Jailbreak Prompt:** {ev.jailbreak_prompt[:300]}")
            lines.append("")
        if ev.harmful_output:
            lines.append(f"**Model Response:** {ev.harmful_output[:500]}")
            lines.append("")
        lines.append("---")
        lines.append("")

    # == OWASP LLM Top 10 ==
    lines.append("## OWASP LLM Top 10")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | Failed | ASR |")
    lines.append("|----------|----------|--------|---------|--------|-----|")
    for owasp_id, info in sorted(evidence.owasp_llm_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |"
        )
    lines.append("")

    # == OWASP ASI Top 10 (Agentic AI) ==
    lines.append("## OWASP ASI Top 10 (Agentic AI)")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | Failed | ASR |")
    lines.append("|----------|----------|--------|---------|--------|-----|")
    for owasp_id, info in sorted(evidence.owasp_asi_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('failed', 0)} | {info.get('asr', 0)}% |"
        )
    lines.append("")

    # == Technique Performance ==
    lines.append("## Technique Performance")
    lines.append("")
    tech_map: dict[str, list[VulnerabilityEvidence]] = {}
    for ev in evidence_list:
        tech = ev.technique_name or "unknown"
        if tech not in tech_map:
            tech_map[tech] = []
        tech_map[tech].append(ev)
    lines.append("| Technique | Tested | Success | Failed | ASR |")
    lines.append("|-----------|--------|---------|--------|-----|")
    for tech, evs in sorted(tech_map.items()):
        tested = len(evs)
        success = sum(1 for ev in evs if ev.is_success)
        failed = tested - success
        asr = (success / tested * 100) if tested > 0 else 0
        lines.append(f"| {_get_technique_display_name(tech)} | {tested} | {success} | {failed} | {asr:.0f}% |")
    lines.append("")

    # == Failure Analysis ==
    # R-06: failure_analysis ,
    lines.append("## Failure Analysis")
    lines.append("")
    fa = evidence.failure_analysis or {}
    _fa_has_data = fa.get("failure_types") or fa.get("technique_ranking")
    if _fa_has_data:
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
                f"- {rank.get('technique', '')}: {rank.get('success_rate', 0)}% ({rank.get('total', 0)} attacks)"
            )
        lines.append("")
    else:
        lines.append("### Failure Classification")
        lines.append("")
        lines.append("| Failure Category | Count | Description |")
        lines.append("|-----------------|-------|-------------|")

        # Failure Classification
        failure_categories: dict[str, int] = {}
        for ev in evidence.evidence:
            if not ev.is_success:
                if ev.converter_chain and "baseline" not in (ev.converter_chain or ""):
                    cat = "converter_blocked"
                elif ev.objective and "jailbreak" in (ev.objective or "").lower():
                    cat = "jailbreak_refused"
                else:
                    cat = "other"
                failure_categories[cat] = failure_categories.get(cat, 0) + 1

        if failure_categories:
            desc_map = {
                "converter_blocked": "Target content filtering blocked encoded payload",
                "jailbreak_refused": "Target refused jailbreak attempt",
                "other": "Uncategorized failure - requires manual analysis",
            }
            for cat, count in sorted(failure_categories.items(), key=lambda x: x[1], reverse=True):
                desc = desc_map.get(cat, "Unknown failure category")
                lines.append(f"| {cat.replace('_', ' ').title()} | {count} | {desc} |")
        else:
            lines.append("| No failures | 0 | All attacks succeeded |")

        lines.append("")

        #
        lines.append("### Failure Breakdown by Technique")
        lines.append("")
        lines.append("| Technique | Failed | Primary Failure Category |")
        lines.append("|-----------|--------|-------------------------|")
        tech_failures: dict[str, int] = {}
        for ev in evidence.evidence:
            if not ev.is_success:
                tech = ev.technique_name or "unknown"
                if tech not in tech_failures:
                    tech_failures[tech] = 0
                tech_failures[tech] += 1
        # Generate failure table from counted data
        if tech_failures:
            for tech, count in sorted(tech_failures.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {tech} | {count} | See failure classification above |")
        else:
            lines.append("| No failures | 0 | N/A |")

        lines.append("")

    # == Three-Tier Evidence Chain ==
    lines.append("## Three-Tier Evidence Chain")
    lines.append("")
    if hasattr(evidence, "findings") and evidence.findings:
        for finding in evidence.findings[:5]:
            lines.append(f"### {finding.finding_id}: {finding.owasp_id}")
            lines.append(f"**Severity:** {finding.owasp_severity} | **ASR:** {finding.asr}%")
            lines.append("")
            for result in finding.results:
                lines.append(
                    f"  - **Result:** {result.get('evidence_id', '')} "
                    f"({result.get('technique', '')}) - "
                    f"{'Success' if result.get('is_success') else 'Failed'}"
                )
            lines.append("")

    return "\n".join(lines)


def _generate_technical_markdown(evidence: EvidenceCollection) -> str:
    """Docstring.
    :  MITRE
    B/C
    """
    lines: list[str] = []

    lines.append("# Technical Appendix - AI Red Team Assessment")
    lines.append("")
    lines.append(f"**Target:** {evidence.target_model}")
    lines.append(f"**Date:** {evidence.timestamp}")
    lines.append("")

    # == Target Fingerprint & Attack Surface () ==
    fp = evidence.target_fingerprint or {}
    attack_surface = evidence.attack_surface or {}
    if fp or attack_surface:
        lines.append("")
        lines.append("| Attribute | Value |")
        lines.append("|-----------|-------|")
        if fp:
            fp_keys = [
                "app_type",
                "target_type",
                "auth_type",
                "capabilities",
                "model_family",
                "language",
                "framework",
                "content_type",
            ]
            for key in fp_keys:
                val = fp.get(key, "")
                if val:
                    lines.append(f"| {key} | {val} |")
            if fp.get("system_prompt_leaked"):
                lines.append(
                    f"| system_prompt_leaked | **LEAKED** via "
                    f"{fp.get('system_prompt_extraction_method', '')} "
                    f"(len={fp.get('system_prompt_length', 0)}) |"
                )
        if attack_surface:
            lines.append(f"| mcp_resource_count | {attack_surface.get('mcp_resource_count', 0)} |")
            lines.append(f"| openapi_endpoint_count | {attack_surface.get('openapi_endpoint_count', 0)} |")
            if attack_surface.get("openapi_spec_path"):
                lines.append(f"| port_endpoint_count | {attack_surface.get('port_endpoint_count', 0)} |")
            lines.append(f"| probe_count | {attack_surface.get('probe_count', 0)} |")
            if attack_surface.get("mcp_tool_safety_risky_count"):
                if attack_surface.get("auth_recovery_attempts"):
                    lines.append("")

    # == Weapon Loadout (ARM Phase) - v59 ==
    # orchestration_log ARM ,
    # ( ARM 1 , )
    _append_weapon_loadout(lines, evidence)

    # == MITRE ATLAS Mapping () - R-08: ==
    lines.append("## MITRE ATLAS Mapping")
    lines.append("")
    lines.append("| OWASP ID | MITRE Tactic | Technique ID | Technique Name |")
    lines.append("|----------|-------------|--------------|----------------|")
    seen_mitre: set[str] = set()
    mitre_count = 0
    for ev in evidence.evidence:
        key = f"{ev.mitre_technique_id}|{ev.mitre_tactic}"
        if key in seen_mitre:
            continue
        seen_mitre.add(key)
        lines.append(f"| {ev.owasp_id} | {ev.mitre_tactic} | {ev.mitre_technique_id} | {ev.mitre_technique_name} |")
        mitre_count += 1
    if mitre_count == 0:
        lines.append("")
        lines.append("> MITRE ATLAS mapping not available for this assessment.")
    lines.append("")

    # == MITRE ATLAS Reference () - R-08: ==
    lines.append("## MITRE ATLAS Reference")
    lines.append("")
    seen_refs: set[str] = set()
    ref_count = 0
    for ev in evidence.evidence:
        ref_key = f"{ev.mitre_technique_id}|{ev.mitre_url}"
        if ref_key in seen_refs:
            continue
        seen_refs.add(ref_key)
        lines.append(f"- [{ev.mitre_technique_id}]({ev.mitre_url}): {ev.mitre_technique_name}")
        ref_count += 1
    if ref_count == 0:
        lines.append("")

    # == Score Consistency Analysis () - R-08: ==
    score_lines = _build_score_consistency_section(evidence)
    if score_lines:
        lines.extend(score_lines)
    else:
        lines.append("")
        lines.append("*No score consistency data available for this assessment.*")
    lines.append("")

    # == Escalation Chain Report - R-08: ==
    lines.append("## Escalation Chain Report")
    lines.append("")
    dashboard = _build_escalation_dashboard_data(evidence)
    if dashboard:
        lines.append("|-------|-----------|-----|--------|")
        for stage in dashboard:
            lines.append(f"| {stage['stage']} | {stage['technique']} | {stage['asr']} | {stage['escalated']} |")
    else:
        lines.append("- No escalation chain data available")

    # == Adaptive Dual Judge Statistics ==
    if hasattr(evidence, "dual_judge_stats") and evidence.dual_judge_stats:
        lines.append("## Adaptive Dual Judge Statistics")
        lines.append("")
        stats = evidence.dual_judge_stats  # P0-5: 修复 stats 未定义
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Scored | {stats.get('total_scored', 0)} |")
        lines.append(
            f"| Dual Judge Invoked | {stats.get('dual_judge_invoked', 0)} ({stats.get('dual_judge_rate', 0)}%) |"
        )
        lines.append(f"| Agreements | {stats.get('agreements', 0)} |")
        lines.append(f"| Disagreements | {stats.get('disagreements', 0)} |")
        lines.append(f"| Agreement Rate | {stats.get('agreement_rate', 0)}% |")
        kappa = stats.get("cohens_kappa", 0.0)
        kappa_interp = (
            "almost perfect"
            if kappa > 0.80
            else "substantial"
            if kappa > 0.60
            else "moderate"
            if kappa > 0.40
            else "fair"
        )
        lines.append(f"| Cohen's Kappa | {kappa:.3f} ({kappa_interp}) |")
        lines.append(
            f"| Third Judge Invoked | {stats.get('third_judge_invoked', 0)} ({stats.get('third_judge_rate', 0)}%) |"
        )
        lines.append(f"| Third Judge Arbitrated Success | {stats.get('third_arbitrated_success', 0)} |")
        lines.append(f"| Judge 1 Successes | {stats.get('judge1_successes', 0)} |")
        lines.append(f"| Judge 2 Successes | {stats.get('judge2_successes', 0)} |")
        lines.append(f"| High Confidence Threshold | {stats.get('high_confidence_threshold', 0)} |")
        lines.append("")

        # OR Aggregation
        or_stats = stats.get("or_aggregation", {})
        if or_stats and or_stats.get("total", 0) > 0:
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| OR Aggregation Total | {or_stats.get('total', 0)} |")
            lines.append(
                f"| Disagreements | {or_stats.get('disagreements', 0)} ({or_stats.get('disagreement_rate', 0)}%) |"
            )
            lines.append(f"| J1-Only Success (potential FP) | {or_stats.get('j1_only_success', 0)} |")
            lines.append(f"| J2-Only Success | {or_stats.get('j2_only_success', 0)} |")
            lines.append(f"| Potential False Positive Rate | {or_stats.get('potential_false_positive_rate', 0)}% |")
            lines.append("")

        # ScorerMetrics
        scorer_metrics = stats.get("scorer_metrics", {})
        if scorer_metrics and scorer_metrics.get("num_responses", 0) > 0:
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| Num Responses | {scorer_metrics.get('num_responses', 0)} |")
            lines.append(f"| Accuracy | {scorer_metrics.get('accuracy', 0)} |")
            lines.append(f"| F1 Score | {scorer_metrics.get('f1_score', 0)} |")
            lines.append(f"| Precision | {scorer_metrics.get('precision', 0)} |")
            lines.append(f"| Recall | {scorer_metrics.get('recall', 0)} |")
            cm = scorer_metrics.get("confusion_matrix", {})
            if cm:
                lines.append(
                    f"| Confusion Matrix | TP={cm.get('tp', 0)}, FP={cm.get('fp', 0)}, FN={cm.get('fn', 0)}, TN={cm.get('tn', 0)} |"
                )
            lines.append("")

    _wilson_ci = getattr(evidence, "wilson_ci", None)
    if _wilson_ci and len(_wilson_ci) == 2 and (_wilson_ci[0] != 0.0 or _wilson_ci[1] != 0.0):
        if hasattr(evidence, "cohens_kappa") and evidence.cohens_kappa != 0.0:
            kappa = evidence.cohens_kappa
            interpretation = (
                "almost perfect"
                if kappa > 0.80
                else "substantial"
                if kappa > 0.60
                else "moderate"
                if kappa > 0.40
                else "fair"
            )
            lines.append(f"- **Cohen's Kappa**: {kappa:.3f} ({interpretation})")
    lines.append("")

    # == Orchestration Decision Log (E: ) - R-09: ==
    _orch_log = getattr(evidence, "orchestration_log", [])
    if _orch_log:
        lines.append("")
        lines.append("> Chronological log of orchestration decisions made during the assessment.")
        lines.append("")

        # Pipeline
        _append_orchestration_flowchart(lines, _orch_log)
        lines.append("")

        # R-09: - ,
        # phase
        orch_by_phase: dict[str, list] = {}
        for entry in _orch_log:
            phase = entry.get("phase", "unknown")
            if phase not in orch_by_phase:
                orch_by_phase[phase] = []
            orch_by_phase[phase].append(entry)

        #
        phase_order = ["recon", "arm", "strike", "escalate", "assess", "report"]
        phase_labels = {
            "recon": "(1) Reconnaissance",
            "arm": "(2) Weaponization (ARM)",
            "strike": "(3) Single-Round Attack (STRIKE)",
            "escalate": "(4) Multi-Turn Escalation",
            "assess": "(5) Scoring & Assessment",
            "report": "(6) Reporting",
        }

        for phase in phase_order:
            entries = orch_by_phase.get(phase, [])  # P0-5: 修复 entries 未定义
            if not entries:
                continue  # 跳过无数据的阶段
            lines.append(f"### {phase_labels.get(phase, phase.upper())}")
            lines.append("")
            lines.append("| # | Decision | Key Parameters | Reasoning |")
            lines.append("|---|----------|----------------|-----------|")

            for idx, entry in enumerate(entries, 1):
                reasoning = entry.get("reasoning", "")[:80]
                if len(entry.get("reasoning", "")) > 80:
                    reasoning += "..."
                decision = entry.get("decision", "unknown")  # P0-5: 修复 decision 未定义
                # Format input/output params
                _input = entry.get("input", {}) or {}
                _output = entry.get("output", {}) or {}
                params = []
                if _input:
                    for k in ["seed_files", "mode", "capabilities", "enabled"]:
                        if k in _input:
                            params.append(f"{k}={_input[k]}")
                if _output:
                    for k in ["seed_count", "total_results", "overall_asr", "converter_count"]:
                        if k in _output:
                            params.append(f"{k}={_output[k]}")

                params_str = ", ".join(params[:3])
                lines.append(f"| {idx} | {decision} | {params_str} | {reasoning} |")

            lines.append("")

    return "\n".join(lines)
