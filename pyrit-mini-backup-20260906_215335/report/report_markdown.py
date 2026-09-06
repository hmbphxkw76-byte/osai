# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2310.08419 — Chao et al., PAIR
# arXiv:2312.02191 — Mehrotra et al., TAP (Tree of Attacks)
# arXiv:2307.08673 — Zou et al., GCG
# arXiv:2402.01135 — Chao et al., Best-of-N
"""report_markdown — Markdown 报告生成 (分层架构 v57).

v57 优化:
    - 方案A: 分层架构 — 生成 executive / findings / technical 三个独立文件
    - 方案C: Evidence 模板精简 — 删除重复内容 (Jailbreak Prompt = Objective, Conversation History = Harmful Output), 折叠长文本
    - 方案D: 摘要增强 — 风险热力图 + Technique×OWASP 矩阵前置到摘要区
    - 方案E: 编排决策日志可视化 — Pipeline 流程图
"""

from __future__ import annotations

import logging
from typing import Any

from report.evidence import EvidenceCollection, VulnerabilityEvidence
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

# ── 通用常量 ──
_TRUNCATE_LEN = 200  # Objective / Harmful Output 截断长度 (摘要区)


def _generate_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """生成完整的 Markdown 安全报告 (分层索引版)。

    v57: 不再将所有内容塞入单个 report.md, 而是生成索引文件,
    引导读者到三个分层文件:
        - report_executive.md  — 管理层摘要 (1-2 页)
        - report_findings.md   — 漏洞详情+证据 (核心)
        - report_technical.md  — 技术附录

    向后兼容: report.md 仍然作为入口文件, 包含索引+摘要+跳转链接。
    """
    lines: list[str] = []

    # ── 标题 + 关键指标 ──
    lines.append("# AI Red Team Assessment Report")
    lines.append("")
    lines.append(f"**Target Model:** {evidence.target_model}")
    lines.append(f"**Assessment Date:** {evidence.timestamp}")
    lines.append(f"**Total Attacks:** {evidence.total_attacks}")
    lines.append(f"**Successful Attacks:** {evidence.successful_attacks}")
    lines.append(f"**Failed Attacks:** {evidence.failed_attacks}")
    lines.append(f"**Overall ASR:** {evidence.overall_asr:.1f}%")
    lines.append("")

    # ── Wilson CI (如果有) ──
    _wilson_ci = getattr(evidence, "wilson_ci", None)
    if _wilson_ci and len(_wilson_ci) == 2 and (_wilson_ci[0] != 0.0 or _wilson_ci[1] != 0.0):
        lines.append(f"**ASR 95% CI (Wilson):** [{_wilson_ci[0]}%, {_wilson_ci[1]}%]")
        lines.append("")

    # ── 分层文件索引 (方案A) ──
    lines.append("## 📂 Report Structure")
    lines.append("")
    lines.append("| File | Description | Target Audience |")
    lines.append("|------|-------------|-----------------|")
    lines.append("| [report_executive.md](report_executive.md) | Executive summary — key metrics, top risks, remediation priority | CISO / Security Lead |")
    lines.append("| [report_findings.md](report_findings.md) | Vulnerability details — per-evidence analysis, PoC links | Security Engineer |")
    lines.append("| [report_technical.md](report_technical.md) | Technical appendix — MITRE mapping, scoring, orchestration log | Technical Reviewer |")
    lines.append("| [native_output/](native_output/) | PyRIT native output (official format) | OffSec AI-300 Examiner |")
    lines.append("| [evidence/](evidence/) | Per-evidence JSON files | Automation / CI/CD |")
    lines.append("| [poc/](poc/) | PoC scripts (Python) | Red Team Operator |")
    lines.append("")

    # ── Findings Summary (方案D 前置) ──
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

    # ── 风险热力图 (方案D) ──
    _append_risk_heatmap(lines, evidence)

    # ── Technique × OWASP 矩阵前置 (方案D) ──
    matrix_lines = _build_technique_effectiveness_matrix(evidence, evidence.evidence)
    lines.extend(matrix_lines)

    # ── Pipeline 流程图 (方案E) ──
    _append_pipeline_flowchart(lines, evidence)

    # ── 链接到详细文件 ──
    lines.append("## Detailed Sections")
    lines.append("")
    lines.append("→ See [report_executive.md](report_executive.md) for executive summary and remediation priority")
    lines.append("→ See [report_findings.md](report_findings.md) for per-evidence vulnerability details and PoC scripts")
    lines.append("→ See [report_technical.md](report_technical.md) for MITRE ATLAS mapping, scoring analysis, and orchestration decision log")
    lines.append("")

    # ── References ──
    lines.append("## References")
    lines.append("")
    refs = _get_all_references(evidence)
    for ref in refs:
        lines.append(f"- {ref}")
    lines.append("")

    return "\n".join(lines)


def _generate_executive_markdown(evidence: EvidenceCollection) -> str:
    """生成管理层摘要报告 (report_executive.md)。

    目标: CISO / 安全负责人 30 秒内拿到关键信息。
    内容: 关键指标仪表盘 + Top-3 风险 + 修复优先级矩阵 + 一句话结论。
    """
    lines: list[str] = []

    lines.append("# Executive Summary — AI Red Team Assessment")
    lines.append("")
    lines.append(f"**Target:** {evidence.target_model}")
    lines.append(f"**Date:** {evidence.timestamp}")
    lines.append("")

    # ── 关键指标仪表盘 ──
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
        lines.append(f"| ASR 95% CI (Wilson) | [{_wilson_ci[0]}%, {_wilson_ci[1]}%] |")

    # OWASP coverage
    llm_covered = sum(1 for v in evidence.owasp_llm_compliance.values() if v.get("tested", 0) > 0)
    asi_covered = sum(1 for v in evidence.owasp_asi_compliance.values() if v.get("tested", 0) > 0)
    lines.append(f"| OWASP LLM Coverage | {llm_covered}/10 |")
    lines.append(f"| OWASP ASI Coverage | {asi_covered}/10 |")

    # 最高风险
    if evidence.findings:
        max_risk = max(evidence.findings, key=lambda f: f.owasp_risk_score)
        lines.append(f"| Highest Risk Score | {max_risk.owasp_risk_score}/10 ({max_risk.owasp_id}) |")
    lines.append("")

    # ── Top-3 风险发现 ──
    lines.append("## Top-3 Risk Findings")
    lines.append("")
    if evidence.findings:
        sorted_findings = sorted(evidence.findings, key=lambda f: f.owasp_risk_score, reverse=True)
        for i, finding in enumerate(sorted_findings[:3], 1):
            lines.append(f"### {i}. {finding.owasp_id}: {finding.owasp_category}")
            lines.append("")
            lines.append(f"- **Severity:** {finding.owasp_severity}")
            lines.append(f"- **Risk Score:** {finding.owasp_risk_score}/10")
            lines.append(f"- **ASR:** {finding.asr}% ({finding.total_success}/{finding.total_tested})")
            lines.append(f"- **Techniques:** {', '.join(sorted({r.get('technique', '') for r in finding.results}))}")
            lines.append("")

    # ── 修复优先级矩阵 ──
    lines.append("## Remediation Priority Matrix")
    lines.append("")
    lines.append("| Priority | OWASP ID | Category | Risk Score | ASR |")
    lines.append("|----------|----------|----------|------------|-----|")
    if evidence.findings:
        sorted_by_risk = sorted(evidence.findings, key=lambda f: f.owasp_risk_score, reverse=True)
        for i, finding in enumerate(sorted_by_risk, 1):
            priority = "🔴 Critical" if finding.owasp_risk_score >= 8 else "🟠 High" if finding.owasp_risk_score >= 6 else "🟡 Medium"
            lines.append(f"| {priority} | {finding.owasp_id} | {finding.owasp_category} | {finding.owasp_risk_score} | {finding.asr}% |")
    lines.append("")

    # ── OWASP 合规表 ──
    lines.append("## OWASP LLM Top 10 Compliance")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | ASR |")
    lines.append("|----------|----------|--------|---------|-----|")
    for owasp_id, info in sorted(evidence.owasp_llm_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('asr', 0)}% |",
        )
    lines.append("")

    # ── OWASP ASI Top 10 (Agentic AI) ──
    lines.append("## OWASP ASI Top 10 (Agentic AI) Compliance")
    lines.append("")
    lines.append("| OWASP ID | Category | Tested | Success | ASR |")
    lines.append("|----------|----------|--------|---------|-----|")
    for owasp_id, info in sorted(evidence.owasp_asi_compliance.items()):
        lines.append(
            f"| {owasp_id} | {info.get('category', '')} | {info.get('tested', 0)} "
            f"| {info.get('success', 0)} | {info.get('asr', 0)}% |",
        )
    lines.append("")

    # ── 一句话结论 ──
    lines.append("## Conclusion")
    lines.append("")
    risk_level = "CRITICAL" if evidence.overall_asr >= 70 else "HIGH" if evidence.overall_asr >= 40 else "MODERATE"
    lines.append(
        f"The target **{evidence.target_model}** has an overall ASR of "
        f"**{evidence.overall_asr:.1f}%**, indicating a **{risk_level}** risk level. "
        f"Immediate remediation is required for the top findings listed above."
    )
    lines.append("")

    # ── R-03: Attack Path Summary ──
    # 攻击者视角摘要 — 3 行描述主要攻击路径
    lines.append("## Attack Path Summary (Offensive Perspective)")
    lines.append("")
    lines.append("> This section describes how an attacker would exploit the identified vulnerabilities.")
    lines.append("")

    # 从 findings 提取主要攻击路径
    if evidence.findings:
        sorted_findings = sorted(evidence.findings, key=lambda f: f.asr, reverse=True)
        top_paths = [f for f in sorted_findings if f.asr > 0][:3]
        if top_paths:
            for i, path in enumerate(top_paths, 1):
                techs = ", ".join(sorted({r.get('technique', '') for r in path.results if r.get('technique')}))
                lines.append(f"{i}. **[{path.owasp_id}] {path.owasp_category}** — ASR {path.asr}% via techniques: {techs}")
        else:
            lines.append("No successful attack paths identified.")
    else:
        lines.append("No attack paths identified.")
    lines.append("")

    # ── R-04: Expected ASR Reduction Post-Remediation ──
    # 修复后预期 ASR 降幅
    lines.append("## Expected ASR Reduction Post-Remediation")
    lines.append("")
    lines.append("| Remediation Action | Target OWASP ID | Current ASR | Expected ASR |")
    lines.append("|-------------------|-----------------|-------------|--------------|")

    if evidence.findings:
        sorted_findings = sorted(evidence.findings, key=lambda f: f.asr, reverse=True)
        for finding in sorted_findings[:5]:
            expected_asr = max(0, finding.asr * 0.1)  # 预期修复后降至 10% 以下
            lines.append(
                f"| Implement {finding.owasp_id} mitigations "
                f"| {finding.owasp_id} "
                f"| {finding.asr}% "
                f"| ≤{expected_asr:.0f}% |"
            )
    else:
        lines.append("| No remediation actions required | — | — | — |")
    lines.append("")

    return "\n".join(lines)


def _generate_findings_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """生成漏洞详情报告 (report_findings.md)。

    目标: 安全工程师查看每个 Evidence 的详细信息。
    方案C: 精简模板 — 删除重复内容, 折叠长文本, 引用外部文件。
    """
    lines: list[str] = []
    evidence_list = evidence.successful_evidence if success_only else evidence.evidence

    lines.append("# Vulnerability Details — AI Red Team Assessment")
    lines.append("")
    lines.append(f"**Target:** {evidence.target_model}")
    lines.append(f"**Date:** {evidence.timestamp}")
    lines.append(f"**Total Evidence:** {len(evidence_list)}")
    lines.append("")

    # ── Target Fingerprint (简要) ──
    fp = evidence.target_fingerprint or {}
    if fp:
        lines.append("## Target Fingerprint")
        lines.append("")
        lines.append("| Attribute | Value |")
        lines.append("|-----------|-------|")
        for key in ("app_type", "target_type", "auth_type", "capabilities", "model_family", "language"):
            val = fp.get(key, "")
            if val:
                lines.append(f"| {key} | {val} |")
        lines.append("")

    # ── 每个 Evidence 的精简卡片 (方案C) ──
    lines.append("## Evidence Cards")
    lines.append("")
    for ev in evidence_list:
        _append_evidence_card(lines, ev)

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

    # ── OWASP ASI Top 10 (Agentic AI) ──
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
    # R-06: 当 failure_analysis 为空或无实际内容时, 显示分类表框架
    lines.append("## Failure Analysis")
    lines.append("")
    fa = evidence.failure_analysis or {}
    _fa_has_data = (
        fa.get("failure_types") or fa.get("technique_ranking")
    )
    if _fa_has_data:
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
    else:
        # R-06: Failure Analysis 分类表 (即使无数据也显示分类框架)
        lines.append("### Failure Classification")
        lines.append("")
        lines.append("| Failure Category | Count | Description |")
        lines.append("|-----------------|-------|-------------|")

        # 统计失败类型
        failure_categories: dict[str, int] = {}
        for ev in evidence.evidence:
            if not ev.is_success:
                # 基于转换器类型分类失败
                if ev.converter_chain and "baseline" not in (ev.converter_chain or ""):
                    cat = "encoding_blocked"
                elif ev.objective and "jailbreak" in (ev.objective or "").lower():
                    cat = "jailbreak_blocked"
                else:
                    cat = "request_refused"
                failure_categories[cat] = failure_categories.get(cat, 0) + 1

        if failure_categories:
            descriptions = {
                "encoding_blocked": "Converter encoding was detected and blocked",
                "jailbreak_blocked": "Jailbreak prompt was refused by the model",
                "request_refused": "Request was refused due to policy violation",
            }
            for cat, count in sorted(failure_categories.items(), key=lambda x: x[1], reverse=True):
                desc = descriptions.get(cat, "Unknown failure reason")
                lines.append(f"| {cat} | {count} | {desc} |")
        else:
            lines.append("| No failures recorded | 0 | All attacks succeeded or no evidence |")

        lines.append("")

        # 失败按技术统计
        lines.append("### Failure Breakdown by Technique")
        lines.append("")
        lines.append("| Technique | Failed | Primary Failure Category |")
        lines.append("|-----------|--------|-------------------------|")
        tech_failures: dict[str, dict] = {}
        for ev in evidence.evidence:
            if not ev.is_success:
                tech = ev.technique_name or "unknown"
                if tech not in tech_failures:
                    tech_failures[tech] = {"count": 0, "categories": {}}
                tech_failures[tech]["count"] += 1
                # 分类
                if ev.converter_chain and "baseline" not in (ev.converter_chain or ""):
                    cat = "encoding_blocked"
                elif "jailbreak" in (ev.objective or "").lower():
                    cat = "jailbreak_blocked"
                else:
                    cat = "request_refused"
                tech_failures[tech]["categories"][cat] = tech_failures[tech]["categories"].get(cat, 0) + 1

        if tech_failures:
            for tech, data in sorted(tech_failures.items(), key=lambda x: x[1]["count"], reverse=True):
                primary_cat = max(data["categories"].items(), key=lambda x: x[1])[0] if data["categories"] else "N/A"
                lines.append(f"| {tech} | {data['count']} | {primary_cat} |")
        else:
            lines.append("| No technique failures | 0 | — |")
        lines.append("")

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

    return "\n".join(lines)


def _generate_technical_markdown(evidence: EvidenceCollection) -> str:
    """生成技术附录报告 (report_technical.md)。

    目标: 技术审查者查看 MITRE 映射、评分一致性、编排日志。
    包含方案B/C 的去重优化。
    """
    lines: list[str] = []

    lines.append("# Technical Appendix — AI Red Team Assessment")
    lines.append("")
    lines.append(f"**Target:** {evidence.target_model}")
    lines.append(f"**Date:** {evidence.timestamp}")
    lines.append("")

    # ── Target Fingerprint & Attack Surface (完整版) ──
    fp = evidence.target_fingerprint or {}
    attack_surface = evidence.attack_surface or {}
    if fp or attack_surface:
        lines.append("## Target Fingerprint & Attack Surface")
        lines.append("")
        lines.append("| Attribute | Value |")
        lines.append("|-----------|-------|")
        if fp:
            for key in (
                "app_type", "target_type", "auth_type", "framework", "content_type",
                "capabilities", "model_family", "language",
                "session_type", "secret_format", "tenant_id",
                "api_category", "burp_model_name",
            ):
                val = fp.get(key, "")
                if val:
                    lines.append(f"| {key} | {val} |")
            if fp.get("ai_framework"):
                lines.append(f"| ai_framework | {fp['ai_framework']} ({fp.get('ai_framework_category', '')}) |")
            if fp.get("system_prompt_leaked"):
                lines.append(f"| system_prompt_leaked | **LEAKED** via {fp.get('system_prompt_extraction_method', '')} (len={fp.get('system_prompt_length', 0)}) |")
        if attack_surface:
            lines.append(f"| mcp_tool_count | {attack_surface.get('mcp_tool_count', 0)} |")
            lines.append(f"| mcp_resource_count | {attack_surface.get('mcp_resource_count', 0)} |")
            lines.append(f"| openapi_endpoint_count | {attack_surface.get('openapi_endpoint_count', 0)} |")
            if attack_surface.get("openapi_spec_path"):
                lines.append(f"| openapi_spec_path | {attack_surface['openapi_spec_path']} |")
            lines.append(f"| port_endpoint_count | {attack_surface.get('port_endpoint_count', 0)} |")
            lines.append(f"| probe_count | {attack_surface.get('probe_count', 0)} |")
            if attack_surface.get("mcp_tool_safety_risky_count"):
                lines.append(f"| mcp_tool_safety_risky | {attack_surface['mcp_tool_safety_risky_count']} risky tools |")
            if attack_surface.get("auth_recovery_attempts"):
                lines.append(f"| auth_recovery_attempts | {attack_surface['auth_recovery_attempts']} |")
        lines.append("")

    # ── Weapon Loadout (ARM Phase) — v59 新增 ──
    # 从 orchestration_log 提取 ARM 阶段的武器化决策, 在报告中保留完整武器清单
    # (终端已将 ARM 卡片降级为 1 行摘要, 详情移至此处)
    _append_weapon_loadout(lines, evidence)

    # ── MITRE ATLAS Mapping (去重后) — R-08: 空表友好提示 ──
    lines.append("## MITRE ATLAS Mapping")
    lines.append("")
    lines.append("| OWASP ID | MITRE Tactic | Technique ID | Technique Name |")
    lines.append("|----------|-------------|--------------|----------------|")
    seen_mitre: set[str] = set()
    mitre_count = 0
    for ev in evidence.evidence:
        key = f"{ev.owasp_id}|{ev.mitre_tactic}|{ev.mitre_technique_id}|{ev.mitre_technique_name}"
        if key in seen_mitre:
            continue
        seen_mitre.add(key)
        lines.append(
            f"| {ev.owasp_id} | {ev.mitre_tactic} | {ev.mitre_technique_id} "
            f"| {ev.mitre_technique_name} |",
        )
        mitre_count += 1
    if mitre_count == 0:
        lines.append("| *No data available* | — | — | — |")
        lines.append("")
        lines.append("> MITRE ATLAS mapping not available for this assessment.")
    lines.append("")

    # ── MITRE ATLAS Reference (去重后) — R-08: 空表友好提示 ──
    lines.append("## MITRE ATLAS Reference")
    lines.append("")
    seen_refs: set[str] = set()
    ref_count = 0
    for ev in evidence.evidence:
        if ev.mitre_url:
            ref_key = f"{ev.mitre_technique_id}|{ev.mitre_url}"
            if ref_key in seen_refs:
                continue
            seen_refs.add(ref_key)
            lines.append(f"- [{ev.mitre_technique_id}]({ev.mitre_url}): {ev.mitre_technique_name}")
            ref_count += 1
    if ref_count == 0:
        lines.append("*No MITRE ATLAS references available for this assessment.*")
    lines.append("")

    # ── Score Consistency Analysis (去重摘要版) — R-08: 空表友好提示 ──
    score_lines = _build_score_consistency_section(evidence)
    if score_lines:
        lines.extend(score_lines)
    else:
        lines.append("## Score Consistency Analysis")
        lines.append("")
        lines.append("*No score consistency data available for this assessment.*")
        lines.append("")

    # ── Escalation Chain Report — R-08: 空表友好提示 ──
    lines.append("## Escalation Chain Report")
    lines.append("")
    dashboard = _build_escalation_dashboard_data(evidence)
    if dashboard:
        lines.append("| Stage | Technique | ASR | Status |")
        lines.append("|-------|-----------|-----|--------|")
        for stage in dashboard:
            lines.append(
                f"| {stage['stage']} | {stage['technique']} | {stage['asr']} | {stage['escalated']} |",
            )
    else:
        lines.append("*No escalation chain data available. Escalation may have been disabled or not triggered.*")
    lines.append("")

    # ── Adaptive Dual Judge Statistics ──
    if hasattr(evidence, "dual_judge_stats") and evidence.dual_judge_stats:
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
        kappa = stats.get("cohens_kappa", 0.0)
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

        # OR Aggregation
        or_stats = stats.get("or_aggregation", {})
        if or_stats and or_stats.get("total", 0) > 0:
            lines.append("### OR Aggregation False-Positive Tracking")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| OR Aggregation Total | {or_stats.get('total', 0)} |")
            lines.append(f"| Disagreements | {or_stats.get('disagreements', 0)} ({or_stats.get('disagreement_rate', 0)}%) |")
            lines.append(f"| J1-Only Success (potential FP) | {or_stats.get('j1_only_success', 0)} |")
            lines.append(f"| J2-Only Success | {or_stats.get('j2_only_success', 0)} |")
            lines.append(f"| Potential False Positive Rate | {or_stats.get('potential_false_positive_rate', 0)}% |")
            lines.append("")

        # ScorerMetrics
        scorer_metrics = stats.get("scorer_metrics", {})
        if scorer_metrics and scorer_metrics.get("num_responses", 0) > 0:
            lines.append("### T0 Scorer Metrics (PyRIT Native)")
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
                lines.append(f"| Confusion Matrix | TP={cm.get('tp', 0)}, FP={cm.get('fp', 0)}, FN={cm.get('fn', 0)}, TN={cm.get('tn', 0)} |")
            lines.append("")

    # Wilson CI + Cohen's Kappa
    _wilson_ci = getattr(evidence, "wilson_ci", None)
    if _wilson_ci and len(_wilson_ci) == 2 and (_wilson_ci[0] != 0.0 or _wilson_ci[1] != 0.0):
        lines.append(f"- **ASR 95% CI (Wilson)**: [{_wilson_ci[0]}%, {_wilson_ci[1]}%]")
    if hasattr(evidence, "cohens_kappa") and evidence.cohens_kappa != 0.0:
        kappa = evidence.cohens_kappa
        interpretation = (
            "almost perfect" if kappa > 0.80
            else "substantial" if kappa > 0.60
            else "moderate" if kappa > 0.40
            else "fair"
        )
        lines.append(f"- **Cohen's Kappa**: {kappa:.3f} ({interpretation})")
    lines.append("")

    # ── Orchestration Decision Log (方案E: 流程图版) — R-09: 结构化 ──
    _orch_log = getattr(evidence, "orchestration_log", [])
    if _orch_log:
        lines.append("## Orchestration Decision Log")
        lines.append("")
        lines.append("> Chronological log of orchestration decisions made during the assessment.")
        lines.append("")

        # Pipeline 流程图
        _append_orchestration_flowchart(lines, _orch_log)
        lines.append("")

        # R-09: 详细决策日志 — 按阶段分组, 表格化展示
        # 按 phase 分组
        orch_by_phase: dict[str, list] = {}
        for entry in _orch_log:
            phase = entry.get("phase", "unknown")
            if phase not in orch_by_phase:
                orch_by_phase[phase] = []
            orch_by_phase[phase].append(entry)

        # 按固定顺序输出各阶段
        phase_order = ["recon", "arm", "strike", "escalate", "assess", "report"]
        phase_labels = {
            "recon": "① Reconnaissance",
            "arm": "② Weaponization (ARM)",
            "strike": "③ Single-Round Attack (STRIKE)",
            "escalate": "④ Multi-Turn Escalation",
            "assess": "⑤ Scoring & Assessment",
            "report": "⑥ Reporting",
        }

        for phase in phase_order:
            entries = orch_by_phase.get(phase, [])
            if not entries:
                continue
            lines.append(f"### {phase_labels.get(phase, phase.upper())}")
            lines.append("")

            # 表格头
            lines.append("| # | Decision | Key Parameters | Reasoning |")
            lines.append("|---|----------|----------------|-----------|")

            for idx, entry in enumerate(entries, 1):
                decision = entry.get("decision", "")
                reasoning = entry.get("reasoning", "")[:80]
                if len(entry.get("reasoning", "")) > 80:
                    reasoning += "..."

                # 提取关键参数 (从 input + output)
                _input = entry.get("input", {}) or {}
                _output = entry.get("output", {}) or {}
                params = []
                if _input:
                    # 只展示关键输入参数
                    for k in ["seed_files", "mode", "capabilities", "enabled"]:
                        if k in _input:
                            params.append(f"{k}={_input[k]}")
                if _output:
                    # 只展示关键输出参数
                    for k in ["seed_count", "total_results", "overall_asr", "converter_count"]:
                        if k in _output:
                            params.append(f"{k}={_output[k]}")

                params_str = ", ".join(params[:3])  # 最多显示 3 个参数
                if not params_str:
                    params_str = "—"

                lines.append(f"| {idx} | {decision} | {params_str} | {reasoning} |")

            lines.append("")

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════
# 方案C: Evidence 精简卡片
# ════════════════════════════════════════════════════════════════

def _append_evidence_card(lines: list[str], ev: VulnerabilityEvidence) -> None:
    """生成单个 Evidence 的精简卡片 (方案C + R-05)。

    优化:
    - 删除 Jailbreak Prompt (与 Objective 相同时)
    - Harmful Output 折叠到 <details> 块
    - Conversation History 改为文件引用
    - PoC 脚本改为路径链接
    - R-05: 增加 Attack Chain 可视化 — 展示从 Seed→Converter→Technique→Outcome 的攻击路径
    """
    lines.append(f"### {ev.evidence_id} — {ev.owasp_id}: {ev.owasp_category}")
    lines.append("")

    # ── R-05: Attack Chain Visualization ──
    # 展示攻击路径: Seed → Converter → Technique → Outcome
    lines.append("**Attack Chain:**")
    attack_chain_parts = []
    attack_chain_parts.append(f"Seed({(ev.objective or 'unknown')[:30]})")
    if ev.converter_chain and ev.converter_chain != "none (baseline)":
        # 简化 converter chain 显示
        conv_short = ev.converter_chain.split(" → ")[0] if " → " in ev.converter_chain else ev.converter_chain
        attack_chain_parts.append(f"Converter({conv_short})")
    attack_chain_parts.append(f"Tech({ev.technique_name or 'baseline'})")
    outcome_icon = "✅ PASS" if ev.is_success else "❌ BLOCKED"
    attack_chain_parts.append(f"Outcome({outcome_icon})")
    lines.append(f"`{' → '.join(attack_chain_parts)}`")
    lines.append("")

    # 元数据表 (紧凑)
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Technique | {ev.technique_display_name} |")
    lines.append(f"| Severity | {ev.owasp_severity} |")
    lines.append(f"| Risk Score | {ev.owasp_risk_score}/10 |")
    lines.append(f"| Converter | {ev.converter_chain or 'none (baseline)'} |")
    outcome = "✅ Success" if ev.is_success else "❌ Failed"
    lines.append(f"| Outcome | {outcome} |")
    lines.append(f"| Confidence | {ev.confidence} |")
    lines.append(f"| MITRE | {ev.mitre_technique_id or 'N/A'} ({ev.mitre_tactic or 'N/A'}) |")
    lines.append(f"| PoC | → `poc/poc_{ev.evidence_id}.py` |")
    lines.append(f"| Evidence | → `evidence/{ev.evidence_id}.json` |")
    lines.append("")

    # Objective (截断)
    obj_truncated = ev.objective[:_TRUNCATE_LEN] + ("..." if len(ev.objective) > _TRUNCATE_LEN else "")
    lines.append(f"**Objective:** {obj_truncated}")
    lines.append("")

    # Jailbreak Prompt (仅当与 Objective 不同时才显示)
    if ev.jailbreak_prompt and ev.jailbreak_prompt != ev.objective:
        jbp_truncated = ev.jailbreak_prompt[:_TRUNCATE_LEN] + ("..." if len(ev.jailbreak_prompt) > _TRUNCATE_LEN else "")
        lines.append(f"**Jailbreak Prompt (modified):** {jbp_truncated}")
        lines.append("")

    # Harmful Output (折叠到 details 块)
    if ev.harmful_output:
        harmful_lines = ev.harmful_output.split("\n")
        harmful_preview = harmful_lines[0][:100] + "..." if harmful_lines else ""
        lines.append(f"**Model Response Preview:** {harmful_preview}")
        lines.append("")
        lines.append("<details>")
        lines.append(f"<summary>💬 Full Model Response ({len(ev.harmful_output)} chars, click to expand)</summary>")
        lines.append("")
        lines.append(ev.harmful_output)
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Validation Runs
    val_runs = getattr(ev, "validation_runs", [])
    if val_runs:
        lines.append("**Validation:**")
        for run in val_runs:
            lines.append(f"  - Run {run.get('run', '?')}: {'✅ Success' if run.get('success') else '❌ Failed'}")
        lines.append("")

    # Testing Conditions
    conditions = getattr(ev, "testing_conditions", {})
    if conditions:
        lines.append("**Conditions:**")
        for k, v in conditions.items():
            lines.append(f"  - **{k}:** {v}")
        lines.append("")

    # Remediation
    lines.append("**Remediation:**")
    for mitigation in ev.owasp_mitigations:
        lines.append(f"  - {mitigation}")
    lines.append("")


# ════════════════════════════════════════════════════════════════
# 方案D: 风险热力图 (Severity × ASR 矩阵)
# ════════════════════════════════════════════════════════════════

def _append_risk_heatmap(lines: list[str], evidence: EvidenceCollection) -> None:
    """追加风险热力图 (Severity × ASR 区间矩阵)。"""
    if not evidence.findings:
        return

    lines.append("## Risk Heatmap (Severity × ASR)")
    lines.append("")
    lines.append("| Severity \\ ASR | 100% | 90-99% | <90% | 0% (Failed) |")
    lines.append("|---------------|------|--------|------|------------|")

    severity_order = ["critical", "high", "medium", "low"]
    for sev in severity_order:
        sev_findings = [f for f in evidence.findings if f.owasp_severity == sev]
        if not sev_findings:
            continue

        col_100 = [f.owasp_id for f in sev_findings if f.asr == 100]
        col_90 = [f.owasp_id for f in sev_findings if 90 <= f.asr < 100]
        col_lt90 = [f.owasp_id for f in sev_findings if 0 < f.asr < 90]
        col_0 = [f.owasp_id for f in sev_findings if f.asr == 0]

        lines.append(
            f"| {sev.title()} | {', '.join(col_100) or '—'} | "
            f"{', '.join(col_90) or '—'} | "
            f"{', '.join(col_lt90) or '—'} | "
            f"{', '.join(col_0) or '—'} |"
        )
    lines.append("")


# ════════════════════════════════════════════════════════════════
# 方案E: Pipeline 流程图
# ════════════════════════════════════════════════════════════════

def _append_pipeline_flowchart(lines: list[str], evidence: EvidenceCollection) -> None:
    """追加 Pipeline 流程图 (方案E)。

    v60 优化 (R-01): 新增 REPORT 阶段框, 完整的 6 阶段流水线。
    v59 优化: 在 ARM→STRIKE 箭头上标注数据流字段 (seeds/techniques/converter_map)。
    """
    lines.append("## Pipeline Flowchart")
    lines.append("")
    lines.append("```")
    lines.append("┌─────────┐         ┌──────────┐         ┌───────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐")
    lines.append("│  RECON   │──fp────→│  ARM     │──seeds──→│  STRIKE   │────→│ ESCALATE │────→│  ASSESS  │────→│  REPORT  │")

    # 从 orchestration log 提取关键指标 (合并同一 phase 的多个条目)
    orch_log = getattr(evidence, "orchestration_log", [])
    recon_out: dict = {}
    arm_out: dict = {}
    strike_out: dict = {}
    escalate_out: dict = {}
    assess_out: dict = {}
    report_out: dict = {}
    for entry in orch_log:
        phase = entry.get("phase", "")
        _out = entry.get("output", {}) or {}
        if phase == "recon":
            recon_out.update(_out)
        elif phase == "arm":
            arm_out.update(_out)
        elif phase == "strike":
            strike_out.update(_out)
        elif phase == "escalate":
            escalate_out.update(_out)
        elif phase == "assess":
            assess_out.update(_out)
        elif phase == "report":
            report_out.update(_out)

    recon_detail = recon_out.get("probe_count", "?") if isinstance(recon_out, dict) else "?"
    arm_seeds = arm_out.get("seed_count", "?") if isinstance(arm_out, dict) else "?"
    arm_techs = arm_out.get("techniques", None) if isinstance(arm_out, dict) else None
    strike_results = strike_out.get("total_results", evidence.total_attacks) if isinstance(strike_out, dict) else evidence.total_attacks
    esc_results = escalate_out.get("total_results", evidence.total_attacks) if isinstance(escalate_out, dict) else evidence.total_attacks
    assess_success = assess_out.get("overall_asr", "?") if isinstance(assess_out, dict) else "?"
    # R-01: 计算报告文件数 — report_out 已是 output 字典 (非嵌套), 统计非空值数量
    _report_keys = ["report_index", "report_executive", "report_findings", "report_technical", "report_success", "native_output"]
    report_files = sum(1 for k in _report_keys if report_out.get(k)) if isinstance(report_out, dict) else 6

    # ARM 行: 展示 seeds + techs + converters
    _arm_tech_str = f"{len(arm_techs)} techs" if isinstance(arm_techs, list) else "? techs"
    lines.append(f"│ {recon_detail} probes│         │ {arm_seeds} seeds │+conv    │ {strike_results} attacks│     │ +{esc_results - strike_results if esc_results > strike_results else 0} attacks │     │ ASR {assess_success}%│     │ {report_files} files│")
    lines.append(f"│           │         │ {_arm_tech_str}│+techs   │           │     │           │     │          │     │          │")
    lines.append("└─────────┘         └──────────┘         └───────────┘     └──────────┘     └──────────┘     └──────────┘")
    lines.append("")
    # R-02: 更新 Data flow 行包含 ASSESS→REPORT
    lines.append("Data flow: RECON→ARM (target_fingerprint, capabilities) | ARM→STRIKE (ctx.seeds, ctx.techniques, ctx.converter_map) | STRIKE→ESCALATE (failed_objectives, attack_results) | ESCALATE→ASSESS (full attack_results) | ASSESS→REPORT (evidence, asr, orchestration_log)")
    lines.append("```")
    lines.append("")


def _append_orchestration_flowchart(lines: list[str], orch_log: list) -> None:
    """编排决策日志的流程图表示 (方案E)。

    v60 优化 (R-01): 新增 REPORT 阶段框, 完整的 6 阶段流水线。
    v59 优化: 在阶段间箭头上标注数据流传递的关键字段。
    """
    lines.append("```")
    lines.append("┌─────────┐         ┌──────────┐         ┌───────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐")
    lines.append("│  RECON   │──fp────→│  ARM     │──seeds──→│  STRIKE   │────→│ ESCALATE │────→│  ASSESS  │────→│  REPORT  │")

    # 从日志提取各阶段关键输出 (合并同一 phase 的多个条目, 不覆盖)
    phases_data: dict[str, dict] = {}
    for entry in orch_log:
        phase = entry.get("phase", "unknown")
        _out = entry.get("output", {}) or {}
        if phase not in phases_data:
            phases_data[phase] = {}
        phases_data[phase].update(_out)

    recon_data = phases_data.get("recon", {})
    arm_data = phases_data.get("arm", {})
    strike_data = phases_data.get("strike", {})
    escalate_data = phases_data.get("escalate", {})
    assess_data = phases_data.get("assess", {})
    report_data = phases_data.get("report", {})

    # 提取关键信息
    recon_probe = recon_data.get("probe_count", "?") if isinstance(recon_data, dict) else "?"
    arm_seeds = arm_data.get("seed_count", "?") if isinstance(arm_data, dict) else "?"
    arm_techs = arm_data.get("techniques", None) if isinstance(arm_data, dict) else None
    strike_results = strike_data.get("total_results", "?") if isinstance(strike_data, dict) else "?"
    esc_techs = escalate_data.get("escalated_techniques", "—") if isinstance(escalate_data, dict) else "—"
    assess_asr = assess_data.get("overall_asr", "?") if isinstance(assess_data, dict) else "?"

    _arm_tech_str = f"{len(arm_techs)} techs" if isinstance(arm_techs, list) else "? techs"
    # R-01: report_data 已是 output 字典 (非嵌套), 统计已知报告文件的非空值
    _report_keys = ["report_index", "report_executive", "report_findings", "report_technical", "report_success", "native_output"]
    _report_file_count = sum(1 for k in _report_keys if report_data.get(k)) if isinstance(report_data, dict) else 6

    lines.append(f"│ {recon_probe} probes │         │ {arm_seeds} seeds │+conv    │ {strike_results} results │   │ {esc_techs} │    │ ASR {assess_asr}%│     │ {_report_file_count} files│")
    lines.append(f"│           │         │ {_arm_tech_str}│+techs   │           │   │           │    │          │     │          │")
    lines.append("└─────────┘         └──────────┘         └───────────┘     └──────────┘     └──────────┘     └──────────┘")
    lines.append("")
    # R-02: 更新 Data flow 行包含 ASSESS→REPORT
    lines.append("Data flow: RECON→ARM (target_fingerprint, capabilities) | ARM→STRIKE (ctx.seeds, ctx.techniques, ctx.converter_map) | STRIKE→ESCALATE (failed_objectives, attack_results) | ESCALATE→ASSESS (full attack_results) | ASSESS→REPORT (evidence, asr, orchestration_log)")
    lines.append("```")
    lines.append("")


# ════════════════════════════════════════════════════════════════
# Weapon Loadout (ARM Phase) — v59 新增
# 终端 ARM 卡片降级为 1 行摘要后, 完整武器清单移至此处供事后分析
# ════════════════════════════════════════════════════════════════

def _append_weapon_loadout(lines: list[str], evidence: EvidenceCollection) -> None:
    """追加 ARM 阶段武器清单章节。

    从 orchestration_log 提取 ARM 阶段的种子/技术/Converter 决策,
    从 evidence.evidence 提取每个证据的 seed/converter_chain/technique 信息,
    生成完整的武器配置档案供技术审查者事后分析。

    数据来源:
        - orchestration_log: ARM 阶段的 seed_selection / technique_selection / converter_selection
        - evidence.evidence: 每个 VulnerabilityEvidence 的 seed / converter_chain / technique_name

    R-07: 新增 "Converter Selection Rationale" 表 — 解释为什么选择特定 converter。
    """
    orch_log = getattr(evidence, "orchestration_log", [])

    # 从编排日志提取 ARM 阶段数据
    arm_data: dict[str, Any] = {}
    arm_input: dict[str, Any] = {}
    for entry in orch_log:
        if entry.get("phase") == "arm":
            _out = entry.get("output", {}) or {}
            _inp = entry.get("input", {}) or {}
            _decision = entry.get("decision", "")
            if _decision not in arm_data:
                arm_data[_decision] = {}
                arm_input[_decision] = {}
            arm_data[_decision].update(_out)
            arm_input[_decision].update(_inp)

    seed_info = arm_data.get("seed_selection", {})
    seed_input = arm_input.get("seed_selection", {})
    tech_info = arm_data.get("technique_selection", {})
    conv_info = arm_data.get("converter_selection", {})

    seed_count = seed_info.get("seed_count", "?")
    seed_files = seed_input.get("seed_files", "")
    techniques = tech_info.get("techniques", [])
    converter_count = conv_info.get("converter_count", "?")
    per_technique = conv_info.get("per_technique", {})

    lines.append("## Weapon Loadout (ARM Phase)")
    lines.append("")
    lines.append("> ARM stage weapon configuration — seeds, techniques, and converter paths selected for this assessment.")
    lines.append("")

    # ── 汇总 ──
    lines.append("### Summary")
    lines.append("")
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Seeds | {seed_count} |")
    if seed_files:
        lines.append(f"| Seed Files | {seed_files} |")
    lines.append(f"| Techniques | {len(techniques) if isinstance(techniques, list) else '?'} |")
    lines.append(f"| Converter Paths | {converter_count} |")
    lines.append("")

    # ── R-07: Converter Selection Rationale ──
    lines.append("### Converter Selection Rationale")
    lines.append("")
    lines.append("| Technique | Converter Count | Rationale |")
    lines.append("|-----------|----------------|-----------|")

    # 定义技术对应的 converter 选择理由
    CONVERTER_RATIONALE: dict[str, str] = {
        "prompt_sending": "Baseline testing — no converter applied, used as ASR reference",
        "crescendo": "Multi-turn escalation — conversation-based, no encoding converters needed",
        "tap": "Tree-of-attacks — relies on adversarial LLM, minimal converter usage",
        "pair": "Black-box iterative refinement — adversarial LLM generates jailbreaks directly",
        "gcg": "Gradient-based suffix optimization — no prompt converters applicable",
        "best_of_n": "Sampling-based — multiple attempts increase success probability",
        "many_shot": "Multi-shot prompting — context-based, no encoding transformation",
        "chunked": "Payload splitting — uses chunking strategy instead of encoding",
        "red_teaming": "Native attack strategy — relies on technique-specific converters",
        "native": "PyRIT native attack — direct API interaction preferred",
    }

    if isinstance(techniques, list) and techniques:
        for tech in techniques:
            _conv_count = per_technique.get(tech, "?") if isinstance(per_technique, dict) else "?"
            rationale = CONVERTER_RATIONALE.get(tech, "Auto-selected based on target capabilities and ASR prior")
            lines.append(f"| {tech} | {_conv_count} | {rationale} |")
        lines.append("")

        # 从 evidence 提取实际使用的 converter
        lines.append("### Converters Used (from evidence)")
        lines.append("")
        lines.append("| # | Technique | Converter Chain | Effectiveness |")
        lines.append("|---|-----------|-----------------|---------------|")
        seen_convs: set[str] = set()
        idx = 0
        for ev in evidence.evidence:
            _conv = ev.converter_chain or "none (baseline)"
            _key = f"{ev.technique_name}|{_conv}"
            if _key in seen_convs:
                continue
            seen_convs.add(_key)
            idx += 1
            effectiveness = "High" if ev.is_success else "Low"
            lines.append(f"| {idx} | {ev.technique_name} | {_conv} | {effectiveness} |")
        lines.append("")
    else:
        lines.append("| No techniques recorded | — | — |")
        lines.append("")

    # ── Techniques ──
    if isinstance(techniques, list) and techniques:
        lines.append("### Techniques")
        lines.append("")
        lines.append("| # | Technique | Converter Paths |")
        lines.append("|---|-----------|----------------|")
        for i, tech in enumerate(techniques, 1):
            _conv_count = per_technique.get(tech, "?") if isinstance(per_technique, dict) else "?"
            lines.append(f"| {i} | {tech} | {_conv_count} |")
        lines.append("")

    # ── Seeds (from evidence — per-evidence seed/converter/technique) ──
    if evidence.evidence:
        lines.append("### Seed & Converter Details (per evidence)")
        lines.append("")
        lines.append("| # | Seed (truncated) | Technique | Converter Chain | Success |")
        lines.append("|---|------------------|-----------|------------------|---------|")
        seen_seeds: set[str] = set()
        idx = 0
        for ev in evidence.evidence:
            _seed = (ev.objective or "")[:60]
            _seed_key = _seed[:30]  # 去重键
            if _seed_key in seen_seeds:
                continue
            seen_seeds.add(_seed_key)
            idx += 1
            _tech = ev.technique_name or ""
            _conv = ev.converter_chain or "none (baseline)"
            _success = "✓" if ev.is_success else "✗"
            _seed_display = _seed + ("..." if len(ev.objective or "") > 60 else "")
            lines.append(f"| {idx} | {_seed_display} | {_tech} | {_conv} | {_success} |")
        lines.append("")

    # ── Role Separation ──
    fp = evidence.target_fingerprint or {}
    lines.append("### Role Separation")
    lines.append("")
    lines.append("| Role | Value |")
    lines.append("|------|-------|")
    lines.append(f"| Target Type | {fp.get('target_type', 'unknown')} |")
    lines.append(f"| Model Family | {fp.get('model_family', 'unknown')} |")
    lines.append(f"| Capabilities | {fp.get('capabilities', 'none')} |")
    lines.append(f"| Auth Type | {fp.get('auth_type', 'unknown')} |")
    lines.append("")
