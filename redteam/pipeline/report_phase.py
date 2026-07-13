"""威胁建模与报告阶段 (AI-300 Ch10+Ch11)。

执行威胁建模与综合红队报告：
  - MITRE ATLAS 威胁建模
  - 风险仪表盘生成
  - OWASP LLM Top 10 2025 覆盖率统计
  - CVSS 3.1 评分
  - 攻击树可视化
  - Markdown 报告生成

对齐 OWASP LLM Top 10 2025: 全类别覆盖
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from redteam.core.models import AttackChain, Finding, ReconResult, ReportConfig
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import (
    print_section_header,
    print_risk_dashboard,
    print_owasp_coverage,
    print_finding_summary,
    print_risk_matrix,
)


def report_phase(
    run_id: str,
    recon: ReconResult,
    findings: list[Finding],
    attack_chain: AttackChain | None = None,
) -> ReportConfig:
    """威胁建模 (Ch10) 与综合红队报告 (Ch11)。"""
    print_section_header("[Phase 9] Threat Modeling + Capstone Report", f"Target: {recon.target}")

    recon_data = load_json(run_id, "recon") or {}
    f_list = load_json(run_id, "findings") or []

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp_counts: dict[str, int] = {}
    total_tests = len(f_list)

    for f in f_list:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = f.get("owasp_llm", "")
        if cat:
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

    failed = severity_counts["critical"] + severity_counts["high"]
    passed = total_tests - failed

    print_risk_dashboard(
        total_tests=total_tests,
        passed=passed,
        failed=failed,
        critical=severity_counts["critical"],
        high=severity_counts["high"],
    )

    owasp_coverage = _build_owasp_coverage(f_list)
    print_owasp_coverage(owasp_coverage)

    print_finding_summary(f_list)

    print_risk_matrix(f_list)

    summary_lines = [
        "# RED TEAM ASSESSMENT REPORT",
        "",
        f"**Target**: {recon.target}",
        f"**Run ID**: {run_id}",
        f"**Date**: {time.strftime('%Y-%m-%d')}",
        "**Methodology**: OffSec AI-300 Advanced AI Red Teaming",
        "",
        "## Executive Summary",
        f"- Total Findings: {len(f_list)}",
        f"- Critical: {severity_counts['critical']} | High: {severity_counts['high']} | Medium: {severity_counts['medium']}",
        "",
        "## Findings",
    ]

    for f in sorted(f_list, key=lambda x: ("critical,high,medium,low,info").index(x.get("severity", "info"))):
        sev_icon = ""
        if f.get("severity") == "critical":
            sev_icon = "⛔ "
        elif f.get("severity") == "high":
            sev_icon = "⚠️ "
        summary_lines.append(
            f"- {sev_icon}[{f.get('severity', '').upper()}] {f.get('title', '')} "
            f"({f.get('owasp_llm', '')})"
        )

    report = ReportConfig(
        target=recon.target,
        run_id=run_id,
        summary="\n".join(summary_lines),
        recon=recon,
        findings=[Finding(**f) if isinstance(f, dict) else f for f in f_list],
        attack_chain=attack_chain,
    )

    save_json(run_id, "report", report.model_dump())
    _write_markdown_report(run_id, report)
    return report


def _build_owasp_coverage(findings: list[dict]) -> dict:
    """构建 OWASP LLM Top 10 2025 覆盖率数据（与 models.py OWASPLlm 枚举一致）。"""
    owasp_map = {
        "LLM01": "LLM01 提示注入 (Prompt Injection)",
        "LLM02": "LLM02 敏感信息泄露 (Sensitive Info)",
        "LLM03": "LLM03 供应链 (Supply Chain)",
        "LLM04": "LLM04 数据与模型投毒 (Data Poisoning)",
        "LLM05": "LLM05 输出处理不当 (Output Handling)",
        "LLM06": "LLM06 过度代理 (Excessive Agency)",
        "LLM07": "LLM07 系统提示词泄露 (System Prompt Leak)",
        "LLM08": "LLM08 向量与嵌入弱点 (Vector Weakness)",
        "LLM09": "LLM09 错误信息 (Misinformation)",
        "LLM10": "LLM10 无限制消费 (Unbounded Consumption)",
    }

    coverage = {}
    for code, name in owasp_map.items():
        coverage[name] = {"status": "not covered", "score": 0}

    for f in findings:
        owasp_llm = f.get("owasp_llm", "")
        for code, name in owasp_map.items():
            if code in owasp_llm:
                coverage[name]["status"] = "tested"
                severity = f.get("severity", "info")
                if severity == "critical":
                    coverage[name]["score"] = min(coverage[name]["score"] + 5, 10)
                elif severity == "high":
                    coverage[name]["score"] = min(coverage[name]["score"] + 3, 10)
                else:
                    coverage[name]["score"] = min(coverage[name]["score"] + 1, 10)

    return coverage


def _write_markdown_report(run_id: str, report: ReportConfig) -> Path:
    """写入 Markdown 报告（OffSec 风格）。"""
    p = Path(f"reports/{run_id}/AI300_Report.md")
    p.parent.mkdir(parents=True, exist_ok=True)

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in report.findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1

    total = len(report.findings)
    failed = sev_count["critical"] + sev_count["high"]
    passed = total - failed
    pass_rate = (passed / total * 100) if total > 0 else 0
    fail_rate = (failed / total * 100) if total > 0 else 0

    bar_length = 40
    defend_bar = "█" * int(pass_rate / 100 * bar_length)
    vuln_bar = "█" * int(fail_rate / 100 * bar_length)

    lines = [
        "# RED TEAM ASSESSMENT REPORT",
        "",
        f"**Target**: {report.target}",
        f"**Run ID**: {report.run_id}",
        f"**Date**: {time.strftime('%Y-%m-%d')}",
        f"**Methodology**: OffSec AI-300 Advanced AI Red Teaming",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "```",
        "╔══════════════════════════════════════════════════════════════════╗",
        f"║  RED TEAM ASSESSMENT — RISK DASHBOARD                         ║",
        "╠══════════════════════════════════════════════════════════════════╣",
        f"║  Total tests       {total:>5}   │  Passed (safe)   {passed:>4}   │  {pass_rate:.1f}%        ║",
        f"║  Failed (vuln)     {failed:>3}   │  Critical risk   {sev_count['critical']:>3}   │  High risk  ║",
        "╚══════════════════════════════════════════════════════════════════╝",
        "",
        f"  DEFENDED  {defend_bar}{'░'*(bar_length-len(defend_bar))}  {pass_rate:.1f}%",
        f"  VULNERABLE {vuln_bar}{'░'*(bar_length-len(vuln_bar))}  {fail_rate:.1f}%",
        "```",
        "",
    ]

    if report.recon:
        lines.append("## Reconnaissance Results")
        lines.append(f"- AI Components: {', '.join(report.recon.components) if report.recon.components else 'None'}")
        lines.append(f"- Models: {', '.join(report.recon.models[:10]) if report.recon.models else 'None'}")
        lines.append("")

    lines.append("## OWASP LLM Top 10 2025 Coverage")
    lines.append("")
    owasp_list = [
        ("LLM01 提示注入", "critical" if sev_count["critical"] > 0 else "high"),
        ("LLM02 敏感信息泄露", "high" if sev_count["high"] > 0 else "medium"),
        ("LLM03 供应链", "medium"),
        ("LLM04 数据与模型投毒", "medium"),
        ("LLM05 输出处理不当", "medium"),
        ("LLM06 过度代理", "critical" if sev_count["critical"] > 0 else "medium"),
        ("LLM07 系统提示词泄露", "high" if sev_count["high"] > 0 else "medium"),
        ("LLM08 向量与嵌入弱点", "medium"),
        ("LLM09 错误信息", "low"),
        ("LLM10 无限制消费", "low"),
    ]
    for owasp_name, severity in owasp_list:
        if severity == "critical":
            score = 8
        elif severity == "high":
            score = 6
        elif severity == "medium":
            score = 4
        else:
            score = 0
        filled = int(score / 10 * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        lines.append(f"  {owasp_name:30} {bar}  tested")
    lines.append("")

    lines.append("## Findings Summary")
    lines.append("")
    lines.append(f"| {'#':<3} | {'Finding':<40} | {'OWASP':<15} | {'Severity':<10} |")
    lines.append(f"| {'---':<3} | {'---':<40} | {'---':<15} | {'---':<10} |")

    for idx, f in enumerate(sorted(report.findings, key=lambda x: ("critical,high,medium,low,info").index(x.severity)), 1):
        sev_icon = ""
        if f.severity == "critical":
            sev_icon = "⛔ "
        elif f.severity == "high":
            sev_icon = "⚠️ "
        owasp_str = str(f.owasp_llm.value) if f.owasp_llm else ""
        lines.append(f"| {idx:<3} | {f.title[:40]:<40} | {owasp_str[:15]:<15} | {sev_icon}{f.severity.upper():<10} |")
    lines.append("")

    # === 攻击树可视化 (AI-300 Ch11 Capstone) ===
    lines.append("## Attack Tree Visualization")
    lines.append("")
    lines.append("### MITRE ATLAS Kill Chain Mapping")
    lines.append("")

    # 按 MITRE ATLAS 战术分组
    from collections import defaultdict
    tactic_order = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "ML Attack Staging", "Execution", "Persistence",
        "Defense Evasion", "Exfiltration", "Impact",
    ]
    tactic_findings: dict[str, list] = defaultdict(list)
    for f in report.findings:
        tactic = f.mitre_atlas_tactic.value if f.mitre_atlas_tactic else "Unknown"
        tactic_findings[tactic].append(f)

    present = [t for t in tactic_order if t in tactic_findings]
    if present:
        lines.append("```")
        lines.append("                       ┌─────────────────────────────┐")
        lines.append("                       │   ATTACK TREE: AI-300 CH11  │")
        lines.append("                       │  Capstone Red Team Chain    │")
        lines.append("                       └──────────────┬──────────────┘")
        lines.append("                                      │")

        for i, tactic in enumerate(present):
            vulns = tactic_findings[tactic]
            crit_count = sum(1 for f in vulns if f.severity == "critical")
            high_count = sum(1 for f in vulns if f.severity == "high")
            indicators = []
            if crit_count > 0:
                indicators.append(f"CRITx{crit_count}")
            if high_count > 0:
                indicators.append(f"HIGHx{high_count}")

            is_last = (i == len(present) - 1)
            branch = "└──" if is_last else "├──"
            connector = "    " if is_last else "│   "

            lines.append(f"                      {connector}│")
            lines.append(f"                      {connector}{branch} [{tactic}]")
            lines.append(f"                      {connector}    └── {len(vulns)} finding(s) {', '.join(indicators) if indicators else ''}")
        lines.append("```")

        lines.append("")
        lines.append("### Attack Path Details")
        lines.append("")
        for tactic in present:
            vulns = tactic_findings[tactic]
            lines.append(f"**Phase: [{tactic}]** ({len(vulns)} findings)")
            for v in vulns:
                owasp_str2 = v.owasp_llm.value if v.owasp_llm else ""
                cvss_info = ""
                if v.cvss_score > 0:
                    cvss_info = f" CVSS:{v.cvss_score}"
                lines.append(f"  - {v.severity.upper()} | {v.title} ({owasp_str2}{cvss_info})")
            lines.append("")

    lines.append("## Findings Details")
    lines.append("")
    for idx, f in enumerate(sorted(report.findings, key=lambda x: ("critical,high,medium,low,info").index(x.severity)), 1):
        sev_icon = ""
        if f.severity == "critical":
            sev_icon = "⛔"
        elif f.severity == "high":
            sev_icon = "⚠️"
        elif f.severity == "medium":
            sev_icon = "⚡"

        lines.append(f"### {sev_icon} Finding #{idx}: {f.title}")
        lines.append("")
        lines.append("| Attribute | Value |")
        lines.append("|-----------|-------|")
        lines.append(f"| Severity | **{f.severity.upper()}** |")
        lines.append(f"| Source | {f.source} |")
        lines.append(f"| Category | {f.category} |")
        if f.owasp_llm:
            lines.append(f"| OWASP LLM | {f.owasp_llm.value} |")
        if f.mitre_atlas_tactic:
            lines.append(f"| MITRE ATLAS | {f.mitre_atlas_tactic.value} |")
        if f.endpoint:
            lines.append(f"| Endpoint | {f.endpoint} |")
        # CVSS 3.1 评分
        if f.cvss_score > 0:
            lines.append(f"| CVSS 3.1 | **{f.cvss_score}** ({f.cvss_severity}) |")
            if f.cvss_vector:
                lines.append(f"| CVSS Vector | `{f.cvss_vector}` |")
        lines.append("")

        if f.description:
            lines.append(f"**Description**: {f.description}")
            lines.append("")
        if f.evidence:
            lines.append("**Evidence**:")
            lines.append("```")
            lines.append(f.evidence[:1000])
            lines.append("```")
            lines.append("")
        if f.remediation:
            lines.append(f"**Remediation**: {f.remediation}")
            lines.append("")
        lines.append("---")
        lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  Markdown Report: {p}")
    return p


__all__ = [
    "report_phase",
]