"""正式报告精加工流水线（Phase 12：Reports Pipeline）。

AI-300 章节映射：Ch11: Comprehensive Red Team Exercise
OSAI 评分维度：报告完整性 — 从 results/ 原始数据精加工为 reports/ 正式报告
技术点：数据聚合、格式化、OSAI 5 维度评分、OWASP LLM + Agentic 双重标注、AI Kill Chain 映射

职责：
  - 读取 results/{run_id}/ 下所有原始攻击数据
  - 聚合分析（Findings 统计、攻击链还原、严重程度分布）
  - 生成格式化正式报告到 reports/{run_id}/AI300_Report.md
  - 面向 OffSec AI-300 考试提交标准的 5 维度报告
  - 覆盖 OWASP LLM Top 10 (2025) + OWASP Agentic Top 10 (2026)
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ...core.store import load_json, load_findings, DEFAULT_STORE_DIR

# 正式报告输出目录
REPORTS_DIR = Path("reports")


def _load_all_data(run_id: str) -> dict[str, Any]:
    """从 results/{run_id}/ 加载所有原始攻击数据。

    Returns:
        dict with keys: recon, services, findings_detect, findings_exploit,
                        attack_chains, infra_recon, gitlab_recon, ...
    """
    data: dict[str, Any] = {
        "run_id": run_id,
        "recon": load_json(run_id, "recon"),
        "services": load_json(run_id, "services", subdir="recon"),
        "findings_detect": load_findings(run_id, subdir="detect"),
        "findings_exploit": load_findings(run_id, subdir="exploit"),
        "attack_chain_injection": load_json(run_id, "attack_chain_injection", subdir="recon"),
        "infra_recon": load_json(run_id, "infra_recon", subdir="recon"),
        "gitlab_recon": load_json(run_id, "gitlab_recon", subdir="recon"),
        "mcp_code_detection": load_json(run_id, "mcp_code_detection", subdir="recon"),
        "deployment_pipeline": load_json(run_id, "deployment_pipeline", subdir="recon"),
    }
    return data


def _count_severity(findings: list[dict]) -> dict[str, int]:
    """统计 Findings 严重级别分布。"""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    return counts


def _make_osai_report(run_id: str, target: str | None, data: dict[str, Any]) -> str:
    """生成 OSAI 5 维度评分报告。

    OSAI 5 维度评分标准：
    - 侦察完整性 (15%)
    - 漏洞发现 (25%)
    - 攻击链构建 (20%)
    - 证据完整性 (20%)
    - 修复建议 (20%)
    """
    detect_findings = data.get("findings_detect", [])
    exploit_findings = data.get("findings_exploit", [])
    all_findings = list(detect_findings) + list(exploit_findings)
    recon = data.get("recon") or {}
    services = data.get("services") or []

    # 去重 (按 title 去重)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = f.get("title", "")
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    sev_counts = _count_severity(unique_findings)
    verified_count = sum(1 for f in all_findings if f.get("verified"))
    exploit_count = len(exploit_findings)

    # OWASP 分布
    owasp_dist: dict[str, int] = {}
    for f in unique_findings:
        owasp = f.get("owasp_llm", "N/A")
        owasp_dist[owasp] = owasp_dist.get(owasp, 0) + 1

    # OWASP Agentic 分布
    agentic_dist: dict[str, int] = {}
    for f in unique_findings:
        agentic = f.get("owasp_agentic", "N/A")
        agentic_dist[agentic] = agentic_dist.get(agentic, 0) + 1

    # ATLAS 战术分布
    atlas_dist: dict[str, int] = {}
    for f in unique_findings:
        tactic = f.get("mitre_atlas_tactic", "N/A")
        atlas_dist[tactic] = atlas_dist.get(tactic, 0) + 1

    # 模型列表
    models = recon.get("models", []) if isinstance(recon, dict) else []
    components = recon.get("components", []) if isinstance(recon, dict) else []
    service_count = len(services)

    lines = []
    lines.append(f"# AI RED TEAM ASSESSMENT REPORT")
    lines.append(f"")
    lines.append(f"**Target**: {target or 'N/A'}")
    lines.append(f"**Run ID**: {run_id}")
    lines.append(f"**Date**: {time.strftime('%Y-%m-%d')}")
    lines.append(f"**Methodology**: OffSec AI-300 Advanced AI Red Teaming")
    lines.append(f"**Classification**: CONFIDENTIAL")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # ─── Executive Summary ───
    lines.append(f"## Executive Summary")
    lines.append(f"")
    total_vulns = len(unique_findings)
    crit_high = sev_counts["critical"] + sev_counts["high"]
    lines.append(
        f"This report presents the findings of an AI red team assessment "
        f"conducted against {service_count} AI service(s). "
        f"A total of **{total_vulns} unique vulnerabilities** were identified, "
        f"with **{crit_high}** rated as high or critical severity."
    )
    if verified_count:
        lines.append(
            f"**{verified_count}** findings were verified through exploitation proof "
            f"demonstrating actual impact."
        )
    lines.append(f"")

    # ─── Reconnaissance Summary ───
    lines.append(f"## 1. Reconnaissance Summary")
    lines.append(f"")
    lines.append(f"| Attribute | Value |")
    lines.append(f"|-----------|-------|")
    lines.append(f"| Target | {target or 'N/A'} |")
    lines.append(f"| AI Services Discovered | {service_count} |")
    lines.append(f"| AI Frameworks | {', '.join(components) if components else 'N/A'} |")
    lines.append(f"| Models Identified | {', '.join(models) if models else 'N/A'} |")
    lines.append(f"")

    # ─── Findings Summary ───
    lines.append(f"## 2. Findings Summary")
    lines.append(f"")
    lines.append(f"### Severity Distribution")
    lines.append(f"")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev, 0)
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(sev, "")
        lines.append(f"| {emoji} {sev.capitalize()} | {count} |")
    lines.append(f"| **Total** | **{total_vulns}** |")
    lines.append(f"")

    if exploit_count:
        lines.append(f"### Exploitation Proof")
        lines.append(f"")
        lines.append(f"- Findings with verified exploitation: **{verified_count}**")
        lines.append(f"- Total exploit attempts: **{exploit_count}**")
        lines.append(f"")

    lines.append(f"### OWASP LLM Top 10 Coverage")
    lines.append(f"")
    lines.append(f"| OWASP Category | Count |")
    lines.append(f"|----------------|-------|")
    for owasp, count in sorted(owasp_dist.items()):
        lines.append(f"| {owasp} | {count} |")
    lines.append(f"")

    lines.append(f"### OWASP Agentic Top 10 (2026) Coverage")
    lines.append(f"")
    lines.append(f"| ASI Category | Count |")
    lines.append(f"|--------------|-------|")
    for agentic, count in sorted(agentic_dist.items()):
        lines.append(f"| {agentic} | {count} |")
    lines.append(f"")

    lines.append(f"### MITRE ATLAS Tactics")
    lines.append(f"")
    lines.append(f"| ATLAS Tactic | Count |")
    lines.append(f"|--------------|-------|")
    for tactic, count in sorted(atlas_dist.items()):
        lines.append(f"| {tactic} | {count} |")
    lines.append(f"")

    # ─── Detailed Findings ───
    lines.append(f"## 3. Detailed Findings")
    lines.append(f"")
    if unique_findings:
        for i, f in enumerate(unique_findings[:50], 1):  # 最多 50 条
            title = f.get("title", "Untitled")
            severity = f.get("severity", "info").upper()
            category = f.get("category", "")
            description = f.get("description", "No description")
            evidence = f.get("evidence", "")
            remediation = f.get("remediation", "")
            owasp = f.get("owasp_llm", "")
            atlas = f.get("mitre_atlas_tactic", "")
            verified = "✅ Verified" if f.get("verified") else "⚠️ Unverified"
            cve = ", ".join(f.get("cve_refs", [])) if f.get("cve_refs") else "N/A"
            endpoint = f.get("endpoint", "N/A")

            lines.append(f"### {i}. {title}")
            lines.append(f"")
            lines.append(f"| Attribute | Value |")
            lines.append(f"|-----------|-------|")
            lines.append(f"| Severity | **{severity}** |")
            lines.append(f"| Category | {category} |")
            lines.append(f"| OWASP LLM | {owasp} |")
            if agentic_val := f.get("owasp_agentic", ""):
                lines.append(f"| OWASP Agentic | {agentic_val} |")
            lines.append(f"| MITRE ATLAS | {atlas} |")
            lines.append(f"| CVE | {cve} |")
            lines.append(f"| Endpoint | {endpoint} |")
            lines.append(f"| Status | {verified} |")
            lines.append(f"")
            lines.append(f"**Description**: {description}")
            lines.append(f"")
            if evidence:
                lines.append(f"**Evidence**:")
                lines.append(f"```")
                lines.append(f"{evidence[:500]}")
                lines.append(f"```")
                lines.append(f"")
            if remediation:
                lines.append(f"**Remediation**: {remediation}")
                lines.append(f"")
            lines.append(f"---")
            lines.append(f"")
    else:
        lines.append(f"_No findings recorded._")
        lines.append(f"")

    # ─── Exploitation Details ───
    if exploit_findings:
        lines.append(f"## 4. Exploitation Details")
        lines.append(f"")

        for i, f in enumerate(exploit_findings[:20], 1):
            title = f.get("title", "Untitled")
            proof = f.get("exploitation_proof", {})
            verified_str = "✅ YES" if f.get("verified") else "❌ NO"

            lines.append(f"### {i}. {title}")
            lines.append(f"")
            lines.append(f"**Verified**: {verified_str}")
            lines.append(f"")

            if isinstance(proof, dict):
                method = proof.get("method", "N/A")
                result = proof.get("result", "N/A")
                confidence = proof.get("confidence", "N/A")
                lines.append(f"| Attribute | Value |")
                lines.append(f"|-----------|-------|")
                lines.append(f"| Method | {method} |")
                lines.append(f"| Result | {result} |")
                lines.append(f"| Confidence | {confidence} |")
                if "details" in proof:
                    lines.append(f"")
                    lines.append(f"**Details**:")
                    lines.append(f"```json")
                    lines.append(f"{proof['details']}")
                    lines.append(f"```")
                lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

    # ─── Risk Dashboard ───
    lines.append(f"## 5. Risk Dashboard")
    lines.append(f"")
    lines.append(f"### Overall Risk Score")
    lines.append(f"")

    # 简单评分模型
    risk_score = (
        sev_counts["critical"] * 10 +
        sev_counts["high"] * 5 +
        sev_counts["medium"] * 2 +
        sev_counts["low"] * 1
    )
    max_score = total_vulns * 10 if total_vulns > 0 else 1
    normalized = min(int(risk_score / max_score * 100), 100)

    lines.append(f"- **Raw Risk Score**: {risk_score} / {max_score}")
    lines.append(f"- **Normalized**: {normalized}%")
    lines.append(f"")

    if normalized >= 70:
        lines.append(f"> 🔴 **CRITICAL RISK** — Immediate remediation required.")
    elif normalized >= 40:
        lines.append(f"> 🟠 **HIGH RISK** — Urgent attention needed.")
    elif normalized >= 20:
        lines.append(f"> 🟡 **MODERATE RISK** — Schedule remediation.")
    else:
        lines.append(f"> 🟢 **LOW RISK** — Monitor and maintain.")

    lines.append(f"")
    lines.append(f"### Attack Surface & Component Analysis")
    lines.append(f"")
    lines.append(f"| Component | Count |")
    lines.append(f"|-----------|-------|")
    lines.append(f"| AI Services | {service_count} |")
    lines.append(f"| Models | {len(models)} |")
    lines.append(f"| Frameworks | {len(components)} |")
    lines.append(f"")

    # ─── AI Kill Chain Mapping ───
    lines.append(f"## 6. AI Kill Chain Mapping")
    lines.append(f"")
    lines.append(f"### Cyber Kill Chain for AI Systems")
    lines.append(f"")
    lines.append(f"Aligning findings to the AI-specific Kill Chain (OffSec AI-300 / MITRE ATLAS):")
    lines.append(f"")
    lines.append(f"| Kill Chain Phase | MITRE ATLAS Tactic | Findings | Key Techniques |")
    lines.append(f"|------------------|--------------------|----------|---------------|")
    lines.append(f"| 1. Reconnaissance | Reconnaissance | {atlas_dist.get('Reconnaissance', 0)} | AI asset discovery, protocol fingerprinting, guardrail profiling |")
    lines.append(f"| 2. Initial Access | Initial Access | {atlas_dist.get('Initial Access', 0)} | Prompt injection, jailbreak, agent goal hijack (ASI01) |")
    lines.append(f"| 3. Execution | Execution | {atlas_dist.get('Execution', 0)} | Tool misuse (ASI02), code execution (ASI05), MCP exploitation |")
    lines.append(f"| 4. Persistence | Persistence | {atlas_dist.get('Persistence', 0)} | Memory/context poisoning (ASI06), system prompt modification |")
    lines.append(f"| 5. Privilege Escalation | ML Attack Staging | {atlas_dist.get('ML Attack Staging', 0)} | Identity abuse (ASI03), inter-agent trust exploit (ASI07) |")
    lines.append(f"| 6. Credential Access | Defense Evasion | {atlas_dist.get('Defense Evasion', 0)} | System prompt extraction, API key leakage, model extraction |")
    lines.append(f"| 7. Discovery | Reconnaissance | {atlas_dist.get('Reconnaissance', 0)} | Config extraction, tool schema enumeration, agent capability mapping |")
    lines.append(f"| 8. Collection | Exfiltration | {atlas_dist.get('Exfiltration', 0)} | RAG data exfiltration, embedding inversion, output harvesting |")
    lines.append(f"| 9. C2 | Persistence | {atlas_dist.get('Persistence', 0)} | Rogue agent deployment (ASI10), supply chain compromise (ASI04) |")
    lines.append(f"| 10. Actions on Objective | Impact | {atlas_dist.get('Impact', 0)} | Data exfiltration, model theft, cascading failures (ASI08) |")
    lines.append(f"")
    lines.append(f"### Attack Chain Completeness")
    lines.append(f"")
    unique_tactics = len([v for v in atlas_dist.values() if v > 0])
    lines.append(f"- Unique MITRE ATLAS tactics covered: **{unique_tactics}/9**")
    lines.append(f"- OWASP LLM categories hit: **{len([v for v in owasp_dist.values() if v > 0])}/10**")
    lines.append(f"- OWASP Agentic categories hit: **{len([v for v in agentic_dist.values() if v > 0])}/10**")
    if unique_tactics >= 4:
        lines.append(f"- ✅ Meets OffSec AI-300 minimum requirement (≥4 tactics)")
    else:
        lines.append(f"- ⚠️ Below OffSec AI-300 minimum requirement (need ≥4 tactics)")
    lines.append(f"")

    # ─── OSAI Scoring ───
    lines.append(f"## 7. OSAI 5-Dimension Scoring")
    lines.append(f"")

    # 侦察完整性 (15%)
    recon_score = min(100, service_count * 20 + len(components) * 10 + len(models) * 5)
    recon_pct = min(15, int(recon_score / 100 * 15))

    # 漏洞发现 (25%)
    vuln_score = min(100, total_vulns * 10 + crit_high * 15)
    vuln_pct = min(25, int(vuln_score / 100 * 25))

    # 攻击链构建 (20%)
    chain_score = min(100, len(atlas_dist) * 15 + (10 if exploit_count > 0 else 0))
    chain_pct = min(20, int(chain_score / 100 * 20))

    # 证据完整性 (20%)
    evid_score = min(100, verified_count * 15 + total_vulns * 5)
    evid_pct = min(20, int(evid_score / 100 * 20))

    # 修复建议 (20%)
    rem_score = min(100, total_vulns * 8 + crit_high * 10)
    rem_pct = min(20, int(rem_score / 100 * 20))

    total_pct = recon_pct + vuln_pct + chain_pct + evid_pct + rem_pct

    lines.append(f"| Dimension | Score | Max | Weight |")
    lines.append(f"|-----------|-------|-----|--------|")
    lines.append(f"| Reconnaissance Completeness | {recon_pct}% | 15% | 15% |")
    lines.append(f"| Vulnerability Discovery | {vuln_pct}% | 25% | 25% |")
    lines.append(f"| Attack Chain Construction | {chain_pct}% | 20% | 20% |")
    lines.append(f"| Evidence Completeness | {evid_pct}% | 20% | 20% |")
    lines.append(f"| Remediation Guidance | {rem_pct}% | 20% | 20% |")
    lines.append(f"| **Total** | **{total_pct}%** | **100%** | |")
    lines.append(f"")

    # ─── Recommendations ───
    lines.append(f"## 7. Recommendations")
    lines.append(f"")
    lines.append(f"### Immediate Actions (Critical/High)")
    lines.append(f"")
    priority_findings = [f for f in unique_findings if f.get("severity") in ("critical", "high")]
    if priority_findings:
        for f in priority_findings[:10]:
            title = f.get("title", "Untitled")
            remediation = f.get("remediation", "No specific remediation provided")
            lines.append(f"- **{title}**: {remediation}")
    else:
        lines.append(f"- No critical or high severity findings.")
    lines.append(f"")

    lines.append(f"### Medium-Term Improvements")
    lines.append(f"")
    medium_findings = [f for f in unique_findings if f.get("severity") == "medium"]
    if medium_findings:
        for f in medium_findings[:5]:
            title = f.get("title", "Untitled")
            remediation = f.get("remediation", "")
            lines.append(f"- **{title}**: {remediation}")
    else:
        lines.append(f"- No medium severity findings.")
    lines.append(f"")

    # ─── Appendix ───
    lines.append(f"## Appendix: Methodology Reference")
    lines.append(f"")
    lines.append(f"- **Framework**: OffSec AI-300 Advanced AI Red Teaming")
    lines.append(f"- **Standards**: OWASP LLM Top 10, MITRE ATLAS, NVIDIA AI Kill Chain")
    lines.append(f"- **Tool**: RedTeam-AI v2.0 (Library-First, YAML Data-Driven)")
    lines.append(f"- **Report Generation**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"")

    return "\n".join(lines)


def publish_report(
    run_id: str,
    target: str | None = None,
    results_dir: Path = DEFAULT_STORE_DIR,
    reports_dir: Path = REPORTS_DIR,
) -> Path:
    """将 results/{run_id}/ 原始数据精加工为正式 reports/{run_id}/AI300_Report.md。

    Args:
        run_id: 运行 ID
        target: 目标 URL（可选，用于标题）
        results_dir: 原始数据目录（默认 results/）
        reports_dir: 正式报告输出目录（默认 reports/）

    Returns:
        正式报告文件路径
    """
    # 1. 加载原始数据
    data = _load_all_data(run_id)

    # 2. 提取目标（优先从 recon 数据）
    if target is None:
        recon = data.get("recon") or {}
        if isinstance(recon, dict):
            target = recon.get("target", "Unknown")
        else:
            target = "Unknown"

    # 3. 生成 OSAI 5 维度报告
    content = _make_osai_report(run_id, target, data)

    # 4. 写入正式报告目录
    report_dir = reports_dir / run_id
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "AI300_Report.md"
    report_path.write_text(content, encoding="utf-8")

    return report_path
