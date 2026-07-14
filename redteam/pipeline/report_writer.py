"""增量报告写入器 — 各阶段攻击/侦察结束后将结果追加到 .md 报告。

AI-300 Ch11: 综合红队报告 (Phase 1 — 增量保存阶段)
Phase 2（未来）将从此 .md 提取内容制作 OffSec AI-300 考试风格报告。
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any


class ReportWriter:
    """增量 Markdown 报告写入器。

    每个攻击/侦察阶段结束后调用对应方法追加内容到 reports/{run_id}/AI300_Report.md。
    finalize() 在所有阶段完成后写入总结性章节（Executive Summary、Findings Summary 等）。
    """

    def __init__(self, run_id: str, target: str) -> None:
        self._run_id = run_id
        self._target = target
        self._report_dir = Path(f"reports/{run_id}")
        self._report_dir.mkdir(parents=True, exist_ok=True)
        self._report_path = self._report_dir / "AI300_Report.md"
        self._all_findings: list[dict[str, Any]] = []
        self._recon_data: dict[str, Any] = {}
        self._sections_written: set[str] = set()

        # 写入报告头部
        self._report_path.write_text(
            f"# RED TEAM ASSESSMENT REPORT\n\n"
            f"**Target**: {target}\n"
            f"**Run ID**: {run_id}\n"
            f"**Date**: {time.strftime('%Y-%m-%d')}\n"
            f"**Methodology**: OffSec AI-300 Advanced AI Red Teaming\n\n"
            f"---\n\n",
            encoding="utf-8",
        )

    def append_recon(
        self,
        components: list[str],
        models: list[str],
    ) -> None:
        """追加侦察结果章节。"""
        self._recon_data = {"components": components, "models": models}
        comp_str = ", ".join(components) if components else "None"
        model_str = ", ".join(models[:15]) if models else "None"
        with open(self._report_path, "a", encoding="utf-8") as f:
            f.write("## Reconnaissance Results\n\n")
            f.write(f"- AI Components: {comp_str}\n")
            f.write(f"- Models: {model_str}\n\n")
        self._sections_written.add("recon")

    def append_phase(
        self,
        phase_name: str,
        phase_num: int,
        findings: list[dict[str, Any]],
        phase_subtitle: str = "",
    ) -> None:
        """追加单个攻击阶段的结果到报告。

        Args:
            phase_name: 阶段名称（如 "Prompt Injection Attack"）
            phase_num: 阶段编号 (2-8)
            findings: Finding 字典列表
            phase_subtitle: 阶段副标题/描述
        """
        if not findings:
            return

        self._all_findings.extend(findings)

        with open(self._report_path, "a", encoding="utf-8") as f:
            title = f"Phase {phase_num}: {phase_name}"
            f.write(f"## {title}\n\n")
            if phase_subtitle:
                f.write(f"_{phase_subtitle}_\n\n")

            # ── Findings Summary Table (per-phase) ──
            f.write(f"### Findings Summary\n\n")
            f.write(f"| {'#':<3} | {'Finding':<40} | {'OWASP':<8} | {'Severity':<10} |\n")
            f.write(f"| {'---':<3} | {'---':<40} | {'---':<8} | {'---':<10} |\n")
            for idx, finding in enumerate(findings, 1):
                sev = finding.get("severity", "info").upper()
                owasp_val = finding.get("owasp_llm", "")
                if hasattr(owasp_val, "value"):
                    owasp_val = owasp_val.value
                owasp = str(owasp_val)[:8] if owasp_val else "-"
                title_text = finding.get("title", "")
                display_title = title_text[:37] + "..." if len(title_text) > 40 else title_text
                sev_icon = {"CRITICAL": "⛔", "HIGH": "⚠️", "MEDIUM": "⚡"}.get(sev, "")
                f.write(f"| {idx:<3} | {display_title:<40} | {owasp:<8} | {sev_icon} {sev:<8} |\n")
            f.write("\n")

            # ── Findings Details ──
            f.write("### Findings Details\n\n")
            for idx, finding in enumerate(findings, 1):
                sev = finding.get("severity", "info")
                sev_icon = {"critical": "⛔", "high": "⚠️", "medium": "⚡"}.get(sev, "")
                title_text = finding.get("title", "")

                f.write(f"#### {sev_icon} Finding #{idx}: {title_text}\n\n")
                f.write("| Attribute | Value |\n")
                f.write("|-----------|-------|\n")
                f.write(f"| Severity | **{sev.upper()}** |\n")
                f.write(f"| Source | {finding.get('source', '')} |\n")
                f.write(f"| Category | {finding.get('category', '')} |\n")
                if finding.get("owasp_llm"):
                    owasp_v = finding["owasp_llm"]
                    if hasattr(owasp_v, "value"):
                        owasp_v = owasp_v.value
                    f.write(f"| OWASP LLM | {owasp_v} |\n")
                if finding.get("mitre_atlas_tactic"):
                    atlas_v = finding["mitre_atlas_tactic"]
                    if hasattr(atlas_v, "value"):
                        atlas_v = atlas_v.value
                    f.write(f"| MITRE ATLAS | {atlas_v} |\n")
                if finding.get("endpoint"):
                    f.write(f"| Endpoint | {finding['endpoint']} |\n")
                if finding.get("cvss_score", 0) > 0:
                    f.write(f"| CVSS 3.1 | **{finding['cvss_score']}** ({finding.get('cvss_severity', '')}) |\n")
                f.write("\n")

                if finding.get("description"):
                    f.write(f"**Description**: {finding['description']}\n\n")
                if finding.get("evidence"):
                    f.write("**Evidence**:\n```\n")
                    f.write(f"{finding['evidence'][:1000]}\n")
                    f.write("```\n\n")
                if finding.get("remediation"):
                    f.write(f"**Remediation**: {finding['remediation']}\n\n")
                f.write("---\n\n")

        self._sections_written.add(f"phase_{phase_num}")

    def finalize(self) -> Path:
        """在所有攻击阶段完成后写入总结章节。

        Returns:
            报告文件路径
        """
        total = len(self._all_findings)
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        owasp_counts: dict[str, int] = {}
        for f in self._all_findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            cat = f.get("owasp_llm", "")
            if cat:
                owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        failed = sev_counts["critical"] + sev_counts["high"]
        passed = total - failed
        pass_rate = (passed / total * 100) if total > 0 else 0
        fail_rate = (failed / total * 100) if total > 0 else 0

        bar_length = 40
        defend_bar = "█" * int(pass_rate / 100 * bar_length)
        vuln_bar = "█" * int(fail_rate / 100 * bar_length)

        exec_lines = [
            "\n",
            "## Executive Summary\n\n",
            "```\n",
            "╔══════════════════════════════════════════════════════════════════╗\n",
            "║  RED TEAM ASSESSMENT — RISK DASHBOARD                         ║\n",
            "╠══════════════════════════════════════════════════════════════════╣\n",
            f"║  Total tests     {total:>5}   │  Passed (safe)   {passed:>4}   │  {pass_rate:.1f}%        ║\n",
            f"║  Failed (vuln)   {failed:>3}   │  Critical risk   {sev_counts['critical']:>3}   │  High risk  ║\n",
            "╚══════════════════════════════════════════════════════════════════╝\n",
            "\n",
            f"  DEFENDED  {defend_bar}{'░'*(bar_length-len(defend_bar))}  {pass_rate:.1f}%\n",
            f"  VULNERABLE {vuln_bar}{'░'*(bar_length-len(vuln_bar))}  {fail_rate:.1f}%\n",
            "```\n\n",
        ]

        # OWASP LLM Top 10 Coverage
        owasp_order = [
            ("LLM01", "LLM01 提示注入 (Prompt Injection)"),
            ("LLM02", "LLM02 敏感信息泄露 (Sensitive Info)"),
            ("LLM03", "LLM03 供应链 (Supply Chain)"),
            ("LLM04", "LLM04 数据与模型投毒 (Data Poisoning)"),
            ("LLM05", "LLM05 输出处理不当 (Output Handling)"),
            ("LLM06", "LLM06 过度代理 (Excessive Agency)"),
            ("LLM07", "LLM07 系统提示词泄露 (System Prompt Leak)"),
            ("LLM08", "LLM08 向量与嵌入弱点 (Vector Weakness)"),
            ("LLM09", "LLM09 错误信息 (Misinformation)"),
            ("LLM10", "LLM10 无限制消费 (Unbounded Consumption)"),
        ]

        coverage_lines = ["## OWASP LLM Top 10 2025 Coverage\n\n"]
        for code, name in owasp_order:
            count = owasp_counts.get(code, 0)
            if count > 0:
                score = min(count * 2, 10)
                status = "tested"
            else:
                score = 0
                status = "not covered"
            filled = int(score / 10 * bar_length)
            bar = "█" * filled + "░" * (bar_length - filled)
            coverage_lines.append(f"  {name:30} {bar}  {status}\n")
        coverage_lines.append("\n")

        # Findings Summary table
        summary_lines = ["## Findings Summary\n\n"]
        summary_lines.append(f"| {'#':<3} | {'Finding':<40} | {'OWASP':<15} | {'Severity':<10} |\n")
        summary_lines.append(f"| {'---':<3} | {'---':<40} | {'---':<15} | {'---':<10} |\n")
        for idx, f in enumerate(
            sorted(self._all_findings, key=lambda x: ("critical,high,medium,low,info").index(x.get("severity", "info"))),
            1,
        ):
            sev = f.get("severity", "").upper()
            sev_icon = {"CRITICAL": "⛔ ", "HIGH": "⚠️ "}.get(sev, "")
            owasp = f.get("owasp_llm", "")[:15]
            title = f.get("title", "")[:40]
            summary_lines.append(f"| {idx:<3} | {title:<40} | {owasp:<15} | {sev_icon}{sev:<10} |\n")
        summary_lines.append("\n")

        # Attack Tree (simplified)
        from collections import defaultdict
        tactic_order = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "ML Attack Staging", "Execution", "Persistence",
            "Defense Evasion", "Exfiltration", "Impact",
        ]
        tactic_findings: dict[str, list] = defaultdict(list)
        for f in self._all_findings:
            tactic = f.get("mitre_atlas_tactic", "Unknown")
            tactic_findings[tactic].append(f)

        present = [t for t in tactic_order if t in tactic_findings]
        tree_lines = [
            "## Attack Tree Visualization\n\n",
            "### MITRE ATLAS Kill Chain Mapping\n\n",
            "```\n",
            "                       ┌─────────────────────────────┐\n",
            "                       │   ATTACK TREE: AI-300 CH11  │\n",
            "                       │  Capstone Red Team Chain    │\n",
            "                       └──────────────┬──────────────┘\n",
            "                                      │\n",
        ]
        for i, tactic in enumerate(present):
            vulns = tactic_findings[tactic]
            crit_count = sum(1 for f in vulns if f.get("severity") == "critical")
            high_count = sum(1 for f in vulns if f.get("severity") == "high")
            indicators = []
            if crit_count > 0:
                indicators.append(f"CRITx{crit_count}")
            if high_count > 0:
                indicators.append(f"HIGHx{high_count}")
            is_last = (i == len(present) - 1)
            branch = "└──" if is_last else "├──"
            connector = "    " if is_last else "│   "
            tree_lines.append(f"                      {connector}│\n")
            tree_lines.append(f"                      {connector}{branch} [{tactic}]\n")
            ind_str = ", ".join(indicators) if indicators else ""
            tree_lines.append(f"                      {connector}    └── {len(vulns)} finding(s) {ind_str}\n")
        tree_lines.append("```\n\n")

        # Read existing content, prepend executive sections
        existing = self._report_path.read_text(encoding="utf-8")
        # Find position after header (after first ---)
        parts = existing.split("---\n", 1)
        if len(parts) == 2:
            header = parts[0] + "---\n\n"
            rest = parts[1]
        else:
            header = ""
            rest = existing

        final_content = (
            header
            + "".join(exec_lines)
            + "".join(coverage_lines)
            + "".join(summary_lines)
            + "".join(tree_lines)
            + rest
        )

        self._report_path.write_text(final_content, encoding="utf-8")
        return self._report_path


__all__ = ["ReportWriter"]
