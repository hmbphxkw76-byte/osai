"""场景报告器模块 — 生成OSCP标准红队评估报告。

基于PyRIT scenarios设计，适配AI-300考试需求：
  - OSCP风格报告格式
  - 执行摘要（定量Dashboard、ASR分布、风险等级）
  - 攻击策略效果矩阵
  - 漏洞详情与攻击证据
  - AI专项严重度评估（Autonomy/Blast Radius/Recoverability）
  - 攻击链叙事
  - 根因分析（Root Cause Analysis）
  - 修复方案（按OWASP分类）

Library-First: 配置即攻击，考试期间仅需修改YAML载荷文件
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .schema import (
    AttackPhaseType,
    AttackStrategy,
    AttackTargetType,
    GrayscaleLevel,
    PhaseResult,
    ScenarioResult,
    Severity,
    StrategyResult,
    VulnerabilityFinding,
)

OWASP_LLM_TOP_10 = {
    "LLM01": ("LLM01 Prompt Injection", "提示注入 — 最普遍、最具影响的攻击"),
    "LLM02": ("LLM02 Sensitive Information Disclosure", "敏感信息泄露 — 通过LLM输出暴露隐私数据"),
    "LLM03": ("LLM03 Supply Chain Vulnerabilities", "供应链漏洞 — 第三方模型/数据/插件风险"),
    "LLM04": ("LLM04 Data and Model Poisoning", "数据与模型投毒 — 训练/微调数据被篡改"),
    "LLM05": ("LLM05 Insecure Output Handling", "输出处理不当 — LLM输出未经验证导致下游漏洞"),
    "LLM06": ("LLM06 Excessive Agency", "过度代理 — LLM拥有过多自主权限执行敏感操作"),
    "LLM07": ("LLM07 System Prompt Leakage", "系统提示词泄露 — 敏感系统指令被提取"),
    "LLM08": ("LLM08 Vector and Embedding Weaknesses", "向量与嵌入弱点 — RAG/向量数据库攻击面"),
    "LLM09": ("LLM09 Misinformation", "错误信息 — LLM生成看似可信的错误内容"),
    "LLM10": ("LLM10 Unbounded Consumption", "无限制消费 — 资源无限消耗导致拒绝服务"),
}

MITRE_ATLAS_TACTICS = {
    "Reconnaissance": ("Reconnaissance", "侦察 — 收集目标AI系统信息"),
    "Resource Development": ("Resource Development", "资源开发 — 准备攻击基础设施"),
    "Initial Access": ("Initial Access", "初始访问 — 获取AI系统入口"),
    "ML Attack Staging": ("ML Attack Staging", "ML攻击准备 — 准备模型/数据攻击"),
    "Execution": ("Execution", "执行 — 运行恶意代码或载荷"),
    "Persistence": ("Persistence", "持久化 — 维持对AI系统的访问"),
    "Defense Evasion": ("Defense Evasion", "防御规避 — 绕过AI安全检测"),
    "Exfiltration": ("Exfiltration", "数据窃取 — 提取模型/训练数据"),
    "Impact": ("Impact", "影响 — 破坏AI系统完整性/可用性"),
}


class ScenarioReporter:
    """场景报告器 — 生成OSCP标准红队评估报告。

    使用方式：
        reporter = ScenarioReporter(result)
        reporter.generate()  # 生成报告文件
        print(reporter.to_text())  # 获取文本报告
    """

    def __init__(self, result: ScenarioResult):
        self.result = result
        self._severity_counts = self._count_severities()
        self._strategy_effectiveness = self._calculate_strategy_effectiveness()
        self._grayscale_distribution = self._calculate_grayscale_distribution()

    def _count_severities(self) -> dict[str, int]:
        """统计各严重等级数量。"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.result.findings:
            counts[finding.severity.value] += 1
        return counts

    def _calculate_strategy_effectiveness(self) -> dict[str, dict]:
        """计算各策略的效果。"""
        effectiveness = {}
        for phase in self.result.phases:
            for result in phase.results:
                strategy = result.strategy.value
                if strategy not in effectiveness:
                    effectiveness[strategy] = {"attempts": 0, "successes": 0, "avg_score": 0.0}
                effectiveness[strategy]["attempts"] += 1
                if result.success:
                    effectiveness[strategy]["successes"] += 1
                effectiveness[strategy]["avg_score"] += result.score

        for strategy in effectiveness:
            attempts = effectiveness[strategy]["attempts"]
            if attempts > 0:
                effectiveness[strategy]["avg_score"] = round(
                    effectiveness[strategy]["avg_score"] / attempts, 3
                )
                effectiveness[strategy]["success_rate"] = round(
                    effectiveness[strategy]["successes"] / attempts * 100, 2
                )
            else:
                effectiveness[strategy]["success_rate"] = 0.0

        return effectiveness

    def _calculate_grayscale_distribution(self) -> dict[str, int]:
        """计算灰度等级分布。"""
        distribution = {level.value: 0 for level in GrayscaleLevel}
        for phase in self.result.phases:
            for result in phase.results:
                distribution[result.grayscale_level.value] += 1
        return distribution

    def generate(self, output_dir: str = "reports") -> Path:
        """生成完整报告文件。

        Args:
            output_dir: 输出目录

        Returns:
            报告文件路径
        """
        report_content = self._build_full_report()
        report_path = self._write_report(report_content, output_dir)
        return report_path

    def _build_full_report(self) -> str:
        """构建完整报告内容。"""
        sections = [
            self._build_header(),
            self._build_executive_summary(),
            self._build_risk_dashboard(),
            self._build_attack_tree(),
            self._build_strategy_matrix(),
            self._build_grayscale_distribution(),
            self._build_findings_summary(),
            self._build_findings_details(),
            self._build_root_cause_analysis(),
            self._build_recommendations(),
            self._build_appendix(),
        ]
        return "\n\n".join(sections)

    def _build_header(self) -> str:
        """构建报告头部。"""
        lines = [
            "# RED TEAM ASSESSMENT REPORT",
            "",
            "**Assessment ID**: " + self.result.run_id,
            "**Target**: " + self.result.target_url,
            "**Target Type**: " + self.result.target_type.value.capitalize(),
            "**Scenario**: " + self.result.scenario_name,
            "**Date**: " + time.strftime("%Y-%m-%d"),
            "**Methodology**: OffSec AI-300 Advanced AI Red Teaming",
            "",
            "---",
        ]
        return "\n".join(lines)

    def _build_executive_summary(self) -> str:
        """构建执行摘要。"""
        total_findings = len(self.result.findings)
        critical = self._severity_counts["critical"]
        high = self._severity_counts["high"]
        medium = self._severity_counts["medium"]
        low = self._severity_counts["low"]

        lines = [
            "## Executive Summary",
            "",
            f"### Assessment Overview",
            "",
            f"- **Total Findings**: {total_findings}",
            f"- **Critical**: {critical}",
            f"- **High**: {high}",
            f"- **Medium**: {medium}",
            f"- **Low**: {low}",
            f"- **Success Rate**: {self.result.success_rate}%",
            f"- **Total Attempts**: {self.result.total_attempts}",
            f"- **Duration**: {self.result.elapsed_seconds:.1f} seconds",
            "",
            f"### Attack Objectives",
            "",
        ]
        for idx, objective in enumerate(self.result.objectives, 1):
            lines.append(f"{idx}. {objective}")

        return "\n".join(lines)

    def _build_risk_dashboard(self) -> str:
        """构建风险仪表盘。"""
        total = self.result.total_attempts
        passed = self.result.total_attempts - self.result.success_count
        failed = self.result.success_count

        pass_rate = (passed / total * 100) if total > 0 else 0
        fail_rate = (failed / total * 100) if total > 0 else 0

        bar_length = 40
        defend_bar = "█" * int(pass_rate / 100 * bar_length)
        vuln_bar = "█" * int(fail_rate / 100 * bar_length)

        lines = [
            "## Risk Dashboard",
            "",
            "```",
            "╔══════════════════════════════════════════════════════════════════╗",
            "║  RED TEAM ASSESSMENT — RISK DASHBOARD                         ║",
            "╠══════════════════════════════════════════════════════════════════╣",
            f"║  Total tests       {total:>5}   │  Passed (safe)   {passed:>4}   │  {pass_rate:.1f}%        ║",
            f"║  Failed (vuln)     {failed:>3}   │  Critical risk   {self._severity_counts['critical']:>3}   │  High risk  ║",
            "╚══════════════════════════════════════════════════════════════════╝",
            "",
            f"  DEFENDED  {defend_bar}{'░'*(bar_length-len(defend_bar))}  {pass_rate:.1f}%",
            f"  VULNERABLE {vuln_bar}{'░'*(bar_length-len(vuln_bar))}  {fail_rate:.1f}%",
            "```",
            "",
            "### Severity Distribution",
            "",
            f"| Severity | Count | Percentage |",
            f"|----------|-------|------------|",
            f"| Critical | {self._severity_counts['critical']} | {self._calculate_percentage('critical')}% |",
            f"| High | {self._severity_counts['high']} | {self._calculate_percentage('high')}% |",
            f"| Medium | {self._severity_counts['medium']} | {self._calculate_percentage('medium')}% |",
            f"| Low | {self._severity_counts['low']} | {self._calculate_percentage('low')}% |",
        ]

        return "\n".join(lines)

    def _calculate_percentage(self, severity: str) -> float:
        """计算严重等级百分比。"""
        total = len(self.result.findings)
        if total == 0:
            return 0.0
        return round(self._severity_counts[severity] / total * 100, 1)

    def _build_attack_tree(self) -> str:
        """构建攻击树可视化。

        基于 MITRE ATLAS 战术链构建多层攻击树。
        """
        findings = self.result.findings
        if not findings:
            return "## Attack Tree Visualization\n\nNo attack paths to visualize."

        # 按 ATLAS 战术分组
        tactics_map: dict[str, list] = {}
        for f in findings:
            tactic = getattr(f, 'mitre_atlas', 'Unknown')
            tactics_map.setdefault(tactic, []).append(f)

        # 确定攻击树层级
        tactic_order = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "ML Attack Staging", "Execution", "Persistence",
            "Defense Evasion", "Exfiltration", "Impact",
        ]
        present_tactics = [t for t in tactic_order if t in tactics_map]

        lines = [
            "## Attack Tree Visualization",
            "",
            "### MITRE ATLAS Kill Chain Mapping",
            "",
            "```",
            "                         ┌─────────────────────────────┐",
            "                         │   ATTACK TREE: AI-300 CH11  │",
            "                         │  Capstone Red Team Chain    │",
            "                         └──────────────┬──────────────┘",
            "                                        │",
        ]

        for i, tactic in enumerate(present_tactics):
            vuln_count = len(tactics_map[tactic])
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in tactics_map[tactic]:
                sev = getattr(f, 'severity', None)
                sev_val = sev.value if hasattr(sev, 'value') else str(sev)
                sev_counts[sev_val] = sev_counts.get(sev_val, 0) + 1

            indicators = []
            if sev_counts["critical"] > 0:
                indicators.append(f"⛔x{sev_counts['critical']}")
            if sev_counts["high"] > 0:
                indicators.append(f"⚠️x{sev_counts['high']}")

            is_last = (i == len(present_tactics) - 1)
            branch = "└──" if is_last else "├──"
            connector = "    " if is_last else "│   "

            lines.append(f"                        {connector}│")
            lines.append(f"                        {connector}{branch} [{tactic}]")
            lines.append(f"                        {connector}    └── {vuln_count} finding(s) {', '.join(indicators) if indicators else ''}")

        # 阶段详情
        lines.append("```")
        lines.append("")
        lines.append("### Attack Path Details")
        lines.append("")

        for tactic in present_tactics:
            vulns = tactics_map[tactic]
            lines.append(f"**Phase: [{tactic}]** ({len(vulns)} findings)")
            for v in vulns:
                sev = getattr(v, 'severity', None)
                sev_str = sev.value.upper() if hasattr(sev, 'value') else str(sev).upper()
                title = getattr(v, 'title', 'Unknown')
                owasp = getattr(v, 'owasp_llm', '')
                lines.append(f"  - {sev_str} | {title} ({owasp})")
            lines.append("")

        return "\n".join(lines)

    def _build_strategy_matrix(self) -> str:
        """构建策略效果矩阵。"""
        lines = [
            "## Attack Strategy Effectiveness",
            "",
            "### Strategy Performance Matrix",
            "",
            f"| Strategy | Attempts | Successes | Success Rate | Avg Score |",
            f"|----------|----------|-----------|--------------|-----------|",
        ]

        for strategy, stats in sorted(
            self._strategy_effectiveness.items(),
            key=lambda x: x[1]["success_rate"],
            reverse=True,
        ):
            lines.append(
                f"| {strategy} | {stats['attempts']} | {stats['successes']} | "
                f"{stats['success_rate']}% | {stats['avg_score']} |"
            )

        lines.append("")
        lines.append("### Key Findings")
        lines.append("")

        top_strategy = max(
            self._strategy_effectiveness.items(),
            key=lambda x: x[1]["success_rate"],
            default=None,
        )
        if top_strategy:
            lines.append(
                f"- **Most Effective Strategy**: {top_strategy[0]} "
                f"(Success Rate: {top_strategy[1]['success_rate']}%)"
            )

        bottom_strategy = min(
            self._strategy_effectiveness.items(),
            key=lambda x: x[1]["success_rate"],
            default=None,
        )
        if bottom_strategy:
            lines.append(
                f"- **Least Effective Strategy**: {bottom_strategy[0]} "
                f"(Success Rate: {bottom_strategy[1]['success_rate']}%)"
            )

        return "\n".join(lines)

    def _build_grayscale_distribution(self) -> str:
        """构建灰度评分分布。"""
        total = sum(self._grayscale_distribution.values()) or 1

        lines = [
            "## Grayscale Score Distribution",
            "",
            "### Attack Outcome Distribution",
            "",
            f"| Outcome | Count | Percentage |",
            f"|---------|-------|------------|",
        ]

        grayscale_labels = {
            "full_success": "Full Success",
            "success_disclaimer": "Success with Disclaimer",
            "ambiguous": "Ambiguous",
            "refusal_leak": "Refusal with Leak",
            "full_refusal": "Full Refusal",
        }

        for level, count in self._grayscale_distribution.items():
            percentage = round(count / total * 100, 1)
            lines.append(f"| {grayscale_labels[level]} | {count} | {percentage}% |")

        return "\n".join(lines)

    def _build_findings_summary(self) -> str:
        """构建漏洞摘要。"""
        lines = [
            "## Findings Summary",
            "",
            f"| # | Finding | OWASP LLM | Severity | Attack Vector |",
            f"|---|---------|-----------|----------|---------------|",
        ]

        for idx, finding in enumerate(
            sorted(
                self.result.findings,
                key=lambda x: ("critical", "high", "medium", "low", "info").index(x.severity.value),
            ),
            1,
        ):
            sev_icon = self._get_severity_icon(finding.severity)
            owasp_text = OWASP_LLM_TOP_10.get(finding.owasp_llm, ("", ""))[0]
            lines.append(
                f"| {idx} | {sev_icon} {finding.title[:40]} | {owasp_text[:20]} | "
                f"{finding.severity.value.upper()} | {finding.attack_vector[:30]} |"
            )

        return "\n".join(lines)

    def _get_severity_icon(self, severity: Severity) -> str:
        """获取严重等级图标。"""
        icons = {
            Severity.CRITICAL: "⛔",
            Severity.HIGH: "⚠️",
            Severity.MEDIUM: "⚡",
            Severity.LOW: "ℹ️",
            Severity.INFO: "🔍",
        }
        return icons.get(severity, "")

    def _build_findings_details(self) -> str:
        """构建漏洞详情。"""
        lines = ["## Findings Details", ""]

        for idx, finding in enumerate(
            sorted(
                self.result.findings,
                key=lambda x: ("critical", "high", "medium", "low", "info").index(x.severity.value),
            ),
            1,
        ):
            sev_icon = self._get_severity_icon(finding.severity)
            owasp_text = OWASP_LLM_TOP_10.get(finding.owasp_llm, ("", ""))[0]
            mitre_text = MITRE_ATLAS_TACTICS.get(finding.mitre_atlas, ("", ""))[0]

            lines.append(f"### {sev_icon} Finding #{idx}: {finding.title}")
            lines.append("")
            lines.append("| Attribute | Value |")
            lines.append("|-----------|-------|")
            lines.append(f"| Severity | **{finding.severity.value.upper()}** |")
            lines.append(f"| OWASP LLM | {owasp_text} |")
            lines.append(f"| MITRE ATLAS | {mitre_text} |")
            lines.append(f"| Attack Vector | {finding.attack_vector} |")

            # CVSS 3.1 评分（如果有）
            if hasattr(finding, 'cvss_score') and finding.cvss_score > 0:
                lines.append(f"| CVSS 3.1 | **{finding.cvss_score}** ({finding.cvss_severity if hasattr(finding, 'cvss_severity') else 'N/A'}) |")
                if hasattr(finding, 'cvss_vector') and finding.cvss_vector:
                    lines.append(f"| CVSS Vector | `{finding.cvss_vector}` |")

            lines.append(f"| Discovered At | {finding.discovered_at} |")
            lines.append("")

            if finding.description:
                lines.append(f"**Description**: {finding.description}")
                lines.append("")

            if finding.payload:
                lines.append("**Exploit Payload**:")
                lines.append("```")
                lines.append(finding.payload)
                lines.append("```")
                lines.append("")

            if finding.evidence:
                lines.append("**Evidence**:")
                lines.append("```")
                lines.append(finding.evidence)
                lines.append("```")
                lines.append("")

            if finding.recommendation:
                lines.append(f"**Recommendation**: {finding.recommendation}")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _build_root_cause_analysis(self) -> str:
        """构建根因分析。"""
        vulnerabilities = self.result.findings
        if not vulnerabilities:
            return "## Root Cause Analysis\n\nNo vulnerabilities found during assessment."

        strategy_counts = {}
        for v in vulnerabilities:
            for phase in self.result.phases:
                for r in phase.results:
                    if r.success:
                        strategy = r.strategy.value
                        strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

        top_strategy = max(strategy_counts.items(), key=lambda x: x[1], default=None)

        lines = [
            "## Root Cause Analysis",
            "",
            "### Attack Surface Analysis",
            "",
            f"- **Target Type**: {self.result.target_type.value.capitalize()}",
            f"- **Primary Attack Vectors**: {', '.join(strategy_counts.keys()) if strategy_counts else 'None'}",
            "",
        ]

        if top_strategy:
            lines.append(
                f"### Most Exploited Vector",
            )
            lines.append(
                f"",
            )
            lines.append(
                f"The most successful attack strategy was **{top_strategy[0]}** "
                f"with {top_strategy[1]} successful exploitation(s). "
                f"This indicates a significant vulnerability in the target's "
                f"defense against this type of attack."
            )
            lines.append("")

        lines.append("### Common Weakness Patterns")
        lines.append("")

        if self._severity_counts["critical"] > 0:
            lines.append(
                "- **Critical Issues**: Prompt injection and system prompt extraction "
                "are the most critical vulnerabilities, indicating weak input validation "
                "and insufficient prompt protection."
            )

        if self._severity_counts["high"] > 0:
            lines.append(
                "- **High Issues**: Tool hijacking and goal hijacking attacks "
                "indicate insufficient access controls and intent verification."
            )

        if self._severity_counts["medium"] > 0:
            lines.append(
                "- **Medium Issues**: Memory poisoning and RAG poisoning attacks "
                "indicate weak data integrity controls."
            )

        return "\n".join(lines)

    def _build_recommendations(self) -> str:
        """构建修复建议。"""
        lines = [
            "## Recommendations",
            "",
            "### Immediate Actions",
            "",
        ]

        if self._severity_counts["critical"] > 0 or self._severity_counts["high"] > 0:
            lines.append("1. **Implement Input Validation**")
            lines.append("   - Sanitize all user inputs before processing")
            lines.append("   - Implement context-aware filtering")
            lines.append("")

            lines.append("2. **Strengthen Prompt Protection**")
            lines.append("   - Implement system prompt hardening")
            lines.append("   - Use prompt obfuscation techniques")
            lines.append("")

            lines.append("3. **Enhance Output Filtering**")
            lines.append("   - Detect and block sensitive information leakage")
            lines.append("   - Implement content classification")
            lines.append("")

        lines.append("### Long-term Improvements")
        lines.append("")

        lines.append("1. **Multi-layer Defense Strategy**")
        lines.append("   - Combine rule-based filtering with ML-based detection")
        lines.append("   - Implement anomaly detection for unusual patterns")
        lines.append("")

        lines.append("2. **Access Control Implementation**")
        lines.append("   - Implement least-privilege principle for tool access")
        lines.append("   - Add authentication and authorization checks")
        lines.append("")

        lines.append("3. **Regular Security Assessments**")
        lines.append("   - Conduct periodic red team exercises")
        lines.append("   - Update defense mechanisms based on new threats")
        lines.append("")

        lines.append("### OWASP LLM Top 10 Coverage")
        lines.append("")

        for code, (name, desc) in OWASP_LLM_TOP_10.items():
            covered = any(f.owasp_llm == code for f in self.result.findings)
            status = "✅ Covered" if covered else "❌ Not Tested"
            lines.append(f"- {name}: {status}")

        return "\n".join(lines)

    def _build_appendix(self) -> str:
        """构建附录。"""
        lines = [
            "## Appendix",
            "",
            "### Attack Phases Executed",
            "",
        ]

        for phase in self.result.phases:
            lines.append(f"- **{phase.phase_name}**: {phase.phase_type.value}")
            lines.append(f"  - Strategies: {', '.join(phase.strategies)}")
            lines.append(f"  - Attempts: {phase.total_attempts}, Successes: {phase.success_count}")
            lines.append(f"  - Success Rate: {phase.success_rate}%")
            lines.append("")

        lines.append("### References")
        lines.append("")
        lines.append("- OffSec AI-300: Advanced AI Red Teaming")
        lines.append("- OWASP LLM Top 10")
        lines.append("- MITRE ATLAS Framework")
        lines.append("- PyRIT Framework")

        return "\n".join(lines)

    def _write_report(self, content: str, output_dir: str) -> Path:
        """写入报告文件。"""
        output_path = Path(output_dir) / self.result.run_id / "Scenario_Report.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def to_text(self) -> str:
        """获取文本格式报告。"""
        return self._build_full_report()

    def to_dict(self) -> dict[str, Any]:
        """获取字典格式报告。"""
        return {
            "summary": {
                "run_id": self.result.run_id,
                "target": self.result.target_url,
                "target_type": self.result.target_type.value,
                "scenario": self.result.scenario_name,
                "total_findings": len(self.result.findings),
                "severity_counts": self._severity_counts,
                "success_rate": self.result.success_rate,
                "duration": self.result.elapsed_seconds,
            },
            "strategy_effectiveness": self._strategy_effectiveness,
            "grayscale_distribution": self._grayscale_distribution,
            "findings": [f.model_dump() for f in self.result.findings],
        }


__all__ = [
    "ScenarioReporter",
]