"""终端输出格式化工具（OffSec 风格）。

提供红队评估所需的 ASCII 可视化组件：
  - 风险仪表盘（总体统计）
  - OWASP 覆盖率进度条
  - 攻击目标列表展示
  - 阶段进度展示

对齐 AI-300 课程和 OWASP ASI Top 10 报告规范。
"""
from __future__ import annotations

from typing import Any, Dict, List


def print_section_header(title: str, subtitle: str = "") -> None:
    """打印带边框的阶段标题。"""
    print(f"\n{'═'*66}")
    print(f"║ {title:62} ║")
    if subtitle:
        print(f"║ {subtitle:62} ║")
    print(f"{'═'*66}")


def print_target_list(targets: List[Dict[str, Any]], phase_name: str) -> None:
    """打印攻击目标列表（OffSec 风格）。

    Args:
        targets: 目标列表，每个元素包含 url, protocol, models, auth_required 等字段
        phase_name: 当前阶段名称
    """
    print(f"\n[Target List] {phase_name}")
    print("-" * 66)
    
    for idx, target in enumerate(targets, 1):
        protocol = target.get("protocol", "").upper()
        url = target.get("url", "")
        models = target.get("models", [])
        auth = "🔒" if target.get("auth_required") else "🔓"
        
        model_str = ", ".join(models[:3]) if models else "Unknown"
        print(f"  [{idx}] {auth} [{protocol}] {url}")
        print(f"        Models: {model_str}")
    
    print(f"  Total targets: {len(targets)}")


def print_risk_dashboard(
    total_tests: int,
    passed: int,
    failed: int,
    critical: int = 0,
    high: int = 0,
) -> None:
    """打印总体风险仪表盘（参照 scan-results.md 图1）。

    Args:
        total_tests: 总测试数
        passed: 通过数（防御成功）
        failed: 失败数（存在漏洞）
        critical: 严重级别数量
        high: 高危级别数量
    """
    pass_rate = (passed / total_tests * 100) if total_tests > 0 else 0
    fail_rate = (failed / total_tests * 100) if total_tests > 0 else 0
    
    print("\n" + "╔" + "═"*70 + "╗")
    print("║  RED TEAM ASSESSMENT — RISK DASHBOARD                      ║")
    print("╠" + "═"*70 + "╣")
    
    pass_str = f"{passed} ({pass_rate:.1f}%)".ljust(20)
    fail_str = f"{failed} ({fail_rate:.1f}%)".ljust(20)
    crit_str = f"{critical} Critical".ljust(20)
    
    print(f"║  Total tests: {total_tests:>5}   │  Passed (safe): {pass_str}│  {crit_str}║")
    print(f"║  Failed (vuln): {failed:>3}   │  High risk: {high:>3}                    ║")
    print("╚" + "═"*70 + "╝")
    
    bar_length = 50
    defend_bar = "█" * int(pass_rate / 100 * bar_length)
    vuln_bar = "█" * int(fail_rate / 100 * bar_length)
    
    print(f"\n  DEFENDED  {defend_bar}{'░'*(bar_length-len(defend_bar))}  {pass_rate:.1f}%")
    print(f"  VULNERABLE {vuln_bar}{'░'*(bar_length-len(vuln_bar))}  {fail_rate:.1f}%")


def print_owasp_coverage(coverage: Dict[str, Any]) -> None:
    """打印 OWASP Agentic Top 10 覆盖率（参照 scan-results.md 图2）。

    Args:
        coverage: 字典，键为 OWASP 类别名称，值包含 status 和 score
    """
    print("\n" + "═"*70)
    print("OWASP Agentic Top 10 Coverage")
    print("═"*70)
    
    owasp_order = [
        "ASI01 Goal Hijacking",
        "ASI02 Tool Misuse",
        "ASI03 Identity & Auth",
        "ASI04 Supply Chain",
        "ASI05 Output Handling",
        "ASI06 Memory Poisoning",
        "ASI07 Sensitive Information",
        "ASI08 Cascading Failures",
        "ASI09 Human Trust",
        "ASI10 Untraceability",
    ]
    
    bar_length = 40
    for category in owasp_order:
        data = coverage.get(category, {})
        status = data.get("status", "not covered")
        score = data.get("score", 0)
        
        filled = int(score / 10 * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        status_icon = ""
        if status == "tested":
            status_icon = "⚠️"
        elif status == "partial":
            status_icon = "⚠️/✅"
        elif status == "not covered":
            status_icon = ""
        elif "critical" in status.lower():
            status_icon = "⛔"
        elif "high" in status.lower():
            status_icon = "⚠️"
        
        print(f"  {category:30} {bar}  {status} {status_icon}")


def print_finding_summary(findings: List[Dict[str, Any]]) -> None:
    """打印发现摘要表格。

    Args:
        findings: 发现列表
    """
    print("\n" + "═"*90)
    print("FINDINGS SUMMARY")
    print("═"*90)
    print(f"  {'#':<3} {'Finding':<40} {'OWASP':<15} {'Severity':<10} {'Evidence':<20}")
    print("  " + "-"*88)
    
    for idx, finding in enumerate(findings, 1):
        title = finding.get("title", "")[:40]
        owasp = finding.get("owasp_llm", "")[:15]
        severity = finding.get("severity", "info").upper()
        evidence = str(finding.get("evidence", ""))[:20]
        
        severity_color = ""
        if severity == "CRITICAL":
            severity_color = "⛔ "
        elif severity == "HIGH":
            severity_color = "⚠️ "
        elif severity == "MEDIUM":
            severity_color = "⚡ "
        
        print(f"  {idx:<3} {title:<40} {owasp:<15} {severity_color}{severity:<10} {evidence:<20}")


def print_risk_matrix(findings: List[Dict[str, Any]]) -> None:
    """打印风险矩阵（Impact vs Exploitability）。

    Args:
        findings: 发现列表
    """
    print("\n" + "═"*70)
    print("RISK MATRIX (Impact vs Exploitability)")
    print("═"*70)
    
    high_impact_high_exp = []
    high_impact_low_exp = []
    low_impact_high_exp = []
    low_impact_low_exp = []
    
    for f in findings:
        severity = f.get("severity", "info").lower()
        owasp = f.get("owasp_llm", "")
        
        if severity in ("critical", "high"):
            if "injection" in owasp.lower() or "hijack" in owasp.lower():
                high_impact_high_exp.append(f.get("title", ""))
            else:
                high_impact_low_exp.append(f.get("title", ""))
        else:
            if "supply" in owasp.lower() or "chain" in owasp.lower():
                low_impact_high_exp.append(f.get("title", ""))
            else:
                low_impact_low_exp.append(f.get("title", ""))
    
    def print_cell(items: List[str], max_lines: int = 3) -> str:
        return "\n".join(items[:max_lines]) if items else ""
    
    print("         LOW IMPACT ◄─────────────────────────────────► HIGH IMPACT")
    print("              │                                                │")
    print("    HIGH      │  " + print_cell(low_impact_high_exp).replace("\n", "\n              │  "))
    print("  EXPLOIT-    │                                                │")
    print("  ABILITY     │                                                │")
    print("              │                                                │")
    print("    ──────────┼────────────────────────────────────────────────┤")
    print("              │                                                │")
    print("    LOW       │  " + print_cell(low_impact_low_exp).replace("\n", "\n              │  "))
    print("  EXPLOIT-    │                                                │")
    print("  ABILITY     │                                                │")
    print("              │                                                │")
    print("              └────────────────────────────────────────────────┘")
    print("                                    HIGH RISK ZONE →")


def print_phase_progress(current: int, total: int, phase_name: str) -> None:
    """打印阶段进度条。"""
    bar_length = 40
    filled = int(current / total * bar_length) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_length - filled)
    percent = (current / total * 100) if total > 0 else 0
    print(f"\n  [{current}/{total}] {bar} {percent:.1f}%")
    print(f"  Phase: {phase_name}")


def print_result_bar(
    category: str,
    success_count: int,
    total_count: int,
    severity: str = "medium",
) -> None:
    """打印单项结果进度条。"""
    bar_length = 30
    rate = success_count / total_count if total_count > 0 else 0
    filled = int(rate * bar_length)
    
    if severity == "critical":
        icon = "⛔"
        color_start = ""
        color_end = ""
    elif severity == "high":
        icon = "⚠️"
        color_start = ""
        color_end = ""
    elif rate >= 0.8:
        icon = "✅"
        color_start = ""
        color_end = ""
    else:
        icon = "⚠️"
        color_start = ""
        color_end = ""
    
    bar = "█" * filled + "░" * (bar_length - filled)
    print(f"  {category:<25} {bar} {success_count}/{total_count} {icon}")


__all__ = [
    "print_section_header",
    "print_target_list",
    "print_risk_dashboard",
    "print_owasp_coverage",
    "print_finding_summary",
    "print_risk_matrix",
    "print_phase_progress",
    "print_result_bar",
]