"""
数据流完整性验证器 — 报告格式化输出

将 DataFlowReport 格式化为可读文本或 JSON。
独立模块便于测试和输出格式扩展。

Academic basis:
    - NIST SP 800-115: Technical Guide to Information Security Testing
"""

from __future__ import annotations

import json
from datetime import datetime

from tools.dataflow.models import DataFlowReport


def format_report(report: DataFlowReport, ascii_only: bool = False) -> str:
    """
    格式化验证报告为可读文本

    Args:
        report: 验证报告
        ascii_only: 是否仅使用 ASCII 字符（兼容 Windows GBK 终端）
    """
    # 符号选择: Unicode emoji 或 ASCII 替代
    if ascii_only:
        S_PASS = "[PASS]"
        S_FAIL = "[FAIL]"
        S_WARN = "[WARN]"
    else:
        S_PASS = "✅"
        S_FAIL = "❌"
        S_WARN = "⚠️"

    lines: list[str] = []

    lines.append("=" * 80)
    lines.append("Recon → ARM → Strike → Assess → Report/Evidence")
    lines.append("=" * 80)
    lines.append(f"验证时间: {report.timestamp}")
    lines.append(f"验证耗时: {report.duration_seconds:.3f}s")
    lines.append(f"规则总数: {report.total_rules}")
    lines.append(f"通过: {report.passed} | 失败: {report.failed} | 警告: {report.warnings}")
    lines.append(f"验证结果: {S_PASS + ' 全部通过' if report.is_valid else S_FAIL + ' 存在失败项'}")
    lines.append("")

    # 按阶段分组展示
    phases_order = ["post_recon", "post_arm", "post_strike", "post_assess", "post_report"]
    phase_labels = {
        "post_recon": "Recon 阶段输出",
        "post_arm": "ARM 阶段输出",
        "post_strike": "Strike 阶段输出",
        "post_assess": "Assess 阶段输出",
        "post_report": "Report/Evidence 阶段输出",
    }

    for phase in phases_order:
        phase_results = [
            r for r in report.results if r.phase_from == phase or r.phase_from == phase.replace("post_", "")
        ]
        if not phase_results:
            continue

        lines.append("-" * 80)
        lines.append(phase_labels.get(phase, phase))
        lines.append("-" * 80)

        for r in phase_results:
            if r.passed:
                icon = S_PASS
            elif r.severity == "warning":
                icon = S_WARN
            else:
                icon = S_FAIL
            lines.append(f"  {icon} [{r.rule_id}] {r.rule_name}")
            lines.append(f"      {r.message}")

        lines.append("")

    # 快照摘要
    lines.append("-" * 80)
    lines.append("数据快照摘要")
    lines.append("-" * 80)
    for snap in report.snapshots:
        ts = datetime.fromtimestamp(snap.timestamp).strftime("%H:%M:%S") if snap.timestamp > 0 else "N/A"
        lines.append(f"\n  [{snap.phase}] @ {ts}")
        key_metrics = {
            "seeds_count": "种子数",
            "techniques_count": "技术数",
            "converter_map_total_converters": "转换器总数",
            "attack_results_total": "攻击结果总数",
            "overall_asr": "总体 ASR",
            "dual_judge_total_scored": "评判总数",
            "service_profile_size": "服务画像项数",
            "evidence_total_attacks": "证据总数",
        }
        for key, label in key_metrics.items():
            if key in snap.fields:
                val = snap.fields[key]
                lines.append(f"      {label}: {val}")

    lines.append("")
    lines.append("=" * 80)
    if report.is_valid:
        lines.append("结论: 全链路数据流完整性验证通过 [PASS]")
    else:
        lines.append("结论: 发现数据传递断点 [FAIL]")
    lines.append("=" * 80)

    return "\n".join(lines)


def report_to_json(report: DataFlowReport) -> str:
    """将报告序列化为 JSON 字符串"""
    return json.dumps(
        {
            "timestamp": report.timestamp,
            "total_rules": report.total_rules,
            "passed": report.passed,
            "failed": report.failed,
            "warnings": report.warnings,
            "is_valid": report.is_valid,
            "results": [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "passed": r.passed,
                    "phase_from": r.phase_from,
                    "phase_to": r.phase_to,
                    "message": r.message,
                    "severity": r.severity,
                }
                for r in report.results
            ],
        },
        indent=2,
        ensure_ascii=False,
    )
