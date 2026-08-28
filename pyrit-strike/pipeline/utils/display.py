"""终端输出格式化。"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def print_banner() -> None:
    """打印启动 Banner。"""
    banner = """
╔══════════════════════════════════════════════════════╗
║           PyRIT-Strike v2.0.0                        ║
║     Burp → Attack → Report — One-Click Pipeline      ║
╚══════════════════════════════════════════════════════╝
"""
    print(banner)


def print_phase(phase: str, description: str) -> None:
    """打印当前阶段信息。"""
    print(f"\n{'─' * 60}")
    print(f"  [{phase}] {description}")
    print(f"{'─' * 60}\n")


def print_summary(
    *,
    total_attacks: int,
    successful_attacks: int,
    overall_asr: float,
    report_path: str,
) -> None:
    """打印最终摘要。"""
    print(f"\n{'═' * 60}")
    print("  Assessment Complete")
    print(f"{'═' * 60}")
    print(f"  Total Attacks:     {total_attacks}")
    print(f"  Successful:        {successful_attacks}")
    print(f"  Overall ASR:       {overall_asr}%")
    print(f"  Report:            {report_path}")
    print(f"{'═' * 60}\n")


def format_asr_table(asr_per_technique: dict[str, float]) -> str:
    """格式化 ASR 表格。"""
    lines = ["", "Technique ASR Summary:", ""]
    lines.append(f"{'Technique':<30} {'ASR':>10}")
    lines.append("─" * 42)
    for tech, asr in sorted(asr_per_technique.items(), key=lambda x: -x[1]):
        lines.append(f"{tech:<30} {asr:>9.1f}%")
    lines.append("─" * 42)
    return "\n".join(lines)
