"""多运行结果对比分析器 — 横向对比不同策略/Converter 的 ASR 效果。

对比维度:
    1. 按技术 ASR: prompt_sending / crescendo / tap / pair
    2. 按 OWASP 类别: LLM01-10 / ASI01-10 覆盖率和 ASR
    3. 按 Converter 链: encoding vs persuasion vs variation
    4. 按种子: Top-10 高成功率 + Bottom-5 低成功率
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class RunSummary:
    """单次运行的摘要信息."""

    run_dir: str
    strategy: str
    timestamp: str
    target: str
    overall_asr: float
    total_attacks: int
    successful_attacks: int
    failed_attacks: int
    technique_asr: dict[str, float] = field(default_factory=dict)
    owasp_coverage: dict[str, int] = field(default_factory=dict)
    owasp_asr: dict[str, float] = field(default_factory=dict)
    converter_paths: list[str] = field(default_factory=list)


def load_run_summary(run_dir: Path) -> RunSummary | None:
    """从运行目录加载摘要信息.

    Args:
        run_dir: 运行输出目录.

    Returns:
        RunSummary 实例, 失败返回 None.
    """
    evidence_path = run_dir / "evidence" / "evidence.json"
    if not evidence_path.exists():
        logger.warning("No evidence.json in %s", run_dir)
        return None

    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load evidence from %s: %s", run_dir, e)
        return None

    # 从目录名提取策略名
    dir_name = run_dir.name
    strategy = "unknown"
    if "quick_scan" in dir_name:
        strategy = "quick_scan"
    elif "stealth_bypass" in dir_name:
        strategy = "stealth_bypass"
    elif "persuasion_heavy" in dir_name:
        strategy = "persuasion_heavy"
    elif "full_offensive" in dir_name:
        strategy = "full_offensive"
    elif "full_coverage" in dir_name:
        strategy = "full_coverage"
    elif "multi_turn_deep" in dir_name:
        strategy = "multi_turn_deep"
    elif "targeted_full" in dir_name:
        strategy = "targeted_full"
    elif "comprehensive" in dir_name:
        strategy = "comprehensive"
    elif "web_vuln" in dir_name:
        strategy = "web_vuln"

    # 提取技术分布 (保留用于未来分析)
    _technique_dist = data.get("technique_distribution", {})

    # 提取 OWASP 覆盖
    owasp_coverage: dict[str, int] = {}
    owasp_asr: dict[str, float] = {}

    for owasp_id, stats in data.get("owasp_web_compliance", {}).items():
        tested = stats.get("tested", 0)
        if tested > 0:
            owasp_coverage[owasp_id] = tested
            owasp_asr[owasp_id] = stats.get("asr", 0.0)

    for owasp_id, stats in data.get("owasp_llm_compliance", {}).items():
        tested = stats.get("tested", 0)
        if tested > 0:
            owasp_coverage[owasp_id] = tested
            owasp_asr[owasp_id] = stats.get("asr", 0.0)

    for owasp_id, stats in data.get("owasp_asi_compliance", {}).items():
        tested = stats.get("tested", 0)
        if tested > 0:
            owasp_coverage[owasp_id] = tested
            owasp_asr[owasp_id] = stats.get("asr", 0.0)

    # 提取 converter 路径
    converter_paths: list[str] = []
    for ev in data.get("evidence", []):
        chain = ev.get("converter_chain", "")
        if chain and chain not in converter_paths:
            converter_paths.append(chain)

    return RunSummary(
        run_dir=str(run_dir),
        strategy=strategy,
        timestamp=data.get("timestamp", ""),
        target=data.get("target_model", ""),
        overall_asr=data.get("overall_asr", 0.0),
        total_attacks=data.get("total_attacks", 0),
        successful_attacks=data.get("successful_attacks", 0),
        failed_attacks=data.get("failed_attacks", 0),
        technique_asr={},
        owasp_coverage=owasp_coverage,
        owasp_asr=owasp_asr,
        converter_paths=converter_paths,
    )


def compare_runs(run_dirs: list[Path], output_dir: Path) -> Path:
    """对比多个运行结果, 生成对比报告.

    Args:
        run_dirs: 运行目录列表.
        output_dir: 输出目录.

    Returns:
        对比报告文件路径.
    """
    summaries: list[RunSummary] = []
    for run_dir in run_dirs:
        summary = load_run_summary(run_dir)
        if summary:
            summaries.append(summary)

    if not summaries:
        logger.warning("No valid runs to compare")
        return output_dir / "comparison.md"

    # 生成 Markdown 对比报告
    md = _generate_comparison_md(summaries)
    md_path = output_dir / "strategy_comparison.md"
    md_path.write_text(md, encoding="utf-8")
    logger.info("Comparison report saved to %s", md_path)

    # 生成 HTML 对比报告
    html = _generate_comparison_html(summaries)
    html_path = output_dir / "strategy_comparison.html"
    html_path.write_text(html, encoding="utf-8")
    logger.info("Comparison HTML saved to %s", html_path)

    return md_path


def _generate_comparison_md(summaries: list[RunSummary]) -> str:
    """生成 Markdown 对比报告."""
    lines: list[str] = []
    lines.append("# Strategy Comparison Report")
    lines.append("")
    lines.append(f"**Generated**: {datetime.now().isoformat()}")
    lines.append(f"**Runs Compared**: {len(summaries)}")
    lines.append("")

    # 总览对比表
    lines.append("## Overall Comparison")
    lines.append("")
    lines.append("| Strategy | Target | Total | Success | Failed | Overall ASR |")
    lines.append("|----------|--------|-------|---------|--------|-------------|")
    for s in summaries:
        lines.append(
            f"| {s.strategy} | `{s.target}` | {s.total_attacks} | "
            f"{s.successful_attacks} | {s.failed_attacks} | {s.overall_asr}% |"
        )
    lines.append("")

    # OWASP 覆盖对比
    lines.append("## OWASP Coverage Comparison")
    lines.append("")
    all_owasp_ids = sorted(
        set().union(*(s.owasp_coverage.keys() for s in summaries))
    )
    if all_owasp_ids:
        header = "| OWASP ID | " + " | ".join(s.strategy for s in summaries) + " |"
        separator = "|----------|" + "|".join(["------"] * len(summaries)) + "|"
        lines.append(header)
        lines.append(separator)
        for owasp_id in all_owasp_ids:
            row = f"| {owasp_id} | "
            row += " | ".join(
                f"{s.owasp_asr.get(owasp_id, 0):.1f}%" for s in summaries
            )
            row += " |"
            lines.append(row)
        lines.append("")

    # 最佳策略推荐
    best = max(summaries, key=lambda s: s.overall_asr)
    lines.append("## Best Strategy")
    lines.append("")
    lines.append(
        f"**{best.strategy}** achieved the highest ASR of {best.overall_asr}% "
        f"with {best.successful_attacks}/{best.total_attacks} successful attacks."
    )
    lines.append("")

    # Converter 路径对比
    lines.append("## Converter Paths Used")
    lines.append("")
    for s in summaries:
        lines.append(f"### {s.strategy}")
        if s.converter_paths:
            for path in s.converter_paths:
                lines.append(f"- `{path}`")
        else:
            lines.append("- (no converters, raw baseline)")
        lines.append("")

    return "\n".join(lines)


def _generate_comparison_html(summaries: list[RunSummary]) -> str:
    """生成 HTML 对比报告."""
    rows = ""
    for s in summaries:
        asr_color = "#ff0000" if s.overall_asr > 50 else "#ff4444" if s.overall_asr > 25 else "#ffaa00" if s.overall_asr > 0 else "#00aa00"
        rows += f"""
<tr>
<td>{s.strategy}</td>
<td><code>{s.target}</code></td>
<td>{s.total_attacks}</td>
<td>{s.successful_attacks}</td>
<td>{s.failed_attacks}</td>
<td style="color: {asr_color}; font-weight: bold;">{s.overall_asr}%</td>
</tr>"""

    best = max(summaries, key=lambda s: s.overall_asr)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Strategy Comparison Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
h2 {{ color: #e94560; background: #16213e; padding: 8px 12px; border-radius: 4px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #333; padding: 8px 12px; text-align: left; }}
th {{ background: #16213e; color: #e94560; }}
tr:nth-child(even) {{ background: #16213e; }}
</style>
</head>
<body>
<h1>Strategy Comparison Report</h1>
<p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
<p><strong>Runs Compared:</strong> {len(summaries)}</p>

<h2>Overall Comparison</h2>
<table>
<tr><th>Strategy</th><th>Target</th><th>Total</th><th>Success</th><th>Failed</th><th>Overall ASR</th></tr>
{rows}
</table>

<h2>Best Strategy</h2>
<p><strong>{best.strategy}</strong> achieved the highest ASR of {best.overall_asr}%</p>
</body>
</html>"""
