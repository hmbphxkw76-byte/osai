# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""G-09: web_redteam 集成桥接器 — 共享主 pipeline 的 OutputManager 和 EvidenceCollector。

将 web_redteam 的攻击结果桥接到主 pipeline 的证据收集和报告体系:
  1. 将 web_redteam 的 AttackResult 转换为 EvidenceCollector 可处理的格式
  2. 使用主 pipeline 的 OutputManager 生成统一的 HTML/PDF 报告
  3. 将 web_redteam 的 ASR 数据注入主 pipeline 的经验 ASR 持久化

使用方式::

    from pipeline.integrations.web_redteam_bridge import (
        collect_web_redteam_evidence,
        create_shared_output_manager,
    )

    # 在 web_redteam Stage 5 (stage_output) 中:
    output_mgr = create_shared_output_manager(timestamp="20260802_120000")
    evidence = collect_web_redteam_evidence(web_ctx, output_mgr)

学术依据:
  - PyRIT (arXiv:2407.01232): 统一的 Memory 和 Evidence 体系
  - OWASP Top 10 for LLM Applications 2025: Web 注入和 Prompt Injection 统一报告

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pipeline.analysis.evidence_collector import EvidenceCollection, EvidenceCollector
from pipeline.reporting.output_manager import OutputManager

if TYPE_CHECKING:
    from web_redteam.pipeline.context import WebRedteamContext

logger = logging.getLogger(__name__)


# ============================================================
# 共享 OutputManager 创建
# ============================================================


def create_shared_output_manager(
    *,
    timestamp: str | None = None,
    base_dir: str = "outputs",
) -> OutputManager:
    """创建与主 pipeline 共享的 OutputManager。

    G-09: web_redteam 使用与主 pipeline 相同的 OutputManager,
    确保证据、报告、日志写入同一目录结构。

    Args:
        timestamp: 时间戳 (如 "20260802_120000"), None 则自动生成。
        base_dir: 输出根目录。

    Returns:
        OutputManager 实例。
    """
    from datetime import datetime

    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return OutputManager(
        base_dir=base_dir,
        timestamp=timestamp,
    )


# ============================================================
# web_redteam 证据收集
# ============================================================


def collect_web_redteam_evidence(
    web_ctx: "WebRedteamContext",
    output_mgr: OutputManager,
    *,
    model_name: str = "web_target",
    model_tier: str = "unknown",
) -> EvidenceCollection | None:
    """收集 web_redteam 攻击结果并生成证据集合。

    G-09: 将 web_redteam 的 AttackResult 桥接到主 pipeline 的
    EvidenceCollector, 生成统一的 VulnerabilityEvidence。

    Args:
        web_ctx: WebRedteamContext 实例 (需包含 result 字段)。
        output_mgr: 主 pipeline 的 OutputManager 实例。
        model_name: 目标模型/网站名称。
        model_tier: 模型等级 (web 目标通常为 unknown)。

    Returns:
        EvidenceCollection 实例, 或 None (如果无结果)。
    """
    result = getattr(web_ctx, "result", None)
    if result is None:
        logger.info("web_redteam: no result to collect evidence from")
        return None

    # 获取 attack_results (可能是 dict 或 list)
    attack_results = getattr(result, "attack_results", None)
    if not attack_results:
        logger.info("web_redteam: no attack_results in result")
        return None

    # 转换为 EvidenceCollector 可处理的格式
    # web_redteam 的 attack_results 可能是 dict[str, list[AttackResult]]
    if isinstance(attack_results, dict):
        results_dict = attack_results
    else:
        # 如果是 list, 用 "web_attack" 作为 key
        results_dict = {"web_attack": list(attack_results)}

    total = sum(len(v) for v in results_dict.values())
    if total == 0:
        return None

    # 使用主 pipeline 的 EvidenceCollector
    collector = EvidenceCollector()

    # 构建 ASR 字典 (如果有)
    asr_per_technique: dict[str, float] = {}
    for tech, results in results_dict.items():
        if not results:
            continue
        successes = sum(1 for ar in results if _is_success(ar))
        asr = (successes / len(results)) * 100 if results else 0
        asr_per_technique[tech] = asr

    overall_asr = sum(asr_per_technique.values()) / len(asr_per_technique) if asr_per_technique else 0

    # 收集证据
    evidence_collection = collector.collect(
        attack_results=results_dict,
        asr_per_technique=asr_per_technique,
        overall_asr=overall_asr,
    )

    # 保存证据到共享 OutputManager
    evidence_path = output_mgr.evidence_dir / f"web_redteam_{output_mgr.timestamp}_evidence.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    import json

    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence_collection.to_dict(), f, indent=2, ensure_ascii=False, default=str)

    logger.info(f"web_redteam evidence saved to {evidence_path}")

    # 经验 ASR 写回 (G-05: 按模型分文件)
    if asr_per_technique:
        try:
            from pipeline.asr.optimizer import save_empirical_asr

            save_empirical_asr(asr_per_technique, model_name=model_name)
            logger.info(f"web_redteam empirical ASR saved (model={model_name})")
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to save web_redteam empirical ASR: {e}")

    return evidence_collection


# ============================================================
# 辅助函数
# ============================================================


def _is_success(attack_result: Any) -> bool:
    """判断 AttackResult 是否成功。"""
    try:
        from pyrit.models import AttackOutcome

        outcome = getattr(attack_result, "outcome", None)
        return outcome == AttackOutcome.SUCCESS
    except (ImportError, AttributeError):
        return False


def generate_web_redteam_report(
    web_ctx: "WebRedteamContext",
    output_mgr: OutputManager,
    *,
    evidence: EvidenceCollection | None = None,
) -> Path | None:
    """生成 web_redteam 的 Markdown + HTML 报告。

    G-09: 使用主 pipeline 的报告生成体系, 确保 web_redteam
    的结果也包含 OWASP 映射、攻击链路和 ASR 分析。

    Args:
        web_ctx: WebRedteamContext 实例。
        output_mgr: 主 pipeline 的 OutputManager 实例。
        evidence: 预收集的证据集合 (可选, None 则自动收集)。

    Returns:
        报告文件路径, 或 None。
    """
    if evidence is None:
        evidence = collect_web_redteam_evidence(web_ctx, output_mgr)

    if evidence is None:
        logger.warning("No evidence to generate report from")
        return None

    # 构建 Markdown 报告
    lines: list[str] = [
        "# Web Red Team 评估报告",
        "",
        f"**时间**: {output_mgr.timestamp}",
        f"**目标**: {getattr(web_ctx, 'profile', None)}",
        "",
        "## 执行概要",
        "",
        f"- 总攻击数: {evidence.total_attacks}",
        f"- 成功: {evidence.successful_attacks}",
        f"- 失败: {evidence.failed_attacks}",
        f"- 整体 ASR: {evidence.overall_asr:.1f}%",
        "",
        "## 证据详情",
        "",
    ]

    for ev in evidence.evidence:
        lines.append(f"### {ev.evidence_id}: {ev.technique_name}")
        lines.append(f"- ASR: {ev.asr:.1f}%")
        lines.append(f"- 置信度: {ev.confidence}")
        if ev.jailbreak_prompt:
            lines.append(f"- 载荷: `{ev.jailbreak_prompt[:100]}...`")
        if ev.harmful_output:
            lines.append(f"- 有害输出: `{ev.harmful_output[:100]}...`")
        lines.append("")

    markdown_content = "\n".join(lines)

    # 使用主 pipeline 的 format_converter 生成 HTML
    from pipeline.reporting.format_converter import convert_report_formats

    report_path = output_mgr.reports_dir / f"web_redteam_{output_mgr.timestamp}_report"
    result = convert_report_formats(
        markdown_content,
        report_path,
        generate_html=True,
        generate_pdf=False,
        title="Web Red Team Report",
    )

    html_path = result.get("html")
    if html_path:
        logger.info(f"web_redteam report generated: {html_path}")
        return html_path

    return None
