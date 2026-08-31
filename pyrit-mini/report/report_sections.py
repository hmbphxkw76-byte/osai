# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2307.08673 — Zou et al., GCG
# arXiv:2407.01232 — PyRIT, SequentialAttack FIRST_SUCCESS
"""report_sections — 报告章节构建函数.

从 generator.py 拆分而来, 负责构建报告中的各种数据章节:
    - 热力图数据 (Technique × OWASP)
    - 升级链仪表盘
    - 技术有效性矩阵
    - 评分一致性分析
    - MITRE ATLAS 映射章节
    - 三级证据链 Findings 章节
    - 升级链报告章节
    - CSV 导出
    - ZIP 证据包打包
"""

from __future__ import annotations

import csv
import io
import logging
import zipfile
from pathlib import Path
from typing import Any

from report.evidence import EvidenceCollection, OWASPFinding, VulnerabilityEvidence
from report.owasp_constants import _MITRE_ATLAS_TECHNIQUES

logger = logging.getLogger(__name__)


def _build_heatmap_data(
    evidence: EvidenceCollection,
    evidence_list: list[VulnerabilityEvidence],
) -> tuple[list[str], list[dict[str, Any]]]:
    """构建 ASR 热力图数据 (Technique × OWASP).

    Args:
        evidence: 证据集合.
        evidence_list: 要包含的证据列表.

    Returns:
        (owasp_ids, rows) 元组:
        - owasp_ids: OWASP ID 列表 (列标题)
        - rows: 行数据列表, 每行含 technique, cells, overall_css, overall_display
    """
    # 收集所有 OWASP ID (按出现顺序)
    owasp_ids_set: set[str] = set()
    tech_owasp_asr: dict[str, dict[str, tuple[int, int]]] = {}

    for ev in evidence_list:
        tech = ev.technique_name
        owasp_id = ev.owasp_id
        owasp_ids_set.add(owasp_id)

        if tech not in tech_owasp_asr:
            tech_owasp_asr[tech] = {}
        if owasp_id not in tech_owasp_asr[tech]:
            tech_owasp_asr[tech][owasp_id] = [0, 0]  # [success, total]

        tech_owasp_asr[tech][owasp_id][1] += 1
        if ev.is_success:
            tech_owasp_asr[tech][owasp_id][0] += 1

    owasp_ids = sorted(owasp_ids_set)

    rows: list[dict[str, Any]] = []
    for tech, owasp_data in sorted(tech_owasp_asr.items()):
        cells: list[dict[str, str]] = []
        total_success = 0
        total_attempts = 0

        for owasp_id in owasp_ids:
            success, total = owasp_data.get(owasp_id, (0, 0))
            total_success += success
            total_attempts += total

            if total == 0:
                cells.append({"css_class": "heat-none", "display": "—"})
            else:
                asr = (success / total) * 100
                css_class = _asr_to_css_class(asr)
                cells.append({"css_class": css_class, "display": f"{asr:.0f}%"})

        overall_asr = (total_success / total_attempts * 100) if total_attempts > 0 else 0
        rows.append({
            "technique": tech,
            "cells": cells,
            "overall_css": _asr_to_css_class(overall_asr),
            "overall_display": f"{overall_asr:.0f}%" if total_attempts > 0 else "—",
        })

    return owasp_ids, rows


def _asr_to_css_class(asr: float) -> str:
    """将 ASR 百分比映射为 CSS 类名."""
    if asr >= 50:
        return "heat-critical"
    if asr >= 25:
        return "heat-high"
    if asr > 0:
        return "heat-medium"
    return "heat-low"


def _build_escalation_dashboard_data(evidence: EvidenceCollection) -> list[dict[str, Any]]:
    """构建升级链仪表盘数据.

    断点修复: 原代码使用硬编码系数 (0.82, 0.65, 0.50, 0.30) 估算各阶段 ASR,
    导致报告中的升级链仪表盘数据与实际 ASR 不一致。
    修复: 从 evidence 中提取真实 ASR per technique, 按技术名匹配各阶段。

    5 个阶段:
        Stage 1: Single-Turn (baseline techniques)
        Stage 2: Crescendo
        Stage 3: TAP
        Stage 4: PAIR
        Stage 5: GCG

    数据源:
        - evidence 中每个 VulnerabilityEvidence 的 technique_name + is_success
        - 按阶段关键词匹配技术名, 计算真实 ASR

    Args:
        evidence: 证据集合.

    Returns:
        5 个阶段的仪表盘数据列表, 每个含 stage, technique, asr, asr_num, escalated.
    """
    # 阶段定义: (stage_name, display_technique, matching_keywords)
    stage_defs = [
        ("Stage 1", "Single-Turn", ["prompt_sending", "baseline", "single"]),
        ("Stage 2", "Crescendo", ["crescendo"]),
        ("Stage 3", "TAP", ["tap"]),
        ("Stage 4", "PAIR", ["pair"]),
        ("Stage 5", "GCG", ["gcg"]),
    ]

    # 从 evidence 列表计算各阶段真实 ASR
    overall_asr = evidence.overall_asr

    stages: list[dict[str, Any]] = []
    for i, (stage_name, display_tech, keywords) in enumerate(stage_defs):
        # 按关键词匹配技术, 收集该阶段的所有证据
        stage_evidence = [
            ev for ev in evidence.evidence
            if any(kw in ev.technique_name.lower() for kw in keywords)
        ]

        if stage_evidence:
            total = len(stage_evidence)
            success = sum(1 for ev in stage_evidence if ev.is_success)
            matched_asr = (success / total * 100) if total > 0 else 0.0
        else:
            # Stage 1 fallback: 使用总体 ASR (baseline 阶段 = 整体)
            if i == 0:
                matched_asr = overall_asr
            else:
                matched_asr = 0.0

        # 判断升级状态
        if matched_asr >= 90:
            escalated = "stop"
        elif matched_asr > 0 and i < len(stage_defs) - 1:
            escalated = "escalate"
        else:
            escalated = "pending"

        stages.append({
            "stage": stage_name,
            "technique": display_tech,
            "asr": f"{matched_asr:.1f}%",
            "asr_num": matched_asr,
            "escalated": escalated,
        })

    return stages


def _build_technique_effectiveness_matrix(
    evidence: EvidenceCollection,
    evidence_list: list[VulnerabilityEvidence],
) -> list[str]:
    """构建攻击技术有效性矩阵 (Markdown 行列表).

    Args:
        evidence: 证据集合.
        evidence_list: 证据列表.

    Returns:
        Markdown 行列表 (含标题、表头、数据行).
    """
    lines: list[str] = []
    lines.append("## Attack Technique Effectiveness Matrix")
    lines.append("")

    # 收集技术 × OWASP 的 ASR 数据
    tech_data: dict[str, dict[str, dict[str, int]]] = {}
    owasp_ids_set: set[str] = set()

    for ev in evidence_list:
        tech = ev.technique_name
        owasp_id = ev.owasp_id
        owasp_ids_set.add(owasp_id)

        if tech not in tech_data:
            tech_data[tech] = {}
        if owasp_id not in tech_data[tech]:
            tech_data[tech][owasp_id] = {"success": 0, "total": 0}

        tech_data[tech][owasp_id]["total"] += 1
        if ev.is_success:
            tech_data[tech][owasp_id]["success"] += 1

    owasp_ids = sorted(owasp_ids_set)

    # 表头
    header = "| Technique | " + " | ".join(owasp_ids) + " | Overall |"
    separator = "|-----------|" + "|".join(["---" for _ in owasp_ids]) + "|---|"
    lines.append(header)
    lines.append(separator)

    # 数据行
    for tech, owasp_data in sorted(tech_data.items()):
        cells: list[str] = []
        total_s = 0
        total_t = 0
        for owasp_id in owasp_ids:
            data = owasp_data.get(owasp_id, {"success": 0, "total": 0})
            s, t = data["success"], data["total"]
            total_s += s
            total_t += t
            if t == 0:
                cells.append("—")
            else:
                cells.append(f"{s}/{t} ({s / t * 100:.0f}%)")

        overall = f"{total_s}/{total_t}" if total_t > 0 else "—"
        lines.append(f"| {tech} | " + " | ".join(cells) + f" | {overall} |")

    lines.append("")
    return lines


def _build_score_consistency_section(evidence: EvidenceCollection) -> list[str]:
    """构建评分一致性分析章节 (去重摘要版).

    v57 优化: 当所有 Evidence 的一致性分类相同时, 合并为单行摘要,
    避免逐行重复 (如 45 行全部 "Score | Post-hoc Dual Judge")。

    Args:
        evidence: 证据集合.

    Returns:
        Markdown 行列表.
    """
    from report.generator import _classify_score_consistency

    lines: list[str] = []
    lines.append("## Score Consistency Analysis")
    lines.append("")

    # 收集所有 Evidence 的一致性分类
    consistency_map: list[tuple[str, str, str]] = []  # (evidence_id, scorer_names, consistency)
    for ev in evidence.evidence:
        score_details = ev.score_details
        if not score_details:
            score_details = [{
                "scorer": "AttackOutcome",
                "score_value": "success" if ev.is_success else "failure",
                "rationale": "Determined by post-hoc scoring",
            }]

        scorer_names = ", ".join(sd.get("scorer", "") for sd in score_details)
        consistency = _classify_score_consistency(score_details)
        consistency_map.append((ev.evidence_id, scorer_names, consistency))

    # 检查是否所有一致性分类相同
    all_same = len({c for _, _, c in consistency_map}) == 1
    if all_same and consistency_map:
        # 摘要模式: 所有 Evidence 的一致性相同
        unique_consistency = consistency_map[0][2]
        unique_scorer = consistency_map[0][1]
        lines.append(f"All {len(consistency_map)} evidence items scored with **{unique_scorer}** — consistency: **{unique_consistency}**.")
        lines.append("")
    else:
        # 详细模式: 存在不一致, 逐行列出
        lines.append("| Evidence ID | Scorer(s) | Consistency |")
        lines.append("|-------------|-----------|-------------|")
        for eid, scorer_names, consistency in consistency_map:
            lines.append(f"| {eid} | {scorer_names} | {consistency} |")
        lines.append("")

    return lines


def _finding_to_dict(finding: OWASPFinding) -> dict[str, Any]:
    """将 Finding 对象转换为字典 (用于 JSON 序列化).

    Args:
        finding: OWASPFinding 对象.

    Returns:
        字典表示.
    """
    return {
        "finding_id": finding.finding_id,
        "owasp_id": finding.owasp_id,
        "owasp_category": finding.owasp_category,
        "owasp_standard": finding.owasp_standard,
        "owasp_severity": finding.owasp_severity,
        "owasp_risk_score": finding.owasp_risk_score,
        "asr": finding.asr,
        "total_tested": finding.total_tested,
        "total_success": finding.total_success,
        "mitigations": finding.mitigations,
        "mitre_tactic": finding.mitre_tactic,
        "mitre_technique_id": finding.mitre_technique_id,
        "mitre_technique_name": finding.mitre_technique_name,
        "results": finding.results,
    }


def _render_attack_summary_csv(evidence: EvidenceCollection) -> str:
    """生成攻击摘要 CSV.

    列: Evidence ID, OWASP ID, OWASP Category, Technique, Converter Chain,
        Success, ASR, MITRE ATLAS, Confidence, Severity, Risk Score

    Args:
        evidence: 证据集合.

    Returns:
        CSV 字符串.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # 表头
    writer.writerow([
        "Evidence ID", "OWASP ID", "OWASP Category", "Technique",
        "Converter Chain", "Success", "ASR", "MITRE ATLAS",
        "Confidence", "Severity", "Risk Score",
    ])

    for ev in evidence.evidence:
        mitre = ev.mitre_technique_id or _MITRE_ATLAS_TECHNIQUES.get(ev.owasp_id, {}).get("technique_id", "")
        writer.writerow([
            ev.evidence_id,
            ev.owasp_id,
            ev.owasp_category,
            ev.technique_name,
            ev.converter_chain or "none (baseline)",
            "YES" if ev.is_success else "NO",
            f"{ev.asr}%",
            mitre,
            ev.confidence,
            ev.owasp_severity,
            ev.owasp_risk_score,
        ])

    return output.getvalue()


def _render_coverage_matrix_csv(evidence: EvidenceCollection) -> str:
    """生成 OWASP 覆盖矩阵 CSV.

    列: OWASP ID, Category, Standard, Tested, Success, Failed, ASR

    包含 LLM Top 10 和 ASI Top 10.

    Args:
        evidence: 证据集合.

    Returns:
        CSV 字符串.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # 表头
    writer.writerow(["OWASP ID", "Category", "Standard", "Tested", "Success", "Failed", "ASR"])

    # LLM Top 10
    for owasp_id in sorted(evidence.owasp_llm_compliance.keys()):
        stats = evidence.owasp_llm_compliance[owasp_id]
        writer.writerow([
            owasp_id,
            stats.get("category", "Unknown"),
            "LLM Top 10",
            stats.get("tested", 0),
            stats.get("success", 0),
            stats.get("failed", 0),
            f"{stats.get('asr', 0.0)}%",
        ])

    # ASI Top 10
    for owasp_id in sorted(evidence.owasp_asi_compliance.keys()):
        stats = evidence.owasp_asi_compliance[owasp_id]
        writer.writerow([
            owasp_id,
            stats.get("category", "Unknown"),
            "ASI Top 10",
            stats.get("tested", 0),
            stats.get("success", 0),
            stats.get("failed", 0),
            f"{stats.get('asr', 0.0)}%",
        ])

    return output.getvalue()


def _export_evidence_zip(output_dir: Path, evidence: EvidenceCollection) -> None:
    """将输出目录中的所有文件打包为 ZIP 证据包.

    Args:
        output_dir: 输出目录.
        evidence: 证据集合 (用于确定要打包的文件).
    """
    output_dir = Path(output_dir)
    zip_path = output_dir / "evidence_package.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # 遍历输出目录中的所有文件
        for file_path in output_dir.rglob("*"):
            if file_path == zip_path:
                continue
            if file_path.is_file():
                arcname = str(file_path.relative_to(output_dir))
                zf.write(file_path, arcname)
