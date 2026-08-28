#!/usr/bin/env python3
"""离线报告重新生成脚本 — 从已有 evidence.json 重新生成所有报告文件。

用途:
    当代码逻辑更新 (如报告合规修复) 后, 无需重新运行完整攻击流水线,
    只需从已有的 evidence.json 加载数据, 通过更新后的代码重新生成:
        - report.md / report_success.md
        - report.html / report_success.html
        - evidence/*.json (重新序列化, 包含新字段)
        - poc/*.py (重新生成 PyRIT 原生 PoC)
        - attack_summary.csv / owasp_coverage_matrix.csv
        - evidence_package.zip

用法:
    python regen_report.py --input-dir outputs/quick_scan_v34 --output-dir outputs/quick_scan_v35

注意:
    此脚本仅重新生成报告, 不会重新执行攻击。
    evidence 数据中的 conversation_history / validation_runs / testing_conditions
    等字段会通过更新后的 _single_evidence_to_dict / _format_evidence_detail 重新序列化。
    如果原始 evidence.json 中这些字段为空, 则报告中仍会为空 —
    需要重新运行完整流水线才能获取新数据。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# UTF-8 强制设置 (Windows GBK 终端兼容)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline.report.evidence import (  # noqa: E402
    EvidenceCollection,
    OWASPFinding,
    VulnerabilityEvidence,
)
from pipeline.report.owasp_constants import (  # noqa: E402
    OWASP_ASI_TOP10_REFERENCE,
    OWASP_LLM_TOP10_REFERENCE,
    OWASP_WEB_TOP10_REFERENCE,
)
from pipeline.report.owasp_mapping import generate_poc_script  # noqa: E402
from pipeline.report.report_html import (  # noqa: E402
    _evidence_to_dict,
    _generate_html,
    _single_evidence_to_dict,
)
from pipeline.report.report_markdown import _generate_markdown  # noqa: E402
from pipeline.report.report_sections import (  # noqa: E402
    _export_evidence_zip,
    _render_attack_summary_csv,
    _render_coverage_matrix_csv,
)

logger = logging.getLogger(__name__)


def _load_evidence_json(json_path: Path) -> dict[str, Any]:
    """加载 evidence.json。"""
    with open(json_path, encoding="utf-8") as f:
        return json.load(f)


def _rebuild_evidence_from_json(data: dict[str, Any]) -> EvidenceCollection:
    """从 JSON 字典重建 EvidenceCollection 对象。

    将已序列化的 evidence.json 反序列化为 EvidenceCollection,
    以便通过更新后的报告生成代码重新生成所有输出文件。
    """
    # 重建 evidence 列表
    evidence_list: list[VulnerabilityEvidence] = []
    successful_list: list[VulnerabilityEvidence] = []

    for ev_dict in data.get("evidence", []):
        ev = _rebuild_single_evidence(ev_dict)
        evidence_list.append(ev)
        if ev.is_success:
            successful_list.append(ev)

    # 重建 findings (如果有)
    findings: list[OWASPFinding] = []
    for fnd_dict in data.get("findings", []):
        findings.append(OWASPFinding(
            finding_id=fnd_dict.get("finding_id", ""),
            owasp_id=fnd_dict.get("owasp_id", ""),
            owasp_category=fnd_dict.get("owasp_category", ""),
            owasp_standard=fnd_dict.get("owasp_standard", ""),
            owasp_severity=fnd_dict.get("owasp_severity", ""),
            owasp_risk_score=fnd_dict.get("owasp_risk_score", 0.0),
            asr=fnd_dict.get("asr", 0.0),
            total_tested=fnd_dict.get("total_tested", 0),
            total_success=fnd_dict.get("total_success", 0),
            mitigations=fnd_dict.get("mitigations", []),
            mitre_tactic=fnd_dict.get("mitre_tactic", ""),
            mitre_technique_id=fnd_dict.get("mitre_technique_id", ""),
            mitre_technique_name=fnd_dict.get("mitre_technique_name", ""),
            results=fnd_dict.get("results", []),
        ))

    collection = EvidenceCollection(
        collection_id=data.get("collection_id", ""),
        timestamp=data.get("timestamp", ""),
        target_model=data.get("target_model", ""),
        total_attacks=data.get("total_attacks", 0),
        successful_attacks=data.get("successful_attacks", 0),
        failed_attacks=data.get("failed_attacks", 0),
        overall_asr=data.get("overall_asr", 0.0),
        evidence=evidence_list,
        successful_evidence=successful_list,
        owasp_coverage=data.get("owasp_coverage", {}),
        owasp_web_compliance=data.get("owasp_web_compliance", {}),
        owasp_llm_compliance=data.get("owasp_llm_compliance", {}),
        owasp_asi_compliance=data.get("owasp_asi_compliance", {}),
        owasp_standard_references=data.get(
            "owasp_standard_references",
            [OWASP_WEB_TOP10_REFERENCE, OWASP_LLM_TOP10_REFERENCE, OWASP_ASI_TOP10_REFERENCE],
        ),
        technique_distribution=data.get("technique_distribution", {}),
        failure_analysis=data.get("failure_analysis", {}),
        target_fingerprint=data.get("target_fingerprint", {}),
        attack_surface=data.get("attack_surface", {}),
        dual_judge_stats=data.get("dual_judge_stats", {}),
        wilson_ci=tuple(data.get("wilson_ci", (0.0, 0.0))),
        cohens_kappa=data.get("cohens_kappa", 0.0),
        findings=findings,
        web_vuln_stats=data.get("web_vuln_stats", {}),
        discovered_endpoints=data.get("discovered_endpoints", []),
        orchestration_log=data.get("orchestration_log", []),
    )

    return collection


def _rebuild_single_evidence(ev_dict: dict[str, Any]) -> VulnerabilityEvidence:
    """从 JSON 字典重建单个 VulnerabilityEvidence。"""
    return VulnerabilityEvidence(
        evidence_id=ev_dict.get("evidence_id", ""),
        attack_id=ev_dict.get("attack_id", ""),
        technique_name=ev_dict.get("technique_name", ""),
        technique_display_name=ev_dict.get("technique_display_name", ""),
        converter_chain=ev_dict.get("converter_chain", ""),
        owasp_id=ev_dict.get("owasp_id", ""),
        owasp_category=ev_dict.get("owasp_category", ""),
        owasp_standard=ev_dict.get("owasp_standard", ""),
        owasp_severity=ev_dict.get("owasp_severity", ""),
        owasp_risk_score=ev_dict.get("owasp_risk_score", 0.0),
        owasp_mitigations=ev_dict.get("owasp_mitigations", []),
        owasp_reference=ev_dict.get("owasp_reference", ""),
        cvss_vector=ev_dict.get("cvss_vector", ""),
        objective=ev_dict.get("objective", ""),
        jailbreak_prompt=ev_dict.get("jailbreak_prompt", ""),
        harmful_output=ev_dict.get("harmful_output", ""),
        is_success=ev_dict.get("is_success", False),
        file_suffix=ev_dict.get("file_suffix", ""),
        conversation_history=ev_dict.get("conversation_history", []),
        asr=ev_dict.get("asr", 0.0),
        confidence=ev_dict.get("confidence", "medium"),
        arxiv_reference=ev_dict.get("arxiv_reference", ""),
        timestamp=ev_dict.get("timestamp", ""),
        target_model=ev_dict.get("target_model", ""),
        attack_chain=ev_dict.get("attack_chain", []),
        converter_log=ev_dict.get("converter_log", []),
        score_details=ev_dict.get("score_details", []),
        mitre_tactic=ev_dict.get("mitre_tactic", ""),
        mitre_technique_id=ev_dict.get("mitre_technique_id", ""),
        mitre_technique_name=ev_dict.get("mitre_technique_name", ""),
        mitre_url=ev_dict.get("mitre_url", ""),
        validation_runs=ev_dict.get("validation_runs", []),
        testing_conditions=ev_dict.get("testing_conditions", {}),
    )


def regenerate_reports(input_dir: Path, output_dir: Path) -> None:
    """从已有 evidence.json 重新生成所有报告文件。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # 加载原始 evidence.json
    evidence_json_path = input_dir / "evidence" / "evidence.json"
    if not evidence_json_path.exists():
        # 尝试 success 版本
        evidence_json_path = input_dir / "evidence" / "evidence_success.json"
        if not evidence_json_path.exists():
            logger.error("No evidence.json found in %s", input_dir / "evidence")
            sys.exit(1)

    logger.info("Loading evidence from %s", evidence_json_path)
    data = _load_evidence_json(evidence_json_path)
    evidence = _rebuild_evidence_from_json(data)

    logger.info(
        "Rebuilt EvidenceCollection: %d total, %d success, ASR=%.1f%%",
        evidence.total_attacks,
        evidence.successful_attacks,
        evidence.overall_asr,
    )

    # 创建输出目录
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    poc_dir = output_dir / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)

    # ── 生成 Markdown 报告 ──
    md_content = _generate_markdown(evidence)
    md_path = output_dir / "report.md"
    md_path.write_text(md_content, encoding="utf-8")
    logger.info("Markdown report saved to %s", md_path)

    # ── 生成仅成功攻击的 Markdown 报告 ──
    if evidence.successful_evidence:
        success_md = _generate_markdown(evidence, success_only=True)
        success_md_path = output_dir / "report_success.md"
        success_md_path.write_text(success_md, encoding="utf-8")
        logger.info("Success-only Markdown report saved to %s", success_md_path)

    # ── 生成 HTML 报告 ──
    html_content = _generate_html(evidence)
    html_path = output_dir / "report.html"
    html_path.write_text(html_content, encoding="utf-8")
    logger.info("HTML report saved to %s", html_path)

    # ── 生成仅成功攻击的 HTML 报告 ──
    if evidence.successful_evidence:
        success_html = _generate_html(evidence, success_only=True)
        success_html_path = output_dir / "report_success.html"
        success_html_path.write_text(success_html, encoding="utf-8")
        logger.info("Success-only HTML report saved to %s", success_html_path)

    # ── 重新序列化 evidence JSON ──
    json_data = _evidence_to_dict(evidence)
    json_path = evidence_dir / "evidence.json"
    json_path.write_text(
        json.dumps(json_data, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Evidence JSON saved to %s", json_path)

    if evidence.successful_evidence:
        success_json_data = _evidence_to_dict(evidence, success_only=True)
        success_json_path = evidence_dir / "evidence_success.json"
        success_json_path.write_text(
            json.dumps(success_json_data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("Success-only evidence JSON saved to %s", success_json_path)

    # ── 每个证据单独保存 ──
    for ev in evidence.evidence:
        ev_filename = f"{ev.evidence_id}.json"
        ev_path = evidence_dir / ev_filename
        ev_path.write_text(
            json.dumps(_single_evidence_to_dict(ev), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

    # ── 重新生成 PoC 脚本 ──
    poc_count = 0
    for ev in evidence.successful_evidence:
        try:
            poc_script = generate_poc_script(ev)
            poc_path = poc_dir / f"poc_{ev.evidence_id}.py"
            poc_path.write_text(poc_script, encoding="utf-8")
            poc_count += 1
        except Exception as e:
            logger.warning("Failed to generate PoC for %s: %s", ev.evidence_id, e)
    if poc_count:
        logger.info("PoC scripts saved to %s (%d files)", poc_dir, poc_count)

    # ── CSV 导出 ──
    try:
        csv_summary = _render_attack_summary_csv(evidence)
        csv_summary_path = output_dir / "attack_summary.csv"
        csv_summary_path.write_text(csv_summary, encoding="utf-8")

        csv_coverage = _render_coverage_matrix_csv(evidence)
        csv_coverage_path = output_dir / "owasp_coverage_matrix.csv"
        csv_coverage_path.write_text(csv_coverage, encoding="utf-8")
        logger.info("CSV exports saved to %s", output_dir)
    except Exception as e:
        logger.warning("Failed to export CSV: %s", e)

    # ── ZIP 证据包 ──
    try:
        _export_evidence_zip(output_dir, evidence)
        logger.info("Evidence ZIP saved to %s", output_dir / "evidence_package.zip")
    except Exception as e:
        logger.warning("Failed to export evidence ZIP: %s", e)

    # ── 汇总 ──
    print()
    print("=" * 70)
    print("Report Regeneration Complete!")
    print("=" * 70)
    print(f"  Input:  {input_dir}")
    print(f"  Output: {output_dir}")
    print(f"  Total Evidence: {len(evidence.evidence)}")
    print(f"  Successful: {len(evidence.successful_evidence)}")
    print(f"  PoC Scripts: {poc_count}")
    print(f"  Overall ASR: {evidence.overall_asr}%")
    print()
    print("Generated files:")
    print("  - report.md / report_success.md")
    print("  - report.html / report_success.html")
    print("  - evidence/evidence.json / evidence_success.json")
    print("  - evidence/EVD-*.json")
    print("  - poc/poc_EVD-*_success.py")
    print("  - attack_summary.csv / owasp_coverage_matrix.csv")
    print("  - evidence_package.zip")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="离线报告重新生成 — 从已有 evidence.json 重新生成所有报告文件",
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        required=True,
        help="输入目录 (包含 evidence/evidence.json)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="输出目录 (重新生成的报告文件)",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        sys.exit(1)

    regenerate_reports(input_dir, output_dir)


if __name__ == "__main__":
    main()
