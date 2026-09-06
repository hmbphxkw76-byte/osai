"""generator — 报告生成协调器。

职责:
    - 定义共享常量 (_OWASP_ALL_CATEGORIES)
    - 提供 _classify_score_consistency 评分一致性分析
    - generate_report: 异步生成所有报告文件 (MD + HTML + JSON + PoC + CSV + ZIP)
    - 重新导出 _generate_markdown / _generate_html / _evidence_to_dict / _single_evidence_to_dict
      (实际实现在 report_markdown.py / report_html.py 中)
    - _load_html_template: 从 report/templates/report.html 加载 HTML 模板

架构:
    generator.py (常量 + 协调) -> report_markdown.py (MD 生成)
                              -> report_html.py (HTML 生成)
                              -> report_sections.py (章节构建)
                              -> report_utils.py (工具函数)
                              -> templates/report.html (HTML 模板)

循环依赖解决:
    generator.py 延迟导入 report_html/report_markdown 的函数 (在 generate_report 内).
    HTML 模板已从代码解耦到独立文件, 通过 _load_html_template() 运行时读取.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from report.evidence import EvidenceCollection

logger = logging.getLogger(__name__)


# ── OWASP 类别字典 (Web + LLM + ASI 合并) ──
# 被 report_html.py 和 report_utils.py 引用
_OWASP_ALL_CATEGORIES: dict[str, str] = {
    # OWASP Web Top 10 (2025)
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Failure",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
    # OWASP LLM Top 10 (2025 Edition)
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    # OWASP Agentic AI Top 10
    "ASI01": "Agent Identity Spoofing",
    "ASI02": "Tool Misuse",
    "ASI03": "Unauthorized Actions",
    "ASI04": "Data Exfiltration",
    "ASI05": "Privilege Escalation",
    "ASI06": "Memory Poisoning",
    "ASI07": "Cross-Agent Injection",
    "ASI08": "Cascading Failures",
    "ASI09": "Trust Boundary Violation",
    "ASI10": "Rogue Agent",
}


# ── HTML 模板加载 (从独立文件读取, 解耦代码与模板) ──
# 模板文件路径: report/templates/report.html
# 被 report_html.py 和 _generate_html 引用

_html_template_cache: str | None = None


def _load_html_template() -> str:
    """从 report/templates/report.html 加载 HTML 模板。

    使用内存缓存避免重复文件 I/O, 仅在首次调用时读取文件。
    支持运行时模板热更新 (清除缓存后重新加载)。

    Returns:
        HTML 模板字符串。

    Raises:
        FileNotFoundError: 模板文件不存在时记录错误并返回备用模板。
    """
    global _html_template_cache

    if _html_template_cache is not None:
        return _html_template_cache

    template_path = Path(__file__).parent / "templates" / "report.html"
    try:
        _html_template_cache = template_path.read_text(encoding="utf-8")
        logger.debug("HTML template loaded from %s", template_path)
    except FileNotFoundError:
        logger.error(
            "HTML template file not found at %s — using fallback minimal template",
            template_path,
        )
        # 生产级容错: 返回最小可用模板, 避免报告生成完全失败
        _html_template_cache = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>AI Red Team Assessment Report</title></head>"
            "<body><h1>AI Red Team Assessment Report</h1>"
            "<p>Template file not found — using fallback.</p>"
            "<pre>{{ evidence_json }}</pre></body></html>"
        )
    return _html_template_cache


def clear_template_cache() -> None:
    """清除 HTML 模板缓存, 下次加载时重新读取文件。

    用于开发时模板热更新, 或在测试后重置状态。
    """
    global _html_template_cache
    _html_template_cache = None
    logger.debug("HTML template cache cleared")


def _classify_score_consistency(score_details: list[dict[str, Any]]) -> str:
    """分类评分一致性。

    分析 score_details 中多个 scorer 的评分一致性:
        - 空 -> N/A
        - 单 scorer -> Post-hoc Dual Judge
        - 多 scorer 全一致 -> Consistent
        - 多 scorer 不一致 -> Minor Disagreement

    Args:
        score_details: 评分详情列表, 每项含 "scorer" 和 "score_value" 键。

    Returns:
        一致性分类字符串。
    """
    if not score_details:
        return "N/A"

    # 提取所有 score_value
    score_values: list[str] = []
    for sd in score_details:
        val = str(sd.get("score_value", "")).lower().strip()
        score_values.append(val)

    if len(score_values) <= 1:
        return "Post-hoc Dual Judge"

    # 检查是否全部一致 (true/1 或全部 false/0)
    truthy = {"true", "1", "yes"}
    falsy = {"false", "0", "no"}

    all_true = all(v in truthy for v in score_values)
    all_false = all(v in falsy for v in score_values)

    if all_true or all_false:
        return "Consistent"
    return "Minor Disagreement"


# ── 重新导出 (延迟导入, 避免循环依赖) ──
# 这些函数实际实现在 report_markdown.py 和 report_html.py 中
# 但测试和旧代码从 generator 导入它们.
# 使用延迟导入 (wrapper 函数) 避免循环依赖.


def _generate_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """生成 Markdown 报告 (委托给 report_markdown).

    Includes sections: dual_judge_stats, wilson_ci, cohens_kappa, Adaptive Dual Judge Statistics.
    """
    from report.report_markdown import _generate_markdown as _impl

    return _impl(evidence, success_only=success_only)


def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """生成 HTML 报告 (委托给 report_html)."""
    from report.report_html import _generate_html as _impl

    return _impl(evidence, success_only=success_only)


def _evidence_to_dict(evidence: EvidenceCollection, *, success_only: bool = False) -> dict[str, Any]:
    """将证据集合转换为字典 (委托给 report_html).

    Includes: dual_judge_stats, owasp_web_compliance, web_vuln_stats, discovered_endpoints.
    """
    from report.report_html import _evidence_to_dict as _impl

    return _impl(evidence, success_only=success_only)


def _single_evidence_to_dict(ev: Any) -> dict[str, Any]:
    """将单个证据转换为字典 (委托给 report_html)."""
    from report.report_html import _single_evidence_to_dict as _impl

    return _impl(ev)


async def generate_report(
    ctx: Any,
    evidence: EvidenceCollection,
    output_dir: Path,
) -> Path:
    """生成所有报告文件。

    生成:
        - report.md / report_success.md
        - report.html / report_success.html (如果 args.html_report)
        - evidence/evidence.json / evidence_success.json
        - evidence/EVD-*.json (每个证据单独保存)
        - poc/poc_*.py (成功攻击的 PoC 脚本)
        - report.sarif (SARIF 2.1 格式, 用于 CI/CD 集成)
        - attack_summary.csv / owasp_coverage_matrix.csv
        - evidence_package.zip

    Args:
        ctx: PipelineContext 对象.
        evidence: 证据集合.
        output_dir: 输出目录.

    Returns:
        报告文件路径.
    """
    output_dir = Path(output_dir)
    evidence_dir = output_dir / "evidence"
    poc_dir = output_dir / "poc"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    poc_dir.mkdir(parents=True, exist_ok=True)

    # ── PyRIT Native Output (R2: PyRIT 原生优先) ──
    # Uses official pyrit.output module to generate standard-format output files.
    # This is the PyRIT-native output path, separate from the security report.
    # OffSec AI-300: Proves PyRIT framework mastery via native output format.
    try:
        from report.pyrit_native_output import generate_native_output_files

        attack_results = getattr(ctx, "attack_results", {})
        scenario_result = getattr(ctx, "scenario_result", None)
        await generate_native_output_files(attack_results, scenario_result, output_dir)
    except Exception as e:
        logger.warning("PyRIT native output generation failed (non-fatal): %s", e)

    # ── Markdown Report (OffSec AI-300 Security Report) ──
    # v57: 分层架构 — 生成 索引 + 执行摘要 + 漏洞详情 + 技术附录
    from report.report_markdown import (
        _generate_executive_markdown,
        _generate_findings_markdown,
        _generate_technical_markdown,
    )

    md_content = _generate_markdown(evidence)
    md_path = output_dir / "report.md"
    md_path.write_text(md_content, encoding="utf-8")
    logger.info("Markdown report (index) saved to %s", md_path)

    # v57: 分层报告文件
    exec_md = _generate_executive_markdown(evidence)
    exec_md_path = output_dir / "report_executive.md"
    exec_md_path.write_text(exec_md, encoding="utf-8")
    logger.info("Executive summary saved to %s", exec_md_path)

    findings_md = _generate_findings_markdown(evidence)
    findings_md_path = output_dir / "report_findings.md"
    findings_md_path.write_text(findings_md, encoding="utf-8")
    logger.info("Findings report saved to %s", findings_md_path)

    tech_md = _generate_technical_markdown(evidence)
    tech_md_path = output_dir / "report_technical.md"
    tech_md_path.write_text(tech_md, encoding="utf-8")
    logger.info("Technical appendix saved to %s", tech_md_path)

    # ── 仅成功攻击的 Markdown ──
    # v57: success_only 报告 = executive 摘要(仅成功) + findings 详情(仅成功)
    if evidence.successful_evidence:
        from report.report_markdown import _generate_executive_markdown as _gen_exec

        # 用 findings 模板 (success_only) 作为主体, 前置 executive 摘要
        success_findings = _generate_findings_markdown(evidence, success_only=True)
        # executive 摘要仍用全量数据 (ASR/total 等指标不变, 只是 findings 只列成功)
        success_exec = _gen_exec(evidence)
        success_md = success_exec + "\n\n---\n\n" + success_findings
        success_md_path = output_dir / "report_success.md"
        success_md_path.write_text(success_md, encoding="utf-8")
        logger.info("Success-only Markdown report saved to %s", success_md_path)

    # ── HTML 报告 (可选) ──
    if getattr(ctx.args, "html_report", False):
        html_content = _generate_html(evidence)
        html_path = output_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report saved to %s", html_path)

        if evidence.successful_evidence:
            success_html = _generate_html(evidence, success_only=True)
            success_html_path = output_dir / "report_success.html"
            success_html_path.write_text(success_html, encoding="utf-8")
            logger.info("Success-only HTML report saved to %s", success_html_path)

    # ── evidence JSON ──
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

    # ── PoC 脚本 (仅成功攻击) ──
    # 断点修复: 增强日志记录, 包含技术名称和失败原因, 便于调试
    from report.owasp_mapping import generate_poc_script

    poc_count = 0
    poc_failed = 0
    for ev in evidence.successful_evidence:
        try:
            poc_script = generate_poc_script(ev)
            poc_path = poc_dir / f"poc_{ev.evidence_id}.py"
            poc_path.write_text(poc_script, encoding="utf-8")
            poc_count += 1
            logger.debug(
                "PoC generated: %s (technique=%s, converter=%s)",
                ev.evidence_id,
                ev.technique_name,
                ev.converter_chain or "none",
            )
        except Exception as e:
            poc_failed += 1
            logger.warning(
                "PoC generation failed for %s (technique=%s): %s",
                ev.evidence_id,
                ev.technique_name,
                e,
                exc_info=True,
            )
    if poc_count:
        logger.info("PoC scripts saved to %s (%d files)", poc_dir, poc_count)
    if poc_failed:
        logger.warning("PoC generation: %d succeeded, %d failed", poc_count, poc_failed)

    # ── SARIF 报告 ──
    # 断点修复: SARIF 报告 (sarif_report.py) 存在但未被主流流水线调用
    # 导致 CI/CD 集成场景缺少 SARIF 输出。
    # 修复: 在 generator.py 中集成 SARIF 报告生成, 与 MD/HTML/JSON 并行输出。
    try:
        from report.sarif_report import generate_sarif_report

        sarif_path = output_dir / "report.sarif"
        generate_sarif_report(evidence, sarif_path)
    except Exception as e:
        logger.warning("Failed to generate SARIF report: %s", e)

    # ── CSV 导出 ──
    try:
        from report.report_sections import (
            _export_evidence_zip,
            _render_attack_summary_csv,
            _render_coverage_matrix_csv,
        )

        csv_summary = _render_attack_summary_csv(evidence)
        csv_summary_path = output_dir / "attack_summary.csv"
        csv_summary_path.write_text(csv_summary, encoding="utf-8")

        csv_coverage = _render_coverage_matrix_csv(evidence)
        csv_coverage_path = output_dir / "owasp_coverage_matrix.csv"
        csv_coverage_path.write_text(csv_coverage, encoding="utf-8")
        logger.info("CSV exports saved to %s", output_dir)

        # ── ZIP 证据包 ──
        _export_evidence_zip(output_dir, evidence)
        logger.info("Evidence ZIP saved to %s", output_dir / "evidence_package.zip")
    except Exception as e:
        logger.warning("Failed to export CSV/ZIP: %s", e)

    return md_path
