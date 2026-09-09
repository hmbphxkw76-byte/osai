"""generator - Multi-format report generation entry point.

Provides:
    - _OWASP_ALL_CATEGORIES: OWASP category name mapping (Web + LLM + ASI)
    - _classify_score_consistency: Score consistency classification
    - generate_report: Main entry point (MD + HTML + JSON + PoC + CSV + ZIP)
    - _generate_markdown / _generate_html / _evidence_to_dict / _single_evidence_to_dict
      (delegates to report_markdown.py / report_html.py)

Data flow:
    generator.py (format selection + orchestration) -> report_markdown.py (MD output)
                                                    -> report_html.py (HTML output)
                                                    -> poc_generator.py (PoC scripts)

Design note:
    generator.py imports functions from report_html/report_markdown lazily (in generate_report).
    P1-4: Jinja2 removed - HTML uses pure Python string formatting.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from report.evidence import EvidenceCollection

logger = logging.getLogger(__name__)

# OWASP category mapping (Web + LLM + Agentic AI)
# Shared with report_html.py
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

def _classify_score_consistency(score_details: list[dict[str, Any]]) -> str:
    """Classify score consistency across multiple scorers.

     Given score_details from converter(s) scorer, determines:
        - N/A -> No scores available
        - Post-hoc Dual Judge -> Only 1 scorer present
        - Consistent -> All scorers agree (all true or all false)
        - Minor Disagreement -> Scorers disagree

    Args:
        score_details: List of score dicts with "scorer" and "score_value" keys

    Returns:
        Consistency classification string
    """
    if not score_details:
        return "N/A"

    # Normalize score values
    score_values: list[str] = []
    for sd in score_details:
        val = str(sd.get("score_value", "")).lower().strip()
        score_values.append(val)

    if len(score_values) <= 1:
        return "Post-hoc Dual Judge"

    # Classify agreement (true/1 false/0)
    truthy = {"true", "1", "yes"}
    falsy = {"false", "0", "no"}

    all_true = all(v in truthy for v in score_values)
    all_false = all(v in falsy for v in score_values)

    if all_true or all_false:
        return "Consistent"
    return "Minor Disagreement"

# Delegated generation functions (lazy import)
# report_markdown.py and report_html.py implement the actual logic;
# generator imports them lazily in generate_report to avoid circular deps.

def _generate_markdown(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Generate Markdown report (delegates to report_markdown).

    Includes sections: dual_judge_stats, wilson_ci, cohens_kappa, Adaptive Dual Judge Statistics.
    """
    from report.report_markdown import _generate_markdown as _impl

    return _impl(evidence, success_only=success_only)

def _generate_html(evidence: EvidenceCollection, *, success_only: bool = False) -> str:
    """Generate HTML report (delegates to report_html)."""
    from report.report_html import _generate_html as _impl

    return _impl(evidence, success_only=success_only)

def _evidence_to_dict(evidence: EvidenceCollection, *, success_only: bool = False) -> dict[str, Any]:
    """ ( report_html).

    Includes: dual_judge_stats, owasp_web_compliance, web_vuln_stats, discovered_endpoints.
    """
    from report.report_html import _evidence_to_dict as _impl

    return _impl(evidence, success_only=success_only)

def _single_evidence_to_dict(ev: Any) -> dict[str, Any]:
    """converter(s) ( report_html)."""
    from report.report_html import _single_evidence_to_dict as _impl

    return _impl(ev)

def _parse_output_formats(args: Any) -> set[str]:
    """ P2-2:  --output-format

    :
        - None / "all" -> {"md", "html", "json", "sarif", "poc", "csv"}
        - "md" -> {"md"}
        - "md,json" / "md+json" -> {"md", "json"}
        - "html" -> {"md", "html"} (html md)

    Args:
        args: CLI

    Returns:
         format  (md/html/json/sarif/poc/csv)
    """
    raw = getattr(args, "output_format", None)

    # --html-report : html
    if getattr(args, "html_report", False) and not raw:
        raw = "html"

    # None / "all"
    if not raw or raw.lower() == "all":
        return {"md", "html", "json", "sarif", "poc", "csv"}

    # + /
    formats: set[str] = set()
    for part in raw.replace("+", ",").split(","):
        fmt = part.strip().lower()
        if fmt in ("md", "html", "json", "sarif", "poc", "csv"):
            formats.add(fmt)

    # html  md ( html  md  )
    if "html" in formats and "md" not in formats:
        formats.add("md")

    return formats if formats else {"md", "html", "json", "sarif", "poc", "csv"}

async def generate_report(
    ctx: Any,
    evidence: EvidenceCollection,
    output_dir: Path,
) -> Path:
    """all ( P2-2: --output-format )

    P2-2 output-format :
        - md: report.md + report_findings.md + report_executive.md + report_technical.md
        - html: report.html (md)
        - json: evidence.json + EVD-*.json
        - sarif: report.sarif ( CI/CD )
        - poc: poc_*.py ( PyRIT )
        - csv: attack_summary.csv + owasp_coverage_matrix.csv

    Args:
        ctx: PipelineContext .
        evidence: .
        output_dir: Output directory.

    Returns:
        .
    """
    output_dir = Path(output_dir)
    evidence_dir = output_dir / "evidence"
    poc_dir = output_dir / "poc"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    poc_dir.mkdir(parents=True, exist_ok=True)

 # == P2-2:  output-format ==
    output_formats = _parse_output_formats(ctx.args)
    logger.info(
        "P2-2: output-format=%s (md=%s html=%s json=%s sarif=%s poc=%s csv=%s)",
        output_formats,
        "md" in output_formats,
        "html" in output_formats,
        "json" in output_formats,
        "sarif" in output_formats,
        "poc" in output_formats,
        "csv" in output_formats,
    )

 # == PyRIT Native Output (R2: PyRIT ) ==
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

 # == Markdown Report (OffSec AI-300 Security Report) ==
 # P2-2: md format
    md_path = output_dir / "report.md"
    if "md" in output_formats:
        # v57: Layer - + + +
        from report.report_markdown import (
            _generate_executive_markdown,
            _generate_findings_markdown,
            _generate_technical_markdown,
        )

        md_content = _generate_markdown(evidence)
        md_path.write_text(md_content, encoding="utf-8")
        logger.info("Markdown report (index) saved to %s", md_path)

        # v57: Layer
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

        # == Markdown ==
        # v57: success_only = executive () + findings ()
        if evidence.successful_evidence:
            from report.report_markdown import _generate_executive_markdown as _gen_exec

            success_findings = _generate_findings_markdown(evidence, success_only=True)
            success_exec = _gen_exec(evidence)
            success_md = success_exec + "\n\n---\n\n" + success_findings
            success_md_path = output_dir / "report_success.md"
            success_md_path.write_text(success_md, encoding="utf-8")
            logger.info("Success-only Markdown report saved to %s", success_md_path)

 # == HTML (P2-2: html format) ==
    if "html" in output_formats:
        html_content = _generate_html(evidence)
        html_path = output_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report saved to %s", html_path)

        if evidence.successful_evidence:
            success_html = _generate_html(evidence, success_only=True)
            success_html_path = output_dir / "report_success.html"
            success_html_path.write_text(success_html, encoding="utf-8")
            logger.info("Success-only HTML report saved to %s", success_html_path)

 # == evidence JSON (P2-2: json format) ==
    if "json" in output_formats:
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

        # == EVD-*.json ==
        for ev in evidence.evidence:
            ev_filename = f"{ev.evidence_id}.json"
            ev_path = evidence_dir / ev_filename
            ev_path.write_text(
                json.dumps(_single_evidence_to_dict(ev), ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )

 # == PoC (P2-2: poc format) ==
    if "poc" in output_formats:
        # : , ,
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

 # == SARIF (P2-2: sarif format) ==
    if "sarif" in output_formats:
        try:
            from report.sarif_report import generate_sarif_report

            sarif_path = output_dir / "report.sarif"
            generate_sarif_report(evidence, sarif_path)
        except Exception as e:
            logger.warning("Failed to generate SARIF report: %s", e)

 # == CSV (P2-2: csv format) ==
    if "csv" in output_formats:
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

            # == ZIP ==
            _export_evidence_zip(output_dir, evidence)
            logger.info("Evidence ZIP saved to %s", output_dir / "evidence_package.zip")
        except Exception as e:
            logger.warning("Failed to export CSV/ZIP: %s", e)

    return md_path
