""" REPORT .

Academic basis:
    - OWASP LLM 2025 - Top 10

"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

async def _run_report_phase(
        ctx: "PipelineContext", output_dir: Path) -> None:
    """(6) REPORT : + """
    from utils.display import print_phase, print_report_card, print_status

    print_phase("REPORT", " & ...")
    from core.phases._helpers import _extract_auth_recovery_log
    from report.evidence import EvidenceCollector
    from report.generator import generate_report

    target_fingerprint = {}
    if ctx.parsed_request:
        target_fingerprint = ctx.parsed_request.target_fingerprint

    collector = EvidenceCollector(
        target_model=ctx.model_name,
        target_fingerprint=target_fingerprint,
    )
    evidence = collector.collect(
        attack_results=ctx.attack_results,
        scenario_result_id=ctx.scenario_result_id,
        asr_per_technique=ctx.asr_per_technique,
        overall_asr=ctx.overall_asr,
        memory_labels=ctx.memory_labels,
        orchestration_log=ctx.orchestration_log,
    )

    # evidence
    if hasattr(ctx, "dual_judge_stats") and ctx.dual_judge_stats:
        evidence.dual_judge_stats = ctx.dual_judge_stats
        evidence.wilson_ci = getattr(ctx, "wilson_ci", (0.0, 0.0))
        evidence.cohens_kappa = ctx.dual_judge_stats.get("cohens_kappa", 0.0) if ctx.dual_judge_stats else 0.0
        evidence.orchestration_log = ctx.orchestration_log

    #
    auth_recovery_log = _extract_auth_recovery_log(ctx)
    if auth_recovery_log:
        if hasattr(evidence, "attack_surface") and evidence.attack_surface:
            evidence.attack_surface["auth_recovery_attempts"] = len(auth_recovery_log)
            evidence.attack_surface["auth_recovery_log"] = auth_recovery_log

    # ( generate_report )
    _native_dir = output_dir / "native_output"
    _report_index_path = str(output_dir / "report.md")
    ctx.orchestration_log.append({
        "phase": "report",
        "decision": "report_generation",
        "input": {
            "evidence_count": evidence.total_attacks,
            "overall_asr": ctx.overall_asr,
        },
        "output": {
            "report_index": _report_index_path,
            "report_executive": str(output_dir / "report_executive.md"),
            "report_findings": str(output_dir / "report_findings.md"),
            "report_technical": str(output_dir / "report_technical.md"),
            "report_success": str(output_dir / "report_success.md") if evidence.successful_evidence else "",
            "native_output": str(_native_dir) if _native_dir.exists() else "",
        },
        "reasoning": f"Layer (ASR={ctx.overall_asr:.1f}%, {evidence.total_attacks} , 4 Layer)",
    })

    report_path = await generate_report(ctx, evidence, output_dir)
    print_report_card(
        total_attacks=evidence.total_attacks,
        successful_attacks=evidence.successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
        evidence_count=evidence.total_attacks,
        wilson_ci=getattr(ctx, "wilson_ci", (0.0, 0.0)),
        native_output_dir=str(_native_dir) if _native_dir.exists() else "",
    )
    print_status("REPORT", "DONE", "", ok=True)

    # === 数据流完整性快照: post_report ===
    try:
        from tools.data_flow_hooks import snapshot_hook
        snapshot_hook(ctx, "post_report")
    except Exception as e:
        logger.debug("[Report] Data flow snapshot skipped: %s", e)
