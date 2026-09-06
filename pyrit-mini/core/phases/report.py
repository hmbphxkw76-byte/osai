"""module."""
from __future__ import annotations
import logging
from pathlib import Path
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from core.context import PipelineContext
logger = logging.getLogger(__name__)
async def _run_report_phase(ctx: "PipelineContext", output_dir: Path) -> None:
    from utils.display import print_phase, print_report_card, print_status
    from report.evidence import EvidenceCollector
    from report.generator import generate_report
    target_fingerprint = {}
    if ctx.parsed_request:
        target_fingerprint = ctx.parsed_request.target_fingerprint
    collector = EvidenceCollector(
        target_model=ctx.model_name,
        target_fingerprint=target_fingerprint,
    evidence = collector.collect(
        attack_results=ctx.attack_results,
        scenario_result_id=ctx.scenario_result_id,
        asr_per_technique=ctx.asr_per_technique,
        overall_asr=ctx.overall_asr,
        memory_labels=ctx.memory_labels,
        orchestration_log=ctx.orchestration_log,
    if hasattr(ctx, "dual_judge_stats") and ctx.dual_judge_stats:
        evidence.dual_judge_stats = ctx.dual_judge_stats
    evidence.wilson_ci = getattr(ctx, "wilson_ci", (0.0, 0.0))
    evidence.cohens_kappa = ctx.dual_judge_stats.get("cohens_kappa", 0.0) if ctx.dual_judge_stats else 0.0
    evidence.orchestration_log = ctx.orchestration_log
    from core.phases._helpers import _extract_auth_recovery_log
    auth_recovery_log = _extract_auth_recovery_log(ctx)
    if auth_recovery_log:
        if hasattr(evidence, "attack_surface") and evidence.attack_surface:
            evidence.attack_surface["auth_recovery_attempts"] = len(auth_recovery_log)
            evidence.attack_surface["auth_recovery_log"] = auth_recovery_log
    _native_dir = output_dir / "native_output"
    _report_index_path = str(output_dir / "report.md")
        "reasoning": f" (ASR={ctx.overall_asr:.1f}%, {evidence.total_attacks} , 4 )",
    report_path = await generate_report(ctx, evidence, output_dir)
        total_attacks=evidence.total_attacks,
        successful_attacks=evidence.successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
        evidence_count=evidence.total_attacks,
        wilson_ci=getattr(ctx, "wilson_ci", (0.0, 0.0)),
        native_output_dir=str(_native_dir) if _native_dir.exists() else "",
    print_status("REPORT", "DONE", "", ok=True)