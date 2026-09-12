"""—  ( orchestrator() ).

:
- run_single_endpoint_to_result:  endpoint  (dict)
- run_single_endpoint:  endpoint  (pipeline 6 )

:
    >>> from core.phases.executor import run_single_endpoint_to_result
    >>> result = await run_single_endpoint_to_result(ctx, output_dir, "endpoint_1")
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_single_endpoint_to_result(
    ctx: "PipelineContext",
    ep_output_dir: Path,
    burp_name: str,
) -> dict[str, Any]:
    """endpoint  (dict).

    Academic basis: Greshake et al. (arXiv:2302.12173) - converter(s)

    Args:
        ctx:  ()
        ep_output_dir:  endpoint Output directory
        burp_name: endpoint  ()

    Returns:
        endpoint
    """
    await run_single_endpoint(ctx, ep_output_dir)

    #
    endpoint_str = ""
    if ctx.parsed_request:
        scheme = "https" if ctx.parsed_request.use_tls else "http"
        endpoint_str = f"{scheme}://{ctx.parsed_request.host}{ctx.parsed_request.path}"

    fp = {}
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint

    # === Gap #3: Credential Consumption ===
    # Generate final credential utilization report for red team deliverable
    try:
        from core.phases._credential_consume import generate_credential_report

        credential_report = generate_credential_report(ctx)
        logger.info(
            "[Execute] Credential report: %s",
            credential_report,
        )
    except Exception as e:
        logger.debug("[Execute] Credential report non-fatal: %s", e)

    return {
        "burp_name": burp_name,
        "endpoint": endpoint_str,
        "overall_asr": ctx.overall_asr,
        "total_attacks": sum(len(v) for v in ctx.attack_results.values()),
        "successful_attacks": sum(
            1 for results in ctx.attack_results.values() for r in results if _get_result_outcome(r) == "success"
        ),
        "asr_per_technique": ctx.asr_per_technique,
        "wilson_ci": getattr(ctx, "wilson_ci", (0.0, 0.0)),
        "capabilities": fp.get("capabilities", ""),
        "model_family": fp.get("model_family", ""),
    }


async def run_single_endpoint(
    ctx: "PipelineContext",
    output_dir: Path,
) -> None:
    """Run complete 6-phase attack pipeline for one endpoint.

    This is the main production entry point for single-endpoint attack execution.
    Academic basis: PyRIT (arXiv:2407.01232) - SequentialAttack +

    Args:
        ctx: Pipeline context with all required fields initialized
        output_dir: Output directory for this endpoint
    """
    from core.cleanup import cleanup_resources
    from core.phases.arm import _run_arm_phase
    from core.phases.assess import _run_assess_phase
    from core.phases.recon import _run_recon_phase
    from core.phases.report import _run_report_phase
    from core.phases.strike import _run_strike_phase

    args = ctx.args

    # == W0-4: EventLog 阶段埋点（REQ-148，旁路；--no-events 时 emit 为 no-op） ==
    # Data flow: 各阶段 -> emit_event(ctx, phase, "phase_start"/"phase_end") -> ctx.event_log
    #            -> 终端/报告/证据/续跑（蓝图第十三章，不变量 I12）
    # escalate 属 strike 内部逻辑（1.1 阶段词汇映射），不单列阶段事件
    from core.events import emit_event

    async def _emit_phase(phase: str, factory) -> Any:
        """执行一个阶段并在前后写事件；阶段异常不影响事件落盘。"""
        emit_event(ctx, phase, "phase_start")
        try:
            return await factory()
        finally:
            emit_event(ctx, phase, "phase_end")

    # ===========================================================================
    # (1) Recon: HTTP -> -> HTTPTarget
    # ===========================================================================
    await _emit_phase("recon", lambda: _run_recon_phase(ctx, output_dir))

    # == --stage recon: , ==
    if getattr(args, "stage", None) == "recon":
        from core.cleanup import cleanup_resources

        await cleanup_resources(ctx, exclude_shared=True)
        return

    # ===========================================================================
    # (3) ARM: + + Converter
    # ===========================================================================
    await _emit_phase("arm", lambda: _run_arm_phase(ctx))

    # == --stage arm: , ==
    if getattr(args, "stage", None) == "arm":
        await cleanup_resources(ctx, exclude_shared=True)
        return

    # ===========================================================================
    # (4) STRIKE: +
    # ===========================================================================
    await _emit_phase("strike", lambda: _run_strike_phase(ctx))

    # ===========================================================================
    # (5) ASSESS:
    # ===========================================================================
    await _emit_phase("assess", lambda: _run_assess_phase(ctx))

    # ===========================================================================
    # (6) REPORT: +
    # ===========================================================================
    await _emit_phase("report", lambda: _run_report_phase(ctx, output_dir))

    # :
    await cleanup_resources(ctx, exclude_shared=True)


#  —  _get_result_outcome
def _get_result_outcome(result: Any) -> str:
    """outcome (, from)"""
    try:
        from assess.asr_stats import _get_outcome

        return _get_outcome(result)
    except ImportError:
        pass

    # Fallback
    if hasattr(result, "converted_value"):
        return "success"
    return "failure"


#  run_attack_pipeline ( endpoints )
async def run_attack_pipeline(ctx: "PipelineContext", router: Any = None) -> None:
    """endpoint converter(s) + ASR.

    Academic basis: Greshake et al. (arXiv:2302.12173) - converter(s)

    Args:
        ctx:  ()
        router:  (optional)
    """
    args = ctx.args
    output_dir = ctx.output_dir

    from core.cleanup import cleanup_resources
    from core.config import ensure_output_dir
    from core.logging_config import switch_log_file
    from core.phases._helpers import (
        _detect_non_burp_mode,
        _print_endpoint_header,
        _print_endpoint_sort_results,
        _print_joint_asr_summary,
        _re_set_memory_labels,
        _register_dynamic_initializers,
        _reset_endpoint_state,
        _resolve_burp_list,
        _setup_memory_labels,
    )
    from utils.display import (
        print_status,
    )

    burp_list = _resolve_burp_list(args)
    _non_burp_mode = _detect_non_burp_mode(args)

    if _non_burp_mode:
        ctx.args.burp = burp_list[0] if burp_list else "request"
        await run_single_endpoint(ctx, output_dir)
        await cleanup_resources(ctx)
        return

    # Dry-run check (v2.0+: 使用 utils/dry_run.py)
    from utils.dry_run import get_dry_run_log_message, is_dry_run

    if is_dry_run(ctx.args):
        logger.info(get_dry_run_log_message("orchestrator"))
        print_status("ORCHESTRATOR", "DRY-RUN", "Skip", ok=True)
        return

    await _setup_memory_labels(ctx)
    await _register_dynamic_initializers(ctx)

    from recon.api.endpoint_sorter import sort_endpoints_by_priority

    sorted_endpoints = sort_endpoints_by_priority(burp_list)
    _print_endpoint_sort_results(sorted_endpoints)

    multi_endpoint_results: list[dict[str, Any]] = []
    for idx, ep_info in enumerate(sorted_endpoints):
        burp_path = ep_info["burp_path"]
        burp_name = ep_info["burp_name"]
        ctx._current_endpoint_idx = idx

        _print_endpoint_header(idx, len(burp_list), burp_name)

        ep_output_dir = output_dir / f"endpoint_{idx + 1}_{burp_name}"
        ensure_output_dir(ep_output_dir)
        ctx.output_dir = ep_output_dir
        switch_log_file(ep_output_dir)

        from core.config import setup_environment

        await setup_environment(ep_output_dir)

        if ctx.memory_labels:
            await _re_set_memory_labels(ctx, burp_name)

        ctx.args.burp = burp_path
        _reset_endpoint_state(ctx)

        try:
            ep_result = await run_single_endpoint_to_result(ctx, ep_output_dir, burp_name)
            multi_endpoint_results.append(ep_result)
        except ConnectionError as e:
            logger.error("Endpoint %s : %s", burp_name, e)
            multi_endpoint_results.append(
                {
                    "burp_name": burp_name,
                    "endpoint": "",
                    "overall_asr": 0.0,
                    "total_attacks": 0,
                    "successful_attacks": 0,
                    "error": str(e),
                }
            )
        except Exception as e:
            logger.error("Endpoint %s : %s", burp_name, e, exc_info=True)
            multi_endpoint_results.append(
                {
                    "burp_name": burp_name,
                    "endpoint": "",
                    "overall_asr": ctx.overall_asr,
                    "total_attacks": sum(len(v) for v in ctx.attack_results.values()),
                    "successful_attacks": sum(
                        1
                        for results in ctx.attack_results.values()
                        for r in results
                        if _get_result_outcome(r) == "success"
                    ),
                    "error": str(e),
                }
            )

    # Joint ASR computation
    switch_log_file(output_dir)
    from assess.asr_manager import build_joint_summary, save_joint_report

    joint_summary = build_joint_summary(multi_endpoint_results)
    joint_report_path = save_joint_report(joint_summary, output_dir)
    _print_joint_asr_summary(joint_summary, joint_report_path)

    print_status("JOINT", "DONE", f"Joint ASR = {joint_summary['joint_asr']:.1f}%", ok=True)
    await cleanup_resources(ctx)
