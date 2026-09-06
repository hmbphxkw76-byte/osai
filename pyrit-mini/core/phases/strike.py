"""module."""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING, Any
if TYPE_CHECKING:
    from core.context import PipelineContext
logger = logging.getLogger(__name__)
async def _run_strike_phase(ctx: "PipelineContext") -> None:
    from utils.display import (
    args = ctx.args
    _has_guardrail = ctx.guardrail_report.get("has_guardrail", False) if ctx.guardrail_report else False
    _guardrail_severity = ctx.guardrail_report.get("severity", "none") if ctx.guardrail_report else "none"
    _guardrail_type = ctx.guardrail_report.get("guardrail_type", "unknown") if ctx.guardrail_report else "unknown"
    _stealth_name = ctx.stealth_policy.get("name", "balanced") if ctx.stealth_policy else "balanced"
    if _has_guardrail:
            "[Strike] Guardrail detected: type=%s, severity=%s  stealth=%s",
        if _guardrail_severity in ("high", "critical") and _stealth_name in ("balanced", "aggressive"):
    try:
        _ep_idx = getattr(ctx, "_current_endpoint_idx", None)
        _total_eps = None
        _burp_list = getattr(args, "_burp_list", None)
        if _burp_list and len(_burp_list) >= 1:
            _total_eps = len(_burp_list)
        print_strike_start_banner(ctx, total_endpoints=_total_eps, current_endpoint_idx=_ep_idx)
    except Exception:
        pass
    _is_dry_run = getattr(args, "dry_run", False)
    if _is_dry_run:
        ctx.attack_results = {}
    else:
        if args.techniques == "adaptive":
            from strike.adaptive_executor import execute_text_adaptive
            try:
                await execute_text_adaptive(ctx)
            except Exception as e:
                from strike.executor import execute_attacks
                try:
                    await execute_attacks(ctx)
                except Exception as e2:
        else:
            from strike.executor import execute_attacks
            try:
                await execute_attacks(ctx)
            except Exception as e:
    if not _is_dry_run:
        await print_strike_report_async(ctx)
    if not _is_dry_run:
        try:
            _strike_elapsed = getattr(ctx, "_strike_elapsed", 0.0)
            _total_results = sum(len(v) for v in ctx.attack_results.values())
            _total_success = sum(
                for r in results if _is_success(r)
                total_results=_total_results,
                total_success=_total_success,
                elapsed_seconds=_strike_elapsed,
        except Exception:
            pass
    from core.context import get_effective_concurrency as _get_concurrency
            "mode": "dry_run" if _is_dry_run else ("adaptive" if args.techniques == "adaptive" else "multi_path"),
    if getattr(args, "stage", None) == "strike":
        print_status("STRIKE", "DONE", "", ok=True)
        return
    await _run_escalate_phase(ctx, args)
    if getattr(args, "stage", None) in ("strike", "escalate"):
        return
async def _run_escalate_phase(ctx: "PipelineContext", args: Any = None) -> None:
    from utils.display import print_phase, print_status
    if args is None:
        args = ctx.args
    _is_dry_run = getattr(args, "dry_run", False)
    should_escalate = getattr(ctx.args, "escalation", True)
    if _is_dry_run:
    elif should_escalate:
        from strike.escalation import check_and_escalate
        try:
            await check_and_escalate(ctx, ctx.attack_results)
        except Exception as e:
    else:
    _esc_threshold_val = getattr(ctx.args, "escalation_asr_threshold", 90)
    _post_l1_val = getattr(ctx.args, "post_l1_exit_threshold", 70)
    _post_l2_val = getattr(ctx.args, "post_l2_exit_threshold", 80)
                if getattr(ctx.args, "escalation_levels_parsed", None) else "L1L2L3L4 (full chain)"
    if not _is_dry_run:
        from utils.display import print_escalate_report_async
        await print_escalate_report_async(ctx)
    if getattr(args, "stage", None) == "escalate":
        print_status("ESCALATE", "DONE", "", ok=True)
        return