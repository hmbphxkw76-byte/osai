""" STRIKE + ESCALADE .

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - converter(s)
    - PyRIT (arXiv:2407.01232) - PromptSendingAttack
    - Shafran et al. (arXiv:2402.07967) - AI-300  OffSec
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

async def _run_strike_phase(
        ctx: "PipelineContext") -> None:
    """(4) STRIKE : + """
    from utils.display import (
        _is_success,
        print_phase,
        print_status,
        print_strike_phase_summary,
        print_strike_start_banner,
    )

    args = ctx.args
    print_phase(
        "STRIKE", " PyRIT ...")

    # == P2: Guardrail/Stealth ==
    _has_guardrail = ctx.guardrail_report.get(
        "has_guardrail", False) if ctx.guardrail_report else False
    _guardrail_severity = ctx.guardrail_report.get(
        "severity", "none") if ctx.guardrail_report else "none"
    _guardrail_type = ctx.guardrail_report.get(
        "guardrail_type", "unknown") if ctx.guardrail_report else "unknown"
    _stealth_name = ctx.stealth_policy.get(
        "name", "balanced") if ctx.stealth_policy else "balanced"

    # MCPSec v2.7.2: Check for MCP surface data
    _has_mcpsec = bool(ctx.mcpsec_surface.get("tools")) if ctx.mcpsec_surface else False
    if _has_mcpsec:
        _mcp_tools_count = len(ctx.mcpsec_surface.get("tools", []))
        _mcp_vulns_count = len(ctx.mcpsec_scan_results.get("vulnerabilities", [])) if ctx.mcpsec_scan_results else 0
        logger.info("[Strike] MCPSec surface data: %d tools, %d vulnerabilities available", _mcp_tools_count, _mcp_vulns_count)

    if _has_guardrail:
        logger.info(
            "[Strike] Guardrail detected: type=%s, severity=%s - stealth=%s",
            _guardrail_type,
            _guardrail_severity,
            _stealth_name,
        )

    #
    try:
        _ep_idx = getattr(
            ctx, "_current_endpoint_idx", None)
        _total_eps = None
        _burp_list = getattr(
            args, "_burp_list", None)
        if _burp_list and len(
                _burp_list) >= 1:
            _total_eps = len(
                _burp_list)
            print_strike_start_banner(
                ctx, total_endpoints=_total_eps, current_endpoint_idx=_ep_idx)
    except Exception:
        pass

    _is_dry_run = getattr(
        args, "dry_run", False)

    if _is_dry_run:
        logger.info(
            "[DRY-RUN] Skip attack execution (strike ) -  token ")
        print_phase(
            "STRIKE", "[DRY-RUN] Skip attack execution - Data flow")
        ctx.attack_results = {}
    else:
        #
        try:
            if args.techniques == "adaptive":
                print_phase(
                    "STRIKE", "TextAdaptive (e-)...")
                from strike.adaptive_executor import execute_text_adaptive
                await execute_text_adaptive(ctx)
            else:
                from strike.executor import execute_attacks
                await execute_attacks(ctx)
        except Exception as e:
            logger.error(
                ": %s - ", e)
            print_phase(
                "STRIKE", f": {e}")

    # == MCPSec IntegRAG/MCP Attacks (Dynamic Seeds) ==
    # Uses MCPSec bridge for dynamic seed generation when target is MCP-enabled
    if _has_mcpsec:
        try:
            print_phase("STRIKE", "MCPSec MCP/RAG Attack (Dynamic Seeds)...")
            from strike.mcp_rag_attack import run_mcp_rag_attacks
            mcp_results = await run_mcp_rag_attacks(ctx, [])
            if mcp_results:
                ctx.attack_results.update(mcp_results)
                logger.info("[Strike] MCPSec MCP/RAG attacks completed: %d results", sum(len(v) for v in mcp_results.values()))
        except Exception as e:
            logger.warning("[Strike] MCPSec MCP/RAG attacks failed: %s", e)

    # == AI300 Gap : OffSec AI-300 ==
    # arXiv:2402.07967 (Shafran) / arXiv:2106.09685 (Hu LoRA) /
    # arXiv:2307.14924 (Shu Backdoor) / arXiv:2301.11916 (Hubinger Sleeper) /
    _attack_count_before_escalation = sum(
        len(v) for v in ctx.attack_results.values())

    # == : orchestration_log ==
    ctx.orchestration_log.append({
        "phase": "strike",
        "decision": "attack_execution",
        "input": {
            "techniques": getattr(ctx, "techniques", []),
            "converter_count": len(getattr(ctx, "converter_map", {})),
            "seed_count": len(getattr(ctx, "seeds", [])),
            "dry_run": _is_dry_run,
            "has_guardrail": _has_guardrail,
            "guardrail_severity": _guardrail_severity,
            "mcpsec_tools": _mcp_tools_count if _has_mcpsec else 0,
            "mcpsec_vulnerabilities": _mcp_vulns_count if _has_mcpsec else 0,
        },
        "output": {
            "total_attacks": _attack_count_before_escalation,
            "results": {
                technique: len(results)
                for technique, results in ctx.attack_results.items()
            },
        },
        "reasoning": (
            f" + {_attack_count_before_escalation} "
        ),
    })

    # === : 2  ===
    _success_count = sum(
        1
        for results in ctx.attack_results.values()
        for r in results
        if _is_success(r)
    )

    _attack_count = sum(
        len(v) for v in ctx.attack_results.values())

    _strike_asr = (
        _success_count / _attack_count * 100
        if _attack_count > 0
        else 0.0
    )

    # attack_results -> Score
    from assess.score_pipeline import precompute_outcomes_async
    try:
        await precompute_outcomes_async(
            ctx.attack_results, score_all=True, reset_stats=True)
    except Exception as e:
        logger.debug(": %s", e)

    print_strike_phase_summary(
        asr=_strike_asr, attack_count=_attack_count)

    print_status(
        "STRIKE", "DONE",
        f"Attack={_attack_count}, Success={_success_count}, ASR={_strike_asr:.1f}%",
        ok=True)

async def _run_escalate_phase(
        ctx: "PipelineContext") -> None:
    """(4.5) ESCALADE :  + crescendo

    Crescende,  ASR
    """
    from utils.display import print_phase

    args = ctx.args

    # escalate
    if not getattr(args, "escalation", True):
        logger.info("[Escalation] Disabled by user (--no-escalation)")
        return

    _escalate_threshold = getattr(args, "escalate_threshold", 30.0)
    _current_asr = getattr(ctx, "overall_asr", 0.0)

    if _current_asr >= _escalate_threshold:
        logger.info(
            "[Escalation] Current ASR (%.1f%%) >= threshold (%.1f%%) - escalation skipped",
            _current_asr, _escalate_threshold)
        return

    # === Gap #5: Escalation Chain Implementation ===
    # Replaces deferred placeholder with real multi-turn escalation
    try:
        from strike.escalation_runtime import run_escalation_chain
        esc_report = await run_escalation_chain(ctx)

        if esc_report.get("status") == "complete":
            logger.info(
                "[Escalation] Chain complete: %.1f%% → %.1f%% via %s",
                esc_report.get("primary_asr", 0.0) * 100,
                esc_report.get("escalated_asr", 0.0) * 100,
                esc_report.get("strategy", "unknown"),
            )
            print_phase(
                "ESCALATION",
                f"ASR {esc_report.get('primary_asr', 0.0) * 100:.1f}% → "
                f"{esc_report.get('escalated_asr', 0.0) * 100:.1f}% "
                f"via {esc_report.get('strategy', 'unknown')}",
            )

            # If escalation improved ASR, update context
            escalated_asr = esc_report.get("escalated_asr", 0.0)
            if escalated_asr > _current_asr:
                ctx.overall_asr = max(ctx.overall_asr, escalated_asr)
                logger.info(
                    "[Escalation] ASR updated: %.1f%% → %.1f%%",
                    _current_asr, ctx.overall_asr,
                )
        else:
            logger.info(
                "[Escalation] No escalation needed: %s",
                esc_report.get("reason", "saturated"),
            )
    except Exception as e:
        logger.warning("[Escalation] Escalation chain error: %s", e)

