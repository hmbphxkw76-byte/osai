"""STRIKE + ESCALADE .

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - converter(s)
    - PyRIT (arXiv:2407.01232) - PromptSendingAttack
    - Shafran et al. (arXiv:2402.07967) - AI-300  OffSec
    - arXiv:2402.14266 - SkeletonKeyAttack (adversarial prefix injection)

This module is the STRIKE-phase orchestrator. The individual sub-phase runners
and report emitters were split out (SRP) into `core/phases/_strike_subphases.py`
and are re-exported here so all existing importers keep working.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


from core.phases._strike_subphases import (  # noqa: E402
    _adopt_escalation_results,
    _asr_as_percent,
    _build_target_info_from_service_profile,
    _emit_native_escalate_report,
    _emit_native_strike_report,
    _get_default_visible_content,
    _run_advanced_attacks_phase,
    _run_escalate_phase,
    _run_file_upload_phase,
    _run_stateful_chain_phase,
    _run_web_attacks_phase,
    _run_web_injection_phase,
)

async def _run_strike_phase(ctx: "PipelineContext") -> None:
    """(4) STRIKE : +"""
    from utils.display import (
        _is_success,
        print_phase,
        print_status,
        print_strike_phase_summary,
        print_strike_start_banner,
    )

    args = ctx.args
    print_phase("STRIKE", " PyRIT ...")

    # == P2: Guardrail/Stealth ==
    _has_guardrail = ctx.guardrail_report.get("has_guardrail", False) if ctx.guardrail_report else False
    _guardrail_severity = ctx.guardrail_report.get("severity", "none") if ctx.guardrail_report else "none"
    _guardrail_type = ctx.guardrail_report.get("guardrail_type", "unknown") if ctx.guardrail_report else "unknown"
    _stealth_name = ctx.stealth_policy.get("name", "balanced") if ctx.stealth_policy else "balanced"

    # MCPSec v2.7.2: Check for MCP surface data
    _has_mcpsec = bool(ctx.mcpsec_surface.get("tools")) if ctx.mcpsec_surface else False
    if _has_mcpsec:
        _mcp_tools_count = len(ctx.mcpsec_surface.get("tools", []))
        _mcp_vulns_count = len(ctx.mcpsec_scan_results.get("vulnerabilities", [])) if ctx.mcpsec_scan_results else 0
        logger.info(
            "[Strike] MCPSec surface data: %d tools, %d vulnerabilities available", _mcp_tools_count, _mcp_vulns_count
        )

    if _has_guardrail:
        logger.info(
            "[Strike] Guardrail detected: type=%s, severity=%s - stealth=%s",
            _guardrail_type,
            _guardrail_severity,
            _stealth_name,
        )

    #
    try:
        _ep_idx = getattr(ctx, "_current_endpoint_idx", None)
        _total_eps = None
        _burp_list = getattr(args, "_burp_list", None)
        if _burp_list and len(_burp_list) >= 1:
            _total_eps = len(_burp_list)
            print_strike_start_banner(ctx, total_endpoints=_total_eps, current_endpoint_idx=_ep_idx)
    except Exception:
        pass

    # v2.0+: dry-run 逻辑使用 utils/dry_run.py
    from utils.dry_run import get_dry_run_log_message, is_dry_run

    if is_dry_run(args):
        logger.info(get_dry_run_log_message("strike"))
        print_phase("STRIKE", "[DRY-RUN] Skip attack execution - Data flow")
        ctx.attack_results = {}
    else:
        #
        try:
            if args.techniques == "adaptive":
                print_phase("STRIKE", "TextAdaptive (e-)...")
                # W0 fix: `strike.adaptive_executor` never existed (the module lives at
                # strike/common/adaptive_executor.py) and `execute_text_adaptive` is not
                # implemented anywhere in this tree. Surface that explicitly (C9 honest
                # reporting) instead of letting ImportError fall into the generic except.
                logger.warning(
                    "[Strike] --techniques adaptive requested, but execute_text_adaptive is not "
                    "implemented. Falling back to standard multi-path attack."
                )
                from strike.common.executor import execute_attacks

                await execute_attacks(ctx)
            else:
                from strike.common.executor import execute_attacks

                await execute_attacks(ctx)
        except Exception as e:
            logger.error(": %s - ", e)
            print_phase("STRIKE", f": {e}")

    # == MCPSec IntegRAG/MCP Attacks (Dynamic Seeds) ==
    # Uses MCPSec bridge for dynamic seed generation when target is MCP-enabled
    if _has_mcpsec:
        try:
            print_phase("STRIKE", "MCPSec MCP/RAG Attack (Dynamic Seeds)...")
            from strike.mcp.rag_attack import run_mcp_rag_attacks

            mcp_results = await run_mcp_rag_attacks(ctx, [])
            if mcp_results:
                ctx.attack_results.update(mcp_results)
                logger.info(
                    "[Strike] MCPSec MCP/RAG attacks completed: %d results", sum(len(v) for v in mcp_results.values())
                )
        except Exception as e:
            logger.warning("[Strike] MCPSec MCP/RAG attacks failed: %s", e)

    # == AI300 Gap : OffSec AI-300 ==
    # arXiv:2402.07967 (Shafran) / arXiv:2106.09685 (Hu LoRA) /
    # arXiv:2307.14924 (Shu Backdoor) / arXiv:2301.11916 (Hubinger Sleeper) /
    _attack_count_before_escalation = sum(len(v) for v in ctx.attack_results.values())

    # === Web Page Injection Integration (arXiv:2302.12173) ===
    # Execute CSS hidden content injection for browser-based AI agents
    await _run_web_injection_phase(ctx)

    # === Web Security Attacks Integration ===
    # Execute web security attacks (JWT/Gateway/Audit) using service_profile data
    await _run_web_attacks_phase(ctx)

    # === Advanced Attacks Integration (arXiv-backed) ===
    # Execute output filter bypass / multimodal injection / backdoor attacks
    # arXiv:2402.05124 (Many-Shot Jailbreaking) / arXiv:2403.07860 (FigStep) / arXiv:2301.11916 (Sleeper Agents)
    await _run_advanced_attacks_phase(ctx)

    # === File Upload Attack Integration ===
    # Execute file upload + trigger chain for document injection attacks
    # arXiv:2302.12173 (Greshake Indirect Injection) / arXiv:2406.04245 (PoisonedRAG)
    await _run_file_upload_phase(ctx)

    # === plan Wave 3：有状态跨组件攻击链 ===
    # 在单组件攻击之后执行：先用 ComponentGraph 规划 DAG 链，再由状态机推进，
    # 步骤间通过 ChainState.acquired 传递产出（跨组件、有状态、可 checkpoint）。
    await _run_stateful_chain_phase(ctx)

    # == Phase Contract: Read ARM outputs (seeds, techniques, converter_map) ==
    # These values are set by the ARM phase and consumed by Strike phase
    _strike_seeds = ctx.seeds if hasattr(ctx, "seeds") else []
    _strike_techniques = ctx.techniques if hasattr(ctx, "techniques") else []
    _strike_converter_map = ctx.converter_map if hasattr(ctx, "converter_map") else {}

    # == : orchestration_log ==
    ctx.orchestration_log.append(
        {
            "phase": "strike",
            "decision": "attack_execution",
            "input": {
                "techniques": _strike_techniques,
                "converter_count": len(_strike_converter_map),
                "seed_count": len(_strike_seeds),
                "dry_run": is_dry_run(args),
                "has_guardrail": _has_guardrail,
                "guardrail_severity": _guardrail_severity,
                "mcpsec_tools": _mcp_tools_count if _has_mcpsec else 0,
                "mcpsec_vulnerabilities": _mcp_vulns_count if _has_mcpsec else 0,
            },
            "output": {
                "total_attacks": _attack_count_before_escalation,
                "results": {technique: len(results) for technique, results in ctx.attack_results.items()},
            },
            "reasoning": (f" + {_attack_count_before_escalation} "),
        }
    )

    # === : 2  ===
    _success_count = sum(1 for results in ctx.attack_results.values() for r in results if _is_success(r))

    _attack_count = sum(len(v) for v in ctx.attack_results.values())

    _strike_asr = _success_count / _attack_count * 100 if _attack_count > 0 else 0.0
    ctx.overall_asr = _strike_asr

    # == Component Bridge: Stamp component_type metadata on attack results ==
    # Ensures downstream scoring (component_router) and reporting (component_reports)
    # can classify results by component type (MCP/A2A/Model/RAG/Session/Web)
    try:
        from core.phases._component_bridge import stamp_component_metadata

        # 传入 RECON 识别出的组件图作为最优先的分类来源（plan Wave 6 / CB-2）
        # REQ-150：同时传入 SurfaceGraph，写入多标签归属（IC-1 / IC-3）
        stamp_component_metadata(
            ctx.attack_results,
            component_graph=getattr(ctx, "component_graph", None),
            surface_graph=getattr(ctx, "surface_graph", None),
        )
        logger.debug("[Strike] Component metadata stamped on attack results")
    except Exception as e:
        logger.debug("[Strike] Component bridge skipped: %s", e)

    # attack_results -> Score
    from assess.score_pipeline import precompute_outcomes_async

    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=True, reset_stats=True, ctx=ctx)
    except Exception as e:
        logger.debug(": %s", e)

    # == plan Wave 2.5（C2 合规）：补齐 ESCALATE 调用点 ==
    # `_run_escalate_phase` 此前**零调用点** —— 宪法 C2「单轮 ASR < 90% 必须可触发升级链」
    # 在运行时从不成立，Crescendo / TAP / SkeletonKey 三类多轮对抗能力完全不可达。
    # 触发判据用评分后的 ASR（上面的 precompute 已落 outcome），阈值走 C7 链路
    # （config/defaults.yaml:escalation_asr_threshold → args.escalate_threshold）。
    _escalation_report: dict[str, Any] = {}
    try:
        _success_count = sum(1 for results in ctx.attack_results.values() for r in results if _is_success(r))
        _attack_count = sum(len(v) for v in ctx.attack_results.values())
        _scored_asr = _success_count / _attack_count * 100 if _attack_count > 0 else 0.0
        ctx.overall_asr = _scored_asr
        _escalation_report = await _run_escalate_phase(ctx, current_asr_pct=_scored_asr)
    except Exception as e:
        logger.warning("[Strike] Escalation phase error (non-fatal): %s", e)
        _escalation_report = {"status": "error", "error": str(e)}

    if _escalation_report.get("adopted_results"):
        # 升级产出并入主结果集后需补盖章 + 补评分。已评分结果会被 precompute 跳过
        # （`_precomputed_outcome` 存在即 continue），因此这里只对新结果产生真实开销。
        try:
            from core.phases._component_bridge import stamp_component_metadata

            stamp_component_metadata(
                ctx.attack_results,
                component_graph=getattr(ctx, "component_graph", None),
                surface_graph=getattr(ctx, "surface_graph", None),
            )
        except Exception as e:
            logger.debug("[Strike] Re-stamp after escalation skipped: %s", e)
        try:
            await precompute_outcomes_async(ctx.attack_results, score_all=True, reset_stats=False, ctx=ctx)
        except Exception as e:
            logger.warning("[Strike] Post-escalation scoring failed: %s", e)

    # 升级可能新增结果 → 终值在此统一重算，保证摘要 / ASSESS / 报告口径一致（C3）
    _success_count = sum(1 for results in ctx.attack_results.values() for r in results if _is_success(r))
    _attack_count = sum(len(v) for v in ctx.attack_results.values())
    _strike_asr = _success_count / _attack_count * 100 if _attack_count > 0 else 0.0
    ctx.overall_asr = _strike_asr

    # W0 修复：按 print_strike_phase_summary(ctx, *, total_results, total_success, elapsed_seconds)
    # 的实际契约传参。此前误传 (asr=..., attack_count=...) → TypeError，
    # 在 STRIKE 阶段收尾处中断，导致后续组件盖章/报告全部拿不到结果。
    print_strike_phase_summary(
        ctx,
        total_results=_attack_count,
        total_success=_success_count,
        elapsed_seconds=float(getattr(ctx, "phase_elapsed", 0.0) or 0.0),
    )

    # == plan Wave 4：PyRIT 原生终端输出（C1 R-NATIVE-6）==
    # print_native_attack_result / print_native_scenario_result 已正确封装，但长期零调用点，
    # 终端上永远看不到 PyRIT 原生渲染的攻击证据。此处接通。
    await _emit_native_strike_report(ctx)

    print_status("STRIKE", "DONE", f"Attack={_attack_count}, Success={_success_count}, ASR={_strike_asr:.1f}%", ok=True)

    # === 数据流完整性快照: post_strike (含 ASR 取证数据) ===
    try:
        from tools.dataflow.hooks import snapshot_hook

        snapshot_hook(ctx, "post_strike")
        # ASR 取证快照: 记录 Why-Success 数据（成功证据/拒绝分类/护栏触发/时序）
        snapshot_hook(ctx, "post_assess_forensic")
    except Exception as e:
        logger.debug("[Strike] Data flow snapshot skipped: %s", e)

