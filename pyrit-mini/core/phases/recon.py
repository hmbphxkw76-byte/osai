""" RECON  +  + .

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - converter(s)
    - PyRIT (arXiv:2407.01232) - Target HTTP
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

async def _run_recon_phase(
        ctx: "PipelineContext", output_dir: Path) -> None:
    """(1) Recon : HTTP & """
    from utils.display import print_phase, print_recon_card, print_status

    print_phase(
        "RECON", " HTTP  & ...")
    from recon.target_router import create_target

    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error(": %s", e)
        from utils.display import print_error
        print_error(f": {e}\nRetry")
        raise
    except Exception as e:
        logger.error(": %s", e)
        from utils.display import print_error
        print_error(f": {e}")
        raise

    #
    _is_recon_only = getattr(
        ctx.args, "stage", None) == "recon"
    if ctx.parsed_request and not _is_recon_only:
        print_recon_card(ctx)

        # :
        from core.phases._helpers import _record_recon_orchestration
        _record_recon_orchestration(ctx)

        # RAG Pipeline Probe (P1 enhancement): KB structure + citations + chunking
        if getattr(ctx.args, "rag_probe", True) and ctx.parsed_request:
            try:
                from recon.rag_pipeline_probe import run_rag_pipeline_probe
                rag_profile = await run_rag_pipeline_probe(ctx.parsed_request)
                if rag_profile.has_rag:
                    ctx.service_profile["rag_pipeline"] = rag_profile.to_dict()
                    logger.info(
                        "[Recon] RAG detected: namespaces=%d, collections=%d, citations=%d",
                        len(rag_profile.kb_namespaces),
                        len(rag_profile.kb_collections),
                        len(rag_profile.citation_markers),
                    )
            except Exception as e:
                logger.debug("[Recon] RAG probe skipped: %s", e)

            # RAG Metadata Auto-Parser: format-agnostic structured field extraction
            # Runs only when RAG pipeline probe confirms RAG presence
            if rag_profile.has_rag and getattr(ctx.args, "rag_metadata", True):
                try:
                    from recon.rag_metadata_parser import run_rag_metadata_collection
                    num_queries = getattr(ctx.args, "rag_metadata_queries", 15)
                    kb_map = await run_rag_metadata_collection(
                        ctx.parsed_request,
                        num_queries=num_queries,
                        max_concurrency=2,
                    )
                    if kb_map.document_count > 0:
                        ctx.service_profile["rag_kb_map"] = kb_map.to_dict()
                        logger.info(
                            "[Recon] RAG KB mapped: documents=%d, formula=%s, chunk_size=%s",
                            kb_map.document_count,
                            kb_map.inferred_retrieval_formula,
                            kb_map.inferred_chunk_size,
                        )
                except Exception as e:
                    logger.debug("[Recon] RAG metadata collection skipped: %s", e)

            # RAG Typo Fuzzer: query rewriting / fuzzy matching detection
            if rag_profile.has_rag and getattr(ctx.args, "rag_typo_fuzz", True):
                try:
                    from recon.rag_typo_fuzzer import run_typo_fuzzing
                    typo_report = await run_typo_fuzzing(
                        ctx.parsed_request,
                        max_concurrency=2,
                        variants_per_query=3,
                    )
                    if typo_report.has_rag:
                        ctx.service_profile["rag_typo_fuzz"] = typo_report.to_dict()
                        logger.info(
                            "[Recon] Typo fuzz: tests=%d, rewriting=%s, bm25_poisoning=%s, failure_rate=%.2f",
                            typo_report.total_tests,
                            typo_report.query_rewriting_detected,
                            typo_report.vulnerable_to_bm25_poisoning,
                            typo_report.failure_rate,
                        )
                except Exception as e:
                    logger.debug("[Recon] RAG typo fuzzing skipped: %s", e)

        # MCPSec v2.7.2: MCP Security Scanning (replaces self-developed mcp_enumerator)
        # Architecture alignment: MCPSecBridge.enumerate_surface() -> ctx.mcpsec_surface
        #                         MCPSecBridge.scan_target() -> ctx.mcpsec_scan_results
        target_url = getattr(ctx.args, "target_url", None) if hasattr(ctx, "args") else None
        if target_url:
            await _run_mcpsec_reconnaissance(ctx, target_url)

        # --stage recon (minimal output, red team focus)
        if _is_recon_only:
            if ctx.parsed_request:
                # Save fingerprint JSON if output_dir provided
                if output_dir:
                    import json
                    fp = ctx.parsed_request.target_fingerprint
                    fp_path = output_dir / "recon_fingerprint.json"
                    fp_path.write_text(
                        json.dumps(fp, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                print_status("RECON", "DONE", "", ok=True)

async def _run_mcpsec_reconnaissance(
        ctx: "PipelineContext", target_url: str) -> None:
    """Execute MCPSec reconnaissance phase with production-grade observability.

    Architecture alignment:
        - enumerate_surface() -> ctx.mcpsec_surface (tools, resources, prompts)
        - scan_target() -> ctx.mcpsec_scan_results (vulnerabilities)

    Data contract:
        ctx.mcpsec_surface = {
            "tools": [{"name", "description", "inputSchema"}],
            "resources": [{"uri", "name", "description"}],
            "prompts": [{"name", "description"}]
        }
        ctx.mcpsec_scan_results = {
            "vulnerabilities": [{"severity", "scanner", "description", "target"}]
        }
    """
    import time

    from tools.mcpsec_factory import get_shared_bridge

    bridge = get_shared_bridge()
    if not bridge or not bridge.is_available:
        logger.info("[Recon] MCPSec not installed reconnaissance skipped")
        return

    mcpsec_start = time.monotonic()
    enum_result: dict[str, Any] = {}
    scan_result: dict[str, Any] = {"vulnerabilities": []}

    try:
        # Phase 1: Enumerate attack surface
        try:
            mcp_info = await bridge.enumerate_surface(target_url)
            # Architecture compliance: ensure dict format for ctx.mcpsec_surface
            if isinstance(mcp_info, dict):
                enum_result = mcp_info
            else:
                # Convert from object format to dict (defensive)
                enum_result = {
                    "tools": getattr(mcp_info, "tools", []),
                    "resources": getattr(mcp_info, "resources", []),
                    "prompts": getattr(mcp_info, "prompts", []),
                    "raw": str(mcp_info),
                }
            ctx.mcpsec_surface = enum_result
            ctx.mcpsec_version = bridge.version or "unknown"

            logger.info(
                "[Recon] MCPSec enumerate complete: %d tools, %d resources, %d prompts",
                len(enum_result.get("tools", [])),
                len(enum_result.get("resources", [])),
                len(enum_result.get("prompts", [])),
            )
        except Exception as e:
            logger.warning("[Recon] MCPSec enumerate failed: %s", e)

        # Phase 2: Vulnerability scan
        try:
            raw_scan_results = await bridge.scan_target(target_url)
            # Architecture compliance: normalize to dict format
            vulns = []
            for r in raw_scan_results:
                vulns.append({
                    "scanner": r.scanner,
                    "vulnerability": r.vulnerability,
                    "severity": r.severity,
                    "description": r.evidence,
                    "target": r.tool_name,
                    "payload": r.payload,
                })
            scan_result["vulnerabilities"] = vulns
            ctx.mcpsec_scan_results = scan_result

            logger.info(
                "[Recon] MCPSec scan complete: %d vulnerabilities (C:%d H:%d M:%d L:%d)",
                len(vulns),
                sum(1 for v in vulns if v["severity"] == "critical"),
                sum(1 for v in vulns if v["severity"] == "high"),
                sum(1 for v in vulns if v["severity"] == "medium"),
                sum(1 for v in vulns if v["severity"] in ("low", "info")),
            )
        except Exception as e:
            logger.debug("[Recon] MCPSec scan non-fatal: %s", e)

    finally:
        # Production observability: orchestration_log audit trail
        elapsed = time.monotonic() - mcpsec_start
        if hasattr(ctx, "orchestration_log"):
            ctx.orchestration_log.append({
                "phase": "recon",
                "decision": "mcpsec_reconnaissance",
                "input": {"target_url": target_url, "mcpsec_version": ctx.mcpsec_version},
                "output": {
                    "tools_found": len(enum_result.get("tools", [])),
                    "vulnerabilities_found": len(scan_result.get("vulnerabilities", [])),
                    "elapsed_seconds": round(elapsed, 2),
                },
                "reasoning": f"MCPSec v{ctx.mcpsec_version} reconnaissance completed",
            })


async def _run_synergy_phase(
        ctx: "PipelineContext") -> None:
    """(2).5 + """
    args = ctx.args
    _synergy_enabled_flag = getattr(
        args, "synergy", True)
    if not _synergy_enabled_flag or not ctx.parsed_request:
        return

    from utils.display import print_phase, print_status
    print_phase(
        "SYNERGY", " + ...")
    try:
        # v61:
        # SynergyOrchestrator
        # data/
        # core/scenario_router.py
        from core.scenario_router import SynergyOrchestrator
        _synergy_orchestrator = SynergyOrchestrator(ctx)
        ctx.synergy_config = await _synergy_orchestrator.run_synergy()
        if ctx.synergy_config:
            logger.info(
                "[Synergy] Attack surface: %s (confidence: %.2f)",
                ctx.synergy_config.attack_surface,
                ctx.synergy_config.confidence,
            )
            print_status(
                "SYNERGY", "DONE",
                f"surface={ctx.synergy_config.attack_surface}",
                ok=True)
    except Exception as e:
        logger.error(
            "[Synergy] : %s - ", e)

async def _run_scenario_routing(
        ctx: "PipelineContext", router: Any = None) -> None:
    """(2).7 Scenario """
    args = ctx.args
    if not getattr(args, "scenario_routing", True):
        return

    from utils.display import print_phase, print_status
    print_phase(
        "SCENARIO", " AI ")

    try:
        from core.scenario_router import ScenarioRouter
        _scenario_router = router or ScenarioRouter(ctx)
        scenario_result = await _scenario_router.run_scenario()
        ctx.scenario_result_id = scenario_result.get("result_id")
        logger.info(
            "[Scenario] %s",
            ctx.scenario_result_id)
        print_status(
            "SCENARIO", "DONE",
            f"={ctx.scenario_result_id}",
            ok=True)
    except Exception as e:
        logger.debug("[Scenario] : %s", e)

async def _run_auto_l4_optimization(
        ctx: "PipelineContext") -> None:
    """(2).6 L4 """
    args = ctx.args
    if not getattr(args, "auto_l4", False):
        return

    from utils.display import print_phase, print_status
    print_phase(
        "L4-OPT", " L4 ")

    try:
        from core.auto_l4_optimizer import AutoL4Optimizer
        _l4_optimizer = AutoL4Optimizer(ctx)
        l4_result = await _l4_optimizer.run()
        logger.info(
            "[L4-Opt] : %s",
            l4_result.get("status", ""))
        print_status("L4-OPT", "DONE", "", ok=True)
    except Exception as e:
        logger.debug("[L4-Opt] : %s", e)
