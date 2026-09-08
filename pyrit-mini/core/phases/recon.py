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
