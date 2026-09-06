"""module."""
from __future__ import annotations
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
if TYPE_CHECKING:
    from core.context import PipelineContext
logger = logging.getLogger(__name__)
async def _run_recon_phase(ctx: "PipelineContext", output_dir: Path) -> None:
    from utils.display import print_phase, print_recon_card, print_status
    from recon.target_router import create_target
    try:
        await create_target(ctx)
    except ConnectionError as e:
        from utils.display import print_error
        raise
    except Exception as e:
        from utils.display import print_error
        raise
    _is_recon_only = getattr(ctx.args, "stage", None) == "recon"
    if ctx.parsed_request and not _is_recon_only:
    from core.phases._helpers import _record_recon_orchestration
    if _is_recon_only:
        from recon.recon_report import print_recon_report
        if ctx.parsed_request:
            print_recon_report(ctx.parsed_request, output_dir=output_dir)
        print_status("RECON", "DONE", "", ok=True)
async def _run_synergy_phase(ctx: "PipelineContext") -> None:
    args = ctx.args
    _synergy_enabled_flag = getattr(args, "synergy", True)
    if not _synergy_enabled_flag or not ctx.parsed_request:
        return
    from utils.display import print_phase, print_status
    try:
        from core.scenario_router import SynergyOrchestrator
        _burp_raw_content = None
        _burp_file_path = Path(ctx.args.burp)
        if not _burp_file_path.is_absolute():
            _burp_file_path = Path("config/burp") / _burp_file_path
        if not str(_burp_file_path).endswith(".txt"):
            _burp_file_path = _burp_file_path.with_suffix(".txt")
        if _burp_file_path.exists():
            _burp_raw_content = _burp_file_path.read_text(encoding="utf-8", errors="ignore")
        _orchestrator = SynergyOrchestrator()
        _syn_cfg = _orchestrator.build_synergy_config(
            burp_profile_name=ctx.args.burp.replace(".txt", ""),
            burp_raw_content=_burp_raw_content,
        ctx.synergy_config = _syn_cfg
        _tags_str = ", ".join(_syn_cfg.technique_tags) if _syn_cfg.technique_tags else "all (no filter)"
            f"={_syn_cfg.attack_surface}, "
            f"=[{_tags_str}], "
            f"={_syn_cfg.confidence:.2f}",
            ok=True,
    except Exception as e:
        ctx.synergy_config = None
async def _run_scenario_routing(ctx: "PipelineContext", router: Any = None) -> None:
    args = ctx.args
    _scenario_enabled = getattr(args, "scenario_enabled", True)
    if not _scenario_enabled or not ctx.synergy_config:
        return
    from core.scenario_router import apply_scenario_overrides
    from utils.display import print_status
    _router = router if router is not None else None
    if _router is None:
        from core.scenario_router import get_router
        _router = get_router()
    _scenario_name, _scenario_config = _router.select_scenario(
        classification=type('ClassificationResult', (), {
        user_override=getattr(args, "scenario", None),
    ctx.scenario_config = _scenario_config
    ctx.scenario_name = _scenario_name
    _filter = getattr(args, "adaptive_technique_filter", None)
    _filter_str = ", ".join(_filter) if _filter else "all (no filter)"
    logger.info("Scenario selected: %s, technique_filter=%s", _scenario_name, _filter_str)
        f"={ctx.synergy_config.attack_surface}, "
        f"Scenario={_scenario_name}, "
        f"=[{_filter_str}], "
        f"={ctx.synergy_config.confidence:.2f}",
        ok=True,
async def _run_auto_l4_optimization(ctx: "PipelineContext") -> None:
    args = ctx.args
    _auto_l4_enabled = getattr(args, "auto_l4_optimization_enabled", True)
    _auto_l4_threshold = getattr(args, "auto_l4_confidence_threshold", 0.8)
    _auto_l4_max_seeds = getattr(args, "auto_l4_max_seeds", 8)
    _auto_l4_surfaces = set(getattr(args, "auto_l4_agent_surfaces", [
    if not _auto_l4_enabled or not ctx.synergy_config:
        return
    _surface = ctx.synergy_config.attack_surface
    _confidence = ctx.synergy_config.confidence
    if _surface in _auto_l4_surfaces and _confidence >= _auto_l4_threshold:
        _user_specified_levels = getattr(args, "escalation_levels_parsed", None)
        if _user_specified_levels is None:
            _user_max_seeds = getattr(args, "max_seeds", None)
            if _user_max_seeds is None or _user_max_seeds > _auto_l4_max_seeds:
                "Auto L4 optimization activated: surface=%s, confidence=%.2f >= %.2f, "
            from utils.display import print_status
                f" Agent/MCP  (surface={_surface}, conf={_confidence:.2f}), "
                ok=True,
                    f"Eidam et al. (arXiv:2407.16924): confidence={_confidence:.2f} >= "
                    f"{_auto_l4_threshold:.2f}, surface={_surface} in auto_l4_surfaces. "
                    f"Using specialty seeds only (MCP/RAG/Agent), max_seeds={_auto_l4_max_seeds}"