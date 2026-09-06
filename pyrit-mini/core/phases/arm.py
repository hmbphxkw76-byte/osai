"""module."""
from __future__ import annotations
import logging
import math
from typing import TYPE_CHECKING, Any
if TYPE_CHECKING:
    from core.context import PipelineContext
logger = logging.getLogger(__name__)
def _get_adaptive_max_seeds(ctx: "PipelineContext", default_max: int = 25) -> int:
    probe_ctx = getattr(ctx, "adaptive_probe_ctx", None) or {}
    budget_raw = probe_ctx.get("probe_budget")
    if not isinstance(budget_raw, int) or budget_raw <= 0:
        return default_max
    calculated = min(50, max(5, int(math.sqrt(budget_raw) * 3.5)))
        "[Adaptive] probe_budget=%d  adaptive max_seeds=%d (default=%d)",
    return calculated
def _is_converter_allowed(converter: Any, allowed_list: list[str]) -> bool:
    if "all" in allowed_list:
        return True
    c_name = converter if isinstance(converter, str) else getattr(converter, "converter_name", None)
    if c_name is None:
        return True
    return c_name in allowed_list
async def _run_arm_phase(ctx: "PipelineContext") -> None:
    from utils.display import print_arm_card, print_arm_highlights, print_phase, print_status
    args = ctx.args
    from arm.converter_presets import _classify_target_type, build_converter_map
    from arm.seed_ranker import load_asr_priors, load_seeds
    from arm.technique_picker import augment_techniques_by_capability, filter_by_adversarial, select_techniques
    from core.phases._helpers import _extract_target_profile
    target_language, target_capabilities, target_model_family = _extract_target_profile(ctx)
    model_priors = load_asr_priors(target_model_family) if target_model_family else {}
    _adaptive_max_seeds = _get_adaptive_max_seeds(ctx, default_max=args.max_seeds or 25)
    ctx.seeds = load_seeds(
        target_language=target_language,
        enable_dos=getattr(args, "enable_dos", False),
        capabilities=target_capabilities,
        model_family=target_model_family,
        seed_filters=getattr(args, "seed_filters_parsed", None),
        model_priors=model_priors,
    _seed_files_count = len(args.seeds.split(",")) if args.seeds else 0
        f" (files={_seed_files_count}, lang={target_language or 'auto'})",
        ok=True,
    from core.phases._helpers import _record_arm_seed_orchestration
    await _generate_openapi_seeds(ctx)
    if getattr(args, "auto_seeds", False) and ctx.converter_target:
        from arm.seed_ranker import auto_generate_seeds_async
        _expansion_factor = getattr(args, "auto_seed_expansion_factor", 3)
        if not isinstance(_expansion_factor, int) or _expansion_factor < 1:
            _expansion_factor = 3
        ctx.seeds = await auto_generate_seeds_async(
            converter_target=ctx.converter_target,
            expansion_factor=_expansion_factor,
        print_status("ARM", "DONE", f"AutoDAN  {len(ctx.seeds)} ", ok=True)
    has_adversarial = ctx.adversarial_target is not None
    ctx.techniques = select_techniques(args.techniques, has_adversarial=has_adversarial)
    ctx.techniques = filter_by_adversarial(ctx.techniques, has_adversarial)
    ctx.techniques = augment_techniques_by_capability(ctx.techniques, target_capabilities)
    _guardrail_report = getattr(ctx, "guardrail_report", None) or {}
    _stealth_policy = getattr(ctx, "stealth_policy", None) or {}
    _has_guardrail = _guardrail_report.get("has_guardrail", False)
    _guardrail_severity = _guardrail_report.get("severity", "unknown")
    if _has_guardrail or _stealth_policy:
        _original_count = len(ctx.techniques)
        _disabled_techniques = _stealth_policy.get("disabled_techniques", [])
        if isinstance(_disabled_techniques, list) and _disabled_techniques:
            ctx.techniques = [t for t in ctx.techniques if t not in _disabled_techniques]
        _recommended_techniques = _stealth_policy.get("recommended_techniques", [])
        if isinstance(_recommended_techniques, list) and _recommended_techniques:
            for _rec_tech in _recommended_techniques:
                if _rec_tech not in ctx.techniques:
        if _has_guardrail and _guardrail_severity in ("high", "critical"):
            _stealth_priority = {"skeleton_key", "context_compliance", "role_play_persuasion"}
                key=lambda t: (0 if t in _stealth_priority else 1, t)
        _new_count = len(ctx.techniques)
        if _original_count != _new_count:
                "%d  %d (guardrail=%s, severity=%s)",
            f"(capabilities={target_capabilities or 'none'}, guardrail={_has_guardrail})"
    if args.converters == "none":
        chain_names = []
    elif args.converters == "auto":
        chain_names = ["l5_optimal"]
    else:
        chain_names = args.converters.split(",")
    _target_fingerprint = None
    if ctx.parsed_request:
        _target_fingerprint = ctx.parsed_request.target_fingerprint
    _target_type = _classify_target_type(target_capabilities, _target_fingerprint)
    if _target_fingerprint is not None:
        _target_fingerprint.extra["target_type"] = _target_type
    ctx.converter_map = build_converter_map(
        technique_names=ctx.techniques,
        chain_names=chain_names,
        converter_target=ctx.converter_target,
        model_family=target_model_family,
        target_type=_target_type,
        target_fingerprint=_target_fingerprint,
        converter_overrides=getattr(args, "converter_overrides", None),
        seeds=ctx.seeds,
    _stealth_allowed = ctx.stealth_policy.get("allowed_converters") if ctx.stealth_policy else None
    if isinstance(_stealth_allowed, list) and len(_stealth_allowed) > 0 and ctx.converter_map:
        _filtered_map = {}
        _dropped_count = 0
        for _tech, _converters in ctx.converter_map.items():
            _filtered = [
                if _is_converter_allowed(_c, _stealth_allowed)
            if _filtered:
                _filtered_map[_tech] = _filtered
            _dropped_count += len(_converters) - len(_filtered)
        if _dropped_count > 0:
                "[Stealth] Filtered %d converters (policy=%s, allowed=%s)",
        ctx.converter_map = _filtered_map
            f"(target_type={_target_type}, model_family={target_model_family or 'default'})"
    _is_arm_only_stage = getattr(args, "stage", None) == "arm"
    if _is_arm_only_stage:
    from core.phases._helpers import _get_arm_target_type
    _arm_target_type = _get_arm_target_type(ctx)
        f"Seeds={len(ctx.seeds)} | Techs={len(ctx.techniques)} | "
        f"Converters={sum(len(v) for v in ctx.converter_map.values())} | "
        ok=True,
    if not _is_arm_only_stage:
        try:
        except Exception:
            pass
async def _generate_openapi_seeds(ctx: "PipelineContext") -> None:
    if not ctx.parsed_request:
        return
    _fp = ctx.parsed_request.target_fingerprint
    _openapi_endpoints = _fp.get("openapi_endpoints", [])
    if not _openapi_endpoints:
        return
    try:
        from recon.openapi_discoverer import (
        _discovery = OpenAPIDiscovery(
            spec_path=_fp.get("openapi_spec_path", ""),
            spec_version=_fp.get("openapi_version", ""),
            title=_fp.get("openapi_title", ""),
            endpoints=[
                    path=ep.get("path", ""),
                    method=ep.get("method", ""),
                    summary=ep.get("summary", ""),
                    parameters=ep.get("parameters", []),
                    has_auth=ep.get("has_auth", False),
                for ep in _openapi_endpoints
            security_schemes=_fp.get("openapi_security_schemes", []),
        _openapi_seeds = build_openapi_attack_seeds(_discovery)
        if _openapi_seeds:
            from arm.seed_ranker import _build_seed_groups
            _openapi_seed_groups = _build_seed_groups(_openapi_seeds)
            from utils.display import print_status
    except Exception as e: