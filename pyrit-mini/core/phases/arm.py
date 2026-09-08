""" ARM  ( Seed  + Converter ).

Academic basis:
    - Challita et al. (arXiv:2406.02062) - LLM  ()
    - Greshake et al. (arXiv:2302.12173) - converter(s)
    - PyRIT (arXiv:2407.01232) - PromptSendingAttack
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


def _inject_mcpsec_tool_seeds(
    ctx: Any,
    mcpsec_tools: list[dict[str, Any]],
    *,
    max_seeds: int = 20,
) -> int:
    """Inject MCPSec-discovered tool-aware seeds into ctx.seeds.

    Architecture alignment:
        Path B: ctx.mcpsec_surface.tools -> _generate_tool_specific_seeds -> prepend to ctx.seeds

    Production-grade features:
    - Deduplication: skips seeds already present in ctx.seeds
    - Orchestration log: audit trail for MCP seed injection
    - Rich metadata: MCPSec tool context preserved

    Args:
        ctx: Pipeline context (must have .seeds and .orchestration_log)
        mcpsec_tools: Tool definitions from MCPSec enumeration
        max_seeds: Maximum seeds to generate

    Returns:
        Number of seeds injected
    """
    if not mcpsec_tools:
        return 0

    from pyrit.models import SeedDataset, SeedPrompt

    from strike.dynamic_mcp_seeds import _generate_tool_specific_seeds

    # Generate tool-specific seeds from MCPSec-discovered tools
    mcpsec_seed_dicts = _generate_tool_specific_seeds(mcpsec_tools, max_count=max_seeds)

    if not mcpsec_seed_dicts:
        return 0

    # Build SeedPrompt list with deduplication
    mcpsec_seed_prompts = []
    existing_values = set()
    for group in ctx.seeds:
        for seed in getattr(group, "seeds", []) if hasattr(group, "seeds") else []:
            val = getattr(seed, "value", None)
            if val:
                existing_values.add(val)

    for sd in mcpsec_seed_dicts:
        value = sd.get("value", "")
        if value and value not in existing_values:
            sp = SeedPrompt(
                value=value,
                data_type="text",
                metadata={"source": "mcpsec_dynamic_tool", **sd.get("metadata", {})},
            )
            mcpsec_seed_prompts.append(sp)
            existing_values.add(value)

    injected = 0
    if mcpsec_seed_prompts:
        mcpsec_dataset = SeedDataset(seeds=mcpsec_seed_prompts)
        # Prepend MCPSec seeds (higher priority for MCP-targeted attacks)
        ctx.seeds = list(mcpsec_dataset.prompts) + list(ctx.seeds)
        injected = len(mcpsec_seed_prompts)

        # Orchestration log audit
        if hasattr(ctx, "orchestration_log"):
            ctx.orchestration_log.append({
                "phase": "arm",
                "decision": "mcpsec_tool_seed_injection",
                "input": {"mcpsec_tools_count": len(mcpsec_tools)},
                "output": {
                    "seeds_injected": injected,
                    "total_seeds": len(ctx.seeds),
                    "tool_names": [t.get("name", "") for t in mcpsec_tools[:5]],
                },
                "reasoning": f"MCPSec dynamic tool-aware seeds ({injected}) prepended",
            })

        logger.info(
            "[ARM] MCPSec dynamic seeds injected: %d tool-aware seeds (total: %d)",
            injected,
            len(ctx.seeds),
        )

    return injected


def _get_adaptive_max_seeds(
        ctx: "PipelineContext", default_max: int = 25) -> int:
    """ ctx.adaptive_probe_ctx["probe_budget"] max_seeds

    P4 :  probe_budget () -> Load
    probe_budget () -> Load,  token

    Data flow:
    recon._init_adaptive_probe -> ctx.adaptive_probe_ctx["probe_budget"]
    -> arm._get_adaptive_max_seeds -> load_seeds(max_seeds)

    Args:
        ctx:
        default_max:  (
            probe_budget )

    Returns:
        max_seeds  (
            clamp  [5, 50])
    """
    probe_ctx = getattr(
        ctx, "adaptive_probe_ctx", None) or {}
    budget_raw = probe_ctx.get(
        "probe_budget")

    # probe_budget
    if not isinstance(
            budget_raw, int) or budget_raw <= 0:
        return default_max

    # : probe_budget -> max_seeds
    import math
    calculated = min(
        50, max(5, int(math.sqrt(budget_raw) * 3.5)))

    logger.debug(
        "[Adaptive] probe_budget=%d -> adaptive max_seeds=%d (default=%d)",
        budget_raw, calculated, default_max,
    )
    return calculated

def _is_converter_allowed(
        converter: Any, allowed_list: list[str]) -> bool:
    """ converter stealth policy

    Args:
        converter: converter
        allowed_list: policy.allowed_converters

    Returns:
        True  converter
    """
    # "all"
    if "all" in allowed_list:
        return True

    # Extract converter name from object or string
    c_name = converter if isinstance(converter, str) else getattr(
        converter, "converter_name", None)
    if c_name is None:
        # , ()
        return True
    return c_name in allowed_list

async def _run_arm_phase(
    ctx: "PipelineContext",
) -> None:
    """(3) ARM : Seed  + Converter

    Academic basis:
        - Challita et al. (arXiv:2406.02062) - LLM  ()
        - Greshake et al. (arXiv:2302.12173) - converter(s)
        - PyRIT (arXiv:2407.01232) - SequentialAttack +
    """
    from utils.display import (
        print_arm_highlights,
        print_phase,
        print_status,
    )

    args = ctx.args
    print_phase(
        "ARM", " ARM : Seed  + Converter ...")

    from core.phases._helpers import (
        _extract_target_profile,
        _get_arm_target_type,
        _record_arm_seed_orchestration,
    )

    target_profile = _extract_target_profile(ctx)
    target_language = target_profile.get("language")
    target_capabilities = target_profile.get("capabilities")
    target_model_family = target_profile.get("model_family")
    target_type = _get_arm_target_type(ctx)

    #
    max_seeds = _get_adaptive_max_seeds(ctx, default_max=25)
    from arm.dataset_config import load_seeds
    await load_seeds(
        ctx,
        max_seeds=max_seeds,
        capabilities=target_capabilities,
        model_family=target_model_family,
        language=target_language,
        target_type=target_type,
    )

    #
    from arm.seed_ranker import rank_seeds_for_target
    rank_seeds_for_target(
        ctx,
        target_language=target_language,
        target_capabilities=target_capabilities,
        target_model_family=target_model_family,
    )

    # == MCPSec v2.7.2: Tool-aware seed selection (Path B in architecture) ==
    # Architecture alignment: ctx.mcpsec_surface.tools -> _generate_tool_specific_seeds -> prepend
    # Priority: MCPSec dynamic seeds > static MCP seeds > other seeds
    _mcpsec_tools = ctx.mcpsec_surface.get("tools", []) if ctx.mcpsec_surface else []
    if _mcpsec_tools:
        _inject_mcpsec_tool_seeds(ctx, _mcpsec_tools, max_seeds=20)

    # == RAG Metadata Consumer: Document-aware seed injection (Path C) ==
    # Architecture alignment: ctx.service_profile["rag_kb_map"] -> targeted seeds
    # Attack value: exploit known document titles, chunk IDs, retrieval formula
    _rag_kb_map = ctx.service_profile.get("rag_kb_map") if hasattr(ctx, "service_profile") else None
    if _rag_kb_map and _rag_kb_map.get("document_count", 0) > 0:
        from strike.rag_targeted_consumer import inject_rag_targeted_seeds
        rag_seeds_count = inject_rag_targeted_seeds(ctx, _rag_kb_map, max_seeds=15)
        if rag_seeds_count > 0:
            logger.info(
                "[ARM] RAG metadata-driven seed injection: %d document-targeted seeds",
                rag_seeds_count,
            )

    #
    from arm.technique_picker import pick_techniques
    ctx.techniques = pick_techniques(
        ctx,
        target_capabilities=target_capabilities,
    )

    #
    has_adversarial = getattr(
        ctx.args, "adversarial", False)

    #
    _stealth_policy = getattr(ctx, "stealth_policy", None) or {}
    _has_guardrail = bool(getattr(ctx, "guardrail_report", None))
    _guardrail_severity = "none"
    if _has_guardrail:
        from recon.guardrail_detector import get_guardrail_severity
        _guardrail_severity = get_guardrail_severity(ctx.guardrail_report)

        #
        _original_count = len(ctx.techniques)

        # stealth_policy.disabled_techniques
        _disabled_techniques = _stealth_policy.get(
            "disabled_techniques", [])
        if isinstance(
                _disabled_techniques, list) and _disabled_techniques:
            ctx.techniques = [
                t for t in ctx.techniques if t not in _disabled_techniques]

            # stealth_policy.recommended_techniques
            _recommended_techniques = _stealth_policy.get(
                "recommended_techniques", [])
            if isinstance(
                    _recommended_techniques, list) and _recommended_techniques:
                for _rec_tech in _recommended_techniques:
                    if _rec_tech not in ctx.techniques:
                        ctx.techniques.append(
                            _rec_tech)

                        #
                        # :
                        # stealth_first
                        # ()
                        if _has_guardrail and _guardrail_severity in (
                                "high", "critical"):
                            # stealth
                            # (skeleton_key,
                            # context_compliance)
                            _stealth_priority = {
                                "skeleton_key", "context_compliance", "role_play_persuasion"}
                            ctx.techniques.sort(
                                key=lambda t: (
                                    0 if t in _stealth_priority else 1, t)
                            )

                            _new_count = len(ctx.techniques)
                            if _original_count != _new_count:
                                logger.info(
                                    "[Adaptive] Technique selection adjusted by guardrail/stealth: "
                                    "%d -> %d (guardrail=%s, severity=%s)",
                                    _original_count, _new_count, _has_guardrail, _guardrail_severity,
                                )

                            ctx.orchestration_log.append({
                                "phase": "arm",
                                "decision": "technique_selection",
                                "input": {
                                    "mode": args.techniques,
                                    "has_adversarial": has_adversarial,
                                    "capabilities": target_capabilities or "",
                                    "guardrail_severity": _guardrail_severity if _has_guardrail else "none",
                                },
                                "output": {"techniques": ctx.techniques},
                                "reasoning": (
                                    f" + guardrail/stealth "
                                    f"(capabilities={target_capabilities or 'none'}, guardrail={_has_guardrail})"
                                ),
                            })

    # == RAG Metadata Consumer: Technique optimization based on KB analysis ==
    # Academic basis: Zou et al. (arXiv:2406.04245) PoisonedRAG technique mapping
    if _rag_kb_map and _rag_kb_map.get("document_count", 0) > 0:
        from strike.rag_targeted_consumer import recommend_techniques_for_rag
        _original_techniques = list(ctx.techniques)
        ctx.techniques = recommend_techniques_for_rag(
            _rag_kb_map,
            existing_techniques=ctx.techniques,
        )
        _added = [t for t in ctx.techniques if t not in _original_techniques]
        if _added:
            logger.info(
                "[ARM] RAG-optimized techniques added: %s (chunk_size=%s, formula=%s)",
                _added,
                _rag_kb_map.get("inferred_chunk_size"),
                _rag_kb_map.get("inferred_retrieval_formula"),
            )

    # == RAG Typo Fuzzer Consumer: BM25 poisoning seed injection ==
    # Architecture alignment: ctx.service_profile["rag_typo_fuzz"] → typo-aware seeds
    # Attack value: exploit query_rewriting=false / BM25 keyword matching weakness
    _rag_typo_fuzz = ctx.service_profile.get("rag_typo_fuzz") if hasattr(ctx, "service_profile") else None
    if _rag_typo_fuzz and _rag_typo_fuzz.get("total_tests", 0) > 0:
        from strike.rag_targeted_consumer import inject_typo_aware_seeds
        typo_seeds_count = inject_typo_aware_seeds(ctx, _rag_typo_fuzz, max_seeds=10)
        if typo_seeds_count > 0:
            logger.info(
                "[ARM] Typo-aware seed injection: %d BM25-poisoning seeds "
                "(rewriting=%s, bm25_vuln=%s, failure_rate=%.2f)",
                typo_seeds_count,
                _rag_typo_fuzz.get("query_rewriting_detected"),
                _rag_typo_fuzz.get("vulnerable_to_bm25_poisoning"),
                _rag_typo_fuzz.get("failure_rate", 0),
            )

    #
    if args.converters == "none":
        chain_names = []
    elif args.converters == "auto":
        chain_names = ["l5_optimal"]
    else:
        chain_names = args.converters.split(
            ",")

    _target_fingerprint = None
    if ctx.parsed_request:
        _target_fingerprint = ctx.parsed_request.target_fingerprint

    from arm.converter_presets import build_converter_map
    ctx.converter_map = build_converter_map(
        technique_names=ctx.techniques,
        chain_names=chain_names,
        converter_target=ctx.converter_target,
        model_family=target_model_family,
        target_type=target_type,
        target_fingerprint=_target_fingerprint,
        converter_overrides=getattr(
            args, "converter_overrides", None),
        seeds=ctx.seeds,
    )

    _record_arm_seed_orchestration(
        ctx,
        target_language=target_language,
        target_capabilities=target_capabilities,
        target_model_family=target_model_family,
    )

    print_arm_highlights(
        seed_count=len(ctx.seeds),
        technique_count=len(ctx.techniques),
        converter_count=len(ctx.converter_map),
    )

    print_status(
        "ARM", "DONE",
        f"Seed={len(ctx.seeds)}, Technique={len(ctx.techniques)}, Converter={len(ctx.converter_map)}",
        ok=True,
    )
