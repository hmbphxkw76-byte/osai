# arXiv:2402.12109 - Russinovich et al., Crescendo
# arXiv:2402.19181 - Zeng et al., Persuasion
# arXiv:2407.01232 - PyRIT, framework foundation
"""Target routing - Burp 

:
    Burp  ->  ->  ->  HTTPTarget -> RateLimitedTarget 

:
    - adversarial_target: imports .env  ( LLM API)
    - scoring_target: imports .env  adversarial

P0-02  ( C2 ):
     <= 5 converter(s) (P0  2 + P1  3P2 )
    all
"""

from __future__ import annotations

import asyncio
import logging
import os
import time as _time
from typing import Any

from core.context import PipelineContext
from recon.burp_parser import (
    build_http_target,
    parse_burp_request,
    probe_active_capabilities,
    probe_response_path,
)

# P2-06: TLS verify (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config
from adapters.rate_limited import RateLimitedTarget

# L5 v54+: Adaptive probe, Guardrail, Behavioral verify, Model seed mapping
from recon.adaptive_probe_config import (
    compute_probe_budget,
    should_run_probe,
)
from recon.behavioral_verifier import behavioral_verify
from recon.capability_monitor import CapabilityDriftMonitor, CapabilitySnapshot, get_drift_monitor
from recon.guardrail_detector import detect_guardrail
from recon.model_seed_mapper import get_seeds_for_model, detect_model_family
from recon.stealth_config import StealthLevelManager, STEALTH_POLICIES, get_stealth_manager
from recon.confidence_scorer import (
    merge_verification_into_capabilities,
    score_capability_with_convergence,
)

_TLS_VERIFY = _get_tls_verify_from_config()

logger = logging.getLogger(__name__)

# ====================================================================
# - >= 3. 10 ()
# L5 v54+: _MAX_PROBE_COUNT is the ABSOLUTE ceiling. Adaptive config lowers it.
_MAX_PROBE_COUNT = int(os.environ.get("RECON_MAX_PROBES", "10"))
_COMPLEXITY_BASED_BUDGET: dict[str, Any] = {}  # Populated by _init_adaptive_probe


# ====================================================================
# P2-07: - orchestration_log
# ====================================================================
def _log_probe_failure(
    ctx: Any,
    probe_phase: str,
    error: Exception,
    is_fatal: bool = False,
) -> None:
 """ orchestration_log (P2-07: )

    Args:
        ctx: PipelineContext  ( orchestration_log ).
        probe_phase:  ( "response_path", "capability", "mcp_enum").
        error: .
        is_fatal:  (True=, False=).
 """
 # : ctx orchestration_log ()
    if ctx is None or not hasattr(ctx, "orchestration_log"):
        return

    ctx.orchestration_log.append({
        "phase": "recon",
        "decision": f"probe_{probe_phase}_failed",
        "input": {"target": getattr(ctx, "model_name", "unknown")},
        "output": {
            "error_type": type(error).__name__,
            "error_message": str(error)[:500],
            "is_fatal": is_fatal,
        },
        "reasoning": (
            f"Probe '{probe_phase}' failed with {type(error).__name__}: {str(error)[:200]}. "
            f"{'Fatal: aborting.' if is_fatal else 'Non-fatal: continuing with degraded capability.'}"
        ),
    })


async def create_target(ctx: PipelineContext) -> None:
 """

    :
        1. --browser-url -> PlaywrightTarget ( Chat UI)
        2. --target-api-endpoint + --target-api-key -> API 
        3. --burp -> Burp  (HTTPTarget + RateLimitedTarget)
        4. --target-url + --api-key -> API 
        5.  -> .env 

    P0-02  ( <= 5 ):
        1.  Burp  -> ParsedBurpRequest
        2. P0-1:  (1 converter(s))
        3. P0-2:  (1-2 converter(s))
        4. P0-3: HTTPTarget  + RateLimitedTarget 
        5. P1 ():  ( 3 converter(s))
           -  ctx._recon_background_tasks
        6. P2  arm  CLI 

    Args:
        ctx: 
 """
 # == L5 v52: OpenAIChatTarget/OpenAIResponseTarget ==
    target_api_endpoint = getattr(ctx.args, "target_api_endpoint", None)
    target_api_key = getattr(ctx.args, "target_api_key", None)
    target_api_model = getattr(ctx.args, "target_api_model", None)
    target_api_type = getattr(ctx.args, "target_api_type", "chat")

 # == LiteLLM ==
    litellm_model = getattr(ctx.args, "litellm_model", None) or os.environ.get("LITELLM_MODEL")
    if litellm_model:
        logger.info("LiteLLM mode - creating native LiteLLMChatTarget for %s", litellm_model)
        await _create_litellm_target(ctx, model_name=litellm_model)
        await _configure_remaining_targets(ctx)
        return

    if target_api_endpoint and target_api_key:
        logger.info(
            "API direct mode - creating native %s for %s",
            "OpenAIResponseTarget" if target_api_type == "responses" else "OpenAIChatTarget",
            target_api_endpoint,
        )
        await _create_native_openai_target(
            ctx,
            endpoint=target_api_endpoint,
            api_key=target_api_key,
            model_name=target_api_model or "gpt-4o",
            api_type=target_api_type,
        )
        await _configure_remaining_targets(ctx)
        return

 # == L5 v38: PlaywrightTarget ==
    browser_url = getattr(ctx.args, "browser_url", None)
    if browser_url:
        logger.info("Browser mode - creating PlaywrightTarget for %s", browser_url)
        await _create_playwright_target(ctx, browser_url)
        await _configure_remaining_targets(ctx)
        return

 # ================================================================
 # Burp - P0-02 
 # ================================================================

 # == Step 1: Burp ==
    parsed = parse_burp_request(ctx.args.burp)
    ctx.parsed_request = parsed
    ctx.model_name = f"HTTP:{parsed.host}{parsed.path}"

 # == L5 v53: Burp ==
    if parsed.burp_model_name:
        ctx.model_name = parsed.burp_model_name
 # P1-05: 
        parsed.target_fingerprint.burp_model_name = parsed.burp_model_name
        logger.info("Model name from Burp response: %s", parsed.burp_model_name)

    if parsed.burp_model_list:
 # P1-05: extra dict Schema 
        parsed.target_fingerprint.extra["burp_model_list"] = "yes"
        logger.info("Model list extracted from Burp (length=%d)", len(parsed.burp_model_list))

    if parsed.original_prompt_value:
 # P1-05: 
        parsed.target_fingerprint.original_prompt = parsed.original_prompt_value[:200]
        logger.info("Original prompt from Burp: %s", parsed.original_prompt_value[:80])

    if parsed.api_category != "chat":
        logger.info(
            "Non-chat API detected (category=%s, path=%s) - model info extracted, "
            "{PROMPT} injection skipped",
            parsed.api_category, parsed.path,
        )

 # == Step 2 (P0): (1 ) ==
    _probe_counter = _ProbeCounter()
    _probe_start = _time.monotonic()

    target_available = await _check_target_availability(parsed)
    _probe_counter.add(1)
    if not target_available:
        logger.error(
            "Target %s://%s%s is NOT available. Aborting.",
            "https" if parsed.use_tls else "http",
            parsed.host, parsed.path,
        )
        raise ConnectionError(
            f"Target {parsed.host}:{parsed.path} is not available."
        )
    logger.info("Target availability check passed.")

 # == Step 3 (P0): (0-1 ) ==
    logger.info("Probing response format...")
    try:
        await probe_response_path(parsed)
        _probe_counter.add(1)
    except Exception as e:
 # P2-07: orchestration_log ()
        logger.warning("Response path probing failed (non-fatal): %s", e)
        _log_probe_failure(ctx, "response_path", e, is_fatal=False)

    if parsed.response_json_path:
        logger.info("Response path detected: %s", parsed.response_json_path)
    else:
        logger.info("No response path detected, using default callback")

 # == Chat ID ==
    if parsed.chat_id:
        logger.info("Chat ID from probe/Burp response: %s", parsed.chat_id)
    elif parsed.has_chat_id_placeholder:
        logger.info(
            "Chat ID field '%s' in body with {CHAT_ID} placeholder, "
            "will extract from first response",
            parsed.chat_id_field,
        )

 # == Step 4 (P0): HTTPTarget (0 - HTTP ) ==
    target = build_http_target(parsed)
    target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.objective_target = target

 # == Step 4.1 (P0): HTTPTarget ==
    multi_turn_target = build_http_target(parsed, enable_multi_turn=True)
    multi_turn_target = RateLimitedTarget(
        target=multi_turn_target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.multi_turn_target = multi_turn_target

 # == Step 4.5 (P0): - 6 ==
 # L5 v54+: Guardrail/Stealth/Behavioral/Capability/Seed/Drift
 # Data flow: create_target -> _init_adaptive_probe -> ctx.adaptive_probe_ctx
 # -> arm phase (seed_preferences, stealth_policy, probe_budget)
 # -> strike phase (drift_monitor, guardrail_report)
    try:
        _probe_ctx = await _init_adaptive_probe(ctx, parsed, _probe_counter)
        ctx.adaptive_probe_ctx = _probe_ctx
        ctx.guardrail_report = _probe_ctx.get("guardrail_report", {})
        ctx.stealth_policy = _probe_ctx.get("stealth_policy", {})
        ctx.drift_monitor = get_drift_monitor()  # 
        logger.info(
            "[Adaptive] Pipeline integration OK: guardrail=%s, stealth=%s, "
            "adaptive_budget=%s",
            ctx.guardrail_report.get("severity", "none"),
            ctx.stealth_policy.get("name", "balanced"),
            _probe_ctx.get("probe_budget", {}).get("budget", "default"),
        )
    except Exception as e:
        logger.warning("[Adaptive] Adaptive probe init failed (non-fatal): %s", e)
        ctx.adaptive_probe_ctx = {}
        ctx.guardrail_report = {"has_guardrail": False, "severity": "none"}
        ctx.stealth_policy = {"name": "balanced", "behavioral_verify": True}

 # == Step 5 (P1 ): ==
 # P0-02: --deep-probe < 
 # ctx._recon_background_tasks
    deep_probe_enabled = getattr(ctx.args, "deep_probe", False)
    always_capability_probe = getattr(ctx.args, "capability_probe", True)

    if always_capability_probe and _probe_counter.value < _MAX_PROBE_COUNT:
 # ()
        bg_task = asyncio.create_task(
 # P2-07: ctx 
            _run_background_probes(parsed, _probe_counter, ctx, deep_probe_enabled),
            name="recon_background_probes",
        )
        if not hasattr(ctx, "_recon_background_tasks"):
            ctx._recon_background_tasks = []
        ctx._recon_background_tasks.append(bg_task)
        logger.info(
            "Background capability probes launched (cap=%d, deep=%s)",
            _MAX_PROBE_COUNT, deep_probe_enabled,
        )

 # == Step 6: ==
    await _configure_remaining_targets(ctx)

 # == ==
    _probe_duration = _time.monotonic() - _probe_start
 # P1-05: 
    parsed.target_fingerprint.probe_count = _probe_counter.value
    parsed.target_fingerprint.probe_duration_seconds = round(_probe_duration, 2)
    logger.info(
        "Recon complete: %d probes sent, %.2fs duration "
        "(attack starts now, background probes continue)",
        _probe_counter.value,
        _probe_duration,
        ctx._recon_background_tasks,
    )


async def _configure_remaining_targets(ctx: PipelineContext) -> None:
 """ adversarial/scoring/converter targets."""
 # adversarial target
    if ctx.adversarial_target is None:
        ctx.adversarial_target = _create_adversarial_target()
    if ctx.adversarial_target:
        logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)

 # extra adversarial targets
    if not ctx.extra_adversarial_targets:
        extra_targets = _create_extra_adversarial_targets()
        if extra_targets:
            ctx.extra_adversarial_targets = extra_targets
            logger.info("Extra adversarial targets: %d", len(extra_targets))

 # scoring target
    if ctx.scoring_target is None:
        ctx.scoring_target = _create_scoring_target(ctx)
    if ctx.scoring_target:
        logger.info("Scoring target: %s", type(ctx.scoring_target).__name__)

 # converter target
    if ctx.converter_target is None:
        ctx.converter_target = ctx.scoring_target or ctx.adversarial_target

    logger.info(
        "Targets configured: objective=%s, adversarial=%s, scorer=%s",
        type(ctx.objective_target).__name__ if ctx.objective_target else "None",
        type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
        type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
    )


# ====================================================================
# - 
# ====================================================================


class _ProbeCounter:
 """

    L5 v54+:  max_probes ( _init_adaptive_probe )
 """

    def __init__(self) -> None:
        self.value: int = 0
        self._adaptive_max: int | None = None  # Set by _init_adaptive_probe

    def add(self, n: int = 1) -> None:
        self.value += n

    def can_probe(self, n: int = 1, max_probes: int = _MAX_PROBE_COUNT) -> bool:
 # max ()
        effective_max = self._adaptive_max if self._adaptive_max is not None else max_probes
        return self.value + n <= effective_max

    def get_budget_remaining(self, max_probes: int = _MAX_PROBE_COUNT) -> int:
 """"""
        effective_max = self._adaptive_max if self._adaptive_max is not None else max_probes
        return max(0, effective_max - self.value)


# ====================================================================
# L5 v54+: Adaptive Probe Initialization - 6-Strategy Integration Hub
# ====================================================================


async def _init_adaptive_probe(
    ctx: Any,
    parsed: Any,
    counter: _ProbeCounter,
) -> dict[str, Any]:
 """ - 6 

     ():
        1. Guardrail Detection -> severity, stealth_level
        2. Stealth Config -> delay_range, max_probes, allowed_converters
        3. Adaptive Probe Budget -> total budget, deep_budget, behavioral_budget
        4. Model Seed Mapping -> preferred_templates, optimal_converters
        5. Behavioral Verify -> adjust confidence for S3 confirmation
        6. Capability Monitor -> baseline snapshot for drift detection

    Args:
        ctx: PipelineContext .
        parsed: ParsedBurpRequest .
        counter: _ProbeCounter .

    Returns:
        dict: all.
 """
    probe_ctx: dict[str, Any] = {
        "guardrail_report": {},
        "stealth_policy": {},
        "probe_budget": {},
        "seed_mapping": {},
        "behavioral_report": {},
    }

    model_name = getattr(parsed, "burp_model_name", "") or "unknown"

 # == Phase 1: Guardrail Detection () ==
    try:
        logger.info("[Adaptive] Phase 1: Guardrail detection...")
        guardrail_report = await detect_guardrail(parsed)
        probe_ctx["guardrail_report"] = guardrail_report.to_dict()
        logger.info(
            "[Adaptive] Guardrail: type=%s, severity=%s, stealth=%s",
            guardrail_report.guardrail_type,
            guardrail_report.severity,
            guardrail_report.stealth_level,
        )
        counter.add(3)  # 3 grayscale probes
    except Exception as e:
        logger.debug("[Adaptive] Guardrail detection failed: %s", e)
        probe_ctx["guardrail_report"] = {
            "has_guardrail": False,
            "severity": "none",
            "stealth_level": "balanced",
        }

 # == Phase 2: Stealth Level -> Policy ==
    try:
        stealth_mgr = get_stealth_manager()
        guardrail_severity = probe_ctx["guardrail_report"].get("severity", "none")
        recommended_stealth = probe_ctx["guardrail_report"].get("stealth_level", "balanced")

 # guardrail , 
        user_stealth = getattr(ctx.args, "stealth_level", None) or recommended_stealth
        stealth_policy = stealth_mgr.get_policy(user_stealth)
        probe_ctx["stealth_policy"] = {
            "name": stealth_policy.name,
            "delay_range": list(stealth_policy.delay_range),
            "allowed_converters": stealth_policy.allowed_converters,
            "behavioral_verify": stealth_policy.behavioral_verify,
        }
        logger.info("[Adaptive] Stealth policy: %s", stealth_policy.name)
    except Exception as e:
        logger.debug("[Adaptive] Stealth config failed: %s", e)
        probe_ctx["stealth_policy"] = {"name": "balanced", "behavioral_verify": True}

 # == Phase 3: Adaptive Probe Budget ==
    try:
 # ( parsed target_fingerprint )
        existing_caps_str = parsed.target_fingerprint.extra.get("capabilities", "")
        existing_caps = {}
        if existing_caps_str:
            for cap in existing_caps_str.split(","):
                if cap.strip():
                    existing_caps[cap.strip()] = True

        app_type = parsed.target_fingerprint.app_type if hasattr(parsed, "target_fingerprint") else "chat"

        probe_budget = compute_probe_budget(
            capabilities=existing_caps,
            guardrail_severity=guardrail_severity,
            app_type=app_type,
            stealth_level=probe_ctx["stealth_policy"].get("name", "balanced"),
        )
        probe_ctx["probe_budget"] = probe_budget
 # max_probes ()
        counter._adaptive_max = probe_budget["budget"]
        logger.info(
            "[Adaptive] Probe budget: total=%d, parallel=%d, deep=%d, behavioral=%d "
            "(complexity=%s)",
            probe_budget["budget"],
            probe_budget["parallel"],
            probe_budget["deep_probe_budget"],
            probe_budget["behavioral_verify_budget"],
            probe_budget["complexity_level"],
        )
    except Exception as e:
        logger.debug("[Adaptive] Probe budget calc failed: %s", e)
        probe_ctx["probe_budget"] = {"budget": 5, "parallel": 1, "complexity_level": "moderate"}

 # == Phase 4: Model Seed Mapping ( model_name ) ==
    try:
        if model_name and model_name != "unknown":
            seed_mapping = get_seeds_for_model(model_name)
            probe_ctx["seed_mapping"] = seed_mapping
            logger.info(
                "[Adaptive] Seed mapping for '%s': templates=%s, converters=%s (source=%s)",
                model_name,
                seed_mapping.get("preferred_templates", []),
                seed_mapping.get("optimal_converters", []),
                seed_mapping.get("source", "default"),
            )

 # ctx arm 
            ctx.seed_preferences = seed_mapping
    except Exception as e:
        logger.debug("[Adaptive] Seed mapping failed: %s", e)

 # == Phase 5: Behavioral Verification ( S1 ) ==
    behavioral_enabled = probe_ctx["stealth_policy"].get("behavioral_verify", True)
    behavioral_budget = probe_ctx["probe_budget"].get("behavioral_verify_budget", 0)

    if behavioral_enabled and behavioral_budget > 0:
        try:
            logger.info("[Adaptive] Phase 5: Behavioral verification...")
 # capabilities 
            caps_for_verify = {}
            for cap, val in existing_caps.items():
                caps_for_verify[cap] = {
                    "confidence": 0.5,
                    "level": "medium",
                    "detected": True,
                    "source": "active",
                }

            behavioral_report = await behavioral_verify(parsed, caps_for_verify)
            probe_ctx["behavioral_report"] = behavioral_report.to_dict()
            counter.add(min(behavioral_budget, 2))  # behavioral probes 
            logger.info(
                "[Adaptive] Behavioral verify: %d/%d verified (ratio=%.0f%%)",
                behavioral_report.summary.get("total_claimed", 0),
                behavioral_report.summary.get("behaviorally_verified", 0),
                behavioral_report.summary.get("verified_ratio", 0) * 100,
            )
        except Exception as e:
            logger.debug("[Adaptive] Behavioral verification failed: %s", e)

    logger.info("[Adaptive] Probe initialization complete: %s", probe_ctx["probe_budget"])
    return probe_ctx


# ====================================================================
# P1 ()
# ====================================================================


async def _run_background_probes(
    parsed: Any,
    counter: _ProbeCounter,
    ctx: Any = None,  # P2-07: PipelineContext, orchestration_log
    deep_probe: bool = False,
) -> None:
 """

     ( ASR ):
        1. probe_active_capabilities (agent/mcp/rag )
        2. MCP  ( MCP )
        3. system_prompt_extraction ()

    P0-02  ( deep_probe=True):
        - deep_probe_capabilities (8 converter(s))
        - OpenAPI  (API schema )
        - Confirmation (RAG )

    Args:
        parsed:  Burp 
        counter: n        ctx:  PipelineContext (P2-07:  orchestration_log)
        deep_probe:  ( False)
 """
    logger.info("Background probes started (cap=%d)...", _MAX_PROBE_COUNT)

 # == P1-1: probe_active_capabilities (3 ) ==
    try:
        active_caps = await probe_active_capabilities(parsed)
        counter.add(3)
        if active_caps:
 # P1-05: 
            existing_caps = parsed.target_fingerprint.extra.get("capabilities", "")
            all_caps = set(existing_caps.split(",")) if existing_caps else set()
            for cap_key, cap_val in active_caps.items():
                if cap_key == "model_family" and cap_val:
                    parsed.target_fingerprint.model_family = cap_val
                elif cap_val:
                    all_caps.add(cap_key)
            parsed.target_fingerprint.extra["capabilities"] = ",".join(sorted(all_caps))
            logger.info("Background: active probe detected: %s", sorted(all_caps))
    except Exception as e:
 # P2-07: orchestration_log ()
        logger.warning("Background: active probe failed: %s", e)
        _log_probe_failure(ctx, "active_capability", e, is_fatal=False)

 # == P1-2: MCP ( - MCP ) ==
    capabilities_str = parsed.target_fingerprint.extra.get("capabilities", "")
    if "mcp" in capabilities_str or "mcp_protocol" in capabilities_str:
        logger.info("MCP capability detected, launching MCP enumeration...")
        try:
            from recon.mcp_enumerator import enumerate_mcp_endpoint
            mcp_results = await enumerate_mcp_endpoint(parsed)
            if mcp_results.get("has_mcp"):
 # P1-05: 
                parsed.target_fingerprint.mcp_tools = mcp_results.get("tools", [])
                parsed.target_fingerprint.mcp_resources = mcp_results.get("resources", [])
                parsed.target_fingerprint.mcp_prompts = mcp_results.get("prompts", [])
                logger.info(
                    "Background: MCP enumeration: %d tools, %d resources",
                    len(mcp_results.get("tools", [])),
                    len(mcp_results.get("resources", [])),
                )
        except Exception as e:
 # P2-07: orchestration_log ()
            logger.warning("Background: MCP enumeration failed: %s", e)
            _log_probe_failure(ctx, "mcp_enum", e, is_fatal=False)

 # == P1-3: ( - ) ==
    if counter.can_probe(3, _MAX_PROBE_COUNT):
        try:
            from recon.system_prompt_extractor import extract_system_prompt
            sp_result = await extract_system_prompt(parsed)
            counter.add(3)
            if sp_result.get("system_prompt_leaked"):
 # P1-05: 
                parsed.target_fingerprint.system_prompt_leaked = True
                parsed.target_fingerprint.extracted_system_prompt = sp_result.get(
                    "extracted_system_prompt", ""
                )
                parsed.target_fingerprint.system_prompt_extraction_method = sp_result.get(
                    "extraction_method", ""
                )
                logger.warning(
                    "Background: System prompt LEAKED via %s (length=%d)",
                    sp_result.get("extraction_method"),
                    sp_result.get("system_prompt_length", 0),
                )
            else:
                parsed.target_fingerprint.system_prompt_leaked = False
        except Exception as e:
 # P2-07: orchestration_log ()
            logger.warning("Background: system prompt extraction failed: %s", e)
            _log_probe_failure(ctx, "system_prompt", e, is_fatal=False)

 # == P2 ( deep_probe=True): ==
    if not deep_probe:
        logger.info("Background probes complete (deep probe disabled).")
        return

 # : deep_probe_capabilities ( 8 )
    if counter.can_probe(8, _MAX_PROBE_COUNT):
        try:
            from recon.capability_probe import deep_probe_capabilities
            deep_caps = await deep_probe_capabilities(parsed)
            counter.add(8)
            if deep_caps:
 # P1-05: 
                existing_caps_str = parsed.target_fingerprint.extra.get("capabilities", "")
                all_caps = set(existing_caps_str.split(",")) if existing_caps_str else set()
                for cap_key in [
                    "has_function_calling", "has_memory", "has_workflow",
                    "has_multi_tenant", "has_session_auth", "has_mcp_protocol",
                    "has_a2a_protocol", "has_embedding_rag",
                ]:
                    if deep_caps.get(cap_key):
                        all_caps.add(cap_key.replace("has_", ""))
                parsed.target_fingerprint.extra["capabilities"] = ",".join(sorted(all_caps))
 # P1-05: , Schema extra dict
                for k in ("secret_format", "tool_schemas", "model_family"):
                    if deep_caps.get(k):
                        parsed.target_fingerprint.extra[k] = deep_caps[k]
 # Schema session_type
                if deep_caps.get("session_type"):
                    parsed.target_fingerprint.session_type = deep_caps["session_type"]
 # extra
                for k in ("model_ids", "api_behavior", "capability_confidence", "capability_recommendations"):
                    if deep_caps.get(k):
                        parsed.target_fingerprint.extra[k] = deep_caps[k]
        except Exception as e:
 # P2-07: orchestration_log ()
            logger.warning("Background: deep probe failed: %s", e)
            _log_probe_failure(ctx, "deep_capability", e, is_fatal=False)

 # OpenAPI ( deep_probe)
    if counter.can_probe(5, _MAX_PROBE_COUNT):
        try:
            from recon.openapi_discoverer import discover_openapi_spec
            openapi_result = await discover_openapi_spec(parsed)
            counter.add(5)
            if openapi_result and openapi_result.endpoints:
 # P1-05: 
                parsed.target_fingerprint.openapi_spec_path = openapi_result.spec_path
                parsed.target_fingerprint.openapi_endpoints = [
                    {"path": ep.path, "method": ep.method, "summary": ep.summary}
                    for ep in openapi_result.endpoints[:20]  # 
                ]
        except Exception as e:
 # P2-07: orchestration_log ()
            logger.warning("Background: OpenAPI discovery failed: %s", e)
            _log_probe_failure(ctx, "openapi_discovery", e, is_fatal=False)

    logger.info("Background probes complete. Total probes: %d", counter.value)


# ====================================================================
# P0 
# ====================================================================


async def _check_target_availability(parsed: Any) -> bool:
 """P0: API 

    :
        1.  POST ,  stream=True 
        2.  5s,  15s
        3.  HTTP  (200/400/401/403 )
        4. 402/503 = ; / = 

    Args:
        parsed:  Burp 

    Returns:
        True , False 
 """
    import httpx

    scheme = "https" if parsed.use_tls else "http"
    check_url = f"{scheme}://{parsed.host}{parsed.path}"

    check_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            check_headers[key] = value

    from recon.capability_detector import _build_probe_body
    check_body = _build_probe_body(parsed, "hi")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0),
            follow_redirects=True,
            verify=_TLS_VERIFY,
        ) as client:
            async with client.stream(
                method=parsed.method,
                url=check_url,
                headers=check_headers,
                content=check_body,
            ) as response:
                if response.status_code == 402:
                    logger.error("Target returned 402 Payment Required.")
                    return False
                if response.status_code == 503:
                    logger.error("Target returned 503 Service Unavailable.")
                    return False
                logger.info("Target availability check: HTTP %d (online)", response.status_code)
                return True

    except httpx.ConnectError as e:
        logger.error("Target connection refused: %s", e)
        return False
    except httpx.TimeoutException:
        logger.error("Target availability check timed out.")
        return False
    except Exception as e:
        logger.error("Target availability check failed: %s", e)
        return False


# ====================================================================
# Adversarial / Scoring Target 
# ====================================================================


def _create_adversarial_target() -> Any:
 """imports .env adversarial chat """
    from pyrit.prompt_target import OpenAIChatTarget

    endpoint = os.environ.get("ADVERSARIAL_CHAT_ENDPOINT")
    api_key = os.environ.get("ADVERSARIAL_CHAT_KEY")
    model = os.environ.get("ADVERSARIAL_CHAT_MODEL", "gpt-4o")
    rpm_str = os.environ.get("RATE_LIMIT", "")
    rpm = int(rpm_str) if rpm_str.isdigit() else None

    if endpoint and api_key:
        return OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model,
            max_requests_per_minute=rpm,
        )

    logger.warning(
        "Adversarial target not configured. "
        "Set ADVERSARIAL_CHAT_ENDPOINT and ADVERSARIAL_CHAT_KEY in .env."
    )
    return None


def _create_extra_adversarial_targets() -> list[Any]:
 """L5 v10: adversarial targets ()"""
    from pyrit.prompt_target import OpenAIChatTarget

    targets: list[Any] = []
    for i in (2, 3, 4):
        endpoint = os.environ.get(f"ADVERSARIAL_CHAT_ENDPOINT_{i}")
        api_key = os.environ.get(f"ADVERSARIAL_CHAT_KEY_{i}")
        model = os.environ.get(f"ADVERSARIAL_CHAT_MODEL_{i}", "gpt-4o")

        if endpoint and api_key:
            try:
                target = OpenAIChatTarget(
                    endpoint=endpoint,
                    api_key=api_key,
                    model_name=model,
                )
                targets.append(target)
                logger.info("Extra adversarial target %d: %s", i, model)
            except Exception as e:
                logger.warning("Failed to create adversarial target %d: %s", i, e)

    return targets


def _create_scoring_target(ctx: PipelineContext) -> Any:
 """imports .env ( adversarial)"""
    from pyrit.prompt_target import OpenAIChatTarget

    endpoint = os.environ.get("SCORING_CHAT_ENDPOINT") or os.environ.get("SCORER_CHAT_ENDPOINT")
    api_key = os.environ.get("SCORING_CHAT_KEY") or os.environ.get("SCORER_CHAT_KEY")
    model = os.environ.get("SCORING_CHAT_MODEL") or os.environ.get("SCORER_CHAT_MODEL", "gpt-4o")

    target = None
    if endpoint and api_key:
        rpm_str = os.environ.get("RATE_LIMIT", "")
        rpm = int(rpm_str) if rpm_str.isdigit() else None
        target = OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model,
            max_requests_per_minute=rpm,
        )
    elif ctx.adversarial_target:
        logger.info("Scorer target not configured, reusing adversarial target")
        target = ctx.adversarial_target

 # D-04 (2026-09-06): recon -> assess 
 # Capability verification assess Layer (assess/scorer.py:74,
 # assess/dual_judge.py:134, assess/judge_utils.py:998) ,
 # recon Layer, ""
    if target:
        logger.info("Scoring target created (capability validation deferred to assess layer)")

    return target


# ====================================================================
# Playwright Target ()
# ====================================================================


async def _create_playwright_target(ctx: PipelineContext, browser_url: str) -> None:
 """ PyRIT PlaywrightTarget - Chat UI """
    import importlib.util

    if importlib.util.find_spec("playwright") is None:
        raise ImportError(
            "Playwright not installed. Install with: pip install playwright"
        )

    from pyrit.prompt_target import PlaywrightTarget

    async def _chat_interaction(page, message):
        prompt_text = (
            message.message_pieces[0].converted_value
            if hasattr(message, "message_pieces") and message.message_pieces
            else str(message)
        )
        await page.goto(browser_url, wait_until="domcontentloaded")
        await page.wait_for_selector(
            "textarea, input[type='text'], [contenteditable='true']",
            timeout=10000,
        )
        input_selector = await page.query_selector("textarea") or \
            await page.query_selector("input[type='text']") or \
            await page.query_selector("[contenteditable='true']")

        if input_selector is None:
            raise RuntimeError("Could not find input element on the page")

        await input_selector.fill(prompt_text)
        send_button = await page.query_selector(
            "button[type='submit'], button[aria-label*='send']"
        )
        if send_button:
            await send_button.click()
        else:
            await input_selector.press("Enter")

        response_selector = (
            ".message:last-child, .response:last-child, "
            "[data-role='assistant']:last-child"
        )
        try:
            await page.wait_for_selector(response_selector, timeout=30000)
            await page.wait_for_timeout(2000)
        except Exception:
            await page.wait_for_timeout(5000)

        response_element = await page.query_selector(response_selector)
        if response_element:
            return (await response_element.inner_text()).strip()
        return await page.inner_text("body")

    from playwright.async_api import async_playwright

    _playwright_instance = await async_playwright().start()
    _browser = await _playwright_instance.chromium.launch(headless=True)
    _context = await _browser.new_context()
    page = await _context.new_page()

    target = PlaywrightTarget(
        interaction_func=_chat_interaction,
        page=page,
        max_requests_per_minute=int(os.environ.get("BROWSER_TARGET_RPM", "10")),
    )
    ctx.objective_target = target
    ctx.multi_turn_target = target
    ctx.model_name = f"Browser:{browser_url}"

    _ensure_parsed_request_for_api_path(ctx, mode="browser", model_name=browser_url, endpoint=browser_url)

    ctx._playwright_instance = _playwright_instance
    ctx._browser = _browser
    ctx._browser_context = _context


# ====================================================================
# OpenAI Native Target (API )
# ====================================================================


async def _create_native_openai_target(
    ctx: PipelineContext,
    *,
    endpoint: str,
    api_key: str,
    model_name: str,
    api_type: str = "chat",
) -> None:
 """L5 v52: PyRIT OpenAIChatTarget OpenAIResponseTarget"""
    from pyrit.prompt_target import OpenAIChatTarget, OpenAIResponseTarget

    rpm = getattr(ctx.args, "rate_limit", None) or None

    if api_type == "responses":
        target = OpenAIResponseTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            max_requests_per_minute=rpm,
        )
    else:
        target = OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            max_requests_per_minute=rpm,
        )

    wrapped_target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.objective_target = wrapped_target
    ctx.multi_turn_target = wrapped_target
    ctx.model_name = f"OpenAI:{model_name}"

    _ensure_parsed_request_for_api_path(ctx, mode=api_type, model_name=model_name, endpoint=endpoint)


# ====================================================================
# LiteLLM Target ()
# ====================================================================


async def _create_litellm_target(
    ctx: PipelineContext,
    *,
    model_name: str,
) -> None:
 """ PyRIT LiteLLMChatTarget - 100+ LLM """
    from pyrit.prompt_target import LiteLLMChatTarget

    api_key = os.environ.get("LITELLM_API_KEY")
    endpoint = os.environ.get("LITELLM_ENDPOINT")
    headers_str = os.environ.get("LITELLM_HEADERS", "")
    rpm_str = os.environ.get("RATE_LIMIT", "")
    rpm = int(rpm_str) if rpm_str.isdigit() else None

    headers: dict[str, str] | None = None
    if headers_str:
        import json
        try:
            headers = json.loads(headers_str)
        except (json.JSONDecodeError, TypeError):
            logger.warning("LITELLM_HEADERS not valid JSON: %s", headers_str)

    target = LiteLLMChatTarget(
        model_name=model_name,
        api_key=api_key,
        endpoint=endpoint,
        headers=headers,
        max_requests_per_minute=rpm,
    )

    wrapped_target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.objective_target = wrapped_target
    ctx.multi_turn_target = wrapped_target
    ctx.model_name = f"LiteLLM:{model_name}"

    _ensure_parsed_request_for_api_path(ctx, mode="litellm", model_name=model_name, endpoint=endpoint)


# ====================================================================
# Burp parsed_request 
# ====================================================================


def _ensure_parsed_request_for_api_path(
    ctx: PipelineContext,
    *,
    mode: str,
    model_name: str,
    endpoint: str | None,
) -> None:
 """Burp parsed_request, EnsureData flow"""
    from recon.burp_parser import ParsedBurpRequest

    capabilities = "text"
    app_type = mode
    auth_type = "api_key"
    language = "en"

    if mode == "litellm":
        provider = model_name.split("/")[0].lower() if "/" in model_name else ""
        model_family_map = {
            "anthropic": "claude",
            "bedrock": "bedrock",
            "vertex_ai": "gemini",
        }
        model_family = model_family_map.get(provider, provider or "litellm")
    elif mode in ("chat", "responses"):
        model_lower = model_name.lower()
        if "gpt" in model_lower or "o1" in model_lower or "o3" in model_lower or "o4" in model_lower:
            model_family = "openai"
        elif "deepseek" in model_lower:
            model_family = "deepseek"
            language = "zh"
        elif "qwen" in model_lower or "" in model_lower:
            model_family = "qwen"
            language = "zh"
        elif "claude" in model_lower:
            model_family = "claude"
        elif "llama" in model_lower:
            model_family = "llama"
        elif "phi" in model_lower:
            model_family = "phi"
        else:
            model_family = "openai_compatible"
    elif mode == "browser":
        model_family = "browser"
        auth_type = "none"
    else:
        model_family = mode

    _use_tls = True
    _host = endpoint or ""
    _path = ""
    if endpoint:
        from urllib.parse import urlparse
        _parsed_url = urlparse(endpoint)
        _use_tls = _parsed_url.scheme == "https"
        _host = _parsed_url.netloc or _parsed_url.path or endpoint
        _path = _parsed_url.path or ""

    fingerprint = {
        "app_type": app_type,
        "auth_type": auth_type,
        "capabilities": capabilities,
        "model_family": model_family,
        "language": language,
        "api_category": mode,
        "target_type": mode,
        "endpoint": endpoint or "",
        "model_name": model_name,
    }

    ctx.parsed_request = ParsedBurpRequest(
        method="POST",
        url=endpoint or "",
        host=_host,
        path=_path,
        use_tls=_use_tls,
        has_prompt_placeholder=False,
        target_fingerprint=fingerprint,
    )
    logger.debug("Non-Burp path: mode=%s, model_family=%s", mode, model_family)
