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

# Target router helpers (extracted to _target_router_helpers.py)
from recon._target_router_helpers import (
    _check_target_availability,
    _configure_remaining_targets,
    _create_litellm_target,
    _create_native_openai_target,
    _create_playwright_target,
    _init_adaptive_probe,
    _ProbeCounter,
    _run_background_probes,
)

# L5 v54+: Adaptive probe, Guardrail, Model seed mapping (v1.5: simplified)
from recon.burp_parser import (
    build_http_target,
    parse_burp_request,
    probe_response_path,
)

# P2-06: TLS verify (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

# RateLimitedTarget: Concurrency control + auth recovery + capability verification
from recon.target_wrapper import RateLimitedTarget

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
    """orchestration_log (P2-07: )

    Args:
        ctx: PipelineContext  ( orchestration_log ).
        probe_phase:  ( "response_path", "capability", "mcp_enum").
        error: .
        is_fatal:  (True=, False=).
    """
    # : ctx orchestration_log ()
    if ctx is None or not hasattr(ctx, "orchestration_log"):
        return

    ctx.orchestration_log.append(
        {
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
        }
    )


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
            "Non-chat API detected (category=%s, path=%s) - model info extracted, {PROMPT} injection skipped",
            parsed.api_category,
            parsed.path,
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
            parsed.host,
            parsed.path,
        )
        raise ConnectionError(f"Target {parsed.host}:{parsed.path} is not available.")
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
            "Chat ID field '%s' in body with {CHAT_ID} placeholder, will extract from first response",
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
    # -> strike phase (guardrail_report)
    try:
        _probe_ctx = await _init_adaptive_probe(ctx, parsed, _probe_counter)
        ctx.adaptive_probe_ctx = _probe_ctx
        ctx.guardrail_report = _probe_ctx.get("guardrail_report", {})
        ctx.stealth_policy = _probe_ctx.get("stealth_policy", {})
        logger.info(
            "[Adaptive] Pipeline integration OK: guardrail=%s, stealth=%s, adaptive_budget=%s",
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
            _MAX_PROBE_COUNT,
            deep_probe_enabled,
        )

    # == Step 6: ==
    await _configure_remaining_targets(ctx)

    # == ==
    _probe_duration = _time.monotonic() - _probe_start
    # P1-05:
    parsed.target_fingerprint.probe_count = _probe_counter.value
    parsed.target_fingerprint.probe_duration_seconds = round(_probe_duration, 2)
    logger.info(
        "Recon complete: %d probes sent, %.2fs duration (attack starts now, background probes continue)",
        _probe_counter.value,
        _probe_duration,
        ctx._recon_background_tasks,
    )
