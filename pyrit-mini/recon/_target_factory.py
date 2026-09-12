# -*- coding: utf-8 -*-
"""Target factory — construction of PyRIT prompt targets.

SRP split from `recon/_target_router_helpers.py` (R-DELIVERY-1): owns the
*creation* of adversarial / scoring / playwright / native-OpenAI / litellm
targets and the derived `ParsedBurpRequest` for non-Burp paths. The probe /
adaptive-orchestration logic stays in `_target_router_helpers.py` and imports
the builders from here.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from recon.target_wrapper import RateLimitedTarget

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)


def _create_adversarial_target() -> Any:
    """imports .env adversarial chat"""
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

    logger.warning("Adversarial target not configured. Set ADVERSARIAL_CHAT_ENDPOINT and ADVERSARIAL_CHAT_KEY in .env.")
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


async def _create_playwright_target(ctx: PipelineContext, browser_url: str) -> None:
    """PyRIT PlaywrightTarget - Chat UI"""
    import importlib.util

    if importlib.util.find_spec("playwright") is None:
        raise ImportError("Playwright not installed. Install with: pip install playwright")

    from pyrit.prompt_target import PlaywrightTarget

    from recon._target_router_helpers import _playwright_handles

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
        input_selector = (
            await page.query_selector("textarea")
            or await page.query_selector("input[type='text']")
            or await page.query_selector("[contenteditable='true']")
        )

        if input_selector is None:
            raise RuntimeError("Could not find input element on the page")

        await input_selector.fill(prompt_text)
        send_button = await page.query_selector("button[type='submit'], button[aria-label*='send']")
        if send_button:
            await send_button.click()
        else:
            await input_selector.press("Enter")

        response_selector = ".message:last-child, .response:last-child, [data-role='assistant']:last-child"
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

    # Store Playwright handles in module-level dict (keeps ctx ASR-centered)
    _playwright_handles["instance"] = _playwright_instance
    _playwright_handles["browser"] = _browser
    _playwright_handles["context"] = _context


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

    from core.resilience import build_target_resilience

    wrapped_target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
        **build_target_resilience(ctx, endpoint),
    )
    ctx.objective_target = wrapped_target
    ctx.multi_turn_target = wrapped_target
    ctx.model_name = f"OpenAI:{model_name}"

    _ensure_parsed_request_for_api_path(ctx, mode=api_type, model_name=model_name, endpoint=endpoint)


async def _create_litellm_target(
    ctx: PipelineContext,
    *,
    model_name: str,
) -> None:
    """PyRIT LiteLLMChatTarget - 100+ LLM"""
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

    from core.resilience import build_target_resilience

    wrapped_target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
        **build_target_resilience(ctx, endpoint),
    )
    ctx.objective_target = wrapped_target
    ctx.multi_turn_target = wrapped_target
    ctx.model_name = f"LiteLLM:{model_name}"

    _ensure_parsed_request_for_api_path(ctx, mode="litellm", model_name=model_name, endpoint=endpoint)


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
