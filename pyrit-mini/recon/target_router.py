# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2402.19181 — Zeng et al., Persuasion
# arXiv:2407.01232 — PyRIT, framework foundation
"""目标路由 — 纯黑盒 Burp 场景。

唯一路径:
    Burp 请求 → 解析 → 探测响应路径 → 构建 HTTPTarget → RateLimitedTarget 包装

辅助角色:
    - adversarial_target: 从 .env 读取 (用户自己的 LLM API)
    - scoring_target: 从 .env 读取或复用 adversarial

P0-02 宪法合规 (修 C2 探测风暴):
    探测总数 ≤ 5 个 (P0 可用 2 + P1 能力 3，P2 延迟至战斗阶段)
    所有非核心探测异步进行，不阻塞攻击启动。
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
from targets.rate_limited import RateLimitedTarget

# P2-06: TLS verify 配置化 (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config
_TLS_VERIFY = _get_tls_verify_from_config()

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════════
# 探测风暴防护 - 硬限制探针宪法上限 ≥ 3. 默认 10 保护交互 (直接为攻击核心服务)
_MAX_PROBE_COUNT = int(os.environ.get("RECON_MAX_PROBES", "10"))


async def create_target(ctx: PipelineContext) -> None:
    """创建并注册攻击目标。

    路由逻辑:
        1. --browser-url → PlaywrightTarget (浏览器渲染 Chat UI)
        2. --target-api-endpoint + --target-api-key → API 直连模式
        3. --burp → Burp 模式 (HTTPTarget + RateLimitedTarget)
        4. --target-url + --api-key → API 直连模式
        5. 无参数 → .env 默认

    P0-02 流程 (限制探测数 ≤ 5 核心):
        1. 解析 Burp 请求 → ParsedBurpRequest
        2. P0-1: 目标可用性预检 (1 个探针)
        3. P0-2: 响应路径探测 (1-2 个探针)
        4. P0-3: HTTPTarget 构建 + RateLimitedTarget 包装
        5. P1 (异步非阻塞): 能力核心探测 (最多 3 个)
           - 任务挂载到 ctx._recon_background_tasks，在攻击执行期间后台运行
        6. P2 完全延后至 arm 或通过 CLI 参数启用

    Args:
        ctx: 流水线上下文。
    """
    # ── L5 v52: OpenAIChatTarget/OpenAIResponseTarget 原生路由 ──
    target_api_endpoint = getattr(ctx.args, "target_api_endpoint", None)
    target_api_key = getattr(ctx.args, "target_api_key", None)
    target_api_model = getattr(ctx.args, "target_api_model", None)
    target_api_type = getattr(ctx.args, "target_api_type", "chat")

    # ── LiteLLM 多提供商路由 ──
    litellm_model = getattr(ctx.args, "litellm_model", None) or os.environ.get("LITELLM_MODEL")
    if litellm_model:
        logger.info("LiteLLM mode — creating native LiteLLMChatTarget for %s", litellm_model)
        await _create_litellm_target(ctx, model_name=litellm_model)
        await _configure_remaining_targets(ctx)
        return

    if target_api_endpoint and target_api_key:
        logger.info(
            "API direct mode — creating native %s for %s",
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

    # ── L5 v38: PlaywrightTarget 路由 ──
    browser_url = getattr(ctx.args, "browser_url", None)
    if browser_url:
        logger.info("Browser mode — creating PlaywrightTarget for %s", browser_url)
        await _create_playwright_target(ctx, browser_url)
        await _configure_remaining_targets(ctx)
        return

    # ════════════════════════════════════════════════════════════════
    # Burp 模式 — P0-02 探测风暴防护核心
    # ════════════════════════════════════════════════════════════════

    # ── Step 1: 解析 Burp 请求 ──
    parsed = parse_burp_request(ctx.args.burp)
    ctx.parsed_request = parsed
    ctx.model_name = f"HTTP:{parsed.host}{parsed.path}"

    # ── L5 v53: 模型信息从 Burp 响应提取 ──
    if parsed.burp_model_name:
        ctx.model_name = parsed.burp_model_name
        # P1-05: 使用属性赋值
        parsed.target_fingerprint.burp_model_name = parsed.burp_model_name
        logger.info("Model name from Burp response: %s", parsed.burp_model_name)

    if parsed.burp_model_list:
        # P1-05: 使用 extra dict 存储非 Schema 字段
        parsed.target_fingerprint.extra["burp_model_list"] = "yes"
        logger.info("Model list extracted from Burp (length=%d)", len(parsed.burp_model_list))

    if parsed.original_prompt_value:
        # P1-05: 使用属性赋值
        parsed.target_fingerprint.original_prompt = parsed.original_prompt_value[:200]
        logger.info("Original prompt from Burp: %s", parsed.original_prompt_value[:80])

    if parsed.api_category != "chat":
        logger.info(
            "Non-chat API detected (category=%s, path=%s) — model info extracted, "
            "{PROMPT} injection skipped",
            parsed.api_category, parsed.path,
        )

    # ── Step 2 (P0): 目标可用性预检 (1 个探针) ──
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

    # ── Step 3 (P0): 响应路径探测 (0-1 个探针) ──
    logger.info("Probing response format...")
    try:
        await probe_response_path(parsed)
        _probe_counter.add(1)
    except Exception as e:
        logger.warning("Response path probing failed (non-fatal): %s", e)

    if parsed.response_json_path:
        logger.info("Response path detected: %s", parsed.response_json_path)
    else:
        logger.info("No response path detected, using default callback")

    # ── Chat ID 日志 ──
    if parsed.chat_id:
        logger.info("Chat ID from probe/Burp response: %s", parsed.chat_id)
    elif parsed.has_chat_id_placeholder:
        logger.info(
            "Chat ID field '%s' in body with {CHAT_ID} placeholder, "
            "will extract from first response",
            parsed.chat_id_field,
        )

    # ── Step 4 (P0): 构建 HTTPTarget (0 个探针 - 仅 HTTP 包装) ──
    target = build_http_target(parsed)
    target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.objective_target = target

    # ── Step 4.1 (P0): 多轮 HTTPTarget ──
    multi_turn_target = build_http_target(parsed, enable_multi_turn=True)
    multi_turn_target = RateLimitedTarget(
        target=multi_turn_target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.multi_turn_target = multi_turn_target

    # ── Step 5 (P1 异步非阻塞): 能力核心探测 ──
    # P0-02: 仅当用户使用 --deep-probe 或探测计数 < 上限时执行
    # 任务挂载到 ctx._recon_background_tasks，在攻击执行期间后台运行
    deep_probe_enabled = getattr(ctx.args, "deep_probe", False)
    always_capability_probe = getattr(ctx.args, "capability_probe", True)

    if always_capability_probe and _probe_counter.value < _MAX_PROBE_COUNT:
        # 启动后台探测任务 (不阻塞攻击启动)
        bg_task = asyncio.create_task(
            _run_background_probes(parsed, _probe_counter, deep_probe_enabled),
            name="recon_background_probes",
        )
        if not hasattr(ctx, "_recon_background_tasks"):
            ctx._recon_background_tasks = []
        ctx._recon_background_tasks.append(bg_task)
        logger.info(
            "Background capability probes launched (cap=%d, deep=%s)",
            _MAX_PROBE_COUNT, deep_probe_enabled,
        )

    # ── Step 6: 剩余目标配置 ──
    await _configure_remaining_targets(ctx)

    # ── 记录探测统计 ──
    _probe_duration = _time.monotonic() - _probe_start
    # P1-05: 使用属性赋值
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
    """配置 adversarial/scoring/converter targets."""
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


# ════════════════════════════════════════════════════════════════════
# 探测计数器 - 防止探测风暴
# ════════════════════════════════════════════════════════════════════


class _ProbeCounter:
    """线程安全的探针计数器，用于限制总探测数。"""

    def __init__(self) -> None:
        self.value: int = 0

    def add(self, n: int = 1) -> None:
        self.value += n

    def can_probe(self, n: int = 1, max_probes: int = _MAX_PROBE_COUNT) -> bool:
        return self.value + n <= max_probes


# ════════════════════════════════════════════════════════════════════
# P1 后台探测任务 (异步非阻塞)
# ════════════════════════════════════════════════════════════════════


async def _run_background_probes(
    parsed: Any,
    counter: _ProbeCounter,
    deep_probe: bool = False,
) -> None:
    """后台运行非核心能力探测，不阻塞攻击主流程。

    探测优先级 (按 ASR 贡献排序):
        1. probe_active_capabilities (agent/mcp/rag 关键词)
        2. MCP 枚举 (如果探测到 MCP 能力)
        3. system_prompt_extraction (泄露探测，高价值用于种子定制)

    P0-02 深度探测 (仅当 deep_probe=True):
        - deep_probe_capabilities (8 个深度探针，高延迟)
        - OpenAPI 发现 (API schema 用于定向注入)
        - 向量数据库确认 (RAG 攻击辅助)

    Args:
        parsed: 解析后的 Burp 请求。
        counter: 全局探针计数器。
        deep_probe: 是否运行深度探测 (默认 False)。
    """
    logger.info("Background probes started (cap=%d)...", _MAX_PROBE_COUNT)

    # ── P1-1: 执行 probe_active_capabilities (3 个关键词探测) ──
    try:
        active_caps = await probe_active_capabilities(parsed)
        counter.add(3)
        if active_caps:
            # P1-05: 使用属性赋值
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
        logger.warning("Background: active probe failed: %s", e)

    # ── P1-2: MCP 枚举 (条件触发 - 仅在检测到 MCP 能力时) ──
    capabilities_str = parsed.target_fingerprint.extra.get("capabilities", "")
    if "mcp" in capabilities_str or "mcp_protocol" in capabilities_str:
        logger.info("MCP capability detected, launching MCP enumeration...")
        try:
            from recon.mcp_enumerator import enumerate_mcp_endpoint
            mcp_results = await enumerate_mcp_endpoint(parsed)
            if mcp_results.get("has_mcp"):
                # P1-05: 使用属性赋值
                parsed.target_fingerprint.mcp_tools = mcp_results.get("tools", [])
                parsed.target_fingerprint.mcp_resources = mcp_results.get("resources", [])
                parsed.target_fingerprint.mcp_prompts = mcp_results.get("prompts", [])
                logger.info(
                    "Background: MCP enumeration: %d tools, %d resources",
                    len(mcp_results.get("tools", [])),
                    len(mcp_results.get("resources", [])),
                )
        except Exception as e:
            logger.warning("Background: MCP enumeration failed: %s", e)

    # ── P1-3: 系统提示泄露探测 (高价值 - 用于种子定制) ──
    if counter.can_probe(3, _MAX_PROBE_COUNT):
        try:
            from recon.system_prompt_extractor import extract_system_prompt
            sp_result = await extract_system_prompt(parsed)
            counter.add(3)
            if sp_result.get("system_prompt_leaked"):
                # P1-05: 使用属性赋值
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
            logger.warning("Background: system prompt extraction failed: %s", e)

    # ── P2 (仅当 deep_probe=True): 深度探测 ──
    if not deep_probe:
        logger.info("Background probes complete (deep probe disabled).")
        return

    # 深度探测: deep_probe_capabilities (并行 8 个)
    if counter.can_probe(8, _MAX_PROBE_COUNT):
        try:
            from recon.capability_probe import deep_probe_capabilities
            deep_caps = await deep_probe_capabilities(parsed)
            counter.add(8)
            if deep_caps:
                # P1-05: 使用属性赋值
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
                # P1-05: 识别字段使用属性赋值, 非 Schema 字段使用 extra dict
                for k in ("secret_format", "tool_schemas", "model_family"):
                    if deep_caps.get(k):
                        parsed.target_fingerprint.extra[k] = deep_caps[k]
                # Schema 中的 session_type
                if deep_caps.get("session_type"):
                    parsed.target_fingerprint.session_type = deep_caps["session_type"]
                # 额外字段存储到 extra
                for k in ("model_ids", "api_behavior", "capability_confidence", "capability_recommendations"):
                    if deep_caps.get(k):
                        parsed.target_fingerprint.extra[k] = deep_caps[k]
        except Exception as e:
            logger.warning("Background: deep probe failed: %s", e)

    # OpenAPI 发现 (仅 deep_probe)
    if counter.can_probe(5, _MAX_PROBE_COUNT):
        try:
            from recon.openapi_discoverer import discover_openapi_spec
            openapi_result = await discover_openapi_spec(parsed)
            counter.add(5)
            if openapi_result and openapi_result.endpoints:
                # P1-05: 使用属性赋值
                parsed.target_fingerprint.openapi_spec_path = openapi_result.spec_path
                parsed.target_fingerprint.openapi_endpoints = [
                    {"path": ep.path, "method": ep.method, "summary": ep.summary}
                    for ep in openapi_result.endpoints[:20]  # 限制存储数量
                ]
        except Exception as e:
            logger.warning("Background: OpenAPI discovery failed: %s", e)

    logger.info("Background probes complete. Total probes: %d", counter.value)


# ════════════════════════════════════════════════════════════════════
# P0 目标可用性预检
# ════════════════════════════════════════════════════════════════════


async def _check_target_availability(parsed: Any) -> bool:
    """P0: 检查目标 API 是否可用。

    检查策略:
        1. 发送简单 POST 请求, 使用 stream=True 只读取响应头
        2. 连接超时 5s, 读取超时 15s
        3. 接受任何 HTTP 响应 (200/400/401/403 都算在线)
        4. 402/503 = 终止; 连接拒绝/超时 = 不可用

    Args:
        parsed: 解析后的 Burp 请求。

    Returns:
        True 如果目标在线, False 如果不可达。
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


# ════════════════════════════════════════════════════════════════════
# Adversarial / Scoring Target 创建
# ════════════════════════════════════════════════════════════════════


def _create_adversarial_target() -> Any:
    """从 .env 创建 adversarial chat 目标。"""
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
    """L5 v10: 创建额外的 adversarial targets (多模型并行攻击)。"""
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
    """从 .env 创建评分器目标 (缺失时复用 adversarial)。"""
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

    # PyRIT 原生验证
    if target:
        try:
            from assess.scorer import validate_scoring_target_capabilities
            if not validate_scoring_target_capabilities(target):
                logger.warning("Scoring target failed capability validation")
            else:
                logger.info("Scoring target passed capability validation")
        except Exception as e:
            logger.debug("Scoring target validation skipped: %s", e)

    return target


# ════════════════════════════════════════════════════════════════════
# Playwright Target (浏览器模式)
# ════════════════════════════════════════════════════════════════════


async def _create_playwright_target(ctx: PipelineContext, browser_url: str) -> None:
    """创建 PyRIT 原生 PlaywrightTarget — 浏览器渲染 Chat UI 攻击。"""
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


# ════════════════════════════════════════════════════════════════════
# OpenAI Native Target (API 直连)
# ════════════════════════════════════════════════════════════════════


async def _create_native_openai_target(
    ctx: PipelineContext,
    *,
    endpoint: str,
    api_key: str,
    model_name: str,
    api_type: str = "chat",
) -> None:
    """L5 v52: 创建 PyRIT 原生 OpenAIChatTarget 或 OpenAIResponseTarget。"""
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


# ════════════════════════════════════════════════════════════════════
# LiteLLM Target (多提供商)
# ════════════════════════════════════════════════════════════════════


async def _create_litellm_target(
    ctx: PipelineContext,
    *,
    model_name: str,
) -> None:
    """创建 PyRIT 原生 LiteLLMChatTarget — 适配 100+ LLM 提供商。"""
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


# ════════════════════════════════════════════════════════════════════
# 非 Burp 路径 parsed_request 兼容
# ════════════════════════════════════════════════════════════════════


def _ensure_parsed_request_for_api_path(
    ctx: PipelineContext,
    *,
    mode: str,
    model_name: str,
    endpoint: str | None,
) -> None:
    """为非Burp路径创建轻量级 parsed_request, 确保数据流一致性。"""
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
        elif "qwen" in model_lower or "通义" in model_lower:
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
