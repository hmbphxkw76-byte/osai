"""目标路由 — 纯黑盒 Burp 场景。
"""

from __future__ import annotations

import logging
import os
from typing import Any

from pipeline.context import PipelineContext
from pipeline.recon.burp_parser import (
    build_http_target,
    parse_burp_request,
    probe_active_capabilities,
    probe_response_path,
)
from pipeline.targets.rate_limited import RateLimitedTarget

logger = logging.getLogger(__name__)

async def create_target(ctx: PipelineContext) -> None:
    """创建并注册攻击目标。
    """
    # OpenAIChatTarget: 支持 gpt-4o, DeepSeek, llama, phi-4 等 OpenAI 兼容模型
    # OpenAIResponseTarget: 支持 o1/o3/o4-mini/GPT-5 Responses API
    # 原生优势: RPM 限速, JSON 输出, 多模态输入, TargetCapabilities 自动匹配
    target_api_endpoint = getattr(ctx.args, "target_api_endpoint", None)
    target_api_key = getattr(ctx.args, "target_api_key", None)
    target_api_model = getattr(ctx.args, "target_api_model", None)
    target_api_type = getattr(ctx.args, "target_api_type", "chat")  # chat | responses

    if target_api_endpoint and target_api_key:
        logger.info(
            "L5 v52: API direct mode — creating native %s for %s",
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
        # 仍需创建 adversarial + scoring target
        ctx.adversarial_target = _create_adversarial_target()
        if ctx.adversarial_target:
            logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)
        ctx.extra_adversarial_targets = _create_extra_adversarial_targets()
        ctx.scoring_target = _create_scoring_target(ctx)
        ctx.converter_target = ctx.scoring_target or ctx.adversarial_target
        logger.info(
            "Targets configured: objective=%s, adversarial=%s, scorer=%s",
            type(ctx.objective_target).__name__,
            type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
            type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
        )
        return

    browser_url = getattr(ctx.args, "browser_url", None)
    if browser_url:
        logger.info("L5 v38: Browser mode — creating PlaywrightTarget for %s", browser_url)
        await _create_playwright_target(ctx, browser_url)
        # 仍需创建 adversarial + scoring target
        ctx.adversarial_target = _create_adversarial_target()
        if ctx.adversarial_target:
            logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)
        ctx.extra_adversarial_targets = _create_extra_adversarial_targets()
        ctx.scoring_target = _create_scoring_target(ctx)
        ctx.converter_target = ctx.scoring_target or ctx.adversarial_target
        logger.info(
            "Targets configured: objective=%s, adversarial=%s, scorer=%s",
            type(ctx.objective_target).__name__,
            type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
            type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
        )
        return
    parsed = parse_burp_request(ctx.args.burp_request)
    ctx.parsed_request = parsed
    ctx.model_name = f"HTTP:{parsed.host}{parsed.path}"

    # 在攻击开始前检测目标是否在线, 避免浪费时间在不可达目标上。
    # 如果目标不可达 (连接拒绝/超时/402/503), 提前终止。
    target_available = await _check_target_availability(parsed)
    if not target_available:
        logger.error(
            "L5 v12: Target %s://%s%s is NOT available. Aborting pipeline.",
            "https" if parsed.use_tls else "http",
            parsed.host,
            parsed.path,
        )
        raise ConnectionError(
            f"Target {parsed.host}:{parsed.path} is not available. "
            "Please ensure the target service is running."
        )

    logger.info("L5 v12: Target availability check passed.")

    logger.info("Probing response format...")
    try:
        await probe_response_path(parsed)
    except Exception as e:
        logger.warning("Response path probing failed (non-fatal): %s — using default", e)
    if parsed.response_json_path:
        logger.info("Response path detected: %s", parsed.response_json_path)
    else:
        logger.info("No response path detected, using default callback")

    # 发送专门的探针 prompt 主动检测 Agent/MCP/RAG 能力
    # 比被动关键词匹配更可靠 — 目标被直接询问时会暴露更多能力
    logger.info("Probing active capabilities (agent/mcp/rag)...")
    try:
        active_caps = await probe_active_capabilities(parsed)
        if active_caps:
            existing_caps = parsed.target_fingerprint.get("capabilities", "")
            all_caps = set(existing_caps.split(",")) if existing_caps else set()
            all_caps.update(k for k, v in active_caps.items() if v)
            parsed.target_fingerprint["capabilities"] = ",".join(sorted(all_caps))
            logger.info("Active probe detected capabilities: %s", sorted(all_caps))
    except Exception as e:
        logger.warning("Active capability probing failed (non-fatal): %s — continuing without active caps", e)

    # 对任意目标进行动态能力探测, 不依赖特定路径或 ID 约定
    try:
        from pipeline.recon.capability_probe import deep_probe_capabilities
        deep_caps = await deep_probe_capabilities(parsed)
        if deep_caps:
            # 合并布尔能力到 capabilities 字段
            existing_caps_str = parsed.target_fingerprint.get("capabilities", "")
            all_caps = set(existing_caps_str.split(",")) if existing_caps_str else set()
            for cap_key in [
                "has_function_calling", "has_memory", "has_workflow",
                "has_multi_tenant", "has_session_auth", "has_mcp_protocol",
            ]:
                if deep_caps.get(cap_key):
                    # 转换 has_function_calling → function_calling
                    cap_name = cap_key.replace("has_", "")
                    all_caps.add(cap_name)
            parsed.target_fingerprint["capabilities"] = ",".join(sorted(all_caps))
            if deep_caps.get("secret_format"):
                parsed.target_fingerprint["secret_format"] = deep_caps["secret_format"]
            if deep_caps.get("tool_schemas"):
                parsed.target_fingerprint["tool_schemas"] = deep_caps["tool_schemas"]
            if deep_caps.get("session_type"):
                parsed.target_fingerprint["session_type"] = deep_caps["session_type"]
            # L5 v48: 写入置信度评分和触发建议到 target_fingerprint
            if deep_caps.get("capability_confidence"):
                parsed.target_fingerprint["capability_confidence"] = deep_caps["capability_confidence"]
            if deep_caps.get("capability_recommendations"):
                parsed.target_fingerprint["capability_recommendations"] = deep_caps["capability_recommendations"]
            logger.info(
                "P2-19: Deep capability probe complete. Capabilities: %s, secret_format: %s",
                sorted(all_caps),
                deep_caps.get("secret_format"),
            )
    except Exception as e:
        logger.warning("P2-19: Deep capability probing failed (non-fatal): %s", e)

    #   - Anthropic MCP Specification (2024) §3.2 — tools/list, resources/list
    #   - Greshake et al. (arXiv:2302.12173) §4 — 间接注入利用工具信任
    #   - 课程 AI-300 Ch7.1 — "Extract detailed tool schemas through error-based enumeration"
    # 当能力探测检测到 MCP 能力时, 主动枚举 MCP Server 的 tools/resources/prompts
    # 枚举结果存入 target_fingerprint, 供后续 mcp_attack 种子精准注入使用
    capabilities_str = parsed.target_fingerprint.get("capabilities", "")
    if "mcp" in capabilities_str or "mcp_protocol" in capabilities_str:
        logger.info("MCP capability detected, launching MCP endpoint enumeration...")
        try:
            from pipeline.recon.mcp_enumerator import enumerate_mcp_endpoint

            mcp_results = await enumerate_mcp_endpoint(parsed)
            if mcp_results.get("has_mcp"):
                # 将 MCP 枚举结果存入 target_fingerprint
                parsed.target_fingerprint["mcp_tools"] = mcp_results.get("tools", [])
                parsed.target_fingerprint["mcp_resources"] = mcp_results.get("resources", [])
                parsed.target_fingerprint["mcp_prompts"] = mcp_results.get("prompts", [])
                parsed.target_fingerprint["mcp_tool_names"] = mcp_results.get("tool_names", [])
                parsed.target_fingerprint["mcp_server_info"] = mcp_results.get("server_info")
                logger.info(
                    "MCP enumeration complete: %d tools, %d resources, %d prompts",
                    len(mcp_results.get("tools", [])),
                    len(mcp_results.get("resources", [])),
                    len(mcp_results.get("prompts", [])),
                )
        except Exception as e:
            logger.warning("MCP endpoint enumeration failed (non-fatal): %s", e)
    else:
        logger.debug("No MCP capability detected, skipping MCP enumeration")

    # 在构建 target 前检测认证类型, 初始化 AuthStateManager
    # 攻击执行中 401/403 时可自动尝试 token 刷新 / 租户切换 / 匿名降级
    auth_manager = None
    auth_state = None
    auth_refresh_enabled = getattr(ctx.args, "auth_refresh_enabled", True)
    if auth_refresh_enabled:
        from pipeline.recon.auth_state_manager import AuthStateManager
        auth_manager = AuthStateManager(
            max_refreshes=getattr(ctx.args, "auth_refresh_max_retries", 3),
        )
        auth_state = await auth_manager.detect_auth_type(parsed)
        logger.info(
            "L5 v48: Auth state detected: type=%s, tenant=%s, csrf=%s",
            auth_state.auth_type,
            auth_state.tenant_id or "N/A",
            "yes" if auth_state.csrf_token else "no",
        )
        parsed.target_fingerprint["auth_type"] = auth_state.auth_type
        if auth_state.tenant_id:
            parsed.target_fingerprint["tenant_id"] = auth_state.tenant_id
        if auth_state.token_expiry:
            import time
            remaining = auth_state.token_expiry - time.time()
            logger.info(
                "Token expiry: %.0fs remaining (auto-refresh at %.0fs)",
                remaining,
                remaining - 60,
            )
            if remaining < 300:
                logger.warning(
                    "Token expires in <5 min — consider refreshing before attack",
                )

    # Agent 服务常部署在非标准端口 (3001, 8080, 11434 等)
    port_discovery_enabled = getattr(ctx.args, "port_discovery_enabled", True)
    if port_discovery_enabled:
        from pipeline.recon.port_expander import discover_port_endpoints

        try:
            port_endpoints = await discover_port_endpoints(
                parsed,
                timeout=getattr(ctx.args, "port_discovery_timeout", 3.0),
                max_concurrent=getattr(ctx.args, "port_discovery_max_concurrent", 10),
                early_stop=getattr(ctx.args, "port_discovery_early_stop", 3),
            )
            if port_endpoints:
                logger.info(
                    "L5 v48: Port discovery found %d additional endpoints",
                    len(port_endpoints),
                )
                parsed.target_fingerprint["port_endpoints"] = [
                    {
                        "port": pe.port,
                        "path": pe.path,
                        "status_code": pe.status_code,
                        "service_type": pe.service_type,
                        "use_tls": pe.use_tls,
                    }
                    for pe in port_endpoints
                ]
        except Exception as e:
            logger.warning("L5 v48: Port discovery failed (non-fatal): %s", e)

    target = build_http_target(parsed)

    target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
        max_retries=3,
        auth_state_manager=auth_manager,
        auth_state=auth_state,
    )
    ctx.objective_target = target

    # HTTPTarget 本身无状态，多轮通过在 prompt 中携带对话历史实现
    multi_turn_target = build_http_target(parsed, enable_multi_turn=True)
    multi_turn_target = RateLimitedTarget(
        target=multi_turn_target,
        max_concurrency=ctx.args.max_concurrency or 3,
        max_retries=3,
    )
    ctx.multi_turn_target = multi_turn_target

    # 将 port_expander 发现的端点构建为独立的 HTTPTarget + RateLimitedTarget
    # 存入 ctx.extra_objective_targets 供后续攻击使用
    port_endpoints_data = parsed.target_fingerprint.get("port_endpoints", [])
    if port_endpoints_data:
        from pipeline.recon.burp_parser import ParsedBurpRequest
        from pipeline.recon.port_expander import build_port_parsed_request

        for pe_data in port_endpoints_data:
            try:
                # 构造 DiscoveredPortEndpoint 对象
                from pipeline.recon.port_expander import DiscoveredPortEndpoint
                pe = DiscoveredPortEndpoint(
                    port=pe_data["port"],
                    path=pe_data["path"],
                    status_code=pe_data["status_code"],
                    service_type=pe_data.get("service_type", "unknown"),
                    use_tls=pe_data.get("use_tls", parsed.use_tls),
                )
                # 构建 ParsedBurpRequest 副本
                port_params = build_port_parsed_request(parsed, pe)
                port_parsed = ParsedBurpRequest(
                    method=port_params["method"],
                    url=f"{('https' if port_params['use_tls'] else 'http')}://{port_params['host']}:{port_params['port']}{port_params['path']}",
                    host=port_params["host"],
                    path=port_params["path"],
                    headers=port_params["headers"],
                    raw_headers=list(port_params["headers"].items()),
                    body="{}",
                    use_tls=port_params["use_tls"],
                    is_sse=False,
                    http_version=parsed.http_version,
                    has_prompt_placeholder=True,
                )
                port_target = build_http_target(port_parsed)
                if port_target:
                    port_target = RateLimitedTarget(
                        target=port_target,
                        max_concurrency=ctx.args.max_concurrency or 3,
                        max_retries=3,
                        auth_state_manager=auth_manager,
                        auth_state=auth_state,
                    )
                    ctx.extra_objective_targets[pe.port] = port_target
                    logger.info(
                        "L5 v48: Built target for port %d (%s) → %s",
                        pe.port, pe.service_type, port_params["path"],
                    )
            except Exception as e:
                logger.debug("Failed to build target for port %d: %s", pe_data.get("port"), e)

        logger.info(
            "L5 v48: %d extra objective targets built from port discovery",
            len(ctx.extra_objective_targets),
        )

    # L5 v10: 支持多 adversarial target (多模型并行攻击)
    ctx.adversarial_target = _create_adversarial_target()
    if ctx.adversarial_target:
        logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)

    # L5 v10: 加载额外 adversarial targets (多模型互补)
    extra_targets = _create_extra_adversarial_targets()
    if extra_targets:
        ctx.extra_adversarial_targets = extra_targets
        logger.info("Extra adversarial targets: %d", len(extra_targets))
    else:
        ctx.extra_adversarial_targets = []

    ctx.scoring_target = _create_scoring_target(ctx)
    if ctx.scoring_target:
        logger.info("Scoring target: %s", type(ctx.scoring_target).__name__)

    # converter target = scoring target (Qwen3-32B, JSON 兼容性好于 DeepSeek-V3)
    # L5 v34: DeepSeek-V3 对 PersuasionConverter 的 JSON schema 返回 500 错误
    # Qwen3-32B 对 PyRIT converter 的 JSON 格式兼容性更好
    # converter 只做文本改写, 不需要最强攻击能力
    ctx.converter_target = ctx.scoring_target or ctx.adversarial_target

    logger.info(
        "Targets configured: objective=%s, adversarial=%s, scorer=%s",
        type(target).__name__,
        type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
        type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
    )

async def _check_target_availability(parsed: Any) -> bool:
    """L5 v12: 检查目标 API 是否可用。
    """
    import httpx

    scheme = "https" if parsed.use_tls else "http"
    check_url = f"{scheme}://{parsed.host}{parsed.path}"

    # 构建探针 headers (排除 Content-Length 和 Host)
    check_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            check_headers[key] = value

    check_body = '{"prompt":"hi"}'

    try:
        # L5 v22: 使用 stream=True 避免等待 SSE 响应体完成
        # SSE 流式连接不会主动关闭, httpx 默认等待整个响应体完成
        # 使用 stream=True 后, httpx 在读取到响应头时即返回
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0),
            follow_redirects=True,
            verify=False,
        ) as client:
            async with client.stream(
                method=parsed.method,
                url=check_url,
                headers=check_headers,
                content=check_body,
            ) as response:
                # 402 Payment Required = 目标 API 余额耗尽
                if response.status_code == 402:
                    logger.error(
                        "Target returned 402 Payment Required — API balance depleted."
                    )
                    return False

                # 503 Service Unavailable = 目标临时不可用
                if response.status_code == 503:
                    logger.error("Target returned 503 Service Unavailable.")
                    return False

                # 任何其他响应 (200/400/401/403/429) = 目标在线
                logger.info(
                    "Target availability check: HTTP %d (target is online)",
                    response.status_code,
                )
                return True

    except httpx.ConnectError as e:
        logger.error("Target connection refused: %s", e)
        return False
    except httpx.TimeoutException:
        logger.error("Target availability check timed out (connect=5s, read=15s).")
        return False
    except Exception as e:
        logger.error("Target availability check failed: %s", e)
        return False

def _create_adversarial_target() -> Any:
    """从 .env 创建 adversarial chat 目标。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    endpoint = os.environ.get("ADVERSARIAL_CHAT_ENDPOINT")
    api_key = os.environ.get("ADVERSARIAL_CHAT_KEY")
    model = os.environ.get("ADVERSARIAL_CHAT_MODEL", "gpt-4o")

    # L5 v52: 从环境变量读取 RPM (PyRIT 原生限速)
    # rate_limit 从 config/defaults.yaml 的 rate_limit 键读取,
    # 在 main.py 的 _apply_defaults 中映射到 args.rate_limit。
    # 这里无法访问 ctx, 从环境变量 RATE_LIMIT 读取 (由 main.py 设置)。
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
        "Set ADVERSARIAL_CHAT_ENDPOINT and ADVERSARIAL_CHAT_KEY in .env. "
        "Multi-turn attacks (Crescendo, TAP) will be skipped."
    )
    return None

def _create_extra_adversarial_targets() -> list[Any]:
    """L5 v10: 创建额外的 adversarial targets (多模型并行攻击)。
    """
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
    """从 .env 创建评分器目标 (缺失时复用 adversarial)。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    # L5 v32: 优先读取 SCORING_CHAT_* (与 asr_tracker 一致), fallback 到 SCORER_CHAT_*
    endpoint = os.environ.get("SCORING_CHAT_ENDPOINT") or os.environ.get("SCORER_CHAT_ENDPOINT")
    api_key = os.environ.get("SCORING_CHAT_KEY") or os.environ.get("SCORER_CHAT_KEY")
    model = os.environ.get("SCORING_CHAT_MODEL") or os.environ.get("SCORER_CHAT_MODEL", "gpt-4o")

    target = None
    if endpoint and api_key:
        # L5 v52: 从环境变量读取 RPM (PyRIT 原生限速)
        rpm_str = os.environ.get("RATE_LIMIT", "")
        rpm = int(rpm_str) if rpm_str.isdigit() else None

        target = OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model,
            max_requests_per_minute=rpm,
        )
    else:
        # 复用 adversarial target
        if ctx.adversarial_target:
            logger.info("Scorer target not configured, reusing adversarial target")
            target = ctx.adversarial_target

    # L5 v52: PyRIT 原生 TargetRequirements 验证
    # 在目标创建后、注册到 ctx 前验证, 确保满足评分器需求
    if target:
        try:
            from pipeline.assess.scorer import validate_scoring_target_capabilities

            if not validate_scoring_target_capabilities(target):
                logger.warning(
                    "L5 v52: Scoring target %s failed capability validation; "
                    "LLM-based scoring may fail — consider configuring "
                    "SCORING_CHAT_* with a model that supports JSON output",
                    type(target).__name__,
                )
            else:
                logger.info(
                    "L5 v52: Scoring target %s passed capability validation",
                    type(target).__name__,
                )
        except Exception as e:
            logger.debug("L5 v52: Scoring target validation skipped: %s", e)

    return target

async def _create_playwright_target(ctx: PipelineContext, browser_url: str) -> None:
    """创建 PyRIT 原生 PlaywrightTarget — 浏览器渲染 Chat UI 攻击。
    """
    # 检查 playwright 是否安装 (使用 find_spec 避免 F401 unused import)
    import importlib.util

    if importlib.util.find_spec("playwright") is None:
        logger.error(
            "Playwright not installed. Install with: pip install playwright && playwright install chromium"
        )
        raise ImportError(
            "Playwright is required for --browser-url mode. "
            "Install with: pip install playwright && playwright install chromium"
        )

    try:
        from pyrit.prompt_target import PlaywrightTarget
    except ImportError as e:
        logger.error("PyRIT PlaywrightTarget not available: %s", e)
        raise

    # 定义浏览器交互函数
    # PyRIT PlaywrightTarget 需要 InteractionFunction 和 Page 对象
    # 对齐 PyRIT 1.0.1: InteractionFunction 签名为
    #   async def __call__(self, page: Page, message: Message) -> str
    # 交互函数接收完整 Message 对象 (非字符串)
    async def _chat_interaction(page, message):
        """与 Web Chat UI 交互的函数。
        """
        # 从 Message 中提取 prompt 文本 — 对齐 PyRIT 1.0.1 MessagePiece API
        # message.message_pieces[0].converted_value 是注入的 prompt 文本
        prompt_text = (
            message.message_pieces[0].converted_value
            if hasattr(message, "message_pieces") and message.message_pieces
            else str(message)
        )
        # 导航到目标 URL
        await page.goto(browser_url, wait_until="domcontentloaded")

        # 等待页面加载完成 (常见 Chat UI 容器)
        await page.wait_for_selector(
            "textarea, input[type='text'], [contenteditable='true']",
            timeout=10000,
        )

        # 定位输入框 (按优先级尝试常见选择器)
        input_selector = await page.query_selector("textarea") or \
            await page.query_selector("input[type='text']") or \
            await page.query_selector("[contenteditable='true']")

        if input_selector is None:
            raise RuntimeError("Could not find input element on the page")

        # 输入 prompt
        await input_selector.fill(prompt_text)

        # 按 Enter 或点击发送按钮
        send_button = await page.query_selector(
            "button[type='submit'], button[aria-label*='send'], button[aria-label*='Send']"
        )
        if send_button:
            await send_button.click()
        else:
            await input_selector.press("Enter")

        # 等待响应出现 (常见响应容器选择器)
        response_selector = (
            ".message:last-child, .response:last-child, "
            "[data-role='assistant']:last-child, .chat-message:last-child"
        )
        try:
            await page.wait_for_selector(response_selector, timeout=30000)
            # 额外等待响应稳定 (内容不再变化)
            await page.wait_for_timeout(2000)
        except Exception:
            logger.warning("Response selector not found, waiting for any text change")
            await page.wait_for_timeout(5000)

        # 提取响应文本
        response_element = await page.query_selector(response_selector)
        if response_element:
            response_text = await response_element.inner_text()
            return response_text.strip()

        # Fallback: 提取页面所有文本
        return await page.inner_text("body")

    # 创建 PlaywrightTarget — 需要有效的 Page 对象
    try:
        from playwright.async_api import async_playwright

        # L5 v38 修复: _create_playwright_target 是 async 函数,
        # 直接 await 获取 Page 对象, 不再创建嵌套事件循环
        # (嵌套事件循环在已有 async 上下文中会崩溃)
        # 生产级修复: 存储引用到 ctx 以便后续清理
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
        ctx.multi_turn_target = target  # PlaywrightTarget 支持多轮
        ctx.model_name = f"Browser:{browser_url}"

        # 生产级资源管理: 存储引用供流水线结束时清理
        ctx._playwright_instance = _playwright_instance
        ctx._browser = _browser
        ctx._browser_context = _context

        logger.info(
            "L5 v38: PlaywrightTarget created for %s (RPM=%s)",
            browser_url,
            os.environ.get("BROWSER_TARGET_RPM", "10"),
        )
    except Exception as e:
        logger.error("Failed to create PlaywrightTarget: %s", e)
        raise

async def _create_native_openai_target(
    ctx: PipelineContext,
    *,
    endpoint: str,
    api_key: str,
    model_name: str,
    api_type: str = "chat",
) -> None:
    """L5 v52: 创建 PyRIT 原生 OpenAIChatTarget 或 OpenAIResponseTarget。
    """
    from pyrit.prompt_target import OpenAIChatTarget, OpenAIResponseTarget

    # 从 config 读取 RPM (与 RateLimitedTarget 一致)
    rpm = getattr(ctx.args, "rate_limit", None) or None

    if api_type == "responses":
        # OpenAIResponseTarget — Responses API (o1/o3/o4-mini/GPT-5)
        # 原生支持 reasoning_effort, reasoning_summary, custom_functions
        target = OpenAIResponseTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            max_requests_per_minute=rpm,
        )
        logger.info(
            "L5 v52: OpenAIResponseTarget created: endpoint=%s, model=%s, RPM=%s",
            endpoint, model_name, rpm or "unlimited",
        )
    else:
        # OpenAIChatTarget — Chat Completions API (gpt-4o, DeepSeek 等)
        # 原生支持 temperature, top_p, frequency_penalty, max_completion_tokens
        target = OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            max_requests_per_minute=rpm,
        )
        logger.info(
            "L5 v52: OpenAIChatTarget created: endpoint=%s, model=%s, RPM=%s",
            endpoint, model_name, rpm or "unlimited",
        )

    # 包装 RateLimitedTarget (并发控制 + 重试)
    # 保留原生 TargetCapabilities (不传 custom_configuration)
    wrapped_target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
        max_retries=3,
        requests_per_minute=rpm,
    )
    ctx.objective_target = wrapped_target
    ctx.multi_turn_target = wrapped_target  # 原生支持多轮

    # 设置 model_name
    ctx.model_name = f"OpenAI:{model_name}"

    # L5 v52: 可选 — 运行 PyRIT 原生能力探测
    # 原生 OpenAIChatTarget/OpenAIResponseTarget 已有正确的 TargetCapabilities,
    # 但运行时探测可以发现端点实际支持的能力 (如 Azure 部署可能禁用了某些能力)
    auto_discover = getattr(ctx.args, "auto_discover_capabilities", False)
    if auto_discover:
        logger.info("L5 v52: Running native capability discovery...")
        await wrapped_target.apply_discovered_capabilities(timeout_s=15.0)
