"""目标路由 — 纯黑盒 Burp 场景。

唯一路径:
    Burp 请求 → 解析 → 探测响应路径 → 构建 HTTPTarget → RateLimitedTarget 包装

辅助角色:
    - adversarial_target: 从 .env 读取 (用户自己的 LLM API)
    - scoring_target: 从 .env 读取或复用 adversarial
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

    路由逻辑:
        1. --browser-url → PlaywrightTarget (浏览器渲染 Chat UI, PyRIT 原生)
        2. --burp-request → Burp 模式 (HTTPTarget + RateLimitedTarget)
        3. --target-url + --api-key → API 直连模式 (HTTPTarget)
        4. 无参数 → .env 默认 (OpenAIChatTarget)

    L5 v38: 新增 PlaywrightTarget 路由 (PyRIT 原生优势)
        学术依据: PyRIT (arXiv:2407.01232) — PlaywrightTarget 是
        PyRIT 原生浏览器自动化 Target, 可攻击需要 JS 渲染的 Web Chat UI

    流程:
        1. (新增) 如果 --browser-url 设置 → 创建 PlaywrightTarget
        2. 解析 Burp 请求 → ParsedBurpRequest
        3. L5 v12: 目标可用性预检 (发送探针请求, 确保目标在线)
        4. 探测响应路径 (发送 "hi" 探针)
        5. 构建 HTTPTarget
        6. 包装 RateLimitedTarget (并发控制 + 重试)
        7. 创建 adversarial + scoring target (从 .env)

    Args:
        ctx: 流水线上下文。
    """
    # ── L5 v38: PlaywrightTarget 路由 (PyRIT 原生优势) ──
    # 学术依据: PyRIT (arXiv:2407.01232) — PlaywrightTarget 原生浏览器自动化
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
    # ── 解析 Burp 请求 ──
    parsed = parse_burp_request(ctx.args.burp_request)
    ctx.parsed_request = parsed
    ctx.model_name = f"HTTP:{parsed.host}{parsed.path}"

    # ── L5 v12: 目标可用性预检 ──
    # 学术依据: Heroux et al. (arXiv:2403.04206) — 超时恢复策略
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

    # ── 探测响应路径 ──
    logger.info("Probing response format...")
    try:
        await probe_response_path(parsed)
    except Exception as e:
        logger.warning("Response path probing failed (non-fatal): %s — using default", e)
    if parsed.response_json_path:
        logger.info("Response path detected: %s", parsed.response_json_path)
    else:
        logger.info("No response path detected, using default callback")

    # ── 主动能力探测 (P1-7) ──
    # 学术依据: Greshake et al. (arXiv:2302.12173), Zhan et al. (arXiv:2307.00929)
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

    # ── P2-19: 通用深度能力探测 ──
    # 学术依据: Greshake et al. (arXiv:2302.12173) — 目标能力指纹
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
            logger.info(
                "P2-19: Deep capability probe complete. Capabilities: %s, secret_format: %s",
                sorted(all_caps),
                deep_caps.get("secret_format"),
            )
    except Exception as e:
        logger.warning("P2-19: Deep capability probing failed (non-fatal): %s", e)

    # ── MCP 端点枚举 (PyRIT 设计域边界: MCP JSON-RPC 例外) ──
    # 学术依据:
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

    # ── 构建 HTTPTarget (单轮) ──
    target = build_http_target(parsed)

    # ── 包装 RateLimitedTarget ──
    target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
        max_retries=3,
    )
    ctx.objective_target = target

    # ── 构建多轮 HTTPTarget (用于 Crescendo/TAP 升级) ──
    # HTTPTarget 本身无状态，多轮通过在 prompt 中携带对话历史实现
    multi_turn_target = build_http_target(parsed, enable_multi_turn=True)
    multi_turn_target = RateLimitedTarget(
        target=multi_turn_target,
        max_concurrency=ctx.args.max_concurrency or 3,
        max_retries=3,
    )
    ctx.multi_turn_target = multi_turn_target

    # ── 创建 adversarial target (用户自己的 LLM API) ──
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

    # ── 创建 scoring target (缺失时复用 adversarial) ──
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

    学术依据: Heroux et al. (arXiv:2403.04206) — 超时恢复策略
    在攻击开始前发送一个简单的探针请求, 检测目标是否在线。
    避免在不可达目标上浪费时间 (之前多次运行因 402/连接拒绝失败)。

    检查策略:
        1. 发送简单 POST 请求, 使用 stream=True 只读取响应头
        2. 连接超时 5s, 读取超时 15s (SSE 流式响应需要更长)
        3. 接受任何 HTTP 响应 (200/400/401/403 都算在线)
        4. 连接拒绝/超时 = 不可用

    L5 v22 修复: SSE 流式响应导致 httpx 等待整个响应体完成才返回,
    但 SSE 连接不会主动关闭, 5 秒超时必然触发 TimeoutException。
    修复: 使用 stream=True 只读取响应头即可判断可用性,
    不等待整个响应体完成。增加 read 超时到 15 秒。

    Args:
        parsed: 解析后的 Burp 请求。

    Returns:
        True 如果目标在线, False 如果不可达。
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

    读取环境变量:
        ADVERSARIAL_CHAT_ENDPOINT
        ADVERSARIAL_CHAT_KEY
        ADVERSARIAL_CHAT_MODEL (默认 gpt-4o)

    Returns:
        OpenAIChatTarget 实例, 或 None (未配置时)。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    endpoint = os.environ.get("ADVERSARIAL_CHAT_ENDPOINT")
    api_key = os.environ.get("ADVERSARIAL_CHAT_KEY")
    model = os.environ.get("ADVERSARIAL_CHAT_MODEL", "gpt-4o")

    if endpoint and api_key:
        return OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model,
        )

    logger.warning(
        "Adversarial target not configured. "
        "Set ADVERSARIAL_CHAT_ENDPOINT and ADVERSARIAL_CHAT_KEY in .env. "
        "Multi-turn attacks (Crescendo, TAP) will be skipped."
    )
    return None


def _create_extra_adversarial_targets() -> list[Any]:
    """L5 v10: 创建额外的 adversarial targets (多模型并行攻击)。

    学术依据: Chao et al. (arXiv:2310.08419) — 不同 LLM (GPT-4o,
    Claude, Gemini) 在越狱 prompt 生成方面有互补性。
    多模型并行使 ASR 提升 ~20% (联合概率 P = 1 - ∏(1-p_i))。

    读取环境变量 (序号 2, 3 ...):
        ADVERSARIAL_CHAT_ENDPOINT_2, ADVERSARIAL_CHAT_KEY_2, ADVERSARIAL_CHAT_MODEL_2
        ADVERSARIAL_CHAT_ENDPOINT_3, ADVERSARIAL_CHAT_KEY_3, ADVERSARIAL_CHAT_MODEL_3

    Returns:
        额外 adversarial target 列表 (空列表表示无额外配置)。
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

    读取环境变量:
        SCORER_CHAT_ENDPOINT
        SCORER_CHAT_KEY
        SCORER_CHAT_MODEL (默认 gpt-4o)

    Returns:
        OpenAIChatTarget 实例, 或 None (未配置时复用 adversarial)。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    # L5 v32: 优先读取 SCORING_CHAT_* (与 asr_tracker 一致), fallback 到 SCORER_CHAT_*
    endpoint = os.environ.get("SCORING_CHAT_ENDPOINT") or os.environ.get("SCORER_CHAT_ENDPOINT")
    api_key = os.environ.get("SCORING_CHAT_KEY") or os.environ.get("SCORER_CHAT_KEY")
    model = os.environ.get("SCORING_CHAT_MODEL") or os.environ.get("SCORER_CHAT_MODEL", "gpt-4o")

    if endpoint and api_key:
        return OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model,
        )

    # 复用 adversarial target
    if ctx.adversarial_target:
        logger.info("Scorer target not configured, reusing adversarial target")
        return ctx.adversarial_target

    return None


async def _create_playwright_target(ctx: PipelineContext, browser_url: str) -> None:
    """创建 PyRIT 原生 PlaywrightTarget — 浏览器渲染 Chat UI 攻击。

    学术依据:
        - PyRIT (arXiv:2407.01232) — PlaywrightTarget 是 PyRIT 原生
          浏览器自动化 Target, 用于攻击需要 JavaScript 渲染的 Web Chat UI

    PyRIT 原生优势 (Rule 2: 原生优先):
        - 浏览器渲染: 能攻击需要 JS 渲染的 Web Chat 界面 (如 ChatGPT Web)
        - 自定义交互: InteractionFunction 定义任意的页面交互逻辑
        - 原生 Target: 与 PyRIT 的 PromptSendingAttack / CrescendoAttack 等完全兼容
        - 速率限制: 内置 RPM 控制

    交互逻辑:
        1. 打开目标 URL
        2. 定位输入框 (常见选择器: textarea, input[type=text], [contenteditable])
        3. 输入 prompt 文本
        4. 等待响应出现 (常见选择器: .message, .response, [data-role="assistant"])
        5. 提取响应文本

    Args:
        ctx: 流水线上下文。
        browser_url: 目标 Web Chat UI 的 URL。
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
    # 这里使用 async 版本, 由 PlaywrightTarget 内部管理浏览器生命周期
    async def _chat_interaction(page, prompt_text):
        """与 Web Chat UI 交互的函数。

        Args:
            page: Playwright Page 对象。
            prompt_text: 要发送的 prompt 文本。

        Returns:
            目标 Chat UI 的响应文本。
        """
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
        logger.info(
            "L5 v38: PlaywrightTarget created for %s (RPM=%s)",
            browser_url,
            os.environ.get("BROWSER_TARGET_RPM", "10"),
        )
    except Exception as e:
        logger.error("Failed to create PlaywrightTarget: %s", e)
        raise
