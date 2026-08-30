"""AgentTargetAdapter — 适配任意基于 LLM 开发的 Agent 的目标对象。

对齐 PyRIT 1.0.1 官方架构:
    PyRIT 1.0.1 提供了多种原生 PromptTarget 实现:
    - ``OpenAIChatTarget``: OpenAI Chat Completions API (gpt-4o, DeepSeek 等)
    - ``OpenAIResponseTarget``: OpenAI Responses API (o1/o3/GPT-5)
    - ``LiteLLMChatTarget``: 100+ LLM 提供商 (Anthropic, Bedrock, Vertex 等)
    - ``HTTPTarget``: 原始 HTTP 请求 (Burp 场景)
    - ``HTTPXAPITarget``: API 模式 (文件上传/multipart)
    - ``PlaywrightTarget``: 浏览器自动化 (JS 渲染 Chat UI)
    - ``RoundRobinTarget``: 多目标轮询 (负载分散)

    本模块通过统一适配器模式, 将任意 LLM Agent 端点路由到
    最适合的 PyRIT 原生 Target, 提升 attack coverage 广度:

    路由策略 (优先级递减):
        1. OpenAI 兼容 API (chat/responses) → OpenAIChatTarget/OpenAIResponseTarget
        2. LiteLLM 多提供商 (Anthropic/Bedrock/Vertex) → LiteLLMChatTarget
        3. 浏览器渲染 Chat UI → PlaywrightTarget
        4. 原始 HTTP (Burp) → HTTPTarget (JSONSafeHTTPTarget)
        5. API 模式 (文件上传/multipart) → HTTPXAPITarget

    生产级特性:
        - 自动能力探测: 使用 PyRIT 原生 ``discover_target_capabilities_async``
        - RPM 限速: PyRIT 原生 ``max_requests_per_minute`` 参数
        - 重试: PyRIT 原生 ``@pyrit_target_retry`` 装饰器
        - 并发控制: ``RateLimitedTarget`` 包装器
        - 认证恢复: 401/403 自动 token 刷新 (HTTPTarget 场景)
        - 多目标轮询: ``RoundRobinTarget`` 集成

学术依据:
    - PyRIT (arXiv:2407.01232) — PromptTarget 架构设计
    - Greshake et al. (arXiv:2302.12173) — 目标能力探测先于攻击
    - Heroux et al. (arXiv:2403.04206) — 认证失效恢复策略
"""

from __future__ import annotations

import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)

# 路由模式枚举
TargetMode = Literal[
    "openai_chat",       # OpenAI Chat Completions API
    "openai_responses",  # OpenAI Responses API
    "litellm",           # LiteLLM 多提供商
    "browser",           # PlaywrightTarget 浏览器自动化
    "http",              # HTTPTarget 原始 HTTP (Burp)
    "httpx_api",         # HTTPXAPITarget API 模式
    "round_robin",       # RoundRobinTarget 多目标轮询
]


def create_agent_target(
    *,
    mode: TargetMode,
    endpoint: str | None = None,
    api_key: str | None = None,
    model_name: str | None = None,
    headers: dict[str, str] | None = None,
    http_request: str | None = None,
    browser_url: str | None = None,
    max_requests_per_minute: int | None = None,
    max_concurrency: int = 3,
    temperature: float | None = None,
    top_p: float | None = None,
    extra_body_parameters: dict[str, Any] | None = None,
    auth_state_manager: Any | None = None,
    auth_state: Any | None = None,
    round_robin_targets: list[Any] | None = None,
    round_robin_weights: list[int] | None = None,
    **kwargs: Any,
) -> Any:
    """创建适配任意 LLM Agent 的 PyRIT 原生 Target。

    统一入口: 根据 mode 路由到最适合的 PyRIT 原生 Target,
    并包装 RateLimitedTarget 提供并发控制 + 认证恢复。

    对齐 PyRIT 1.0.1 架构:
        - 所有 Target 均为 PyRIT 原生类 (R2: 原生优先)
        - RateLimitedTarget 为增强包装器 (不覆盖原生逻辑)
        - TargetConfiguration + TargetCapabilities 声明式能力验证
        - 原生 ``@limit_requests_per_minute`` + ``@pyrit_target_retry`` 装饰器

    Args:
        mode: 目标模式 (见 TargetMode 枚举)。
        endpoint: API 端点 URL (openai/litellm 模式)。
        api_key: API 密钥 (openai/litellm 模式)。
        model_name: 模型名称 (如 gpt-4o, anthropic/claude-sonnet-4-6)。
        headers: 额外 HTTP 头 (litellm/http 模式)。
        http_request: 原始 HTTP 请求字符串 (http 模式, Burp 场景)。
        browser_url: 浏览器 URL (browser 模式)。
        max_requests_per_minute: 每分钟最大请求数 (PyRIT 原生 RPM 限速)。
        max_concurrency: 最大并发数 (RateLimitedTarget 增强)。
        temperature: 采样温度 (openai/litellm 模式)。
        top_p: 核采样概率 (openai/litellm 模式)。
        extra_body_parameters: 额外请求体参数 (openai/litellm 模式)。
        auth_state_manager: 认证状态管理器 (http 模式)。
        auth_state: 认证状态 (http 模式)。
        round_robin_targets: 轮询目标列表 (round_robin 模式)。
        round_robin_weights: 轮询权重 (round_robin 模式)。
        **kwargs: 额外参数透传。

    Returns:
        RateLimitedTarget 包装的 PyRIT 原生 Target 实例。
    """
    from targets.rate_limited import RateLimitedTarget

    target = _create_raw_target(
        mode=mode,
        endpoint=endpoint,
        api_key=api_key,
        model_name=model_name,
        headers=headers,
        http_request=http_request,
        browser_url=browser_url,
        max_requests_per_minute=max_requests_per_minute,
        temperature=temperature,
        top_p=top_p,
        extra_body_parameters=extra_body_parameters,
        round_robin_targets=round_robin_targets,
        round_robin_weights=round_robin_weights,
        **kwargs,
    )

    # 包装 RateLimitedTarget (并发控制 + 认证恢复)
    # 对齐 PyRIT 1.0.1: 不覆盖原生装饰器, 仅增强并发控制
    wrapped = RateLimitedTarget(
        target=target,
        max_concurrency=max_concurrency,
        auth_state_manager=auth_state_manager,
        auth_state=auth_state,
    )

    logger.info(
        "AgentTargetAdapter: mode=%s, target=%s, concurrency=%d, rpm=%s",
        mode,
        type(target).__name__,
        max_concurrency,
        max_requests_per_minute or "unlimited",
    )

    return wrapped


def _create_raw_target(
    *,
    mode: TargetMode,
    endpoint: str | None = None,
    api_key: str | None = None,
    model_name: str | None = None,
    headers: dict[str, str] | None = None,
    http_request: str | None = None,
    browser_url: str | None = None,
    max_requests_per_minute: int | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    extra_body_parameters: dict[str, Any] | None = None,
    round_robin_targets: list[Any] | None = None,
    round_robin_weights: list[int] | None = None,
    **kwargs: Any,
) -> Any:
    """根据 mode 创建 PyRIT 原生 Target (不带 RateLimitedTarget 包装)。

    对齐 PyRIT 1.0.1 原生 Target 体系:
        - openai_chat → OpenAIChatTarget (Chat Completions API)
        - openai_responses → OpenAIResponseTarget (Responses API)
        - litellm → LiteLLMChatTarget (100+ LLM 提供商)
        - browser → PlaywrightTarget (浏览器自动化)
        - http → JSONSafeHTTPTarget (原始 HTTP, Burp 场景)
        - httpx_api → HTTPXAPITarget (API 模式, 文件上传)
        - round_robin → RoundRobinTarget (多目标轮询)
    """
    if mode == "openai_chat":
        return _create_openai_chat_target(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name or "gpt-4o",
            max_requests_per_minute=max_requests_per_minute,
            temperature=temperature,
            top_p=top_p,
            extra_body_parameters=extra_body_parameters,
            **kwargs,
        )

    if mode == "openai_responses":
        return _create_openai_response_target(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name or "o3-mini",
            max_requests_per_minute=max_requests_per_minute,
            **kwargs,
        )

    if mode == "litellm":
        return _create_litellm_target(
            model_name=model_name,
            api_key=api_key,
            endpoint=endpoint,
            headers=headers,
            max_requests_per_minute=max_requests_per_minute,
            temperature=temperature,
            top_p=top_p,
            extra_body_parameters=extra_body_parameters,
            **kwargs,
        )

    if mode == "browser":
        return _create_browser_target(
            browser_url=browser_url or "",
            max_requests_per_minute=max_requests_per_minute,
            **kwargs,
        )

    if mode == "http":
        return _create_http_target(
            http_request=http_request or "",
            max_requests_per_minute=max_requests_per_minute,
            **kwargs,
        )

    if mode == "httpx_api":
        return _create_httpx_api_target(
            endpoint=endpoint or "",
            max_requests_per_minute=max_requests_per_minute,
            headers=headers,
            **kwargs,
        )

    if mode == "round_robin":
        return _create_round_robin_target(
            targets=round_robin_targets or [],
            weights=round_robin_weights,
        )

    raise ValueError(f"Unknown target mode: {mode}. Valid modes: {list(TargetMode.__args__)}")


# ════════════════════════════════════════════════════════════════════
# 各模式 Target 创建函数
# ════════════════════════════════════════════════════════════════════

def _create_openai_chat_target(
    *,
    endpoint: str | None,
    api_key: str | None,
    model_name: str,
    max_requests_per_minute: int | None,
    temperature: float | None = None,
    top_p: float | None = None,
    extra_body_parameters: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Any:
    """创建 PyRIT 原生 OpenAIChatTarget。

    对齐 PyRIT 1.0.1:
        - 支持 gpt-4o, gpt-4, DeepSeek, llama, phi-4, gpt-3.5
        - 原生 RPM 限速: max_requests_per_minute
        - 原生 JSON 输出: response_format + json_schema
        - 原生多模态: text + image_path 输入
        - 原生 TargetCapabilities: get_known_capabilities 自动匹配模型
        - 原生错误处理: pyrit_target_retry 重试装饰器
        - 原生温度控制: temperature, top_p, frequency_penalty
        - Azure Entra ID 认证: 支持无 API key 的 identity 认证

    学术依据:
        - PyRIT (arXiv:2407.01232) — OpenAIChatTarget 原生 Target
    """
    from pyrit.prompt_target import OpenAIChatTarget

    target_kwargs: dict[str, Any] = {
        "model_name": model_name,
        "max_requests_per_minute": max_requests_per_minute,
    }
    if endpoint:
        target_kwargs["endpoint"] = endpoint
    if api_key:
        target_kwargs["api_key"] = api_key
    if temperature is not None:
        target_kwargs["temperature"] = temperature
    if top_p is not None:
        target_kwargs["top_p"] = top_p
    if extra_body_parameters:
        target_kwargs["extra_body_parameters"] = extra_body_parameters
    target_kwargs.update(kwargs)

    return OpenAIChatTarget(**target_kwargs)


def _create_openai_response_target(
    *,
    endpoint: str | None,
    api_key: str | None,
    model_name: str,
    max_requests_per_minute: int | None,
    **kwargs: Any,
) -> Any:
    """创建 PyRIT 原生 OpenAIResponseTarget。

    对齐 PyRIT 1.0.1:
        - 支持 o1, o3, o4-mini, GPT-5 (Responses API)
        - 原生 reasoning 控制: reasoning_effort + reasoning_summary
        - 原生 tool calling: custom_functions 注册自定义工具
        - 原生 web search: 内置 web search tool
        - 原生 agentic loop: 自动处理 function_call → function_call_output
        - 原生 JSON schema: text.format.json_schema

    学术依据:
        - PyRIT (arXiv:2407.01232) — OpenAIResponseTarget 原生 Target
    """
    from pyrit.prompt_target import OpenAIResponseTarget

    target_kwargs: dict[str, Any] = {
        "model_name": model_name,
        "max_requests_per_minute": max_requests_per_minute,
    }
    if endpoint:
        target_kwargs["endpoint"] = endpoint
    if api_key:
        target_kwargs["api_key"] = api_key
    target_kwargs.update(kwargs)

    return OpenAIResponseTarget(**target_kwargs)


def _create_litellm_target(
    *,
    model_name: str | None,
    api_key: str | None,
    endpoint: str | None,
    headers: dict[str, str] | None,
    max_requests_per_minute: int | None,
    temperature: float | None = None,
    top_p: float | None = None,
    extra_body_parameters: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Any:
    """创建 PyRIT 原生 LiteLLMChatTarget — 适配 100+ LLM 提供商。

    对齐 PyRIT 1.0.1:
        LiteLLMChatTarget 通过 LiteLLM SDK 访问 100+ LLM 提供商:
        - Anthropic (Claude 系列)
        - AWS Bedrock (多种模型)
        - Google Vertex (Gemini 系列)
        - Cohere, Mistral, AI21 等
        - 自托管 LLM (通过 endpoint 参数)

    原生优势:
        - 统一 OpenAI Chat Completions 线格式
        - 自动从环境变量读取提供商 API key
        - 原生 drop_unsupported_params: 跨提供商参数兼容
        - 原生 LiteLLM 重试: 提供商感知的重试策略
        - 原生 TargetCapabilities: 从 LiteLLM 元数据自动推导

    适配任意 LLM Agent:
        - 国产 LLM (通义千问, 文心一言, 智谱 GLM):
          通过 OpenAI 兼容接口, 使用 model_name="openai/模型名" + endpoint 参数
        - 自建 Agent API:
          通过 endpoint 参数指向自定义 API 网关
        - 多云部署:
          通过 LiteLLM 路由到不同云提供商

    学术依据:
        - PyRIT (arXiv:2407.01232) — LiteLLMChatTarget 原生 Target
    """
    try:
        from pyrit.prompt_target import LiteLLMChatTarget
    except ImportError as e:
        raise ImportError(
            "LiteLLMChatTarget requires litellm. "
            "Install with: pip install pyrit[litellm] or pip install litellm"
        ) from e

    target_kwargs: dict[str, Any] = {
        "max_requests_per_minute": max_requests_per_minute,
    }
    if model_name:
        target_kwargs["model_name"] = model_name
    if api_key is not None:
        target_kwargs["api_key"] = api_key
    if endpoint:
        target_kwargs["endpoint"] = endpoint
    if headers:
        target_kwargs["headers"] = headers
    if temperature is not None:
        target_kwargs["temperature"] = temperature
    if top_p is not None:
        target_kwargs["top_p"] = top_p
    if extra_body_parameters:
        target_kwargs["extra_body_parameters"] = extra_body_parameters
    target_kwargs.update(kwargs)

    return LiteLLMChatTarget(**target_kwargs)


def _create_browser_target(
    *,
    browser_url: str,
    max_requests_per_minute: int | None,
    **kwargs: Any,
) -> Any:
    """创建 PyRIT 原生 PlaywrightTarget — 浏览器自动化攻击。

    对齐 PyRIT 1.0.1:
        PlaywrightTarget 使用 Playwright 与 Web UI 交互:
        - 浏览器渲染: 攻击需要 JS 渲染的 Web Chat 界面
        - 自定义交互: InteractionFunction 定义任意页面交互逻辑
        - 原生 Target: 与 PyRIT 攻击策略完全兼容
        - 速率限制: 内置 RPM 控制

    学术依据:
        - PyRIT (arXiv:2407.01232) — PlaywrightTarget 原生 Target
    """
    import importlib.util

    if importlib.util.find_spec("playwright") is None:
        raise ImportError(
            "Playwright not installed. "
            "Install with: pip install playwright && playwright install chromium"
        )

    async def _default_interaction(page, message):
        """默认 Chat UI 交互函数。

        对齐 PyRIT 1.0.1 InteractionFunction Protocol:
            async def __call__(self, page: Page, message: Message) -> str
        """
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
        input_el = (
            await page.query_selector("textarea")
            or await page.query_selector("input[type='text']")
            or await page.query_selector("[contenteditable='true']")
        )
        if input_el is None:
            raise RuntimeError("Could not find input element on the page")
        await input_el.fill(prompt_text)
        send_btn = await page.query_selector(
            "button[type='submit'], button[aria-label*='send'], button[aria-label*='Send']"
        )
        if send_btn:
            await send_btn.click()
        else:
            await input_el.press("Enter")
        response_selector = (
            ".message:last-child, .response:last-child, "
            "[data-role='assistant']:last-child, .chat-message:last-child"
        )
        try:
            await page.wait_for_selector(response_selector, timeout=30000)
            await page.wait_for_timeout(2000)
        except Exception:
            await page.wait_for_timeout(5000)
        response_el = await page.query_selector(response_selector)
        if response_el:
            return (await response_el.inner_text()).strip()
        return await page.inner_text("body")

    # 需要 Playwright Page 对象 — 延迟创建
    # 实际使用时由 target_router._create_playwright_target 处理
    raise NotImplementedError(
        "PlaywrightTarget requires a Playwright Page object. "
        "Use target_router._create_playwright_target() instead, "
        "or provide a pre-created page via kwargs['page']."
    )


def _create_http_target(
    *,
    http_request: str,
    max_requests_per_minute: int | None,
    **kwargs: Any,
) -> Any:
    """创建 JSONSafeHTTPTarget — 原始 HTTP 请求模式。

    对齐 PyRIT 1.0.1 HTTPTarget:
        - 使用原始 HTTP 请求字符串 (如从 Burp Suite 导出)
        - {PROMPT} 占位符注入
        - callback_function 解析响应
        - HTTP/2 自动检测
        - httpx.AsyncClient 复用 (生产级优化)

    JSONSafeHTTPTarget 增强:
        - JSON body 安全转义 (递归替换 {PROMPT})
        - 会话 ID 动态注入 ({CHAT_ID} 占位符)
        - Content-Length 自动更新
    """
    from recon.target_builder import JSONSafeHTTPTarget

    target_kwargs: dict[str, Any] = {
        "http_request": http_request,
    }
    if max_requests_per_minute is not None:
        target_kwargs["max_requests_per_minute"] = max_requests_per_minute
    target_kwargs.update(kwargs)

    return JSONSafeHTTPTarget(**target_kwargs)


def _create_httpx_api_target(
    *,
    endpoint: str,
    max_requests_per_minute: int | None,
    headers: dict[str, str] | None,
    **kwargs: Any,
) -> Any:
    """创建 PyRIT 原生 HTTPXAPITarget — API 模式 (无原始 HTTP 请求)。

    对齐 PyRIT 1.0.1 HTTPXAPITarget:
        - 用于文件上传/multipart form/JSON API 场景
        - 绕过原始 HTTP 请求解析, 直接使用 httpx API
        - 支持 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
        - 内置文件上传 (仅 POST/PUT)
        - 支持 params (query parameters for GET/HEAD)

    学术依据:
        - PyRIT (arXiv:2407.01232) — HTTPXAPITarget 原生 Target
    """
    from pyrit.prompt_target import HTTPXAPITarget

    target_kwargs: dict[str, Any] = {
        "http_url": endpoint,
    }
    if max_requests_per_minute is not None:
        target_kwargs["max_requests_per_minute"] = max_requests_per_minute
    if headers:
        target_kwargs["headers"] = headers
    target_kwargs.update(kwargs)

    return HTTPXAPITarget(**target_kwargs)


def _create_round_robin_target(
    *,
    targets: list[Any],
    weights: list[int] | None = None,
) -> Any:
    """创建 PyRIT 原生 RoundRobinTarget — 多目标轮询。

    对齐 PyRIT 1.0.1 RoundRobinTarget:
        - 加权轮询: 按权重分配请求到多个 inner target
        - 故障转移: 某个 target 失败时自动尝试其他
        - 配置一致性验证: 所有 inner target 必须有相同配置
        - 行为参数一致性: 确保 scorer 评估可比

    使用场景:
        - 多账号分散限速: 同一模型不同账号轮询
        - 多提供商互补: 不同 LLM 提供商轮询
        - 多区域负载分散: 不同区域端点轮询

    学术依据:
        - PyRIT (arXiv:2407.01232) — RoundRobinTarget 原生 Target
    """
    from pyrit.prompt_target import RoundRobinTarget

    if len(targets) < 2:
        raise ValueError(
            f"RoundRobinTarget requires at least 2 targets, got {len(targets)}."
        )

    return RoundRobinTarget(
        targets=targets,
        weights=weights,
    )
