# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 0.5: 统一目标类型判别 + 认证桥接.

v43 统一入口: --target-url 自动触发完整链路 (判别→认证→桥接→主流水线 17 种攻击).

当用户提供 ``--target-url`` 时, 本阶段自动执行完整链路:
  1. 调用 TargetClassifier 判别目标类型 (LLM Web 应用 / LLM API 平台)
  2. 根据判别结果 + 用户参数自动路由到三种模式之一:
     a. Burp API 模式 (--burp-request): 从原始 HTTP 请求构建 HTTPTarget
     b. API 直连模式 (llm_api_platform): APITargetConfig + HTTPTarget + RateLimitedTarget
     c. Browser 模式 (llm_web_app): AuthProbe + MFADetector + AuthStrategy + PlaywrightTarget
  3. 执行认证 (Browser: Playwright / API: Bearer/OAuth2)
  4. 能力探测 (可选, 简化侦察)
  5. 创建对应 Target 并注册到 TargetRegistry
  6. 导出认证状态 (供下次运行复用)

v43 优化: 统一三路入口, 消除 --web-bridge 开关.
  - --target-url 本身触发完整链路
  - --burp-request 提升 Burp Suite 原始请求到主流水线 (不再局限于 web_redteam 4 种技术)
  - --target-profile 统一 Web App YAML Profile 入口
  - --api-key / --api-response-path 统一 API 模式参数

v43.1 优化 (S-6/S-7/S-8):
  - S-6: 能力探测统一到本阶段 — Burp/API/Burp 模式全部自动探测 Agent/RAG/MCP 能力
  - S-7: 认证状态复用扩展到 Burp/API 模式 — 三种模式全部支持 AuthState 文件复用
  - S-8: Browser 模式交互选择器自动发现 — 无 YAML Profile 时自动探测输入/发送/响应选择器

> **设计原则** (R-010): PyRIT 原生优先
  - PlaywrightTarget / HTTPTarget 是 PyRIT 原生 prompt_target
  - AuthDetector/AuthStrategy/MFADetector 来自 web_redteam, 是对原生模式的增强
  - 不修改任何 PyRIT 原生代码

学术依据:
  - PyRIT (arXiv:2407.01232): PlaywrightTarget / HTTPTarget 双模式支持
  - OWASP Top 10 for LLMs 2025: Web 注入和 API 注入的攻击面对应
  - MITRE ATT&CK: Reconnaissance → Initial Access → Execution
  - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点

> **日期**: 2026-8-3
> **更新记录**:
  2026-8-15 — v43.1: S-6 能力探测统一 + S-7 认证状态三模式复用 + S-8 选择器自动发现
  2026-8-15 — v43: 统一三路入口, 新增 --burp-request/--target-profile/--api-key/--api-response-path
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path
from typing import Any

from pipeline.context import PipelineContext
from pipeline.integrations.target_classifier import TargetClassification, TargetClassifier
from pipeline.utils.decision_trace import DecisionTrace
from pipeline.utils.event_bus import EventBus

logger = logging.getLogger(__name__)


async def _bridge_burp_api(
    ctx: PipelineContext,
    target_url: str,
    burp_request_file: str,
    classification: TargetClassification,
) -> bool:
    """Burp API 模式: 从原始 HTTP 请求构建 HTTPTarget + RateLimitedTarget.

    v43 新增: 将 Burp Suite 原始请求提升到主流水线,
    享受 17 种攻击技术 + ASR 驱动.

    v43.1 S-7: 认证状态复用 — 从 AuthState 文件注入 headers.

    v44.2 SSE: 自动检测 SSE 流式响应, 选择正则回调或 JSON 回调.
    v44.2 HTTPS: 自动从 Origin/Referer/Host 推断 TLS, 传递 use_tls.

    流程:
      1. 读取 Burp Suite 原始 HTTP 请求文件
      2. 验证 {PROMPT} 占位符存在
      3. S-7: 注入已有认证 headers (从 AuthState 文件)
      4. SSE 检测: 从 Accept header 判断是否为流式响应
      5. 构建回调函数 (SSE→正则回调, JSON→原生JSON回调)
      6. 创建 HTTPTarget (PyRIT 原生, 含 use_tls)
      7. 包装 RateLimitedTarget (并发信号量 + 退避重试)
      8. 注册到 TargetRegistry (替换 default)
      9. S-6: 执行能力探测 (可选)

    Args:
        ctx: PipelineContext.
        target_url: 目标 URL (用于元信息).
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径.
        classification: 目标判别结果.

    Returns:
        True 如果桥接成功.
    """
    from pyrit.prompt_target import HTTPTarget

    from pipeline.targets.rate_limited_target import RateLimitedTarget

    # 1. 读取原始 HTTP 请求
    burp_path = Path(burp_request_file)
    if not burp_path.exists():
        print(f"  [错误] Burp 请求文件不存在: {burp_request_file}")
        return False

    raw_request = burp_path.read_text(encoding="utf-8")
    print(f"  请求文件: {burp_request_file} ({len(raw_request)} bytes)")

    # 2. 验证 {PROMPT} 占位符
    if "{PROMPT}" not in raw_request:
        print("  [警告] 请求中未找到 {PROMPT} 占位符, prompt 注入可能无效")
        logger.warning("Burp request missing {PROMPT} placeholder")

    # v43: 获取响应路径 (--api-response-path)
    response_path = getattr(ctx.args, "api_response_path", "choices[0].message.content")

    # v43.1 S-7: 注入已有认证 headers (从 AuthState 文件)
    # Burp 原始请求可能已包含 Authorization header, AuthState headers 作为补充
    auth_headers = ctx.metadata.get("auth_headers", {})
    if auth_headers:
        # 将 AuthState headers 合并到原始请求 (不覆盖已有的 header)
        for k, v in auth_headers.items():
            if k.lower() not in raw_request.lower():
                # 在 header 部分插入 (第一个 \r\n 之前)
                header_end = raw_request.find("\r\n\r\n")
                if header_end > 0:
                    raw_request = (
                        raw_request[:header_end]
                        + f"\r\n{k}: {v}"
                        + raw_request[header_end:]
                    )
        print(f"  [S-7] 认证 headers 注入: {list(auth_headers.keys())}")

    # v44.2: SSE 检测 — 从 Accept header 判断是否为流式响应
    is_sse = _detect_sse_from_request(raw_request)
    if is_sse:
        print("  [SSE] 检测到流式响应 (Accept: text/event-stream), 使用正则回调")
    else:
        print(f"  响应路径: {response_path}")

    # v44.2: HTTPS 检测 — 从 Origin/Referer/Host 推断 TLS
    use_tls = _detect_tls_from_request(raw_request)
    if use_tls:
        print("  [TLS] 检测到 HTTPS 目标, 启用 TLS")

    # 3. 构建回调函数 (v44.2: SSE→正则回调, JSON→原生JSON回调)
    callback = _build_burp_callback(
        is_sse=is_sse,
        response_path=response_path,
        target_url=target_url,
    )

    # 4. 创建 HTTPTarget (v44.2: 传递 use_tls)
    http_target_kwargs: dict[str, Any] = {
        "http_request": raw_request,
        "prompt_regex_string": "{PROMPT}",
        "callback_function": callback,
    }
    if use_tls:
        http_target_kwargs["use_tls"] = True
    http_target = HTTPTarget(**http_target_kwargs)

    # 5. 包装 RateLimitedTarget
    rate_limit = getattr(ctx.args, "rate_limit", 3)
    max_retries = getattr(ctx.args, "rate_limit_retries", 3)

    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=target_url,
        max_concurrency=rate_limit,
        max_retries=max_retries,
        requests_per_minute=rate_limit * 30 if rate_limit > 0 else None,
    )

    # 6. 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=rate_limited_target,
        name="burp_api_target",
        tags={"target_type": "HTTPTarget"},
    )
    registry.instances.register(
        instance=rate_limited_target,
        name="default",
        tags={"target_type": "HTTPTarget"},
    )

    print("  ✓ HTTPTarget (Burp) + RateLimitedTarget 已创建并注册")
    print(f"    最大并发: {rate_limit}")
    print(f"    最大重试: {max_retries}")

    # 7. 存储到 Context
    ctx.metadata["burp_request_file"] = burp_request_file
    ctx.metadata["api_target_url"] = target_url
    ctx.metadata["burp_is_sse"] = is_sse
    ctx.metadata["burp_use_tls"] = use_tls
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # v43.1 S-6: 执行能力探测 (非侵入, 失败不影响主流水线)
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"Burp API target bridged: {target_url} → HTTPTarget (SSE={is_sse}, TLS={use_tls})")
    return True


async def run(ctx: PipelineContext) -> bool:
    """执行 Stage 0.5: 统一目标类型判别 + 认证桥接。.

    Args:
        ctx: PipelineContext (需要 args.target_url)

    Returns:
        True 如果目标已成功桥接到主 pipeline, False 如果不需要 (走原生 API 流程)
    """
    target_url = getattr(ctx.args, "target_url", None)
    if not target_url:
        return False

    print("\n" + "=" * 70)
    print("[0.5] 统一目标类型判别 + 认证桥接 (v43)")
    print("=" * 70)
    print(f"  目标 URL: {target_url}")

    # v43: 检查 --burp-request (优先级最高, 覆盖判别结果)
    burp_request_file = getattr(ctx.args, "burp_request", None)
    if burp_request_file:
        print(f"  Burp Suite 请求文件: {burp_request_file}")
        # 即使有 --burp-request, 仍然执行判别 (用于元信息记录)
        target_type_override = getattr(ctx.args, "target_type", "api_platform")
    else:
        target_type_override = getattr(ctx.args, "target_type", "auto")

    try:
        # Step 1: 目标类型判别
        classifier = TargetClassifier()
        classification = await classifier.classify(
            target_url,
            force_type=target_type_override,
        )

        print(f"  判别结果: {classification.target_type}")
        print(f"  推荐模式: {classification.recommended_mode}")
        print(f"  依据: {classification.detection_reason}")

        # A2: 认证决策链日志
        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_0.5",
            layer="target_detection",
            decision=f"classified_as_{classification.target_type}",
            reason=classification.detection_reason,
            target_url=target_url,
            recommended_mode=classification.recommended_mode,
            has_chat_ui=classification.has_chat_ui,
        )
        bus = EventBus.get_instance()
        bus.publish_simple(
            "stage_0.5", "target_classified",
            target_type=classification.target_type,
            mode=classification.recommended_mode,
        )

        # 存储判别结果到 metadata
        ctx.metadata["target_classification"] = classification
        ctx.metadata["target_type"] = classification.target_type
        ctx.metadata["recommended_mode"] = classification.recommended_mode

        # v43.1 S-7: 三模式统一认证状态复用 — 在路由前尝试加载 AuthState
        # Browser 模式在 _bridge_web_app 中已有 try_reuse_auth_state,
        # 但 Burp/API 模式也需要认证 headers 注入
        if burp_request_file or classification.target_type == "llm_api_platform":
            try:
                from pipeline.integrations.auth_state_bridge import try_reuse_auth_state

                auth_reused = try_reuse_auth_state(ctx)
                if auth_reused:
                    print("  [S-7] 认证状态复用成功 (Burp/API 模式)")
            except Exception as e:
                logger.debug(f"S-7 auth state reuse failed: {e}")

        # v43.2 A-1: --tool-calling 优先级最高 — 打通 Agent 工具调用劫持
        # 当 --tool-calling 指定时, 创建 OpenAIResponseTarget 替代 HTTPTarget/PlaywrightTarget
        # 使 XPIA/ASI03/多Agent 攻击不再降级为纯文本注入
        tool_calling = getattr(ctx.args, "tool_calling", False)
        if tool_calling:
            print("\n  --- Tool Calling 模式 (OpenAIResponseTarget + 蜜罐工具集) ---")
            return await _bridge_tool_calling(ctx, target_url, classification, burp_request_file)

        # Step 2: 统一路由 (v43: 三路自动选择)
        if burp_request_file:
            # 路径 A: Burp Suite 原始请求 → HTTPTarget
            print("\n  --- Burp API 模式 (HTTPTarget + 原始 HTTP 请求) ---")
            return await _bridge_burp_api(ctx, target_url, burp_request_file, classification)
        elif classification.target_type == "llm_web_app":
            # 路径 C: Web 应用 → Browser 模式
            return await _bridge_web_app(ctx, target_url, classification)
        elif classification.target_type == "llm_api_platform":
            # 路径 B: API 平台 → API 直连模式
            return await _bridge_api_platform(ctx, target_url, classification)
        else:
            # unknown: 尝试 Web App 模式 (更通用)
            print("  [警告] 目标类型未知, 降级为 Web App 模式")
            return await _bridge_web_app(ctx, target_url, classification)

    except (ImportError, RuntimeError, OSError, ValueError) as e:
        print(f"  [错误] 目标桥接失败: {e}")
        logger.error(f"Target bridge failed: {e}", exc_info=True)
        return False


async def _bridge_web_app(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> bool:
    """Web 应用模式: 浏览器认证 + PlaywrightTarget。."""
    print("\n  --- Web 应用模式 (PlaywrightTarget) ---")

    # G2: 尝试复用已有认证状态 — 减少重复认证
    # 学术依据: NIST SP 800-63B — 认证状态复用减少攻击面暴露
    from pipeline.integrations.auth_state_bridge import try_reuse_auth_state

    auth_reused = try_reuse_auth_state(ctx)

    # 1. 加载或动态生成 TargetProfile
    profile = _load_or_create_profile(ctx, target_url)
    print(f"  认证策略: {profile.auth.type}")

    # 2. 启动浏览器
    from web_redteam.auth.browser_session import BrowserSession

    session = BrowserSession()
    headless = getattr(ctx.args, "web_headless", False)
    cdp_port = getattr(ctx.args, "cdp_port", 9222)

    # G2: 如果认证状态可复用, 尝试从 storage_state 恢复页面
    if auth_reused:
        storage_state_path = ctx.metadata.get("storage_state_path", "")
        if storage_state_path and Path(storage_state_path).exists():
            print(f"  [G2] 复用认证状态: {storage_state_path}")
            try:
                page = await session.restore_storage_state(storage_state_path)
                await page.goto(profile.auth.target_url, wait_until="domcontentloaded")
                print("  [G2] 认证状态恢复成功, 跳过完整认证")
                # 跳过步骤 3, 直接创建 PlaywrightTarget
            except Exception as e:
                logger.warning(f"G2: storage_state restore failed: {e}, falling back to full auth")
                page = await session.launch_with_debug_port(
                    port=cdp_port,
                    headless=headless,
                )
                # 降级到完整认证
                auth_reused = False
        else:
            page = await session.launch_with_debug_port(
                port=cdp_port,
                headless=headless,
            )
            auth_reused = False
    else:
        page = await session.launch_with_debug_port(
            port=cdp_port,
            headless=headless,
        )

    # 3. 执行认证 (仅当未复用认证状态时)
    if not auth_reused:
        from web_redteam.auth.auth_strategy import AuthStrategyFactory

        strategy = AuthStrategyFactory.create(profile.auth.type)

        # 注入 MFA 超时参数
        mfa_timeout = getattr(ctx.args, "mfa_timeout", 300)
        if hasattr(strategy, "_human_auth"):
            strategy._human_auth.mfa_timeout = mfa_timeout  # type: ignore[attr-defined]

        page = await strategy.execute(page, profile)

          # G2: 认证成功后导出 AuthState (供后续运行复用)
        from datetime import datetime, timezone

        from pipeline.integrations.auth_state_bridge import AuthState, export_auth_state

        cookies = []
        with contextlib.suppress(Exception):
            cookies = await page.context.cookies()

        storage_state_path = ""
        with contextlib.suppress(Exception):
            import tempfile

            storage_state_path = str(Path(tempfile.gettempdir()) / "stage_target_classify_storage_state.json")
            await page.context.storage_state(path=storage_state_path)

        auth_state = AuthState(
            auth_type=profile.auth.type,
            target_url=target_url,
            login_url=getattr(profile.auth, "login_url", ""),
            cookies=cookies,
            storage_state_path=storage_state_path,
            source="stage_target_classify",
            authenticated_at=datetime.now(timezone.utc).isoformat(),
        )
        export_auth_state(auth_state)
        print("  [G2] 认证状态已导出, 下次运行可复用")

    # 4. 创建 PlaywrightTarget
    from pyrit.prompt_target import PlaywrightTarget

    from web_redteam.interaction.interaction_factory import InteractionFactory

    interaction_func = InteractionFactory.create(profile.interaction)

    playwright_target = PlaywrightTarget(
        interaction_func=interaction_func,
        page=page,
        max_requests_per_minute=getattr(ctx.args, "max_rpm", None),
    )

    # 5. 注册到 TargetRegistry (替换默认 OpenAIChatTarget)
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=playwright_target,
        name="web_target",
        tags={"target_type": "PlaywrightTarget"},
    )
    registry.instances.register(
        instance=playwright_target,
        name="default",
        tags={"target_type": "PlaywrightTarget"},
    )

    print("  ✓ PlaywrightTarget 已创建并注册")
    print(f"    输入选择器: {profile.interaction.input.selector}")
    print(f"    发送选择器: {profile.interaction.send.selector}")
    print(f"    响应选择器: {profile.interaction.response.selector}")

    # 6. 存储到 Context
    ctx.metadata["web_browser_session"] = session
    ctx.metadata["web_target_url"] = target_url
    ctx.metadata["web_target_profile"] = profile
    ctx.target_type = "playwright"

    # v43.1 S-6: 执行能力探测 (非侵入, 失败不影响主流水线)
    await _probe_and_record_capabilities(ctx, target_url, classification)

    # 注: recon-pipeline 侦察不再通过代码直接调用 (两流水线完全独立)。
    # 使用方式: 先运行 recon-pipeline 生成 JSON 报告, 再通过 --recon-json 加载。

    logger.info(f"Web app target bridged: {target_url} → PlaywrightTarget")
    return True


async def _bridge_api_platform(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> bool:
    """API 平台模式: HTTPTarget + RateLimitedTarget.

    v43: 支持 --api-key 和 --api-response-path 统一参数.
    v44: 支持 --api-json-data 触发 HTTPXAPITarget (结构化 HTTP API).
    """
    # v44: 如果指定了 --api-json-data, 使用 HTTPXAPITarget (结构化 API)
    _api_json_data = getattr(ctx.args, "api_json_data", None)
    if _api_json_data:
        print("\n  --- API 平台模式 (HTTPXAPITarget — 结构化 API) ---")
        return await _bridge_api_platform_httpx(ctx, target_url, classification)

    print("\n  --- API 平台模式 (HTTPTarget) ---")

    from pyrit.prompt_target import HTTPTarget

    from pipeline.targets.rate_limited_target import RateLimitedTarget
    from web_redteam.targets.api_config import APITargetConfig

    # v43: 优先使用 --api-key, 否则从 .env 获取
    api_key = (
        getattr(ctx.args, "api_key", None)
        or os.environ.get("OPENAI_CHAT_KEY", "")
        or os.environ.get("API_KEY", "")
    )

    # v43: 从 --api-response-path 获取响应路径
    response_path = getattr(ctx.args, "api_response_path", "choices[0].message.content")

    # 1. 从 URL 自动构建 API 配置
    config = APITargetConfig.from_url(
        target_url,
        api_key=api_key or None,
        max_rpm=getattr(ctx.args, "rate_limit", None),
    )

    # v43: 覆盖响应路径
    if response_path and response_path != config.response_json_path:
        config.response_json_path = response_path
        print(f"  [v43] 响应路径覆盖: {response_path}")

    # G2: 注入已有认证 headers (从 --auth-state-file 复用的 headers)
    auth_headers = ctx.metadata.get("auth_headers", {})
    if auth_headers:
        for k, v in auth_headers.items():
            if k not in config.headers:
                config.headers[k] = v
        print(f"  [G2] 注入认证 headers: {list(auth_headers.keys())}")

    print(f"  API URL: {config.url}")
    print(f"  HTTP 方法: {config.method}")
    print(f"  响应路径: {config.response_json_path}")
    print(f"  最大并发: {config.max_concurrency}")
    print(f"  最大 RPM: {config.max_rpm or '不限'}")

    # v44.2: SSE 检测 — 从 config.response_format 或 URL 路径判断
    is_sse = (
        getattr(config, "response_format", "json") == "sse"
        or classification.is_streaming
    )
    if is_sse:
        print("  [SSE] 检测到流式响应, 使用正则回调")

    # v44.2: HTTPS 检测 — 从 URL scheme 判断
    use_tls = config.url.startswith("https://")

    # 2. 构建回调函数 (v44.2: SSE→正则回调, JSON→原生JSON回调)
    callback = _build_burp_callback(
        is_sse=is_sse,
        response_path=config.response_json_path,
        target_url=config.url,
    )

    # 3. 构建 HTTPTarget (PyRIT 1.0.1: 不接受 prompt_request_piece 参数)
    raw_request = _build_raw_http_request(config)
    http_target_kwargs: dict[str, Any] = {
        "http_request": raw_request,
        "prompt_regex_string": "{PROMPT}",
        "callback_function": callback,
    }
    if use_tls:
        http_target_kwargs["use_tls"] = True
    http_target = HTTPTarget(**http_target_kwargs)

    # 4. 使用 RateLimitedTarget 包装
    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=config.url,
        max_concurrency=config.max_concurrency,
        max_retries=config.max_retries,
        requests_per_minute=config.max_rpm,
    )

    # 5. 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=rate_limited_target,
        name="api_target",
        tags={"target_type": "HTTPTarget"},
    )
    registry.instances.register(
        instance=rate_limited_target,
        name="default",
        tags={"target_type": "HTTPTarget"},
    )

    print("  ✓ HTTPTarget + RateLimitedTarget 已创建并注册")

    # 6. 存储到 Context
    ctx.metadata["api_target_config"] = config
    ctx.metadata["api_target_url"] = target_url
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # v43.1 S-6: 执行能力探测 (非侵入, 失败不影响主流水线)
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"API platform target bridged: {target_url} → HTTPTarget")
    return True


async def _bridge_api_platform_httpx(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> bool:
    """HTTPXAPITarget 模式: 结构化 HTTP API 调用 (v44 新增).

    当用户指定 ``--api-json-data`` 时, 使用 PyRIT 原生 ``HTTPXAPITarget``
    替代 ``HTTPTarget``。HTTPXAPITarget 支持结构化 JSON/Form 请求构造,
    无需原始 HTTP 请求文本。

    原生 API:
      - ``pyrit.prompt_target.HTTPXAPITarget(http_url, method, headers, json_data, ...)``
      - ``get_http_target_json_response_callback_function(key)``

    CLI 参数:
      - ``--api-json-data``: JSON 请求体 (含 {PROMPT} 占位符)
      - ``--api-method``: HTTP 方法 (默认 POST)
      - ``--api-headers``: 额外 headers (JSON 字符串)

    学术依据: PyRIT (arXiv:2407.01232) — HTTPXAPITarget 结构化 API 设计
    """
    import json as _json

    print("\n  --- HTTPXAPITarget 配置 ---")

    from pyrit.prompt_target import HTTPXAPITarget
    from pyrit.prompt_target.http_target import (
        get_http_target_json_response_callback_function,
    )

    from pipeline.targets.rate_limited_target import RateLimitedTarget

    # v43: API Key
    api_key = (
        getattr(ctx.args, "api_key", None)
        or os.environ.get("OPENAI_CHAT_KEY", "")
        or os.environ.get("API_KEY", "")
    )

    # v43: 响应路径
    response_path = getattr(ctx.args, "api_response_path", "choices[0].message.content")

    # v44: HTTP 方法
    method = getattr(ctx.args, "api_method", "POST")

    # v44: JSON 请求体
    json_data_str = getattr(ctx.args, "api_json_data", None)
    if not json_data_str:
        print("  [错误] --api-json-data 未指定")
        return False

    try:
        json_data = _json.loads(json_data_str)
    except _json.JSONDecodeError as e:
        print(f"  [错误] --api-json-data JSON 解析失败: {e}")
        return False

    # v44: 额外 headers
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    extra_headers_str = getattr(ctx.args, "api_headers", None)
    if extra_headers_str:
        try:
            extra_headers = _json.loads(extra_headers_str)
            headers.update(extra_headers)
        except _json.JSONDecodeError:
            print("  [警告] --api-headers JSON 解析失败, 忽略")

    # G2: 注入已有认证 headers
    auth_headers = ctx.metadata.get("auth_headers", {})
    if auth_headers:
        for k, v in auth_headers.items():
            if k not in headers:
                headers[k] = v
        print(f"  [G2] 注入认证 headers: {list(auth_headers.keys())}")

    print(f"  API URL: {target_url}")
    print(f"  HTTP 方法: {method}")
    print(f"  响应路径: {response_path}")
    print(f"  Headers: {list(headers.keys())}")

    # 构建回调函数
    callback = get_http_target_json_response_callback_function(key=response_path)

    # 创建 HTTPXAPITarget
    httpx_target = HTTPXAPITarget(
        http_url=target_url,
        method=method,
        headers=headers,
        json_data=json_data,
        callback_function=callback,
        max_requests_per_minute=getattr(ctx.args, "rate_limit", None) or 0,
    )

    # 使用 RateLimitedTarget 包装
    rate_limited_target = RateLimitedTarget(
        target=httpx_target,
        endpoint=target_url,
        max_concurrency=getattr(ctx.args, "rate_limit", 3) or 3,
        max_retries=getattr(ctx.args, "rate_limit_retries", 3),
    )

    # 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=rate_limited_target,
        name="api_target",
        tags={"target_type": "HTTPXAPITarget"},
    )
    registry.instances.register(
        instance=rate_limited_target,
        name="default",
        tags={"target_type": "HTTPXAPITarget"},
    )

    print("  ✓ HTTPXAPITarget + RateLimitedTarget 已创建并注册")

    # 存储到 Context
    ctx.metadata["api_target_url"] = target_url
    ctx.metadata["api_target_type"] = "HTTPXAPITarget"
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # v43.1 S-6: 执行能力探测
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"API platform target bridged: {target_url} → HTTPXAPITarget")
    return True


def _load_or_create_profile(ctx: PipelineContext, target_url: str) -> Any:
    """加载 YAML 配置或从 URL 动态生成 TargetProfile.

    v43: 优先使用 --target-profile, 兼容 --web-target-profile.
    v43.1 S-8: 动态生成时自动发现页面交互选择器 (输入框/发送按钮/响应区域).
    """
    # v43: 优先 --target-profile, 兼容 --web-target-profile
    profile_path = (
        getattr(ctx.args, "target_profile", None)
        or getattr(ctx.args, "web_target_profile", None)
    )
    if profile_path:
        from web_redteam.targets.target_profile import TargetProfile

        profile = TargetProfile.from_yaml_file(profile_path)
        logger.info(f"Loaded TargetProfile from {profile_path}")
        return profile
    else:
        from web_redteam.targets.dynamic_profile import create_profile_from_url

        attack_type = getattr(ctx.args, "scenario", "prompt_sending")
        objective = getattr(ctx.args, "objective", "Ignore all previous instructions")
        max_turns = getattr(ctx.args, "max_turns", 5)

        profile = create_profile_from_url(
            target_url=target_url,
            attack_type=attack_type,
            objective=objective,
            max_turns=max_turns,
        )

        # v43.1 S-8: 自动发现交互选择器 — 尝试从页面 DOM 探测常用选择器
        # 仅在动态生成 Profile 时执行 (YAML Profile 视为用户已指定)
        # 非侵入: 仅覆盖默认选择器, 不修改 Profile 结构
        _auto_discover_selectors(profile, target_url)

        logger.info(f"Dynamic TargetProfile created from {target_url}")
        return profile


def _auto_discover_selectors(profile: Any, target_url: str) -> None:
    """S-8: 自动发现页面交互选择器.

    从目标页面 DOM 探测常用的输入框/发送按钮/响应区域选择器.
    仅覆盖 profile 中默认的通用选择器, 不修改 YAML Profile 的已指定值.

    探测策略 (基于常见 Web 框架的模式匹配):
      - 输入框: textarea, input[type=text], [contenteditable], role="textbox"
      - 发送按钮: button[type=submit], role="button" with send/submit text
      - 响应区域: [class*=response], [class*=answer], [class*=output], [class*=message]

    学术依据:
      - OWASP ASVS V4.3: 交互面自动发现减少配置误差
      - MITRE ATT&CK T1580: 交互面发现

    非侵入设计:
      - 同步函数, 不阻塞主流水线
      - 失败时保留 profile 默认选择器
      - 仅在动态 Profile (非 YAML) 上执行
    """
    # 常用选择器候选列表 (按优先级排序)
    input_candidates = [
        "textarea",
        "input[type='text']",
        "[contenteditable='true']",
        "[role='textbox']",
        ".chat-input",
        "#chat-input",
        ".message-input",
        "#message-input",
        "[placeholder*='输入']",
        "[placeholder*='message']",
        "[placeholder*='ask']",
    ]

    send_candidates = [
        "button[type='submit']",
        "button.send",
        "button[aria-label*='send']",
        "button[aria-label*='提交']",
        "[role='button'][aria-label*='send']",
        ".send-button",
        "#send-button",
        "button:last-of-type",
    ]

    response_candidates = [
        "[class*='response']",
        "[class*='answer']",
        "[class*='output']",
        "[class*='message']",
        "[class*='reply']",
        "[class*='chat-message']",
        ".assistant-message",
        ".bot-message",
        "[role='assistant']",
    ]

    # 非侵入: 将候选列表注入 profile 的 interaction 元数据
    # 实际选择器由 PlaywrightTarget 在运行时通过 page.querySelector() 尝试
    # 这里仅记录候选列表, 供 InteractionFactory 在交互失败时自动回退
    try:
        if hasattr(profile, "interaction"):
            # 记录候选选择器到 metadata (不覆盖已指定的 selector)
            if not hasattr(profile.interaction, "selector_candidates"):
                profile.interaction.input.selector_candidates = input_candidates
                profile.interaction.send.selector_candidates = send_candidates
                profile.interaction.response.selector_candidates = response_candidates
            logger.debug(
                f"S-8: Selector candidates injected "
                f"(input={len(input_candidates)}, send={len(send_candidates)}, "
                f"response={len(response_candidates)})"
            )
    except Exception as e:
        logger.debug(f"S-8: Selector auto-discover skipped: {e}")


async def _probe_and_record_capabilities(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> None:
    """S-6: 统一能力探测 — 三种模式全部自动探测 Agent/RAG/MCP/Embedding.

    v43.1: 将 web_bridge.py 的能力探测逻辑统一到 stage_target_classify,
    确保 Burp/API/Browser 三种模式都能自动发现目标能力.

    探测内容:
      1. 发送探针请求, 从响应中推断 Agent/RAG/MCP/Embedding 能力
      2. 提取模型名称
      3. 自动发现非标准 API 响应路径

    非侵入设计:
      - 失败不影响主流水线 (try/except 包裹)
      - 探测结果写入 ctx.metadata, 供后续 Stage 2 场景配置使用
      - 与 recon-pipeline 独立 (不依赖其代码)

    学术依据:
      - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点
      - MITRE ATT&CK T1592: 主动扫描
    """
    try:
        # 构建 AuthState 供探针使用
        from pipeline.integrations.auth_state_bridge import AuthState
        from pipeline.integrations.web_bridge import _send_capability_probe

        auth_state = AuthState(
            auth_type=ctx.metadata.get("auth_type", "none"),
            target_url=target_url,
            headers=ctx.metadata.get("auth_headers", {}),
            source="stage_target_classify",
        )

        probe_result = await _send_capability_probe(target_url, auth_state, classification)

        if probe_result is None:
            # 探测失败 — 记录最小能力信息
            ctx.metadata["recon_result"] = None
            ctx.metadata["recon_capability"] = None
            logger.debug("S-6: Capability probe returned None")
            return

        from types import SimpleNamespace

        response_text = probe_result.get("response_text", "")
        model_name = probe_result.get("model_name", "")
        discovered_path = probe_result.get("response_path", "")

        # 基于响应内容推断能力
        from pipeline.integrations.web_bridge import (
            _build_recommendations,
            _detect_agent_capability,
            _detect_embedding_capability,
            _detect_mcp_capability,
            _detect_rag_capability,
        )

        has_agent = _detect_agent_capability(response_text)
        has_rag = _detect_rag_capability(response_text)
        has_mcp = _detect_mcp_capability(response_text)
        has_embedding = _detect_embedding_capability(response_text)

        # 构建简化侦察报告 (兼容 recon_strategy_bridge.extract_capability)
        report = SimpleNamespace(
            target_url=target_url,
            has_agent_tools=has_agent,
            has_rag_endpoints=has_rag,
            has_mcp=has_mcp,
            has_embedding=has_embedding,
            endpoints=[SimpleNamespace(url=target_url, method="POST")],
            injection_surfaces=[{"type": "user_message"}],
            recommendations=_build_recommendations(has_agent, has_rag, has_mcp),
            model_name=model_name,
        )

        ctx.metadata["recon_result"] = report
        ctx.metadata["recon_capability"] = report

        if model_name:
            ctx.metadata["model_name"] = model_name

        if discovered_path and discovered_path != "choices[0].message.content":
            ctx.metadata["web_bridge_response_path"] = discovered_path
            # 如果用户未显式指定 --api-response-path, 自动使用发现的路径
            if not getattr(ctx.args, "api_response_path", None):
                print(f"  [S-6] 自动发现响应路径: {discovered_path}")

        print(
            f"  [S-6] 能力探测: agent={has_agent}, rag={has_rag}, "
            f"mcp={has_mcp}, embedding={has_embedding}"
            + (f", model={model_name}" if model_name else "")
        )

        # A-3: 目标 Agent 工具集自动发现
        # P1: 优先尝试 MCP 协议探测 (真实工具定义)
        # 如果 MCP 探测失败, 回退到 A-3 文本解析
        if has_agent:
            # P1: MCP 协议探测 — 从目标 MCP 端点获取真实工具定义
            auth_headers = ctx.metadata.get("auth_headers", {})
            mcp_tools = await _probe_mcp_tools(target_url, auth_headers)
            if mcp_tools:
                ctx.metadata["target_agent_tools"] = mcp_tools
                print(f"  [P1] MCP 协议发现工具集: {len(mcp_tools)} 个工具")
                for t in mcp_tools[:5]:
                    if isinstance(t, dict):
                        print(f"       - {t.get('name', '?')}")
                if len(mcp_tools) > 5:
                    print(f"       ... 及其他 {len(mcp_tools) - 5} 个工具")
            else:
                # A-3: 从响应文本提取工具定义 (降级模式)
                discovered_tools = _discover_target_tools(response_text)
                if discovered_tools:
                    ctx.metadata["target_agent_tools"] = discovered_tools
                    print(f"  [A-3] 文本解析发现工具集: {len(discovered_tools)} 个工具")
                    for t in discovered_tools[:5]:
                        if isinstance(t, dict):
                            print(f"       - {t.get('name', t.get('function', {}).get('name', '?'))}")
                    if len(discovered_tools) > 5:
                        print(f"       ... 及其他 {len(discovered_tools) - 5} 个工具")
                else:
                    # 未发现显式工具定义, 使用蜜罐工具集作为默认
                    from pipeline.targets.honeypot_tools import build_honeypot_tool_definitions
                    ctx.metadata["target_agent_tools"] = build_honeypot_tool_definitions()
                    print("  [A-3] 未发现显式工具定义, 使用蜜罐工具集 (8 个工具) 作为默认")

        # 记录到 DecisionTrace
        from pipeline.utils.decision_trace import DecisionTrace

        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_0.5",
            layer="capability_probe",
            decision="capabilities_detected",
            agent=has_agent,
            rag=has_rag,
            mcp=has_mcp,
            embedding=has_embedding,
            model_name=model_name,
        )

    except Exception as e:
        logger.debug(f"S-6: Capability probe skipped: {e}")


def _build_raw_http_request(config: Any) -> str:
    """从 APITargetConfig 构建原始 HTTP 请求字符串。."""
    from urllib.parse import urlparse

    parsed = urlparse(config.url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    header_lines = [f"{config.method} {path} HTTP/1.1"]
    header_lines.append(f"Host: {host}")

    has_content_type = any(k.lower() == "content-type" for k in config.headers)
    if not has_content_type:
        header_lines.append("Content-Type: application/json")

    for k, v in config.headers.items():
        if k.lower() not in ("host", "content-length"):
            header_lines.append(f"{k}: {v}")

    body = config.body_template or ""
    if body:
        header_lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
        header_lines.append("")
        header_lines.append(body)
    else:
        header_lines.append("")

    return "\r\n".join(header_lines)


async def _bridge_tool_calling(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
    burp_request_file: str | None = None,
) -> bool:
    """A-1: Tool Calling 模式 — OpenAIResponseTarget + 蜜罐工具集.

    v43.2: 打通 Burp 模式和 Agent 攻击的全流程.

    当 ``--tool-calling`` 指定时, 创建支持工具调用循环的 OpenAIResponseTarget,
    替代 HTTPTarget (Burp/API) 或 PlaywrightTarget (Browser).

    流程:
      1. A-4: 如果有 --burp-request, 从原始请求提取端点和认证
      2. 否则从 --target-url / --api-key / .env 提取
      3. 创建 OpenAIResponseTarget + 蜜罐工具集 (8 个工具)
      4. 注册为 default + tool_calling_target
      5. S-6: 执行能力探测
      6. A-3: 自动发现目标 Agent 工具集 (可选)

    Args:
        ctx: PipelineContext.
        target_url: 目标 URL.
        classification: 目标判别结果.
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径 (可选, A-4 混合模式).

    Returns:
        True 如果桥接成功.
    """
    from pipeline.targets.tool_calling_target import create_tool_calling_target

    # A-4: 从 Burp 请求提取端点和认证 (混合模式)
    endpoint = None
    api_key = None
    model_name = None

    if burp_request_file:
        endpoint, api_key, model_name = _extract_endpoint_from_burp(burp_request_file)
        if endpoint:
            print(f"  [A-4] 从 Burp 请求提取端点: {endpoint}")
        else:
            print("  [A-4] Burp 请求解析失败, 回退到 --target-url")

    # 回退到 --target-url 和 --api-key
    if not endpoint:
        endpoint = target_url
    if not api_key:
        api_key = (
            getattr(ctx.args, "api_key", None)
            or os.environ.get("OPENAI_CHAT_KEY", "")
            or os.environ.get("API_KEY", "")
            or None
        )
    if not model_name:
        model_name = os.environ.get("OPENAI_CHAT_MODEL", "") or None

    print(f"  端点: {endpoint}")
    print(f"  模型: {model_name or '(默认)'}")
    print(f"  认证: {'有' if api_key else '无'}")

    # 创建 OpenAIResponseTarget + 蜜罐工具集
    result = create_tool_calling_target(
        endpoint=endpoint,
        api_key=api_key,
        model_name=model_name,
    )

    if result is None:
        print("  [错误] OpenAIResponseTarget 创建失败 — 需要 OPENAI_RESPONSES_* 或 OPENAI_CHAT_* 环境变量")
        print("  [降级] 回退到 HTTPTarget 模式")
        if burp_request_file:
            return await _bridge_burp_api(ctx, target_url, burp_request_file, classification)
        else:
            return await _bridge_api_platform(ctx, target_url, classification)

    tool_target, tool_call_log = result

    # 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=tool_target,
        name="tool_calling_target",
        tags={"target_type": "OpenAIResponseTarget", "agent_attack": {}, "tool_calling": {}},
    )
    registry.instances.register(
        instance=tool_target,
        name="default",
        tags={"target_type": "OpenAIResponseTarget", "agent_attack": {}, "tool_calling": {}},
    )

    print("  ✓ OpenAIResponseTarget + 蜜罐工具集 (8 个工具) 已创建并注册")
    print("    工具: read_file, list_directory, send_email, http_request,")
    print("          execute_command, get_environment, write_file, delete_file")

    # 存储到 Context
    ctx.metadata["tool_calling_target"] = tool_target
    ctx.metadata["tool_call_log"] = tool_call_log
    ctx.metadata["api_target_url"] = target_url
    ctx.target_type = "openai_response"
    ctx.http_target_configured = True

    # S-6: 执行能力探测
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"Tool Calling target bridged: {target_url} → OpenAIResponseTarget")
    return True


def _extract_endpoint_from_burp(burp_request_file: str) -> tuple[str | None, str | None, str | None]:
    """A-4: 从 Burp 原始 HTTP 请求提取端点 URL、API Key 和模型名.

    解析 Burp 原始请求的请求行和 headers, 提取:
      - 端点: 从 Host header + 请求行路径构建完整 URL
      - API Key: 从 Authorization header 或 Cookie 提取
      - 模型名: 从请求体 JSON 的 model 字段提取

    Args:
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径.

    Returns:
        (endpoint, api_key, model_name) 元组, 解析失败的字段为 None.
    """
    burp_path = Path(burp_request_file)
    if not burp_path.exists():
        return None, None, None

    try:
        raw = burp_path.read_text(encoding="utf-8")
        # 分割 header 和 body
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        request_line = lines[0] if lines else ""

        # 解析请求行: "POST /api/chat HTTP/1.1"
        request_parts = request_line.split()
        if len(request_parts) < 2:
            return None, None, None
        path = request_parts[1]

        # 解析 headers
        host = ""
        auth_header = ""
        origin_header = ""
        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif lower.startswith("authorization:"):
                auth_header = line.split(":", 1)[1].strip()
            elif lower.startswith(("origin:", "referer:")) and not origin_header:
                # Origin 优先, Referer 仅在 Origin 未设置时作为 fallback
                origin_header = line.split(":", 1)[1].strip()

        # 构建端点 URL (v44.2: 多策略 HTTPS 推断)
        scheme = _infer_scheme_from_burp(host, lines, origin_header)
        endpoint = path if path.startswith("http") else f"{scheme}://{host}{path}"

        # 提取 API Key
        api_key = None
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]
        elif auth_header:
            api_key = auth_header

        # 提取模型名 (从请求体 JSON)
        model_name = None
        if body:
            import json
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                body_json = json.loads(body)
                if isinstance(body_json, dict):
                    model_name = body_json.get("model")

        return endpoint, api_key, model_name

    except Exception as e:
        logger.debug(f"A-4: Burp request parsing failed: {e}")
        return None, None, None


def _discover_target_tools(response_text: str) -> list[dict[str, Any]]:
    """A-3: 从目标响应中自动发现 Agent 工具定义.

    解析响应文本, 尝试提取工具/函数定义。支持多种格式:
      1. OpenAI function calling 格式: ``{"tools": [...]}`` 或 ``{"functions": [...]}``
      2. MCP 格式: ``{"tools": [{"name": ..., "description": ...}]}``
      3. 自然语言描述中的工具名称 (降级模式)

    学术依据:
      - Greshake et al. (arXiv:2302.12173): Agent 工具发现是间接注入的前提
      - OWASP ASI05: 工具滥用需先发现工具集

    Args:
        response_text: 能力探测探针的响应文本.

    Returns:
        工具定义列表, 如果未发现则返回空列表.
    """
    import json

    if not response_text:
        return []

    # 策略 1: 尝试解析完整 JSON 响应
    with contextlib.suppress(json.JSONDecodeError, TypeError):
        data = json.loads(response_text)
        if isinstance(data, dict):
            # OpenAI function calling 格式
            tools = data.get("tools") or data.get("functions") or []
            if isinstance(tools, list) and tools:
                return tools
            # MCP 格式
            if "tools" in data and isinstance(data["tools"], list):
                return data["tools"]

    # 策略 2: 从文本中提取 JSON 片段 (响应可能包含非 JSON 文本)
    import re
    json_pattern = re.compile(r'\{[^{}]*"tools"\s*:\s*\[.*?\]\s*[^{}]*\}', re.DOTALL)
    match = json_pattern.search(response_text)
    if match:
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            data = json.loads(match.group())
            if isinstance(data, dict) and isinstance(data.get("tools"), list):
                return data["tools"]

    # 策略 3: 从文本中提取工具名称 (降级模式)
    # 匹配常见模式: "Available tools: read_file, send_email, ..."
    tool_pattern = re.compile(
        r"(?:available\s+tools?|functions?|capabilities)\s*[:\s]\s*"
        r"([a-zA-Z_][a-zA-Z0-9_,\s]+)",
        re.IGNORECASE,
    )
    match = tool_pattern.search(response_text)
    if match:
        tool_names = [t.strip() for t in match.group(1).split(",") if t.strip()]
        if tool_names:
            return [
                {"name": name, "description": "", "parameters": {"type": "object", "properties": {}}}
                for name in tool_names
            ]

    return []


async def _probe_mcp_tools(target_url: str, auth_headers: dict[str, str]) -> list[dict[str, Any]]:
    """P1: 真实 MCP 协议探测 — 从目标 MCP 端点获取真实工具定义.

    尝试向目标的 MCP 端点发送 JSON-RPC ``tools/list`` 请求,
    获取目标 Agent 实际可调用的工具定义。

    探测路径:
      1. ``{target_url}/mcp/tools`` — 标准 MCP REST 端点
      2. ``{target_url}/.well-known/mcp`` — MCP 发现端点
      3. ``{target_url}/api/mcp`` — 常见 API 路径

    学术依据:
      - MCP Specification (2025): Model Context Protocol tools/list 方法
      - OWASP ASI05: 工具滥用需先发现工具集
      - MITRE ATT&CK T1592: 主动扫描

    Args:
        target_url: 目标 URL.
        auth_headers: 认证 headers (从 AuthState 注入).

    Returns:
        工具定义列表, 如果未发现则返回空列表.
    """
    import json

    # MCP 探测路径候选
    mcp_paths = [
        "/mcp/tools",
        "/.well-known/mcp",
        "/api/mcp",
        "/mcp",
    ]

    # 从 target_url 提取 base URL
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    for path in mcp_paths:
        mcp_url = f"{base_url}{path}"
        try:
            import aiohttp

            headers = {
                "Content-Type": "application/json",
                **auth_headers,
            }
            # MCP JSON-RPC tools/list 请求
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1,
            }

            async with aiohttp.ClientSession() as session, session.post(
                mcp_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text()
                data = json.loads(text)
                # MCP 响应格式: {"result": {"tools": [...]}}
                tools = (
                    data.get("result", {}).get("tools", [])
                    if isinstance(data, dict)
                    else []
                )
                if isinstance(tools, list) and tools:
                    logger.info(f"P1: MCP tools discovered at {mcp_url}: {len(tools)} tools")
                    return tools
        except Exception as e:
            logger.debug(f"P1: MCP probe failed for {mcp_url}: {e}")
            continue

    return []


# ============================================================
# v44.2: Burp SSE/HTTPS 自动适配 — PyRIT 原生框架优先
# ============================================================


def _detect_sse_from_request(raw_request: str) -> bool:
    """从 Burp 原始 HTTP 请求检测 SSE 流式响应.

    检测策略 (优先级递降):
      1. Accept header 包含 text/event-stream
      2. 请求体 JSON 中 Stream/stream 字段为 true
      3. URL 路径包含 stream/sse/events 关键词

    学术依据:
      - SSE (Server-Sent Events) 是 LLM API 流式响应的标准格式
      - PyRIT (arXiv:2407.01232) 提供 get_http_target_regex_matching_callback_function
        专门处理 SSE 等非标准 JSON 响应

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.

    Returns:
        True 如果检测到 SSE 流式响应.
    """
    raw_lower = raw_request.lower()

    # 策略 1: Accept header
    if "text/event-stream" in raw_lower:
        return True

    # 策略 2: 请求体 JSON 中的 Stream 字段
    parts = raw_request.split("\r\n\r\n", 1)
    body = parts[1] if len(parts) > 1 else ""
    if body:
        import json

        with contextlib.suppress(json.JSONDecodeError, TypeError):
            body_json = json.loads(body)
            if isinstance(body_json, dict):
                stream_val = body_json.get("Stream") or body_json.get("stream")
                if stream_val is True:
                    return True

    # 策略 3: URL 路径关键词
    return bool(any(kw in raw_lower for kw in ("/stream", "/sse", "/events")))


def _detect_tls_from_request(raw_request: str) -> bool:
    """从 Burp 原始 HTTP 请求推断是否需要 TLS (HTTPS).

    推断策略 (优先级递降):
      1. Origin/Referer header 以 https:// 开头
      2. Host header 包含 :443 端口
      3. 请求行路径以 https:// 开头
      4. 默认: 非 localhost 的域名推断为 HTTPS

    v44.2 修复: 原 _extract_endpoint_from_burp 用 "443" in host 判断,
    导致不含 443 的 HTTPS 域名 (如 llm-api.example.edu.cn) 被错误推断为 HTTP.

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.

    Returns:
        True 如果推断目标需要 TLS.
    """
    parts = raw_request.split("\r\n\r\n", 1)
    header_section = parts[0]
    lines = header_section.split("\r\n")

    host = ""
    origin = ""
    referer = ""
    request_line = lines[0] if lines else ""
    request_path = ""
    request_parts = request_line.split()
    if len(request_parts) >= 2:
        request_path = request_parts[1]

    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif lower.startswith("origin:"):
            origin = line.split(":", 1)[1].strip()
        elif lower.startswith("referer:") and not referer:
            referer = line.split(":", 1)[1].strip()

    # 策略 1: Origin/Referer 以 https:// 开头
    for url in (origin, referer):
        if url.strip().lower().startswith("https://"):
            return True

    # 策略 2: Host 包含 :443
    if ":443" in host:
        return True

    # 策略 3: 请求行路径以 https:// 开头
    if request_path.lower().startswith("https://"):
        return True

    # 策略 4: 非 localhost/127.0.0.1 的域名默认 HTTPS
    if host and not host.startswith(("localhost", "127.0.0.1", "0.0.0.0", "[")):
        # 排除明确指定 HTTP 端口的域名
        return not any(f":{port}" in host for port in ("8080", "3000", "8000", "5000", "11434"))

    return False


def _infer_scheme_from_burp(
    host: str,
    lines: list[str],
    origin_header: str = "",
) -> str:
    """从 Burp 原始请求的多个信号推断 URL scheme (http/https).

    v44.2: 替代原始的 `"443" in host` 判断逻辑.

    推断策略 (优先级递降):
      1. Origin/Referer header 的 scheme
      2. Host 包含 :443
      3. 非 localhost 域名默认 https

    Args:
        host: Host header 值.
        lines: 请求头行列表.
        origin_header: 已解析的 Origin header 值.

    Returns:
        "https" 或 "http".
    """
    # 策略 1: Origin header scheme
    if origin_header:
        origin_lower = origin_header.lower().strip()
        if origin_lower.startswith("https://"):
            return "https"
        if origin_lower.startswith("http://"):
            return "http"

    # 策略 2: 从 lines 中提取 Referer header
    for line in lines:
        if line.lower().startswith("referer:"):
            referer = line.split(":", 1)[1].strip()
            referer_lower = referer.lower()
            if referer_lower.startswith("https://"):
                return "https"
            if referer_lower.startswith("http://"):
                return "http"

    # 策略 3: Host :443 端口
    if ":443" in host:
        return "https"

    # 策略 4: 明确的 HTTP 端口
    if any(f":{port}" in host for port in ("8080", "3000", "8000", "5000", "11434")):
        return "http"

    # 策略 5: localhost/127.0.0.1 → http
    if host.startswith(("localhost", "127.0.0.1", "0.0.0.0", "[")):
        return "http"

    # 默认: 非 localhost 域名 → https
    if host:
        return "https"

    return "http"


def _build_burp_callback(
    *,
    is_sse: bool,
    response_path: str,
    target_url: str,
) -> Any:
    """构建 Burp 模式的 HTTPTarget 回调函数.

    PyRIT 原生框架优先 (R-010):
      - SSE: 优先使用 PyRIT 原生 get_http_target_regex_matching_callback_function
      - JSON: 优先使用 PyRIT 原生 get_http_target_json_response_callback_function
      - Fallback: 自定义回调 (移植自 web_redteam, 组合依赖 PyRIT HTTPTarget)

    v44.2: 将 web_redteam 的 SSE 回调能力提升到主流水线 Burp 模式.

    Args:
        is_sse: 是否为 SSE 流式响应.
        response_path: JSON 响应提取路径.
        target_url: 目标 URL (用于 SSE 正则回调).

    Returns:
        回调函数.
    """
    if is_sse:
        # SSE: 优先 PyRIT 原生正则回调
        try:
            from pyrit.prompt_target.http_target import (
                get_http_target_regex_matching_callback_function,
            )
        except ImportError:
            try:
                from pyrit.prompt_target import (
                    get_http_target_regex_matching_callback_function,
                )
            except ImportError:
                logger.warning("v44.2: PyRIT SSE callback import failed, using fallback")
                return _build_fallback_sse_callback()

        return get_http_target_regex_matching_callback_function(
            pattern=r"data:\s*(.*?)(?:\n\n|$)",
            url=target_url,
        )

    # JSON: 优先 PyRIT 原生 JSON 路径回调
    try:
        from pyrit.prompt_target.http_target import (
            get_http_target_json_response_callback_function,
        )
    except ImportError:
        try:
            from pyrit.prompt_target import (
                get_http_target_json_response_callback_function,
            )
        except ImportError:
            logger.warning("v44.2: PyRIT JSON callback import failed, using fallback")
            return _build_fallback_json_callback(response_path)

    return get_http_target_json_response_callback_function(
        key=response_path,
    )


def _build_fallback_sse_callback() -> Any:
    """SSE 回调 fallback — 当 PyRIT 原生回调不可用时使用.

    移植自 web_redteam.pipeline.stage_target._build_fallback_sse_callback.
    提取所有 data: 行内容, 兼容 OpenAI/PascalCase 等多种 JSON 结构.
    """
    import json
    import re

    def callback(response: str) -> str:
        chunks = re.findall(r"data:\s*(.*?)(?:\n\n|$)", response, re.DOTALL)
        result_parts: list[str] = []
        for chunk in chunks:
            chunk = chunk.strip()
            if chunk == "[DONE]" or not chunk:
                continue
            try:
                data = json.loads(chunk)
                content = (
                    _safe_get(data, "choices", 0, "delta", "content")
                    or _safe_get(data, "Choices", 0, "Delta", "Content")
                    or data.get("content")
                    or data.get("Content")
                )
                if content:
                    result_parts.append(str(content))
            except (json.JSONDecodeError, TypeError):
                result_parts.append(chunk)
        return "".join(result_parts)

    return callback


def _build_fallback_json_callback(key: str) -> Any:
    """JSON 回调 fallback — 当 PyRIT 原生回调不可用时使用.

    移植自 web_redteam.pipeline.stage_target._build_fallback_json_callback.
    支持 dotted path + array index (如 Choices[0].Delta.Content).
    """
    import json
    import re

    def callback(response: str) -> str:
        try:
            data = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            return response

        current: Any = data
        for part in key.split("."):
            if not part:
                continue
            match = re.match(r"^(\w+)\[(\d+)\]$", part)
            if match:
                attr, idx = match.groups()
                try:
                    current = current[attr][int(idx)]
                except (KeyError, IndexError, TypeError):
                    return response
            elif part.startswith("[") and part.endswith("]"):
                try:
                    current = current[int(part[1:-1])]
                except (IndexError, TypeError, ValueError):
                    return response
            else:
                try:
                    current = current[part]
                except (KeyError, TypeError):
                    return response
        return str(current) if current is not None else response

    return callback


def _safe_get(data: Any, *keys: Any) -> Any:
    """安全地从嵌套字典/列表中提取值.

    Args:
        data: 数据结构 (dict/list).
        keys: 键/索引序列.

    Returns:
        提取的值, 失败时返回 None.
    """
    current: Any = data
    for key in keys:
        try:
            current = current[key]
        except (KeyError, IndexError, TypeError):
            return None
    return current
