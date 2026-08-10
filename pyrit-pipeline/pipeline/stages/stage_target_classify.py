# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 0.5: 统一目标类型判别 + 认证桥接。.

当用户提供 ``--target-url`` 时, 本阶段:
  1. 调用 TargetClassifier 判别目标类型 (LLM Web 应用 / LLM API 平台)
  2. 根据判别结果自动路由:
     - llm_web_app → 浏览器模式 (AuthProbe + MFADetector + AuthStrategy + PlaywrightTarget)
     - llm_api_platform → API 模式 (APITargetConfig + HTTPTarget + RateLimitedTarget)
  3. 创建对应 Target 并注册到 TargetRegistry
  4. 可选: 触发 recon-pipeline 侦察, 结果驱动 Stage 2 场景选择

此阶段替代原 stage_web_auth.py, 将 Web 认证和 API Target 创建统一到一处。

> **设计原则** (R-010): PyRIT 原生优先
  - PlaywrightTarget / HTTPTarget 是 PyRIT 原生 prompt_target
  - AuthDetector/AuthStrategy/MFADetector 来自 web_redteam, 是对原生模式的增强
  - 不修改任何 PyRIT 原生代码

学术依据:
  - PyRIT (arXiv:2407.01232): PlaywrightTarget / HTTPTarget 双模式支持
  - OWASP Top 10 for LLMs 2025: Web 注入和 API 注入的攻击面对应
  - MITRE ATT&CK: Reconnaissance → Initial Access → Execution

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from typing import Any

from pipeline.context import PipelineContext
from pipeline.integrations.target_classifier import TargetClassification, TargetClassifier
from pipeline.utils.decision_trace import DecisionTrace
from pipeline.utils.event_bus import EventBus

logger = logging.getLogger(__name__)


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
    print("[0.5] 统一目标类型判别 + 认证桥接")
    print("=" * 70)
    print(f"  目标 URL: {target_url}")

    # 获取目标类型 (auto / web_app / api_platform)
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

        # Step 2: 根据判别结果路由
        if classification.target_type == "llm_web_app":
            return await _bridge_web_app(ctx, target_url, classification)
        elif classification.target_type == "llm_api_platform":
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

    # 1. 加载或动态生成 TargetProfile
    profile = _load_or_create_profile(ctx, target_url)
    print(f"  认证策略: {profile.auth.type}")

    # 2. 启动浏览器
    from web_redteam.auth.browser_session import BrowserSession

    session = BrowserSession()
    headless = getattr(ctx.args, "web_headless", False)
    cdp_port = getattr(ctx.args, "cdp_port", 9222)

    page = await session.launch_with_debug_port(
        port=cdp_port,
        headless=headless,
    )

    # 3. 执行认证 (AutoAuthStrategy 自动探测 + MFA 检测)
    from web_redteam.auth.auth_strategy import AuthStrategyFactory

    strategy = AuthStrategyFactory.create(profile.auth.type)

    # 注入 MFA 超时参数
    mfa_timeout = getattr(ctx.args, "mfa_timeout", 300)
    if hasattr(strategy, "_human_auth"):
        strategy._human_auth.mfa_timeout = mfa_timeout  # type: ignore[attr-defined]

    page = await strategy.execute(page, profile)

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
    from pyrit.common import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register_instance(
        instance=playwright_target,
        instance_name="web_target",
        target_type="PlaywrightTarget",
    )
    registry.instances.register_instance(
        instance=playwright_target,
        instance_name="default",
        target_type="PlaywrightTarget",
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

    # 注: recon-pipeline 侦察不再通过代码直接调用 (两流水线完全独立)。
    # 使用方式: 先运行 recon-pipeline 生成 JSON 报告, 再通过 --recon-json 加载。

    logger.info(f"Web app target bridged: {target_url} → PlaywrightTarget")
    return True


async def _bridge_api_platform(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> bool:
    """API 平台模式: HTTPTarget + RateLimitedTarget。."""
    print("\n  --- API 平台模式 (HTTPTarget) ---")

    from pyrit.prompt_target import HTTPTarget
    from pyrit.prompt_target.http_target import (
        get_http_target_json_response_callback_function,
    )

    from pipeline.targets.rate_limited_target import RateLimitedTarget
    from web_redteam.targets.api_config import APITargetConfig

    # 1. 从 URL 自动构建 API 配置
    config = APITargetConfig.from_url(target_url)

    print(f"  API URL: {config.url}")
    print(f"  HTTP 方法: {config.method}")
    print(f"  响应路径: {config.response_json_path}")
    print(f"  最大并发: {config.max_concurrency}")
    print(f"  最大 RPM: {config.max_rpm or '不限'}")

    # 2. 构建回调函数
    callback = get_http_target_json_response_callback_function(
        key=config.response_json_path,
    )

    # 3. 构建 HTTPTarget (PyRIT 1.0.1: 不接受 prompt_request_piece 参数)
    raw_request = _build_raw_http_request(config)
    http_target = HTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
    )

    # 4. 使用 RateLimitedTarget 包装
    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=config.url,
        max_concurrency=config.max_concurrency,
        max_retries=config.max_retries,
        requests_per_minute=config.max_rpm,
    )

    # 5. 注册到 TargetRegistry
    from pyrit.common import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register_instance(
        instance=rate_limited_target,
        instance_name="api_target",
        target_type="HTTPTarget",
    )
    registry.instances.register_instance(
        instance=rate_limited_target,
        instance_name="default",
        target_type="HTTPTarget",
    )

    print("  ✓ HTTPTarget + RateLimitedTarget 已创建并注册")

    # 6. 存储到 Context
    ctx.metadata["api_target_config"] = config
    ctx.metadata["api_target_url"] = target_url
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # 注: recon-pipeline 侦察不再通过代码直接调用 (两流水线完全独立)。
    # 使用方式: 先运行 recon-pipeline 生成 JSON 报告, 再通过 --recon-json 加载。

    logger.info(f"API platform target bridged: {target_url} → HTTPTarget")
    return True


def _load_or_create_profile(ctx: PipelineContext, target_url: str) -> Any:
    """加载 YAML 配置或从 URL 动态生成 TargetProfile。."""
    profile_path = getattr(ctx.args, "web_target_profile", None)
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
        logger.info(f"Dynamic TargetProfile created from {target_url}")
        return profile


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
