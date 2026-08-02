# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 1.5: Web 目标自动认证桥接 — 检测 URL → 认证 → 注入主 pipeline。

当用户提供 ``--web-target-url`` 时, 本阶段:
  1. 加载/动态生成 TargetProfile
  2. 启动 Playwright 浏览器
  3. **AutoAuthStrategy 自动探测**:
     - 访问目标 URL → 检查是否重定向到登录页
     - 如果需要认证 → 执行认证流程 (同域/跨域, 人工辅助+自动填充)
     - 如果不需要 → 直接使用目标页面
  4. 创建 PlaywrightTarget (从已认证的 Page)
  5. 注册到 TargetRegistry (替换默认的 OpenAIChatTarget)
  6. 存储浏览器会话到 Context (供 finally 清理)

此后 Stage 2 (scenario) 及后续阶段正常使用 PlaywrightTarget 进行攻击。

> **设计原则** (R-010): PyRIT 原生优先
  - PlaywrightTarget 是 PyRIT 原生 prompt_target
  - AuthDetector/AuthStrategy 来自 web_redteam, 是对原生模式的增强
  - 不修改任何 PyRIT 原生代码

学术依据:
  - PyRIT (arXiv:2407.01232): PlaywrightTarget 支持 Web 应用红队评估
  - CopilotAuthenticator: page.on("response") 拦截网络响应提取 Token

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from pipeline.context import PipelineContext

if TYPE_CHECKING:
    pass  # Page used in type hints below

logger = logging.getLogger(__name__)


async def run(ctx: PipelineContext) -> bool:
    """执行 Stage 1.5: Web 目标自动认证桥接。

    Args:
        ctx: PipelineContext (需要 args.web_target_url)

    Returns:
        True 如果 web 目标已成功桥接到主 pipeline, False 如果不需要 (走原生 API 流程)
    """
    web_target_url = getattr(ctx.args, "web_target_url", None)
    if not web_target_url:
        return False

    print("\n" + "=" * 70)
    print("[1.5] Web 目标自动认证桥接")
    print("=" * 70)
    print(f"  目标 URL: {web_target_url}")

    try:
        result = await _bridge_web_target(ctx, web_target_url)
        if result:
            print("  ✓ Web 目标已桥接到主 pipeline (PlaywrightTarget 已注册)")
        return result
    except (ImportError, RuntimeError, OSError, ValueError) as e:
        print(f"  [错误] Web 目标桥接失败: {e}")
        logger.error(f"Web target bridge failed: {e}", exc_info=True)
        return False


async def _bridge_web_target(ctx: PipelineContext, target_url: str) -> bool:
    """执行实际的 web 目标桥接逻辑。"""
    # 1. 加载或生成 TargetProfile
    profile = _load_or_create_profile(ctx, target_url)
    print(f"  认证策略: {profile.auth.type}")
    if profile.auth.login_url:
        print(f"  登录页: {profile.auth.login_url}")
    print(f"  目标页: {profile.auth.target_url}")

    # 2. 启动浏览器
    from web_redteam.auth.browser_session import BrowserSession

    session = BrowserSession()
    headless = getattr(ctx.args, "web_headless", False)
    cdp_port = getattr(ctx.args, "cdp_port", 9222)

    page = await session.launch_with_debug_port(
        port=cdp_port,
        headless=headless,
    )

    # 3. 执行认证 (AutoAuthStrategy 自动探测)
    from web_redteam.auth.auth_strategy import AuthStrategyFactory

    strategy = AuthStrategyFactory.create(profile.auth.type)
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
    # 注册为 "default" 目标, 后续 stage_scenario 会自动使用
    registry.instances.register_instance(
        instance=playwright_target,
        instance_name="web_target",
        target_type="PlaywrightTarget",
    )
    # 同时注册为 "default" 以覆盖 OpenAIChatTarget
    registry.instances.register_instance(
        instance=playwright_target,
        instance_name="default",
        target_type="PlaywrightTarget",
    )

    print("  PlaywrightTarget 已创建并注册")
    print(f"    输入选择器: {profile.interaction.input.selector}")
    print(f"    发送选择器: {profile.interaction.send.selector}")
    print(f"    响应选择器: {profile.interaction.response.selector}")

    # 6. 存储浏览器会话到 Context (供 finally 清理)
    ctx.metadata["web_browser_session"] = session
    ctx.metadata["web_target_url"] = target_url
    ctx.metadata["web_target_profile"] = profile

    logger.info(f"Web target bridged: {target_url} → PlaywrightTarget registered")
    return True


def _load_or_create_profile(ctx: PipelineContext, target_url: str) -> Any:
    """加载 YAML 配置或从 URL 动态生成 TargetProfile。"""
    profile_path = getattr(ctx.args, "web_target_profile", None)
    if profile_path:
        from web_redteam.targets.target_profile import TargetProfile

        profile = TargetProfile.from_yaml_file(profile_path)
        logger.info(f"Loaded TargetProfile from {profile_path}")
        return profile
    else:
        # 动态生成 Profile (从 URL 自动推断)
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
