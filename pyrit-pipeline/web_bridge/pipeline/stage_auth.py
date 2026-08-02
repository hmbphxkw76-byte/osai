# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 2: 认证 (人工辅助 + 自动检测)。.

职责:
  1. 加载 TargetProfile (YAML)
  2. 创建 BrowserSession, 启动浏览器
  3. 尝试恢复已有认证状态 (storage_state)
  4. 如果无法恢复, 执行认证策略 (同域/跨域)
  5. AuthDetector 检测认证完成
  6. 保存认证状态 (供下次复用)

产出 (写入 WebBridgeContext):
  - ctx.profile = TargetProfile
  - ctx.browser_session = BrowserSession
  - ctx.page = 已认证的 Playwright Page

依赖的原生 API:
  - 无 (纯 Playwright + 自定义模块)
"""

import logging
from pathlib import Path

from web_bridge.pipeline.context import WebBridgeContext

logger = logging.getLogger(__name__)


async def run(ctx: WebBridgeContext) -> None:
    """执行 Stage 2: 认证。."""
    print("\n" + "=" * 70)
    print("[Stage 2] 认证 (人工辅助 + 自动检测)")
    print("=" * 70)

    from web_bridge.auth.auth_detector import AuthDetectorFactory
    from web_bridge.auth.auth_strategy import AuthStrategyFactory
    from web_bridge.auth.browser_session import BrowserSession
    from web_bridge.targets.dynamic_profile import create_profile_from_url
    from web_bridge.targets.target_profile import TargetProfile

    args = ctx.args

    # 1. 加载 TargetProfile — 两种方式
    if args.target_profile:
        # 方式 A: 从 YAML 文件加载
        profile = TargetProfile.from_yaml_file(args.target_profile)
    else:
        # 方式 B: 从 --target-url 动态生成
        profile = create_profile_from_url(
            target_url=args.target_url,
            attack_type=args.attack_type,
            objective=args.objective,
            max_turns=args.max_turns,
        )
    ctx.profile = profile
    print(f"  目标: {profile.target.name} ({profile.target.description})")
    print(f"  认证类型: {profile.auth.type}")
    if profile.auth.login_url:
        print(f"  登录页: {profile.auth.login_url}")
    print(f"  目标页: {profile.auth.target_url}")

    # 2. 尝试恢复已有认证状态 (仅对 same_domain / cross_domain 有效)
    # auto 和 none 不需要恢复 (auto 需要探测, none 无需认证)
    storage_state_path = getattr(args, "storage_state", None)
    if (
        storage_state_path
        and Path(storage_state_path).exists()
        and profile.auth.type in ("same_domain", "cross_domain")
    ):
        print(f"  尝试恢复已有认证状态: {storage_state_path}")
        session = BrowserSession()
        try:
            page = await session.restore_storage_state(storage_state_path)
            await page.goto(profile.auth.target_url, wait_until="domcontentloaded")

            # 验证认证是否仍然有效
            configs = profile.get_detection_configs()
            if configs:
                detector = AuthDetectorFactory.from_configs(configs, timeout_seconds=10)
                if await detector.check_immediate(page):
                    print("  认证状态有效, 跳过认证")
                    ctx.page = page
                    ctx.browser_session = session
                    return
                else:
                    print("  认证状态已过期, 需要重新认证")
                    await session.close()
            else:
                # 无检测策略配置, 假设认证状态有效
                print("  无检测策略配置, 假设认证状态有效")
                ctx.page = page
                ctx.browser_session = session
                return
        except Exception as e:
            logger.warning(f"恢复认证状态失败: {e}, 将执行完整认证")
            await session.close()

    # 3. 启动浏览器 (开启 CDP 调试端口)
    session = BrowserSession()
    page = await session.launch_with_debug_port(
        port=args.cdp_port,
        headless=args.headless,
    )
    ctx.browser_session = session

    # 4. 执行认证策略
    strategy = AuthStrategyFactory.create(profile.auth.type)
    page = await strategy.execute(page, profile)
    ctx.page = page

    # 5. 保存认证状态 (仅对需要认证的场景)
    if storage_state_path and profile.auth.type in ("same_domain", "cross_domain"):
        try:
            await session.save_storage_state(page.context, storage_state_path)
            print(f"  认证状态已保存: {storage_state_path}")
        except Exception as e:
            logger.warning(f"保存认证状态失败: {e}")

    print("  认证完成, 已到达目标页面")
    logger.info(f"Stage 2: authentication completed (type={profile.auth.type})")
