# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 2: 认证 (人工辅助 + 自动检测)。.

Browser 模式:
  1. 加载 TargetProfile (YAML)
  2. 创建 BrowserSession, 启动浏览器
  3. 尝试恢复已有认证状态 (storage_state)
  4. 如果无法恢复, 执行认证策略 (同域/跨域)
  5. AuthDetector 检测认证完成
  6. 保存认证状态 (供下次复用)

API 模式:
  - 跳过浏览器认证 (认证信息已在 API headers 中)
  - 仅加载 APITargetConfig 到 ctx.api_config

产出 (写入 WebRedTeamContext):
  Browser 模式:
    - ctx.profile = TargetProfile
    - ctx.browser_session = BrowserSession
    - ctx.page = 已认证的 Playwright Page
  API 模式:
    - ctx.api_config = APITargetConfig
"""

import asyncio
import contextlib
import logging
from pathlib import Path

from web_redteam.pipeline.context import WebRedTeamContext

logger = logging.getLogger(__name__)

# G16: 认证重试参数
_AUTH_MAX_RETRIES = 2
_AUTH_RETRY_BASE_DELAY = 2.0  # 指数退避基数 (秒)


async def run(ctx: WebRedTeamContext) -> None:
    """执行 Stage 2: 认证。."""
    logger.info("=" * 70)
    logger.info("[Stage 2] 认证 (人工辅助 + 自动检测)")
    logger.info("=" * 70)

    # API 模式: 跳过浏览器认证
    if ctx.api_mode:
        await _run_api_mode(ctx)
        return

    # Browser 模式: 执行浏览器认证
    await _run_browser_mode(ctx)


async def _run_api_mode(ctx: WebRedTeamContext) -> None:
    """API 模式: 跳过浏览器认证, 仅加载 API 配置。."""
    from web_redteam.targets.api_config import APITargetConfig

    logger.info("  [API 模式] 跳过浏览器认证 (认证信息在 API headers 中)")

    config = APITargetConfig.from_args(ctx.args)
    if config is None:
        raise ValueError("API 模式但未能从参数构建 APITargetConfig")

    ctx.api_config = config

    # 打印配置摘要 (脱敏)
    display = config.to_display_dict()
    logger.info(f"  目标 URL: {display['url']}")
    logger.info(f"  HTTP 方法: {display['method']}")
    logger.info("  请求头:")
    for k, v in display["headers"].items():
        logger.info(f"    {k}: {v}")
    logger.info(f"  请求体: {display['body_template']}")
    logger.info(f"  响应路径: {display['response_json_path']}")
    logger.info(f"  最大 RPM: {display['max_rpm'] or '不限'}")
    logger.info(f"  最大并发: {display['max_concurrency']}")
    logger.info(f"  最大重试: {display['max_retries']}")
    logger.info(f"  超时: {display['timeout']}s")

    logger.info(
        f"Stage 2 (API): config loaded (url={config.url}, "
        f"rpm={config.max_rpm}, concurrency={config.max_concurrency})"
    )


async def _run_browser_mode(ctx: WebRedTeamContext) -> None:
    """Browser 模式: 执行完整的浏览器认证流程。."""
    from web_redteam.auth.auth_detector import AuthDetectorFactory
    from web_redteam.auth.auth_strategy import AuthStrategyFactory
    from web_redteam.auth.browser_session import BrowserSession
    from web_redteam.targets.dynamic_profile import create_profile_from_url
    from web_redteam.targets.target_profile import TargetProfile

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
    logger.info(f"  目标: {profile.target.name} ({profile.target.description})")
    logger.info(f"  认证类型: {profile.auth.type}")
    if profile.auth.login_url:
        logger.info(f"  登录页: {profile.auth.login_url}")
    logger.info(f"  目标页: {profile.auth.target_url}")

    # 2. 尝试恢复已有认证状态 (对 same_domain / cross_domain / auto 有效)
    storage_state_path = getattr(args, "storage_state", None)
    session: BrowserSession | None = None
    if (
        storage_state_path
        and Path(storage_state_path).exists()
        and profile.auth.type in ("same_domain", "cross_domain", "auto")
    ):
        logger.info(f"  尝试恢复已有认证状态: {storage_state_path}")
        session = BrowserSession()
        try:
            page = await session.restore_storage_state(storage_state_path)
            await page.goto(profile.auth.target_url, wait_until="domcontentloaded")

            # 验证认证是否仍然有效
            configs = profile.get_detection_configs()
            if configs:
                detector = AuthDetectorFactory.from_configs(configs, timeout_seconds=10)
                if await detector.check_immediate(page):
                    logger.info("  认证状态有效, 跳过认证")
                    ctx.page = page
                    ctx.browser_session = session
                    return
                else:
                    logger.info("  认证状态已过期, 需要重新认证")
                    await session.close()
                    session = None
            else:
                # 无检测策略配置, 假设认证状态有效
                logger.info("  无检测策略配置, 假设认证状态有效")
                ctx.page = page
                ctx.browser_session = session
                return
        except Exception as e:
            logger.warning(f"恢复认证状态失败: {e}, 将执行完整认证")
            if session is not None:
                with contextlib.suppress(Exception):
                    await session.close()
            session = None

    # 3. 启动浏览器 (开启 CDP 调试端口)
    if session is None:
        session = BrowserSession()
    if session.page is None:
        page = await session.launch_with_debug_port(
            port=args.cdp_port,
            headless=args.headless,
        )
    else:
        page = session.page
    ctx.browser_session = session

    # 4. 执行认证策略 (G16: 重试 + 指数退避)
    strategy = AuthStrategyFactory.create(profile.auth.type)
    last_auth_error: Exception | None = None
    for attempt in range(1, _AUTH_MAX_RETRIES + 1):
        try:
            page = await strategy.execute(page, profile)
            ctx.page = page
            last_auth_error = None
            break
        except (TimeoutError, RuntimeError) as e:
            last_auth_error = e
            logger.warning(
                f"认证失败 (attempt {attempt}/{_AUTH_MAX_RETRIES}): {e}"
            )
            if attempt < _AUTH_MAX_RETRIES:
                delay = _AUTH_RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.warning(f"  [警告] 认证失败, {delay:.0f}s 后重试...")
                await asyncio.sleep(delay)

    if last_auth_error is not None:
        raise last_auth_error

    # 5. 保存认证状态 (对需要认证的场景)
    if storage_state_path and profile.auth.type in ("same_domain", "cross_domain"):
        try:
            await session.save_storage_state(page.context, storage_state_path)
            logger.info(f"  认证状态已保存: {storage_state_path}")
        except Exception as e:
            logger.warning(f"保存认证状态失败: {e}")

    logger.info("  认证完成, 已到达目标页面")
    logger.info(f"Stage 2: authentication completed (type={profile.auth.type})")
