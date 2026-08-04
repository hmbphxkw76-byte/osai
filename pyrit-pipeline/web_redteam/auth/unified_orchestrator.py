# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""统一认证编排器 — 所有 URL 的入口处理器。

**核心职责**:
  1. 接收任意 URL → 调用 TargetClassifier 自动判别类型
  2. 根据类型路由到浏览器认证流程或 API 认证流程
  3. 认证完成后提取认证数据 (cookies/headers/tokens)
  4. 将认证数据注入 PipelineContext → 自动衔接 PyRIT 攻击流程

**两条路径互不影响**:
  - 浏览器认证路径: BrowserSession → AuthStrategy → AuthDetector → MFADetector
  - API 认证路径: APIAuthenticator → headers/cookies
  - 两条路径完全隔离, 各自独立执行

**认证失败容错**:
  - 认证失败不阻塞流水线 — 降级为无认证模式, 打印警告
  - 认证成功时自动导出 AuthState 文件供下次复用
  - 认证复用优先: 先检查 auth_state.json, 有效则跳过认证

设计原则 (R-022: PyRIT 原生优先):
  - 纯选择层模块, 不修改原生 Target 生命周期
  - AuthState 为纯数据层, 不覆盖原生认证
  - 使用 Playwright 原生 API (context.cookies / storage_state)

学术依据:
  - PyRIT (arXiv:2407.01232): 统一的 Target + Memory 体系
  - OWASP ASVS V2.4: 认证验证要求
  - NIST SP 800-63B: 多因素认证分类

> **日期**: 2026-8-4
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pipeline.integrations.auth_state_bridge import (
    AuthState,
    export_auth_state,
    inject_auth_state_to_context,
    try_reuse_auth_state,
)
from web_redteam.auth.api_auth import APIAuthenticator
from web_redteam.auth.auth_data_extractor import AuthDataExtractor

if TYPE_CHECKING:
    from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


class UnifiedAuthOrchestrator:
    """统一认证编排器 — 所有 URL 的入口处理器。

    用法::

        from web_redteam.auth.unified_orchestrator import UnifiedAuthOrchestrator

        orchestrator = UnifiedAuthOrchestrator()
        auth_state = await orchestrator.authenticate_and_route(
            url="https://chat.example.com",
            ctx=ctx,
        )
        # auth_state.headers → {"Authorization": "Bearer xxx", "Cookie": "..."}
        # ctx.metadata["auth_headers"] 已注入
    """

    def __init__(self, *, headless: bool = False, cdp_port: int = 9222) -> None:
        """初始化统一认证编排器。

        Args:
            headless: 浏览器是否无头模式 (认证场景建议 False)。
            cdp_port: CDP 调试端口。
        """
        self._headless = headless
        self._cdp_port = cdp_port
        self._browser_session: Any = None

    async def authenticate_and_route(
        self,
        url: str,
        ctx: PipelineContext,
        *,
        api_key: str = "",
        target_profile: str = "",
        stream: bool | None = None,
    ) -> AuthState:
        """统一认证入口 — 接收 URL, 自动判别并路由认证流程。

        流程:
          0. 尝试复用已有认证状态 (auth_state.json)
          1. TargetClassifier 判别目标类型
          2. 路由到浏览器认证或 API 认证
          3. 提取认证数据 → AuthState
          4. 注入到 PipelineContext.metadata
          5. 导出 AuthState 文件 (供下次复用)

        Args:
            url: 目标 URL。
            ctx: PipelineContext 实例。
            api_key: API Key (可选, 用于 API 平台认证)。
            target_profile: Target Profile YAML 路径 (可选, 用于浏览器认证)。
            stream: 流式模式覆盖 (None=自动检测, True=强制流式, False=强制非流式)。

        Returns:
            AuthState 实例 (包含认证数据)。
        """
        logger.info(f"UnifiedAuthOrchestrator: processing URL: {url}")

        # Step 0: 尝试复用已有认证状态
        if try_reuse_auth_state(ctx):
            auth_state = ctx.metadata.get("_auth_state")
            if auth_state is None:
                # try_reuse_auth_state 注入了 metadata, 构建 AuthState
                auth_state = AuthState(
                    auth_type=ctx.metadata.get("auth_type", "none"),
                    target_url=url,
                    headers=ctx.metadata.get("auth_headers", {}),
                    cookies=ctx.metadata.get("auth_cookies", []),
                    tokens=ctx.metadata.get("auth_tokens", {}),
                    source="reused",
                )
            logger.info(f"UnifiedAuthOrchestrator: auth state reused (type={auth_state.auth_type})")
            ctx.metadata["_auth_state"] = auth_state
            return auth_state

        # Step 1: 判别目标类型
        classification = await self._classify_target(url, stream=stream)
        target_type = classification.target_type
        recommended_mode = classification.recommended_mode

        logger.info(
            f"UnifiedAuthOrchestrator: classified as {target_type} "
            f"(mode={recommended_mode}, reason={classification.detection_reason})"
        )

        # Step 2: 路由到对应认证流程
        auth_state: AuthState | None = None

        try:
            if target_type == "llm_web_app" and recommended_mode == "browser":
                auth_state = await self._browser_auth_flow(
                    url=url,
                    ctx=ctx,
                    target_profile=target_profile,
                )
            elif target_type == "llm_api_platform" or recommended_mode == "api":
                auth_state = await self._api_auth_flow(
                    url=url,
                    api_key=api_key,
                    ctx=ctx,
                )
            else:
                # unknown: 尝试 API 认证 (更安全)
                auth_state = await self._api_auth_flow(
                    url=url,
                    api_key=api_key,
                    ctx=ctx,
                )
        except Exception as e:
            # P6: 认证失败容错 — 降级为无认证模式
            logger.warning(
                f"UnifiedAuthOrchestrator: authentication failed, "
                f"degrading to no-auth mode: {e}"
            )
            auth_state = AuthState(
                auth_type="none",
                target_url=url,
                source="pyrit_degraded",
            )

        # Step 3: 注入到 PipelineContext
        inject_auth_state_to_context(ctx, auth_state)
        ctx.metadata["_auth_state"] = auth_state

        # Step 4: 导出 AuthState 文件 (供下次复用)
        try:
            export_auth_state(auth_state)
        except Exception as e:
            logger.warning(f"UnifiedAuthOrchestrator: failed to export auth state: {e}")

        # Step 5: 清理浏览器会话 (如有)
        if self._browser_session is not None:
            with contextlib.suppress(Exception):
                await self._browser_session.close()
            self._browser_session = None

        logger.info(
            f"UnifiedAuthOrchestrator: authentication completed "
            f"(type={auth_state.auth_type}, source={auth_state.source}, "
            f"valid={auth_state.is_valid()})"
        )
        return auth_state

    async def _classify_target(self, url: str) -> Any:
        """判别目标类型。

        Args:
            url: 目标 URL。

        Returns:
            TargetClassification 判别结果。
        """
        from pipeline.integrations.target_classifier import TargetClassifier

        classifier = TargetClassifier()
        return await classifier.classify(url)

    async def _browser_auth_flow(
        self,
        *,
        url: str,
        ctx: PipelineContext,
        target_profile: str = "",
    ) -> AuthState:
        """浏览器认证流程 (Web URL 类型)。

        流程:
          1. 创建 BrowserSession, 启动浏览器
          2. 加载 TargetProfile (YAML 或动态生成)
          3. 执行 AuthStrategy (auto/same_domain/cross_domain/none)
          4. MFADetector 检测二次认证
          5. HumanAssistedAuth 等待人工完成 MFA
          6. AuthDataExtractor 从 BrowserContext 提取认证数据

        Args:
            url: 目标 URL。
            ctx: PipelineContext。
            target_profile: Target Profile YAML 路径 (可选)。

        Returns:
            AuthState 实例。
        """
        from web_redteam.auth.auth_strategy import AuthStrategyFactory
        from web_redteam.auth.browser_session import BrowserSession
        from web_redteam.targets.dynamic_profile import create_profile_from_url
        from web_redteam.targets.target_profile import TargetProfile

        logger.info("UnifiedAuthOrchestrator: starting browser auth flow")

        # 1. 加载 TargetProfile
        if target_profile and Path(target_profile).exists():
            profile = TargetProfile.from_yaml_file(target_profile)
        else:
            args = ctx.args
            profile = create_profile_from_url(
                target_url=url,
                attack_type=getattr(args, "attack_type", "prompt_sending"),
                objective=getattr(args, "objective", ""),
                max_turns=getattr(args, "max_turns", 10),
            )

        # 2. 启动浏览器
        session = BrowserSession()
        self._browser_session = session
        page = await session.launch_with_debug_port(
            port=self._cdp_port,
            headless=self._headless,
        )

        # 3. 尝试恢复已有认证状态
        storage_state = getattr(ctx.args, "storage_state", None)
        if storage_state and Path(storage_state).exists():
            try:
                page = await session.restore_storage_state(storage_state)
                # 验证认证是否有效
                configs = profile.get_detection_configs()
                if configs:
                    from web_redteam.auth.auth_detector import AuthDetectorFactory

                    detector = AuthDetectorFactory.from_configs(configs, timeout_seconds=10)
                    if await detector.check_immediate(page):
                        logger.info("UnifiedAuthOrchestrator: storage state valid, skipping auth")
                        auth_state = await AuthDataExtractor.extract_from_browser_context(
                            context=page.context,
                            target_url=url,
                            auth_type=profile.auth.type,
                            login_url=profile.auth.login_url,
                        )
                        return auth_state
            except Exception as e:
                logger.warning(f"UnifiedAuthOrchestrator: storage state restore failed: {e}")

        # 4. 执行认证策略
        strategy = AuthStrategyFactory.create(profile.auth.type)
        page = await strategy.execute(page, profile)

        # 5. 保存 storage_state (供下次复用)
        if storage_state and profile.auth.type in ("same_domain", "cross_domain"):
            try:
                await session.save_storage_state(page.context, storage_state)
                logger.info(f"UnifiedAuthOrchestrator: storage state saved to {storage_state}")
            except Exception as e:
                logger.warning(f"UnifiedAuthOrchestrator: failed to save storage state: {e}")

        # 6. 提取认证数据
        auth_state = await AuthDataExtractor.extract_from_browser_context(
            context=page.context,
            target_url=url,
            auth_type=profile.auth.type,
            login_url=profile.auth.login_url,
        )

        return auth_state

    async def _api_auth_flow(
        self,
        *,
        url: str,
        api_key: str,
        ctx: PipelineContext,
    ) -> AuthState:
        """API 认证流程 (API 平台类型)。

        流程:
          1. APIAuthenticator.from_url() 自动判别认证方式
          2. 生成 auth_headers / auth_cookies
          3. 构建 AuthState

        Args:
            url: 目标 URL。
            api_key: API Key (可选)。
            ctx: PipelineContext。

        Returns:
            AuthState 实例。
        """
        logger.info("UnifiedAuthOrchestrator: starting API auth flow")

        # 从环境变量获取 API_KEY (如果未显式传入)
        if not api_key:
            from web_redteam.auth.credential_store import CredentialStore

            api_key = CredentialStore.get_credential("API_KEY", "")

        authenticator = APIAuthenticator.from_url(url, api_key)
        headers = authenticator.get_headers()
        cookies = authenticator.get_cookies()

        auth_state = AuthState(
            auth_type=authenticator.config.auth_type,
            target_url=url,
            headers=headers,
            cookies=[{"name": k, "value": v} for k, v in cookies.items()] if cookies else [],
            source="pyrit_api",
        )

        logger.info(
            f"UnifiedAuthOrchestrator: API auth completed "
            f"(type={auth_state.auth_type}, headers={len(headers)}, cookies={len(cookies)})"
        )
        return auth_state
