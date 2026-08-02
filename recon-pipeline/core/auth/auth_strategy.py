# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证策略选择器。.

根据 TargetProfile.auth.type 选择认证策略:
  same_domain  → SameDomainAuthStrategy
  cross_domain → CrossDomainAuthStrategy

两种策略共享 HumanAssistedAuth 的核心流程,
区别在于跨域策略需要追踪重定向链和处理跨域 Cookie/Token。
"""

from __future__ import annotations

import contextlib
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from core.auth.auth_detector import AuthDetector, AuthDetectorFactory
from core.auth.auth_probe import AuthProbe, ProbeResult
from core.auth.human_assisted_auth import HumanAssistedAuth
# TargetProfile moved to TYPE_CHECKING (depends on PyRIT YamlLoadable)

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)


class AuthStrategy(ABC):
    """认证策略抽象基类。."""

    def __init__(self) -> None:
        """Initialize AuthStrategy."""
        self._human_auth = HumanAssistedAuth()

    @abstractmethod
    async def execute(self, page: Page, profile: TargetProfile) -> Page:
        """执行认证, 返回已认证的 Page。.

        Args:
            page: Playwright Page 对象。
            profile: 目标配置 Profile。

        Returns:
            已认证的 Page 对象。
        """
        ...

    def _create_detector(self, profile: TargetProfile) -> AuthDetector:
        """从 Profile 的检测配置创建 AuthDetector。."""
        configs = profile.get_detection_configs()
        if not configs:
            raise ValueError(f"No detection strategies configured for auth type '{profile.auth.type}'")
        return AuthDetectorFactory.from_configs(configs)


class NoAuthStrategy(AuthStrategy):
    """无需认证策略。.

    目标页面无需认证即可直接访问。
    直接导航到 target_url, 不执行任何认证操作。
    """

    async def execute(self, page: Page, profile: TargetProfile) -> Page:
        """Execute no-auth strategy: navigate to target."""
        logger.info("NoAuthStrategy: no authentication needed, navigating to target URL")
        await page.goto(profile.auth.target_url, wait_until="domcontentloaded")
        return page


class SameDomainAuthStrategy(AuthStrategy):
    """同域认证策略。.

    认证过程在一个域名内完成:
      example.com/login → example.com/chat

    检测: page.url 匹配目标 URL 正则 + 目标 DOM 元素出现
    """

    async def execute(self, page: Page, profile: TargetProfile) -> Page:
        """Execute same-domain authentication."""
        logger.info("SameDomainAuthStrategy: starting same-domain authentication")
        detector = self._create_detector(profile)
        return await self._human_auth.authenticate(page, profile, detector)


class CrossDomainAuthStrategy(AuthStrategy):
    """跨域认证策略 (SSO / OAuth / CAS)。.

    认证过程涉及多个域名跳转:
      app.com → idp.com (登录) → app.com (回调)

    增强:
      1. 追踪重定向链: page.on("framenavigated") 记录域名变化
      2. 在 IdP 域名上执行 auto_fill (如果有配置)
      3. 在 IdP 域名上等待人工操作 (验证码/扫码)
      4. 检测回到应用域名 + 目标元素出现
      5. 处理 OAuth 回调 (可能有 code/token 在 URL 中)
    """

    def __init__(self) -> None:
        """Initialize CrossDomainAuthStrategy."""
        super().__init__()
        self._domain_transitions: list[str] = []

    async def execute(self, page: Page, profile: TargetProfile) -> Page:
        """Execute cross-domain authentication."""
        logger.info("CrossDomainAuthStrategy: starting cross-domain authentication")

        auth = profile.auth
        detector = self._create_detector(profile)

        # 注册域名跳转追踪
        self._domain_transitions = []

        def on_navigated(frame: Any) -> None:
            if frame == page.main_frame:
                from urllib.parse import urlparse

                domain = urlparse(frame.url).netloc
                if domain and (not self._domain_transitions or self._domain_transitions[-1] != domain):
                    self._domain_transitions.append(domain)
                    logger.info(
                        f"CrossDomainAuthStrategy: domain transition → {domain} "
                        f"(chain: {' → '.join(self._domain_transitions)})"
                    )

        page.on("framenavigated", on_navigated)

        try:
            # 导航到登录页 (可能重定向到 IdP)
            logger.info(f"CrossDomainAuthStrategy: navigating to login URL: {auth.login_url}")
            await page.goto(auth.login_url, wait_until="domcontentloaded")

            # 等待重定向稳定 (可能跳转到 IdP)
            await page.wait_for_load_state("domcontentloaded")

            # 在 IdP 域名上自动填充
            if auth.auto_fill:
                await self._human_auth._auto_fill(page, auth.auto_fill)

            # 提示人工
            if auth.human_assisted_steps:
                self._human_auth._print_human_instructions(auth.human_assisted_steps)

            # 检测认证完成 (检测回到应用域名 + DOM 元素)
            is_complete = await detector.wait_for_completion(page)
            if not is_complete:
                raise TimeoutError(
                    f"Cross-domain authentication did not complete within timeout. "
                    f"Domain transitions: {' → '.join(self._domain_transitions)}"
                )

            logger.info("CrossDomainAuthStrategy: authentication completed")
            logger.info(f"CrossDomainAuthStrategy: final domain transitions: {' → '.join(self._domain_transitions)}")

            # 跳转到目标页面
            logger.info(f"CrossDomainAuthStrategy: navigating to target URL: {auth.target_url}")
            await page.goto(auth.target_url, wait_until="domcontentloaded")

            return page
        finally:
            with contextlib.suppress(Exception):
                page.remove_listener("framenavigated", on_navigated)


class AutoAuthStrategy(AuthStrategy):
    """自动认证探测策略。.

    当 auth.type = "auto" 时使用。流程:
      1. 用 AuthProbe 探测 target_url 的认证拓扑
      2. 根据探测结果自动选择策略:
         - none          → NoAuthStrategy (直接访问)
         - same_domain   → SameDomainAuthStrategy
         - cross_domain  → CrossDomainAuthStrategy
      3. 如果探测到需要认证但 Profile 中未配置 login_url,
         使用探测到的 login_url 动态补全 Profile

    设计原则:
      探测 → 委托: AutoAuthStrategy 自身不执行认证,
      而是将认证工作委托给探测到的具体策略。
    """

    def __init__(self) -> None:
        """Initialize AutoAuthStrategy."""
        super().__init__()
        self._probe = AuthProbe()

    async def execute(self, page: Page, profile: TargetProfile) -> Page:
        """Execute auto auth type detection."""
        logger.info("AutoAuthStrategy: starting automatic auth type detection")

        # Step 1: 探测认证拓扑
        result: ProbeResult = await self._probe.probe(page, profile.auth.target_url)
        print(f"  探测结果: {result.auth_type}")
        print(f"  {result.detection_reason}")

        # Step 2: 根据探测结果动态补全 Profile (如需要)
        self._patch_profile(profile, result)

        # Step 3: 委托给具体策略
        if result.auth_type == "none":
            logger.info("AutoAuthStrategy: delegating to NoAuthStrategy")
            # 已经在探测时导航到 target_url, 直接返回 page
            return page
        elif result.auth_type == "same_domain":
            logger.info("AutoAuthStrategy: delegating to SameDomainAuthStrategy")
            strategy = SameDomainAuthStrategy()
            return await strategy.execute(page, profile)
        elif result.auth_type == "cross_domain":
            logger.info("AutoAuthStrategy: delegating to CrossDomainAuthStrategy")
            strategy = CrossDomainAuthStrategy()
            return await strategy.execute(page, profile)
        else:
            raise ValueError(f"AuthProbe returned unknown auth_type: {result.auth_type}")

    def _patch_profile(self, profile: TargetProfile, probe_result: ProbeResult) -> None:
        """根据探测结果动态补全 Profile 中缺失的配置。.

        当 auth.type=auto 时, Profile 可能未配置 login_url,
        AuthProbe 探测到了实际的 login_url, 在此补全。
        """
        if probe_result.auth_type == "none":
            # 无需认证, 不需要补全
            return

        # 补全 login_url (如果探测到了且 Profile 中未配置)
        if probe_result.login_url_detected and not profile.auth.login_url:
            profile.auth.login_url = probe_result.login_url_detected
            logger.info(f"AutoAuthStrategy: patched profile.auth.login_url = {probe_result.login_url_detected}")

        # 如果探测到 same_domain 但 Profile 未配置检测策略,
        # 动态生成默认检测策略
        if probe_result.auth_type == "same_domain" and not profile.auth.same_domain.detection:
            # 默认: 检测 target_url 出现 (URL pattern) + 登录表单消失
            import re as _re

            from core.auth.models import DetectionConfig

            target_domain = probe_result.target_domain
            # 从 target_url 提取路径部分作为 pattern
            from urllib.parse import urlparse

            target_path = urlparse(profile.auth.target_url).path
            if target_path and target_path != "/":
                pattern = _re.escape(target_domain) + _re.escape(target_path)
            else:
                pattern = _re.escape(target_domain)

            profile.auth.same_domain.detection = [
                DetectionConfig(strategy="url_pattern", pattern=pattern),
            ]
            logger.info(f"AutoAuthStrategy: generated default detection strategy (url_pattern: {pattern})")

        # 如果探测到 cross_domain 但 Profile 未配置检测策略,
        # 动态生成默认检测策略
        if probe_result.auth_type == "cross_domain" and not profile.auth.cross_domain.detection:
            import re as _re

            from core.auth.models import DetectionConfig

            target_domain = probe_result.target_domain
            from urllib.parse import urlparse

            target_path = urlparse(profile.auth.target_url).path
            if target_path and target_path != "/":
                pattern = _re.escape(target_domain) + _re.escape(target_path)
            else:
                pattern = _re.escape(target_domain)

            profile.auth.cross_domain.detection = [
                DetectionConfig(strategy="url_pattern", pattern=pattern),
            ]
            logger.info(f"AutoAuthStrategy: generated default cross-domain detection strategy (url_pattern: {pattern})")


class AuthStrategyFactory:
    """认证策略工厂: 根据 auth.type 创建对应策略。."""

    @staticmethod
    def create(auth_type: str) -> AuthStrategy:
        """根据 auth.type 创建认证策略。.

        Args:
            auth_type: "auto", "none", "same_domain" 或 "cross_domain"。

        Returns:
            对应的 AuthStrategy 实例。

        Raises:
            ValueError: 如果 auth_type 不支持。
        """
        if auth_type == "auto":
            return AutoAuthStrategy()
        elif auth_type == "none":
            return NoAuthStrategy()
        elif auth_type == "same_domain":
            return SameDomainAuthStrategy()
        elif auth_type == "cross_domain":
            return CrossDomainAuthStrategy()
        else:
            raise ValueError(
                f"Unsupported auth type: '{auth_type}'. Supported types: 'auto', 'none', 'same_domain', 'cross_domain'"
            )

