# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证策略选择器。.

根据 TargetProfile.auth.type 选择认证策略:
  same_domain  → SameDomainAuthStrategy
  cross_domain → CrossDomainAuthStrategy

两种策略共享 HumanAssistedAuth 的核心流程,
区别在于跨域策略需要追踪重定向链和处理跨域 Cookie/Token。

G1 修复:
  AutoAuthStrategy._patch_profile() 将 profile.auth.type 更新为
  探测到的实际类型 (same_domain/cross_domain), 使 stage_auth.py
  的 storage_state 保存/恢复逻辑对 auto 模式生效。

G3 修复:
  CrossDomainAuthStrategy 使用 HumanAssistedAuth 的公开方法
  auto_fill() 和 print_human_instructions(), 不再调用私有方法。

G4 修复:
  CrossDomainAuthStrategy 新增 _wait_for_url_stable() 方法,
  在 auto_fill 前等待页面 URL 稳定 (域名跳转完成),
  避免在错误页面上填充凭据。

G5 修复:
  CrossDomainAuthStrategy 读取 redirect_chain 配置,
  使用其中各节点的 human_steps 指导人工操作提示,
  而非仅依赖全局 human_assisted_steps。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from web_redteam.auth.auth_detector import AuthDetector, AuthDetectorFactory
from web_redteam.auth.auth_probe import AuthProbe, ProbeResult
from web_redteam.auth.human_assisted_auth import HumanAssistedAuth
from web_redteam.auth.mfa_detector import MFADetectionResult, MFADetector

if TYPE_CHECKING:
    from playwright.async_api import Page

    from web_redteam.targets.target_profile import TargetProfile

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

    async def _detect_mfa(self, page: Page) -> MFADetectionResult:
        """检测页面是否需要二次认证 (MFA)."""
        detector = MFADetector()
        result = await detector.detect(page)
        if result.has_mfa:
            logger.info(f"  [MFA] {result.detection_reason}")
            logger.info(f"MFA detected: {result.mfa_types}")
        return result


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

    MFA 增强:
      在 auto_fill 后、等待认证完成前, 自动检测二次认证 (OTP/QR/CAPTCHA/滑窗/SMS)。
      如检测到 MFA, 打印人工辅助指令并延长等待超时。
    """

    async def execute(self, page: Page, profile: TargetProfile) -> Page:
        """Execute same-domain authentication."""
        logger.info("SameDomainAuthStrategy: starting same-domain authentication")
        detector = self._create_detector(profile)
        # G10: 导航前附加网络监听器 (与 CrossDomainAuthStrategy 一致)
        if hasattr(detector, "attach_to_page"):
            await detector.attach_to_page(page)
        return await self._human_auth.authenticate(page, profile, detector)


class CrossDomainAuthStrategy(AuthStrategy):
    """跨域认证策略 (SSO / OAuth / CAS)。.

    认证过程涉及多个域名跳转:
      app.com → idp.com (登录) → app.com (回调)

    G4 修复:
      在 auto_fill 前等待页面 URL 稳定 (域名跳转完成)。

    G5 修复:
      读取 redirect_chain 配置, 使用各节点的 human_steps
      指导人工操作提示。

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

        # G2: 附加网络监听器 (导航前)
        if hasattr(detector, "attach_to_page"):
            await detector.attach_to_page(page)

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

            # G4: 等待 URL 稳定后再 auto_fill, 避免在错误页面上填充凭据
            await self._wait_for_url_stable(page)

            # G3: 使用公开方法 auto_fill
            if auth.auto_fill:
                await self._human_auth.auto_fill(page, auth.auto_fill)

            # MFA 检测: 在 auto_fill 后检测二次认证
            mfa_result = await self._detect_mfa(page)
            if mfa_result.has_mfa:
                # 更新检测器超时为 MFA 超时
                mfa_timeout = getattr(self._human_auth, "mfa_timeout", 300)
                detector._timeout = mfa_timeout  # type: ignore[attr-defined]

            # G5: 优先使用 redirect_chain 中各节点的 human_steps
            # G3: 使用公开方法 print_human_instructions
            human_steps = self._collect_human_steps(profile)
            # 合并 MFA 人工指令
            if mfa_result.has_mfa:
                human_steps = list(human_steps) + mfa_result.human_instructions
            if human_steps:
                self._human_auth.print_human_instructions(human_steps)

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

    async def _wait_for_url_stable(
        self,
        page: Page,
        max_wait_seconds: float = 10.0,
        stable_threshold: float = 2.0,
    ) -> None:
        """等待页面 URL 不再变化 (G4 修复).

        在跨域认证中, 导航到 login_url 后可能触发 JS 重定向到 IdP。
        如果在重定向完成前执行 auto_fill, 凭据可能被填充到错误页面。

        此方法轮询 page.url, 当 URL 连续 stable_threshold 秒不变时认为稳定。

        Args:
            page: Playwright Page 对象。
            max_wait_seconds: 最大等待时间 (秒)。
            stable_threshold: URL 不变化即认为稳定的阈值 (秒)。
        """
        logger.debug(
            f"CrossDomainAuthStrategy: waiting for URL to stabilize "
            f"(max={max_wait_seconds}s, threshold={stable_threshold}s)"
        )
        last_url = page.url
        stable_time = 0.0
        total_time = 0.0
        poll_interval = 0.5

        while total_time < max_wait_seconds:
            await asyncio.sleep(poll_interval)
            total_time += poll_interval
            current_url = page.url
            if current_url == last_url:
                stable_time += poll_interval
                if stable_time >= stable_threshold:
                    logger.debug(f"CrossDomainAuthStrategy: URL stable at '{current_url}'")
                    return
            else:
                logger.debug(f"CrossDomainAuthStrategy: URL changed '{last_url}' → '{current_url}'")
                last_url = current_url
                stable_time = 0.0

        logger.warning(
            f"CrossDomainAuthStrategy: URL did not stabilize within {max_wait_seconds}s, "
            f"current URL: {page.url}"
        )

    def _collect_human_steps(self, profile: TargetProfile) -> list[str]:
        """收集需要人工完成的步骤 (G5 修复).

        优先使用 redirect_chain 中各节点的 human_steps,
        如果 redirect_chain 为空则回退到全局 human_assisted_steps。

        Args:
            profile: 目标配置 Profile。

        Returns:
            需要人工完成的步骤列表。
        """
        redirect_chain = profile.auth.cross_domain.redirect_chain
        if redirect_chain:
            # G5: 从 redirect_chain 各节点收集 human_steps
            chain_steps: list[str] = []
            for entry in redirect_chain:
                chain_steps.extend(entry.human_steps)
            if chain_steps:
                logger.info(
                    f"CrossDomainAuthStrategy: using human_steps from redirect_chain "
                    f"({len(chain_steps)} steps)"
                )
                return chain_steps

        # 回退到全局 human_assisted_steps
        if profile.auth.human_assisted_steps:
            logger.info("CrossDomainAuthStrategy: using global human_assisted_steps")
            return profile.auth.human_assisted_steps

        return []


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

    G1 修复:
      _patch_profile() 将 profile.auth.type 更新为探测到的实际类型,
      使 stage_auth.py 的 storage_state 保存/恢复逻辑对 auto 模式生效。

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
        logger.info(f"  探测结果: {result.auth_type}")
        logger.info(f"  {result.detection_reason}")

        # Step 2: 根据探测结果动态补全 Profile (如需要) — G1: 更新 auth.type
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
        """根据探测结果动态补全 Profile 中缺失的配置 (G1 修复).

        G1 修复:
          将 profile.auth.type 更新为探测到的实际类型,
          使 stage_auth.py 的 storage_state 保存/恢复逻辑对 auto 模式生效。

        当 auth.type=auto 时, Profile 可能未配置 login_url,
        AuthProbe 探测到了实际的 login_url, 在此补全。
        """
        if probe_result.auth_type == "none":
            # 无需认证, 不需要补全
            return

        # G1: 更新 auth.type 为探测到的实际类型
        old_type = profile.auth.type
        profile.auth.type = probe_result.auth_type
        if old_type != probe_result.auth_type:
            logger.info(f"AutoAuthStrategy: patched profile.auth.type: '{old_type}' → '{probe_result.auth_type}'")

        # 补全 login_url (如果探测到了且 Profile 中未配置)
        if probe_result.login_url_detected and not profile.auth.login_url:
            profile.auth.login_url = probe_result.login_url_detected
            logger.info(f"AutoAuthStrategy: patched profile.auth.login_url = {probe_result.login_url_detected}")

        # 如果探测到 same_domain 但 Profile 未配置检测策略,
        # 动态生成默认检测策略
        if probe_result.auth_type == "same_domain" and not profile.auth.same_domain.detection:
            from web_redteam.auth.models import DetectionConfig

            target_domain = probe_result.target_domain
            # 从 target_url 提取路径部分作为 pattern
            target_path = urlparse(profile.auth.target_url).path
            if target_path and target_path != "/":
                pattern = re.escape(target_domain) + re.escape(target_path)
            else:
                pattern = re.escape(target_domain)

            profile.auth.same_domain.detection = [
                DetectionConfig(strategy="url_pattern", pattern=pattern),
            ]
            logger.info(f"AutoAuthStrategy: generated default detection strategy (url_pattern: {pattern})")

        # 如果探测到 cross_domain 但 Profile 未配置检测策略,
        # 动态生成默认检测策略
        if probe_result.auth_type == "cross_domain" and not profile.auth.cross_domain.detection:
            from web_redteam.auth.models import DetectionConfig

            target_domain = probe_result.target_domain
            target_path = urlparse(profile.auth.target_url).path
            if target_path and target_path != "/":
                pattern = re.escape(target_domain) + re.escape(target_path)
            else:
                pattern = re.escape(target_domain)

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
