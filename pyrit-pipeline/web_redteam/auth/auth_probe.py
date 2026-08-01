# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AuthProbe: 自动认证探测器。.

当 auth.type = "auto" 时, AuthProbe 会:
  1. 导航到 target_url
  2. 观察页面行为 (URL 变化 / DOM 特征 / HTTP 状态)
  3. 自动判断认证拓扑:
     - none:         页面直接加载成功, 无重定向到登录页 → 无需认证
     - same_domain:  页面重定向到同域名下的登录页 → 同域认证
     - cross_domain: 页面重定向到不同域名的登录页 (SSO/IdP) → 跨域认证

判断依据 (按优先级):
  a) URL 域名变化: target_url 域名 ≠ 最终页面域名 → cross_domain
  b) URL 路径变化但域名不变: 同域名下出现 login/auth/signin → same_domain
  c) URL 无变化且页面正常加载 → none

  同时检查 DOM 特征:
  - 存在 <input type="password"> 或登录表单 → 需要认证
  - 存在目标交互元素 (如 .chat-container) → 无需认证

对齐 PyRIT 原生模式:
  - CopilotAuthenticator 用 page.url 和 page.wait_for_selector 检测页面状态
  - PlaywrightCopilotTarget 检查 page.url 判断是否在正确页面
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)

# ── 登录页 URL 路径关键词 (用于判断重定向后是否在登录页) ──
LOGIN_PATH_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "auth",
    "sso",
    "oauth",
    "account/login",
    "user/login",
    "cas/",
    "idp",
    "authorize",
    "callback",
]

# ── 登录表单 DOM 选择器 (用于判断页面是否为登录页) ──
LOGIN_FORM_SELECTORS = [
    'input[type="password"]',
    'form[action*="login"]',
    'form[action*="auth"]',
    'form[action*="signin"]',
    '[class*="login-form"]',
    '[id*="login-form"]',
    'button[type="submit"][formaction*="login"]',
]


@dataclass
class ProbeResult:
    """AuthProbe 探测结果。.

    Attributes:
        auth_type: 探测到的认证类型 ("none" | "same_domain" | "cross_domain")
        target_domain: target_url 的域名
        final_domain: 探测后页面最终停留的域名
        final_url: 探测后页面最终 URL
        redirected: 是否发生了重定向
        login_url_detected: 检测到的登录页 URL (如需认证)
        domain_transitions: 域名跳转链 (跨域场景)
        detection_reason: 判断依据的人类可读描述
    """

    auth_type: str = "none"
    target_domain: str = ""
    final_domain: str = ""
    final_url: str = ""
    redirected: bool = False
    login_url_detected: str = ""
    domain_transitions: list[str] = field(default_factory=list)
    detection_reason: str = ""

    def __str__(self) -> str:
        lines = [
            "AuthProbe Result:",
            f"  auth_type:        {self.auth_type}",
            f"  target_domain:    {self.target_domain}",
            f"  final_domain:     {self.final_domain}",
            f"  redirected:       {self.redirected}",
            f"  login_url:        {self.login_url_detected or '(none)'}",
            f"  domain_transitions: {' → '.join(self.domain_transitions) or '(none)'}",
            f"  reason:           {self.detection_reason}",
        ]
        return "\n".join(lines)


class AuthProbe:
    """自动认证探测器。.

    通过导航到 target_url 并观察页面行为, 自动判断认证拓扑。

    用法:
        probe = AuthProbe()
        result = await probe.probe(page, target_url)
        # result.auth_type → "none" | "same_domain" | "cross_domain"
    """

    def __init__(
        self,
        navigation_timeout_ms: int = 15000,
        settle_wait_ms: int = 2000,
    ) -> None:
        """Args:
        navigation_timeout_ms: 导航超时 (毫秒)。
        settle_wait_ms: 导航后等待页面稳定的时间 (毫秒), 用于捕获重定向链。.
        """
        self._nav_timeout = navigation_timeout_ms
        self._settle_wait = settle_wait_ms

    async def probe(self, page: Page, target_url: str) -> ProbeResult:
        """探测 target_url 的认证拓扑。.

        流程:
          1. 记录 target_url 的域名
          2. 导航到 target_url (不抛异常, 捕获重定向)
          3. 等待页面稳定 (settle)
          4. 分析最终 URL 和 DOM 特征
          5. 返回 ProbeResult

        Args:
            page: Playwright Page 对象。
            target_url: 目标页面 URL。

        Returns:
            ProbeResult 探测结果。
        """
        target_domain = _extract_domain(target_url)
        domain_transitions: list[str] = [target_domain]

        # 注册 framenavigated 监听器, 追踪域名跳转
        def on_navigated(frame: object) -> None:
            if frame == page.main_frame:
                domain = _extract_domain(page.url)
                if domain and (not domain_transitions or domain_transitions[-1] != domain):
                    domain_transitions.append(domain)
                    logger.debug(f"AuthProbe: domain transition → {domain}")

        page.on("framenavigated", on_navigated)

        try:
            # 导航到 target_url
            logger.info(f"AuthProbe: probing target URL: {target_url}")
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=self._nav_timeout)
            except Exception as e:
                logger.debug(f"AuthProbe: navigation raised (may be redirect): {e}")
                # 导航异常可能是重定向导致, 继续分析当前 URL

            # 等待页面稳定 (可能还有 JS 重定向)
            import asyncio

            await asyncio.sleep(self._settle_wait / 1000)

            final_url = page.url
            final_domain = _extract_domain(final_url)
            redirected = final_url != target_url and final_domain != target_domain

            logger.info(f"AuthProbe: final URL: {final_url} (domain: {final_domain})")
            logger.info(f"AuthProbe: domain transitions: {' → '.join(domain_transitions)}")

            # 分析并判断认证类型
            return await self._analyze(
                target_url=target_url,
                target_domain=target_domain,
                final_url=final_url,
                final_domain=final_domain,
                redirected=redirected,
                domain_transitions=domain_transitions,
                page=page,
            )
        finally:
            with contextlib.suppress(Exception):
                page.remove_listener("framenavigated", on_navigated)

    async def _analyze(
        self,
        target_url: str,
        target_domain: str,
        final_url: str,
        final_domain: str,
        redirected: bool,
        domain_transitions: list[str],
        page: Page,
    ) -> ProbeResult:
        """分析探测结果, 判断认证类型。."""
        result = ProbeResult(
            target_domain=target_domain,
            final_domain=final_domain,
            final_url=final_url,
            redirected=redirected,
            domain_transitions=domain_transitions,
        )

        # ── 判断 1: 跨域重定向 ──
        # 最终域名 ≠ 目标域名 → 跨域 (SSO/IdP)
        if redirected and final_domain != target_domain:
            result.auth_type = "cross_domain"
            result.login_url_detected = final_url
            result.detection_reason = (
                f"Redirected from '{target_domain}' to different domain '{final_domain}' "
                f"(likely SSO/IdP). Transitions: {' → '.join(domain_transitions)}"
            )
            logger.info("AuthProbe: detected cross_domain auth")
            return result

        # ── 判断 2: 同域重定向到登录页 ──
        # 同域名, 但 URL 路径包含登录关键词
        if (redirected or _is_login_path(final_url)) and (
            _is_login_path(final_url) or await self._has_login_form(page)
        ):
            result.auth_type = "same_domain"
            result.login_url_detected = final_url
            result.detection_reason = (
                f"Same-domain redirect to login path: {final_url} (domain unchanged: {target_domain})"
            )
            logger.info("AuthProbe: detected same_domain auth")
            return result

        # ── 判断 3: 同域但页面有登录表单 (可能 URL 没变, 但页面内容是登录) ──
        if await self._has_login_form(page):
            result.auth_type = "same_domain"
            result.login_url_detected = final_url
            result.detection_reason = f"Login form detected on page (URL may be unchanged): {final_url}"
            logger.info("AuthProbe: detected same_domain auth (login form on page)")
            return result

        # ── 判断 4: 无需认证 ──
        result.auth_type = "none"
        result.detection_reason = "No redirect and no login form detected. Target URL accessible directly."
        logger.info("AuthProbe: detected no auth needed")
        return result

    async def _has_login_form(self, page: Page) -> bool:
        """检查页面是否存在登录表单。."""
        for selector in LOGIN_FORM_SELECTORS:
            try:
                element = await page.query_selector(selector)
                if element:
                    logger.debug(f"AuthProbe: login form element found: {selector}")
                    return True
            except Exception:
                continue
        return False


def _extract_domain(url: str) -> str:
    """从 URL 中提取域名 (netloc)。."""
    if not url:
        return ""
    parsed = urlparse(url)
    return parsed.netloc or ""


def _is_login_path(url: str) -> bool:
    """检查 URL 路径是否包含登录关键词。."""
    if not url:
        return False
    path = urlparse(url).path.lower()
    # 也检查完整的 URL (query 参数可能包含 redirect_uri 等)
    full = url.lower()
    return any(keyword in path or keyword in full for keyword in LOGIN_PATH_KEYWORDS)
