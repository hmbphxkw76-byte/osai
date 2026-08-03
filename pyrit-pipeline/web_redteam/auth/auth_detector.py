# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""多策略认证完成检测器。.

支持四种检测策略 (OR 逻辑, 任一满足即认为认证完成):
  1. URLPatternStrategy     — 检测 page.url 匹配正则 (同域 + 跨域)
  2. DOMElementStrategy     — 检测目标 DOM 元素出现
  3. CookiePresenceStrategy — 检测特定 Cookie 已设置
  4. NetworkTokenStrategy   — 拦截网络响应提取 Token (对齐 CopilotAuthenticator)

G2 修复:
  AuthDetector 新增 attach_to_page() 方法, 在导航前自动将
  NetworkTokenStrategy 的 response handler 附加到 Page,
  确保 Token 拦截策略能正常工作。

对齐 PyRIT 原生模式:
  - CopilotAuthenticator 用 page.on("response", handler) 拦截网络响应
  - PlaywrightCopilotTarget 用 page.wait_for_selector 等待元素
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from web_redteam.auth.models import DetectionConfig

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)


class AuthDetectionStrategy(ABC):
    """认证完成检测策略抽象基类。."""

    @abstractmethod
    async def is_auth_complete(self, page: Page) -> bool:
        """检测认证是否已完成。.

        Args:
            page: Playwright Page 对象。

        Returns:
            True 如果认证已完成, False 否则。
        """
        ...

    async def check_immediate(self, page: Page) -> bool:
        """立即检测一次 (不等待), 用于检查已有认证状态是否有效。.

        默认实现等同于 is_auth_complete, 子类可覆盖以提供更快的一次性检测。
        """
        return await self.is_auth_complete(page)


class URLPatternStrategy(AuthDetectionStrategy):
    """URL 模式匹配策略。.

    同域: 检测 page.url 是否匹配目标 URL 正则。
    跨域: 同样检测 page.url, 但结合重定向链追踪判断是否回到目标域名。
    """

    def __init__(self, pattern: str) -> None:
        """Initialize URLPatternStrategy."""
        self._pattern = re.compile(pattern)

    async def is_auth_complete(self, page: Page) -> bool:
        """Check if auth is complete by URL pattern."""
        current_url = page.url
        match = self._pattern.search(current_url)
        if match:
            logger.debug(f"URLPatternStrategy: URL '{current_url}' matches pattern '{self._pattern.pattern}'")
            return True
        return False


class DOMElementStrategy(AuthDetectionStrategy):
    """DOM 元素存在策略。.

    检测目标 DOM 元素是否出现 (如 .chat-container)。
    对齐 PlaywrightCopilotTarget 的 page.wait_for_selector 模式。
    """

    def __init__(self, selector: str, timeout_seconds: int = 300) -> None:
        """Initialize DOMElementStrategy."""
        self._selector = selector
        self._timeout_ms = timeout_seconds * 1000

    async def is_auth_complete(self, page: Page) -> bool:
        """Check if auth is complete by element presence."""
        try:
            element = await page.query_selector(self._selector)
            if element:
                logger.debug(f"DOMElementStrategy: element '{self._selector}' found")
                return True
        except Exception as e:
            logger.debug(f"DOMElementStrategy: error checking selector '{self._selector}': {e}")
        return False

    async def check_immediate(self, page: Page) -> bool:
        """Check immediately without waiting."""
        return await self.is_auth_complete(page)


class CookiePresenceStrategy(AuthDetectionStrategy):
    """Cookie 存在策略。.

    检测特定 Cookie 是否已设置。
    使用 Playwright 原生 API: page.context.cookies()。
    """

    def __init__(self, cookie_names: list[str], domain: str | None = None) -> None:
        """Initialize CookiePresenceStrategy."""
        self._cookie_names = set(cookie_names)
        self._domain = domain

    async def is_auth_complete(self, page: Page) -> bool:
        """Check if auth is complete by cookie presence."""
        try:
            cookies = await page.context.cookies()
            if self._domain:
                cookies = [c for c in cookies if self._domain in c.get("domain", "")]
            existing_names = {c["name"] for c in cookies}
            if self._cookie_names.issubset(existing_names):
                logger.debug(f"CookiePresenceStrategy: all cookies {self._cookie_names} found")
                return True
        except Exception as e:
            logger.debug(f"CookiePresenceStrategy: error checking cookies: {e}")
        return False


class NetworkTokenStrategy(AuthDetectionStrategy):
    """网络响应 Token 拦截策略。.

    对齐 CopilotAuthenticator 的 response_handler_async 模式:
    注册 page.on("response", handler) 拦截网络响应, 解析 JSON 提取 Token。

    适用于: API 认证场景 (如 OAuth Token 端点响应)。

    G2 修复:
      attach_to_page() 必须在导航前调用, 否则 Token 永远不会捕获。
      AuthDetector.attach_to_page() 会自动调用此方法。
    """

    def __init__(
        self,
        url_pattern: str = "/oauth2/v2.0/token",
        token_field: str = "access_token",
        token_keyword: str | None = None,
    ) -> None:
        """Initialize NetworkTokenStrategy."""
        self._url_pattern = url_pattern
        self._token_field = token_field
        self._token_keyword = token_keyword
        self._captured_token: str | None = None

    def _create_response_handler(self) -> Any:
        """创建网络响应处理器 (对齐 CopilotAuthenticator.response_handler_async)。."""

        async def handler(response: Any) -> None:
            if self._captured_token:
                return
            try:
                url = response.url
                if self._url_pattern in url:
                    text = await response.text()
                    data = json.loads(text)
                    if self._token_field in data:
                        token = data[self._token_field]
                        if self._token_keyword is None or self._token_keyword in text:
                            self._captured_token = token
                            logger.info(f"NetworkTokenStrategy: token captured from {url}")
            except Exception as e:
                logger.debug(f"NetworkTokenStrategy: error handling response: {e}")

        return handler

    async def is_auth_complete(self, page: Page) -> bool:
        """Check if auth is complete by captured token."""
        return self._captured_token is not None

    async def check_immediate(self, page: Page) -> bool:
        """Check immediately by captured token."""
        return self._captured_token is not None

    def attach_to_page(self, page: Page) -> None:
        """将响应处理器附加到 Page (在导航前调用)。."""
        page.on("response", self._create_response_handler())

    @property
    def captured_token(self) -> str | None:
        """Get the captured auth token."""
        return self._captured_token


class AuthDetector:
    """多策略认证完成检测器。.

    使用 OR 逻辑: 任一策略满足即认为认证完成。
    轮询检测, 直到任一策略满足或超时。

    G2 修复:
      新增 attach_to_page() 方法, 在导航前自动将需要页面级监听的
      策略 (如 NetworkTokenStrategy) 附加到 Page。

    用法:
        detector = AuthDetector(strategies=[...], timeout_seconds=300)
        await detector.attach_to_page(page)  # G2: 导航前附加监听器
        is_complete = await detector.wait_for_completion(page)
    """

    def __init__(
        self,
        strategies: list[AuthDetectionStrategy],
        poll_interval_seconds: float = 1.0,
        timeout_seconds: int = 300,
    ) -> None:
        """Initialize AuthDetector."""
        if not strategies:
            raise ValueError("AuthDetector requires at least one strategy")
        self._strategies = strategies
        self._poll_interval = poll_interval_seconds
        self._timeout = timeout_seconds

    async def attach_to_page(self, page: Page) -> None:
        """将需要页面级监听的策略附加到 Page (G2 修复).

        在导航前调用此方法, 确保 NetworkTokenStrategy 等
        需要注册事件监听器的策略能正常工作。

        Args:
            page: Playwright Page 对象。
        """
        for strategy in self._strategies:
            if hasattr(strategy, "attach_to_page"):
                strategy.attach_to_page(page)
                logger.debug(f"AuthDetector: attached {type(strategy).__name__} to page")

    async def wait_for_completion(self, page: Page) -> bool:
        """轮询检测, 直到任一策略满足或超时。.

        Args:
            page: Playwright Page 对象。

        Returns:
            True 如果认证完成, False 如果超时。
        """
        logger.info(f"AuthDetector: waiting for auth completion (timeout={self._timeout}s)")
        start = time.time()
        while time.time() - start < self._timeout:
            for strategy in self._strategies:
                try:
                    if await strategy.is_auth_complete(page):
                        elapsed = time.time() - start
                        logger.info(f"AuthDetector: auth completed after {elapsed:.1f}s")
                        return True
                except Exception as e:
                    logger.debug(f"AuthDetector: strategy {type(strategy).__name__} error: {e}")
            await asyncio.sleep(self._poll_interval)

        logger.warning(f"AuthDetector: timed out after {self._timeout}s")
        return False

    async def check_immediate(self, page: Page) -> bool:
        """立即检测一次 (不轮询), 用于检查已有认证状态。.

        Returns:
            True 如果任一策略立即满足, False 否则。
        """
        for strategy in self._strategies:
            try:
                if await strategy.check_immediate(page):
                    return True
            except Exception as e:
                logger.debug(f"AuthDetector: check_immediate strategy error: {e}")
        return False


class AuthDetectorFactory:
    """从 TargetProfile 的 DetectionConfig 列表创建 AuthDetector。."""

    @staticmethod
    def from_configs(
        configs: list[DetectionConfig],
        poll_interval_seconds: float = 1.0,
        timeout_seconds: int = 300,
    ) -> AuthDetector:
        """Create composite detector from config list."""
        strategies: list[AuthDetectionStrategy] = []
        for cfg in configs:
            strategy = AuthDetectorFactory._create_strategy(cfg)
            if strategy:
                strategies.append(strategy)
        if not strategies:
            raise ValueError("No valid detection strategies configured")
        return AuthDetector(
            strategies=strategies,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    @staticmethod
    def _create_strategy(cfg: DetectionConfig) -> AuthDetectionStrategy | None:
        if cfg.strategy == "url_pattern":
            if not cfg.pattern:
                logger.warning("url_pattern strategy missing 'pattern', skipping")
                return None
            return URLPatternStrategy(pattern=cfg.pattern)
        elif cfg.strategy == "dom_element":
            if not cfg.selector:
                logger.warning("dom_element strategy missing 'selector', skipping")
                return None
            return DOMElementStrategy(selector=cfg.selector, timeout_seconds=cfg.timeout_seconds)
        elif cfg.strategy == "cookie_presence":
            if not cfg.cookie_names:
                logger.warning("cookie_presence strategy missing 'cookie_names', skipping")
                return None
            return CookiePresenceStrategy(cookie_names=cfg.cookie_names, domain=cfg.domain)
        elif cfg.strategy == "network_token":
            return NetworkTokenStrategy()
        else:
            logger.warning(f"Unknown detection strategy: {cfg.strategy}, skipping")
            return None
