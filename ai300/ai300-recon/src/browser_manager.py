# -*- coding: utf-8 -*-
"""
Browser Manager
===============

浏览器生命周期管理：启动、认证注入、导航、storage_state 复用、关闭。

增强点：
  - 支持 AuthProfile 注入（Cookie + Header）
  - 支持 storage_state 复用
  - 支持 viewport / ignore_https_errors / headless 等配置
  - 统一截图与状态保存
"""

import asyncio
import logging
import os
import time
from typing import Any, Dict, Optional

from src.utils import truncate_error

logger = logging.getLogger(__name__)


class BrowserManager:
    """Playwright 浏览器管理器"""

    def __init__(
        self,
        headless: bool = False,
        auth_profile: Optional[Any] = None,
        storage_state_path: str = "",
        browser_type: str = "chromium",
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Args:
            headless: 是否无头模式
            auth_profile: AuthProfile 实例（可选）
            storage_state_path: 浏览器状态文件路径（可选）
            browser_type: chromium / firefox / webkit
            config: 全局配置，用于读取日志截断等参数
        """
        self.headless = headless
        self.auth_profile = auth_profile
        self.storage_state_path = storage_state_path
        self.browser_type = browser_type
        self.config = config or {}
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

    async def start(
        self,
        url: str = "",
        connection: Optional[Dict[str, Any]] = None,
    ) -> "BrowserManager":
        """
        启动浏览器并导航到目标 URL

        Args:
            url: 目标 URL（为空时仅启动浏览器）
            connection: 扩展连接配置（viewport、wait_until、timeout 等）

        Returns:
            self
        """
        from playwright.async_api import async_playwright

        connection = connection or {}
        self._playwright = await async_playwright().start()

        browser_launcher = {
            "chromium": self._playwright.chromium,
            "firefox": self._playwright.firefox,
            "webkit": self._playwright.webkit,
        }.get(self.browser_type, self._playwright.chromium)

        self._browser = await browser_launcher.launch(
            headless=self.headless,
            args=["--disable-blink-features=AutomationControlled"],
        )

        viewport = connection.get("viewport", {"width": 1366, "height": 768})
        context_kwargs = {
            "viewport": viewport,
            "ignore_https_errors": connection.get("ignore_https_errors", True),
        }

        if self.storage_state_path:
            context_kwargs["storage_state"] = self.storage_state_path

        context = await self._browser.new_context(**context_kwargs)

        # 注入认证信息
        page = await context.new_page()
        if self.auth_profile and self.auth_profile.has_auth():
            from src.auth import inject_auth

            await inject_auth(context, page, self.auth_profile)

        self._context = context
        self._page = page

        # 设置反检测 UA（优先从 connection 读取，保留默认兜底）
        user_agent = connection.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        )
        await page.set_extra_http_headers({"User-Agent": user_agent})

        if url:
            await self.navigate(url, connection=connection)
        return self

    async def navigate(
        self,
        url: str,
        connection: Optional[Dict[str, Any]] = None,
    ) -> "BrowserManager":
        """
        导航到指定 URL

        Args:
            url: 目标 URL
            connection: 导航配置（wait_until、timeout、post_load_wait 等）

        Returns:
            self
        """
        if not self._page:
            raise RuntimeError("Browser not started")

        connection = connection or {}
        logger.info("Navigating to: %s", url)
        wait_until = connection.get("wait_until", "domcontentloaded")
        timeout = connection.get("timeout", 30000)
        try:
            await self._page.goto(url, wait_until=wait_until, timeout=timeout)
        except Exception as e:
            # SSO 重定向可能触发超时，属于正常情况
            logger.warning("Navigation timeout/exception (common for SSO redirects): %s", truncate_error(str(e), self.config))

        await self._page.wait_for_load_state("domcontentloaded")
        await asyncio.sleep(connection.get("post_load_wait", 2))
        return self

    @property
    def page(self):
        return self._page

    @property
    def context(self):
        return self._context

    async def save_storage_state(self, path: str = "") -> str:
        """保存浏览器 storage_state 到文件"""
        if not self._context:
            return ""
        if not path:
            ts = str(int(time.time()))
            path = os.path.join("results", "recon", "storage_states", f"state_{ts}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        await self._context.storage_state(path=path)
        logger.info("Storage state saved: %s", path)
        return path

    async def screenshot(self, filename: str = "", full_page: bool = True) -> str:
        """保存截图"""
        if not self._page:
            return ""
        if not filename:
            ts = str(int(time.time()))
            filename = os.path.join("results", "recon", "screenshots", f"shot_{ts}.png")
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        await self._page.screenshot(path=filename, full_page=full_page)
        logger.info("Screenshot saved: %s", filename)
        return filename

    async def close(self):
        """关闭浏览器：按 page → context → browser → playwright 顺序关闭，减少资源警告。"""
        try:
            if self._page and not self._page.is_closed():
                await self._page.close()
        except Exception:
            pass
        try:
            if self._context:
                await self._context.close()
        except Exception:
            pass
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None
        logger.info("Browser closed")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
