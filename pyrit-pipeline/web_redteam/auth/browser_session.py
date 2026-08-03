# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""浏览器会话管理器。.

支持两种模式:
  1. launch_with_debug_port(): 启动新浏览器, 开启 CDP 调试端口
     → 人工可在浏览器窗口中操作 (滑块/扫码/OTP)
  2. connect_via_cdp(): 连接已有浏览器会话 (复用已登录状态)

认证状态持久化:
  - save_storage_state(): 保存 cookies + localStorage 到 JSON
  - restore_storage_state(): 从 JSON 恢复, 跳过重复认证

G7 修复:
  新增 relaunch() 方法, 在认证状态恢复失败时复用 BrowserSession 实例,
  仅重建浏览器进程, 避免不必要的对象创建/销毁。

对齐 PyRIT 原生模式:
  - doc/code/targets/10_2_playwright_target_copilot.py 的 connect_to_existing_browser
  - Playwright 原生 context.storage_state() API
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.async_api import Browser, BrowserContext, Page

logger = logging.getLogger(__name__)


class BrowserSession:
    """浏览器会话管理器。.

    管理 Playwright 浏览器生命周期, 支持 CDP 连接和认证状态持久化。

    用法:
        session = BrowserSession()
        page = await session.launch_with_debug_port(port=9222, headless=False)
        # ... 认证 + 攻击 ...
        await session.save_storage_state(page.context, "auth_state.json")
        await session.close()

    下次运行:
        session = BrowserSession()
        page = await session.restore_storage_state("auth_state.json")
        # ... 直接攻击, 无需再次认证 ...
        await session.close()
    """

    def __init__(self) -> None:
        """Initialize BrowserSession."""
        self._playwright: Any = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._subprocess: subprocess.Popen[bytes] | None = None
        self._owns_browser: bool = False

    async def launch_with_debug_port(
        self,
        port: int = 9222,
        headless: bool = False,
        browser_path: str | None = None,
    ) -> Page:
        """启动 Chromium, 开启远程调试端口。.

        流程:
          1. 通过 subprocess 启动 Chrome/Chromium: --remote-debugging-port={port}
          2. async_playwright().chromium.connect_over_cdp(f"http://localhost:{port}")
          3. 获取或创建 context + page
          4. 返回 page (人工可在浏览器窗口操作)

        对齐 doc/code/targets/10_2_playwright_target_copilot.py 的
        connect_to_existing_browser 模式, 但由程序自动启动浏览器。

        Args:
            port: CDP 调试端口, 默认 9222。
            headless: 是否无头模式 (认证场景建议 False)。
            browser_path: 浏览器可执行文件路径 (可选, 默认自动检测)。

        Returns:
            Playwright Page 对象。
        """
        from playwright.async_api import async_playwright

        # A6: 动态端口检测 — 如果指定端口被占用, 自动寻找可用端口
        port = self._find_available_port(port)

        # 启动浏览器进程 (带远程调试端口)
        if not headless:
            self._subprocess = self._launch_browser_process(port, browser_path)
            self._owns_browser = True
            # 等待浏览器就绪
            await asyncio.sleep(2)

        self._playwright = await async_playwright().start()

        if self._owns_browser:
            # 连接到刚启动的浏览器
            self._browser = await self._playwright.chromium.connect_over_cdp(f"http://localhost:{port}")
        else:
            # 无头模式直接启动
            self._browser = await self._playwright.chromium.launch(headless=True)
            self._owns_browser = True

        # 获取或创建 context
        contexts = self._browser.contexts if hasattr(self._browser, "contexts") else []
        if contexts:
            self._context = contexts[0]
            pages = self._context.pages
            if pages:
                self._page = pages[0]
            else:
                self._page = await self._context.new_page()
        else:
            self._context = await self._browser.new_context()
            self._page = await self._context.new_page()

        logger.info(f"BrowserSession: browser launched (headless={headless}, port={port})")
        return self._page

    async def connect_via_cdp(self, port: int = 9222) -> Page:
        """通过 CDP 连接已有浏览器会话。.

        对齐 doc/code/targets/10_2_playwright_target_copilot.py 的
        connect_to_existing_browser 函数。

        适用于: 用户已手动打开浏览器并登录, 程序直接接管。

        Args:
            port: CDP 调试端口。

        Returns:
            Playwright Page 对象。
        """
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.connect_over_cdp(f"http://localhost:{port}")

        contexts = self._browser.contexts if hasattr(self._browser, "contexts") else []
        if contexts:
            self._context = contexts[0]
            pages = self._context.pages
            if pages:
                self._page = pages[0]
            else:
                self._page = await self._context.new_page()
        else:
            self._context = await self._browser.new_context()
            self._page = await self._context.new_page()

        logger.info(f"BrowserSession: connected via CDP (port={port})")
        return self._page

    async def save_storage_state(self, context: BrowserContext, path: str) -> None:
        """保存认证状态 (cookies + localStorage) 到 JSON 文件。.

        使用 Playwright 原生 API: await context.storage_state(path=path)
        下次运行可通过 restore_storage_state() 跳过认证。

        Args:
            context: 要保存的 BrowserContext。
            path: 保存路径。
        """
        storage_path = Path(path)
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        await context.storage_state(path=str(storage_path))
        logger.info(f"BrowserSession: storage state saved to {storage_path}")

    async def restore_storage_state(self, storage_state_path: str) -> Page:
        """从 JSON 文件恢复认证状态, 创建已认证的 BrowserContext。.

        使用 Playwright 原生 API: browser.new_context(storage_state=path)

        Args:
            storage_state_path: 认证状态 JSON 文件路径。

        Returns:
            已认证的 Page 对象。
        """
        from playwright.async_api import async_playwright

        if not Path(storage_state_path).exists():
            raise FileNotFoundError(f"Storage state file not found: {storage_state_path}")

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=False)
        self._owns_browser = True
        self._context = await self._browser.new_context(storage_state=storage_state_path)
        self._page = await self._context.new_page()

        logger.info(f"BrowserSession: storage state restored from {storage_state_path}")
        return self._page

    async def relaunch(
        self,
        port: int = 9222,
        headless: bool = False,
    ) -> Page:
        """关闭当前浏览器进程并重新启动 (G7 修复).

        在认证状态恢复失败时, 复用 BrowserSession 实例,
        仅重建浏览器进程, 避免不必要的对象创建/销毁。

        Args:
            port: CDP 调试端口。
            headless: 是否无头模式。

        Returns:
            新的 Playwright Page 对象。
        """
        logger.info("BrowserSession: relaunching browser session")
        await self.close()

        # 重置所有内部状态
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._subprocess = None
        self._owns_browser = False

        return await self.launch_with_debug_port(port=port, headless=headless)

    async def navigate_cross_domain(
        self,
        page: Page,
        target_url: str,
        expected_final_domain: str | None = None,
        timeout_seconds: int = 60,
    ) -> Page:
        """跨域导航: 处理跨域重定向链。.

        在跨域认证场景中, 登录过程可能涉及多个域名跳转:
          app.com → sso.idp.com → app.com

        此方法:
          1. 导航到 target_url
          2. 监听 framenavigated 事件, 追踪域名变化
          3. 等待重定向链完成 (回到目标域名或超时)
          4. 返回最终停留在目标域名的 page

        Args:
            page: Playwright Page 对象。
            target_url: 目标 URL。
            expected_final_domain: 期望的最终域名 (可选, 用于判断重定向完成)。
            timeout_seconds: 超时秒数。

        Returns:
            停留在目标域名的 Page。
        """
        domain_transitions: list[str] = []

        def on_navigated(frame: Any) -> None:
            if frame == page.main_frame:
                from urllib.parse import urlparse

                domain = urlparse(frame.url).netloc
                if domain and (not domain_transitions or domain_transitions[-1] != domain):
                    domain_transitions.append(domain)
                    logger.info(f"CrossDomain navigation: {domain} (chain: {' → '.join(domain_transitions)})")

        page.on("framenavigated", on_navigated)

        await page.goto(target_url, wait_until="domcontentloaded")

        if expected_final_domain:
            start = asyncio.get_event_loop().time()
            while asyncio.get_event_loop().time() - start < timeout_seconds:
                from urllib.parse import urlparse

                current_domain = urlparse(page.url).netloc
                if expected_final_domain in current_domain:
                    logger.info(f"CrossDomain navigation: reached final domain '{current_domain}'")
                    break
                await asyncio.sleep(0.5)
            else:
                logger.warning(
                    f"CrossDomain navigation: timeout waiting for '{expected_final_domain}', "
                    f"current URL: {page.url}, transitions: {domain_transitions}"
                )

        page.remove_listener("framenavigated", on_navigated)
        return page

    @property
    def page(self) -> Page | None:
        """Get the current page."""
        return self._page

    @property
    def context(self) -> BrowserContext | None:
        """Get the browser context."""
        return self._context

    async def close(self) -> None:
        """关闭浏览器会话 (G16: 增强强制清理).."""
        if self._page:
            with contextlib.suppress(Exception):
                await self._page.close()
        if self._context and self._owns_browser:
            with contextlib.suppress(Exception):
                await self._context.close()
        if self._browser:
            with contextlib.suppress(Exception):
                await self._browser.close()
        if self._playwright:
            with contextlib.suppress(Exception):
                await self._playwright.stop()
        if self._subprocess:
            try:
                self._subprocess.terminate()
                self._subprocess.wait(timeout=5)
            except Exception:
                # G16: terminate 超时后强制 kill, 避免僵尸进程
                with contextlib.suppress(Exception):
                    self._subprocess.kill()
                with contextlib.suppress(Exception):
                    self._subprocess.wait(timeout=3)

        logger.info("BrowserSession: closed")

    @staticmethod
    def _find_available_port(preferred: int = 9222, max_attempts: int = 10) -> int:
        """A6: 动态查找可用的 CDP 端口。.

        如果首选端口被占用, 自动递增查找可用端口。

        Args:
            preferred: 首选端口号。
            max_attempts: 最大尝试次数。

        Returns:
            可用的端口号。
        """
        import socket

        for offset in range(max_attempts):
            port = preferred + offset
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex(("localhost", port))
                    if result != 0:
                        # 端口未被占用
                        if offset > 0:
                            logger.info(f"BrowserSession: port {preferred} in use, using {port}")
                        return port
            except Exception:
                return port
        # 所有尝试都失败, 返回首选端口 (让浏览器报错)
        logger.warning(
            f"BrowserSession: no available port found in {preferred}-{preferred + max_attempts}, using {preferred}"
        )
        return preferred

    def _launch_browser_process(
        self,
        port: int,
        browser_path: str | None = None,
    ) -> subprocess.Popen[bytes]:
        """启动浏览器进程, 开启远程调试端口。."""
        if browser_path is None:
            browser_path = self._find_browser_executable()

        args = [
            browser_path,
            f"--remote-debugging-port={port}",
            "--no-first-run",
            "--no-default-browser-check",
        ]

        logger.info(f"Launching browser: {' '.join(args)}")
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def _find_browser_executable() -> str:
        """自动检测系统上的 Chrome/Chromium 可执行文件路径。."""
        if sys.platform == "win32":
            candidates = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            ]
        elif sys.platform == "darwin":
            candidates = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ]
        else:
            candidates = [
                "google-chrome",
                "google-chrome-stable",
                "chromium-browser",
                "chromium",
                "microsoft-edge",
            ]

        for path in candidates:
            if Path(path).exists() or _is_in_path(path):
                return path

        raise RuntimeError(
            "Could not find a browser executable. Please specify browser_path or install Chrome/Chromium."
        )


def _is_in_path(command: str) -> bool:
    """检查命令是否在 PATH 中。."""
    import shutil

    return shutil.which(command) is not None
