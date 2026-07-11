"""
浏览器管理器 — 多层反检测 Playwright 浏览器生命周期管理。

支持四种 stealth 后端，按优先级自动降级：
  1. CloakBrowser (C++ 源码级 Chromium 修改，30+ 检测站点全过)
  2. Patchright      (Playwright 补丁版，移除 CDP 泄漏)
  3. playwright-stealth (JS 注入层反检测)
  4. 手动注入         (内置 stealth JS 脚本)

所有后端均叠加 humanize 行为模拟层（贝塞尔鼠标、拟人键入、随机滚动）。
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import random
from enum import Enum
from typing import Optional

from rich.console import Console

from recon.scanners.humanize_utils import (
    HumanBehavior,
    STEALTH_INIT_SCRIPT,
)

console = Console()
logger = logging.getLogger(__name__)


class StealthMode(Enum):
    NONE = "none"
    PLAYWRIGHT_STEALTH = "playwright_stealth"
    PATCHRIGHT = "patchright"
    CLOAKBROWSER = "cloakbrowser"
    AUTO = "auto"  # 自动检测最佳可用后端


# ── 已知 CloakBrowser 默认路径 ──
_CLOAKBROWSER_PATHS = {
    "win32": [
        os.path.expandvars(r"%LOCALAPPDATA%\CloakBrowser\cloakbrowser\chrome.exe"),
        os.path.expandvars(r"%PROGRAMFILES%\CloakBrowser\chrome.exe"),
        os.path.expandvars(r"%USERPROFILE%\cloakbrowser\chrome.exe"),
    ],
    "darwin": [
        "/Applications/CloakBrowser.app/Contents/MacOS/CloakBrowser",
        os.path.expanduser("~/cloakbrowser/chrome"),
    ],
    "linux": [
        "/opt/cloakbrowser/chrome",
        os.path.expanduser("~/cloakbrowser/chrome"),
    ],
}

_SYSTEM_CHROME_PATHS = {
    "win32": [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ],
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ],
    "linux": [
        "/usr/bin/google-chrome",
        "/usr/bin/chromium-browser",
    ],
}


class BrowserManager:
    """Playwright 浏览器实例管理器 — 多层反检测。

    管理 Chromium 浏览器的启动、页面创建和优雅关闭。
    支持 headless / headed 模式、代理配置、自定义启动参数，
    以及 CloakBrowser / Patchright / playwright-stealth 多层反检测。

    使用示例::

        # 自动检测最佳 stealth 后端
        bm = BrowserManager(headless=False, stealth_mode="auto", humanize=True)
        await bm.start()
        page = await bm.new_page()

        # 指定 CloakBrowser 路径
        bm = BrowserManager(
            headless=False,
            stealth_mode="cloakbrowser",
            executable_path="/opt/cloakbrowser/chrome",
        )
    """

    def __init__(
        self,
        headless: bool = True,
        output_dir: str = "outputs",
        proxy: Optional[str] = None,
        user_data_dir: Optional[str] = None,
        storage_state: Optional[str] = None,
        viewport_width: int = 1440,
        viewport_height: int = 900,
        locale: str = "zh-CN",
        stealth_mode: str = "auto",
        executable_path: Optional[str] = None,
        humanize: bool = True,
        extra_launch_args: Optional[list[str]] = None,
        record_har_path: Optional[str] = None,
    ):
        self.headless = headless
        self.output_dir = output_dir
        self.proxy = proxy
        self.user_data_dir = user_data_dir
        self.storage_state_path = storage_state  # Playwright storageState 文件路径
        self._storage_state_data: Optional[dict] = None  # 加载后的数据
        self.record_har_path = record_har_path  # HAR 录制输出路径 (context 级)
        self.viewport = {"width": viewport_width, "height": viewport_height}
        self.locale = locale
        self._stealth_mode_raw = stealth_mode
        self._executable_path_raw = executable_path
        self.humanize = humanize
        self._extra_launch_args = extra_launch_args or []

        # 解析后的实际配置
        self._playwright = None
        self._browser = None
        self._context = None
        self._started = False
        self._active_stealth: StealthMode = StealthMode.NONE
        self._using_cloakbrowser = False
        self._using_patchright = False
        self._using_playwright_stealth = False

        # 页面追踪，用于 cleanup 时批量关闭
        self._pages: list = []

    # ── Stealth 后端检测 ──

    @staticmethod
    def _detect_cloakbrowser(explicit_path: Optional[str] = None) -> Optional[str]:
        """检测 CloakBrowser 可执行文件路径。"""
        if explicit_path and os.path.isfile(explicit_path):
            return explicit_path
        os_name = platform.system().lower()
        paths = _CLOAKBROWSER_PATHS.get(os_name, [])
        for p in paths:
            if os.path.isfile(p):
                return p
        return None

    @staticmethod
    def _detect_system_chrome() -> Optional[str]:
        """检测系统中已安装的 Chrome 浏览器路径。"""
        os_name = platform.system().lower()
        paths = _SYSTEM_CHROME_PATHS.get(os_name, [])
        for p in paths:
            if os.path.isfile(p):
                return p
        return None

    @staticmethod
    def _is_patchright_available() -> bool:
        try:
            import patchright  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def _is_playwright_stealth_available() -> bool:
        try:
            import playwright_stealth  # noqa: F401
            return True
        except ImportError:
            return False

    def _resolve_stealth(self) -> tuple[StealthMode, Optional[str]]:
        """解析最终使用的 stealth 策略和可执行文件路径。

        Returns:
            (active_stealth_mode, executable_path_or_None)
        """
        mode_raw = self._stealth_mode_raw.lower()

        # ── 显式指定模式 ──
        if mode_raw == "cloakbrowser":
            path = self._detect_cloakbrowser(self._executable_path_raw)
            if path:
                return StealthMode.CLOAKBROWSER, path
            console.print("  [yellow]⚠ CloakBrowser 未找到，降级到 AUTO[/yellow]")
            mode_raw = "auto"

        if mode_raw == "patchright":
            if self._is_patchright_available():
                return StealthMode.PATCHRIGHT, None
            console.print("  [yellow]⚠ Patchright 未安装 (pip install patchright)，降级到 AUTO[/yellow]")
            mode_raw = "auto"

        if mode_raw == "playwright_stealth":
            return StealthMode.PLAYWRIGHT_STEALTH, None

        if mode_raw == "none":
            return StealthMode.NONE, None

        # ── AUTO 模式：按优先级自动检测 ──
        if mode_raw == "auto":
            # 1. 检查 explicit executable_path
            if self._executable_path_raw and os.path.isfile(self._executable_path_raw):
                console.print("  [dim]  → 使用指定可执行文件[/dim]")
                # 如果路径包含 "cloakbrowser"，标记为 CloakBrowser
                is_cloak = "cloakbrowser" in self._executable_path_raw.lower()
                return (
                    StealthMode.CLOAKBROWSER if is_cloak else StealthMode.NONE,
                    self._executable_path_raw,
                )

            # 2. 尝试 CloakBrowser
            cloak_path = self._detect_cloakbrowser()
            if cloak_path:
                console.print("  [green]  → CloakBrowser 已检测[/green]")
                return StealthMode.CLOAKBROWSER, cloak_path

            # 3. 尝试 Patchright
            if self._is_patchright_available():
                console.print("  [dim]  → Patchright 可用[/dim]")
                return StealthMode.PATCHRIGHT, None

            # 4. playwright-stealth (纯 JS 注入)
            if self._is_playwright_stealth_available():
                console.print("  [dim]  → playwright-stealth 可用[/dim]")
                return StealthMode.PLAYWRIGHT_STEALTH, None

            # 5. 系统 Chrome（至少 JA3 指纹真实）
            chrome_path = self._detect_system_chrome()
            if chrome_path:
                console.print("  [dim]  → 使用系统 Chrome[/dim]")
                return StealthMode.NONE, chrome_path

            # 6. 兜底：Playwright 内置 Chromium + 手动注入 JS
            console.print("  [yellow]  ⚠ 无 stealth 可用，使用 Playwright 内置 Chromium + 手动脚本[/yellow]")
            return StealthMode.NONE, None

        # 默认
        return StealthMode.NONE, None

    # ── 存储状态管理 ──

    def load_storage_state(self, path: str, base_url: str = "") -> dict:
        """加载 Playwright storageState JSON 文件。

        自动检测格式：storageState JSON / 纯 Cookie 字符串 / Netscape cookies.txt。

        Returns:
            Playwright storageState dict (可直接传给 new_context)
        """
        from recon.scanners.storage_state_utils import load_storage_state as _load
        self._storage_state_data = _load(path, base_url)
        self.storage_state_path = path
        console.print(f"  [dim]📂 已加载存储状态: {path} ({len(self._storage_state_data.get('cookies', []))} cookies)[/dim]")
        return self._storage_state_data

    async def save_storage_state(self, output_path: Optional[str] = None) -> str:
        """保存当前浏览器上下文到 Playwright storageState 文件。

        Args:
            output_path: 输出路径 (默认: outputs/storage_state.json)

        Returns:
            保存的文件路径
        """
        if not self._context:
            raise RuntimeError("浏览器上下文未初始化")

        output = output_path or os.path.join(self.output_dir, "storage_state.json")
        os.makedirs(os.path.dirname(output) or ".", exist_ok=True)

        state = await self._context.storage_state(path=output)
        console.print(f"  [dim]💾 存储状态已保存: {output}[/dim]")
        return output

    # ── 浏览器启动 ──

    async def start(self):
        """启动浏览器实例，自动应用多层反检测 + 会话恢复 + HAR 录制。"""
        if self._started:
            return

        self._active_stealth, exe_path = self._resolve_stealth()

        try:
            # ── Patchright 模式：替换 Playwright import ──
            if self._active_stealth == StealthMode.PATCHRIGHT:
                from patchright.async_api import async_playwright
                self._playwright = await async_playwright().start()
                self._using_patchright = True
                console.print("  [dim]🌐 Patchright 浏览器引擎已就绪[/dim]")
            else:
                from playwright.async_api import async_playwright
                self._playwright = await async_playwright().start()

            # ── 构建启动参数 ──
            launch_options = {
                "headless": self.headless,
                "args": self._build_launch_args(),
            }

            # 可执行文件路径（CloakBrowser、系统 Chrome 或自定义）
            if exe_path:
                launch_options["executable_path"] = exe_path

            if self.proxy:
                launch_options["proxy"] = {"server": self.proxy}

            self._browser = await self._playwright.chromium.launch(**launch_options)

            # 日志
            mode_labels = {
                StealthMode.CLOAKBROWSER: f"CloakBrowser (C++ stealth) [green]{exe_path or ''}[/green]",
                StealthMode.PATCHRIGHT: "Patchright (CDP patched)",
                StealthMode.PLAYWRIGHT_STEALTH: "Playwright + playwright-stealth (JS injection)",
                StealthMode.NONE: "Playwright Chromium (内置脚本注入)" if not exe_path else f"System Chrome [dim]{exe_path}[/dim]",
            }
            stealth_label = mode_labels.get(self._active_stealth, "Unknown")

            # 存储状态信息
            storage_info = ""
            if self.storage_state_path:
                try:
                    self.load_storage_state(self.storage_state_path)
                    storage_info = f"\n  [dim]  📂 Session: {self.storage_state_path}[/dim]"
                except Exception as e:
                    console.print(f"  [yellow]⚠ 存储状态加载失败: {e}[/yellow]")

            console.print(
                f"  [dim]🌐 浏览器已启动 (headless={self.headless})[/dim]\n"
                f"  [dim]  🛡 Stealth: {stealth_label}[/dim]\n"
                f"  [dim]  👤 Humanize: {'✓' if self.humanize else '✗'}[/dim]"
                f"{storage_info}"
            )

            # ── 创建浏览器上下文 ──
            context_options = {
                "viewport": self.viewport,
                "locale": self.locale,
                "ignore_https_errors": True,
                "bypass_csp": True,
            }

            # 存储状态 (Playwright 原生会话恢复)
            if self._storage_state_data:
                context_options["storage_state"] = self._storage_state_data
                console.print("  [dim]  🔄 已注入会话状态 (cookies + localStorage)[/dim]")

            # HAR 录制 (Playwright 原生 context 级 HAR)
            if self.record_har_path:
                os.makedirs(os.path.dirname(self.record_har_path) or ".", exist_ok=True)
                context_options["record_har_path"] = self.record_har_path
                console.print(f"  [dim]  📡 HAR 录制: {self.record_har_path}[/dim]")

            if self.user_data_dir:
                context_options["user_data_dir"] = self.user_data_dir

            self._context = await self._browser.new_context(**context_options)

            # ── 应用上下文级隐身脚本 ──
            await self._apply_context_stealth()

            self._started = True

        except ImportError as e:
            if "patchright" in str(e).lower():
                console.print(
                    "  [yellow]⚠ Patchright 未安装。请运行: pip install patchright[/yellow]"
                )
                raise
            console.print(
                "  [yellow]⚠ Playwright 未安装。请运行:[/yellow]\n"
                "  [dim]    pip install playwright[/dim]\n"
                "  [dim]    playwright install chromium[/dim]"
            )
            raise
        except Exception as e:
            console.print(f"  [red]❌ 浏览器启动失败: {e}[/red]")
            raise

    def _build_launch_args(self) -> list[str]:
        """构建浏览器启动参数，包含反检测开关。"""
        args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-blink-features",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
            # 额外反检测参数
            "--disable-features=TranslateUI",
            "--disable-ipc-flooding-protection",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--disable-features=AudioServiceOutOfProcess",
            "--enable-features=NetworkService,NetworkServiceInProcess",
            # 指纹伪装
            f"--window-size={self.viewport['width']},{self.viewport['height']}",
        ]

        # CloakBrowser/Patchright 模式下不需要某些 flag
        if self._active_stealth in (StealthMode.CLOAKBROWSER, StealthMode.PATCHRIGHT):
            # 移除可能冲突的参数
            args = [a for a in args if "--disable-blink-features" not in a]

        # 用户自定义参数
        args.extend(self._extra_launch_args)

        return args

    async def _apply_context_stealth(self):
        """对浏览器上下文应用隐身脚本。"""
        if not self._context:
            return

        # ── Layer 1: playwright-stealth (pip 包) ──
        if self._active_stealth == StealthMode.PLAYWRIGHT_STEALTH:
            try:
                from playwright_stealth import stealth_async
                # stealth_async 需要在每个 page 上调用，这里先标记
                self._using_playwright_stealth = True
            except ImportError:
                pass

        # ── Layer 2: 内置 stealth init script (兜底) ──
        # CloakBrowser 已从 C++ 层面处理，无需 JS 注入，但加一层也无害
        # Patchright 可能也不完全需要，但双重保险
        if self._active_stealth not in (StealthMode.CLOAKBROWSER,):
            await self._context.add_init_script(STEALTH_INIT_SCRIPT)

        # ── Layer 3: humanize 行为注入 ──
        if self.humanize:
            await self._context.add_init_script("""
                // ── Humanize behavior hooks ──
                // Track user-like events to warm up behavior profile
                (function() {
                    if (window.__humanize_patched) return;
                    window.__humanize_patched = true;

                    // Warm up scroll position
                    let scrollY = Math.random() * 200;
                    window.scrollTo(0, scrollY);
                })();
            """)

    async def _stealth_page(self, page):
        """对新创建的页面应用隐身补丁。"""
        # playwright-stealth per-page 调用
        if self._using_playwright_stealth:
            try:
                from playwright_stealth import stealth_async
                await stealth_async(page)
            except Exception:
                pass

    # ── 页面管理 ──

    async def new_page(self) -> "Page":
        """创建新页面（继承 context 的 cookies 和设置），自动应用 stealth。"""
        if not self._started:
            await self.start()
        page = await self._context.new_page()
        await self._stealth_page(page)
        self._pages.append(page)
        return page

    async def new_context(self, **kwargs):
        """创建新的浏览器上下文（隔离的 cookie/session）。"""
        if not self._started:
            await self.start()
        ctx_options = {
            "viewport": self.viewport,
            "locale": self.locale,
            "ignore_https_errors": True,
            **kwargs,
        }
        return await self._browser.new_context(**ctx_options)

    async def close_page(self, page):
        """关闭单个页面。"""
        try:
            if page in self._pages:
                self._pages.remove(page)
            await page.close()
        except Exception:
            pass

    # ── Cookie 管理 ──

    @property
    def cookies(self) -> list:
        """获取当前 context 的所有 cookies。"""
        if not self._context:
            return []
        return self._context.cookies()

    async def set_cookies(self, cookies: list[dict]):
        """设置浏览器 cookies。"""
        if self._context:
            await self._context.add_cookies(cookies)

    # ── JS 内容提取 ──

    async def extract_js_contents(self, page) -> dict[str, str]:
        """从页面提取所有内联和外部 JS 脚本内容。

        Returns:
            {文件名或来源URL: JS内容} 字典
        """
        scripts = {}
        try:
            js_elements = await page.evaluate("""
                () => {
                    const results = {};
                    const scripts = document.querySelectorAll('script');
                    scripts.forEach((s, i) => {
                        const src = s.src || '';
                        const content = s.textContent || '';
                        const key = src || 'inline-' + i;
                        if (content.length > 50) {
                            results[key] = content;
                        }
                    });
                    return results;
                }
            """)
            if isinstance(js_elements, dict):
                scripts.update(js_elements)

            js_requests = await page.evaluate("""
                () => {
                    const resources = performance.getEntriesByType('resource');
                    return resources
                        .filter(r => r.name.endsWith('.js') || r.name.includes('.js?'))
                        .map(r => r.name);
                }
            """)
            self._js_resources = js_requests if isinstance(js_requests, list) else []

        except Exception as e:
            console.print(f"  [dim]  JS 内容提取警告: {e}[/dim]")

        return scripts

    # ── 人机行为便利方法 ──

    async def human_navigate(self, page, url: str, timeout: int = 30000):
        """以人类方式导航到 URL（带随机前导延迟）。"""
        if self.humanize:
            await asyncio.sleep(HumanBehavior.think_delay(100, 800))
        await page.goto(url, wait_until="networkidle", timeout=timeout)
        if self.humanize:
            await asyncio.sleep(1.5)  # 模拟页面浏览

    async def human_type(self, page, text: str, field=None):
        """以人类方式输入文本。

        若提供 field (Playwright element)，则先 focus 再 typing。
        否则使用全局键盘事件。
        """
        if field:
            await field.click()
            await asyncio.sleep(random.uniform(0.2, 0.6))
        if self.humanize:
            await HumanBehavior.human_type(page, text)
        else:
            await page.keyboard.type(text, delay=20)

    async def human_click(self, page, element):
        """以人类方式点击元素。"""
        if self.humanize:
            return await HumanBehavior.human_click_element(page, element)
        return await element.click()

    async def human_scroll(self, page, distance: Optional[int] = None):
        """以人类方式滚动页面。"""
        if self.humanize:
            await HumanBehavior.human_scroll(page, distance=distance)
        else:
            dist = distance or 500
            await page.mouse.wheel(0, dist)

    async def random_delay(self, min_s: float = 0.2, max_s: float = 1.5):
        """随机延迟（仅在 humanize 模式下）。"""
        if self.humanize:
            await asyncio.sleep(random.uniform(min_s, max_s))

    # ── 状态报告 ──

    @property
    def stealth_summary(self) -> dict:
        """返回当前 stealth 配置摘要。"""
        return {
            "mode": self._active_stealth.value,
            "cloakbrowser": self._using_cloakbrowser,
            "patchright": self._using_patchright,
            "playwright_stealth": self._using_playwright_stealth,
            "humanize": self.humanize,
            "headless": self.headless,
        }

    # ── 清理 ──

    async def stop(self):
        """优雅关闭浏览器。"""
        for page in list(self._pages):
            try:
                await page.close()
            except Exception:
                pass
        self._pages.clear()

        if self._context:
            try:
                await self._context.close()
            except Exception:
                pass
            self._context = None
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        self._started = False
        console.print("  [dim]🌐 浏览器已关闭[/dim]")
