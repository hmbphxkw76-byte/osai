"""
浏览器管理器 — Playwright 浏览器生命周期管理。
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console

console = Console()


class BrowserManager:
    """Playwright 浏览器实例管理器。

    管理 Chromium 浏览器的启动、页面创建和优雅关闭。
    支持 headless / headed 模式、代理配置和自定义启动参数。
    """

    def __init__(
        self,
        headless: bool = True,
        output_dir: str = "outputs",
        proxy: Optional[str] = None,
        user_data_dir: Optional[str] = None,
        viewport_width: int = 1440,
        viewport_height: int = 900,
        locale: str = "zh-CN",
    ):
        self.headless = headless
        self.output_dir = output_dir
        self.proxy = proxy
        self.user_data_dir = user_data_dir
        self.viewport = {"width": viewport_width, "height": viewport_height}
        self.locale = locale

        self._playwright = None
        self._browser = None
        self._context = None
        self._started = False

    async def start(self):
        """启动浏览器实例。"""
        if self._started:
            return

        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()

            launch_options = {
                "headless": self.headless,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                ],
            }
            if self.proxy:
                launch_options["proxy"] = {"server": self.proxy}

            self._browser = await self._playwright.chromium.launch(**launch_options)
            console.print(f"  [dim]🌐 Playwright 浏览器已启动 (headless={self.headless})[/dim]")

            context_options = {
                "viewport": self.viewport,
                "locale": self.locale,
                "ignore_https_errors": True,
                "bypass_csp": True,
            }
            if self.user_data_dir:
                context_options["user_data_dir"] = self.user_data_dir

            self._context = await self._browser.new_context(**context_options)
            self._started = True

        except ImportError:
            console.print(
                "  [yellow]⚠ Playwright 未安装。请运行:[/yellow]\n"
                "  [dim]    pip install playwright[/dim]\n"
                "  [dim]    playwright install chromium[/dim]"
            )
            raise
        except Exception as e:
            console.print(f"  [red]❌ 浏览器启动失败: {e}[/red]")
            raise

    async def new_page(self):
        """创建新页面（继承 context 的 cookies 和设置）。"""
        if not self._started:
            await self.start()
        return await self._context.new_page()

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
            await page.close()
        except Exception:
            pass

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

    async def extract_js_contents(self, page) -> dict[str, str]:
        """从页面提取所有内联和外部 JS 脚本内容。

        Returns:
            {文件名或来源URL: JS内容} 字典
        """
        scripts = {}
        try:
            # 提取所有 script 标签内容
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

            # 尝试从网络请求中提取 .js 资源
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

    async def stop(self):
        """优雅关闭浏览器。"""
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
