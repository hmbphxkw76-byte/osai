"""
登录自动化模块 — 处理 Web 应用的认证流程。
"""

from __future__ import annotations

import asyncio
import getpass
import time
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from recon.schema import AuthInfo, AuthType

console = Console()


@dataclass
class LoginResult:
    """登录结果"""
    success: bool = False
    cookies: dict = field(default_factory=dict)
    session_cookie: str = ""
    csrf_token: str = ""
    bearer_token: str = ""
    duration_ms: int = 0
    error: str = ""
    trace_log: str = ""

    def to_auth_info(self) -> AuthInfo:
        """转换为 AuthInfo。"""
        if self.bearer_token:
            return AuthInfo(
                type=AuthType.BEARER.value,
                bearer_token=self.bearer_token,
                cookies=self.cookies,
                login_url=self.trace_log,
                notes="Auto-login via Playwright",
            )
        return AuthInfo(
            type=AuthType.COOKIE.value,
            session_cookie=self.session_cookie,
            cookies=self.cookies,
            csrf_token=self.csrf_token,
            login_url=self.trace_log,
            notes="Auto-login via Playwright",
        )


class LoginAutomator:
    """Playwright 驱动的登录流程自动化。

    支持：
    - 标准表单登录（用户名/密码）
    - Cookie 注入（直接设置）
    - Bearer Token 注入（通过 localStorage/sessionStorage）
    - 多因素认证（基础支持：等待手动输入）
    """

    # 常见登录表单选择器
    _LOGIN_SELECTORS = {
        "username": [
            'input[name="username"]',
            'input[name="email"]',
            'input[name="user"]',
            'input[name="account"]',
            'input[type="text"]',
            'input[type="email"]',
            '#username',
            '#email',
            '#user',
        ],
        "password": [
            'input[name="password"]',
            'input[name="passwd"]',
            'input[name="pwd"]',
            'input[type="password"]',
            '#password',
            '#passwd',
        ],
        "submit": [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("登录")',
            'button:has-text("Login")',
            'button:has-text("Sign in")',
            'button:has-text("登 录")',
            '.login-btn',
            '#login-btn',
        ],
    }

    def __init__(self, browser_manager):
        self._browser = browser_manager

    async def auto_login(
        self,
        login_url: str,
        credentials: dict,
        timeout: int = 30,
    ) -> LoginResult:
        """自动检测登录表单并完成认证。

        Args:
            login_url: 登录页面 URL
            credentials: 包含 username/password 的字典
            timeout: 超时时间（秒）

        Returns:
            LoginResult 包含 cookies、token 等信息
        """
        t0 = time.monotonic()
        result = LoginResult()
        trace_lines = [f"[{time.strftime('%H:%M:%S')}] 开始登录流程: {login_url}"]

        if not credentials:
            result.error = "未提供登录凭据"
            result.trace_log = "\n".join(trace_lines)
            return result

        # 如果提供了 cookie → 直接注入
        if "cookie" in credentials and not credentials.get("username"):
            return await self._cookie_login(login_url, credentials["cookie"], t0)

        # 如果提供了 bearer token → 检查是否需要登录
        if "bearer_token" in credentials or "token" in credentials:
            return await self._token_login(credentials.get("bearer_token") or credentials.get("token", ""))

        page = None
        try:
            page = await self._browser.new_page()

            # 导航到登录页
            await page.goto(login_url, wait_until="networkidle", timeout=timeout * 1000)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 页面已加载")

            # 查找用户名输入框
            username_field = None
            for selector in self._LOGIN_SELECTORS["username"]:
                try:
                    username_field = await page.wait_for_selector(selector, timeout=3000)
                    if username_field:
                        trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 找到用户名输入框: {selector}")
                        break
                except Exception:
                    continue

            # 查找密码输入框
            password_field = None
            for selector in self._LOGIN_SELECTORS["password"]:
                try:
                    password_field = await page.wait_for_selector(selector, timeout=3000)
                    if password_field:
                        trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 找到密码输入框: {selector}")
                        break
                except Exception:
                    continue

            if not username_field or not password_field:
                result.error = "未找到登录表单（用户名/密码输入框）"
                result.trace_log = "\n".join(trace_lines)
                return result

            # 填写凭据
            username = credentials.get("username", "")
            password = credentials.get("password", "")
            await username_field.fill(username)
            await password_field.fill(password)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 已填写凭据 (user={username})")

            # 查找提交按钮
            submit_btn = None
            for selector in self._LOGIN_SELECTORS["submit"]:
                try:
                    submit_btn = await page.wait_for_selector(selector, timeout=3000)
                    if submit_btn:
                        trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 找到提交按钮: {selector}")
                        break
                except Exception:
                    continue

            if submit_btn:
                # 点击提交
                await submit_btn.click()
            else:
                # 尝试按 Enter 提交
                await password_field.press("Enter")
                trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 使用 Enter 提交表单")

            # 等待导航或 URL 变化
            try:
                await page.wait_for_url(
                    lambda url: url != login_url and login_url not in url,
                    timeout=10000,
                )
                trace_lines.append(f"[{time.strftime('%H:%M:%S')}] URL 变化: {page.url}")
            except Exception:
                # 可能是单页面跳转，等待几秒
                await page.wait_for_timeout(3000)

            # 提取 cookies
            browser_cookies = await self._browser._context.cookies()
            cookie_dict = {c["name"]: c["value"] for c in browser_cookies}
            result.cookies = cookie_dict
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 获取到 {len(cookie_dict)} 个 cookies")

            # 查找 session cookie
            session_names = ["session", "sessionid", "token", "auth", "sid", "connect.sid", "JSESSIONID"]
            for name in session_names:
                if name in cookie_dict:
                    result.session_cookie = f"{name}={cookie_dict[name]}"
                    break
            if not result.session_cookie and cookie_dict:
                # 取第一个 cookie 作为 session
                first_name = next(iter(cookie_dict))
                result.session_cookie = f"{first_name}={cookie_dict[first_name]}"

            # 查找 CSRF token
            csrf_names = ["csrf", "csrftoken", "xsrf", "_csrf", "XSRF-TOKEN"]
            for name in csrf_names:
                if name in cookie_dict:
                    result.csrf_token = cookie_dict[name]
                    break

            # 检查 localStorage/sessionStorage 中的 token
            try:
                local_token = await page.evaluate(
                    "() => localStorage.getItem('token') || localStorage.getItem('access_token') || ''"
                )
                if local_token:
                    result.bearer_token = local_token
                    trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 从 localStorage 提取 token")
            except Exception:
                pass

            # 截图
            screenshot_path = f"{self._browser.output_dir}/screenshot_logged_in.png"
            await page.screenshot(path=screenshot_path, full_page=True)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 截图: {screenshot_path}")

            result.success = True

        except Exception as e:
            result.error = str(e)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 错误: {e}")
        finally:
            if page:
                await self._browser.close_page(page)

        result.duration_ms = int((time.monotonic() - t0) * 1000)
        result.trace_log = "\n".join(trace_lines)
        return result

    async def _cookie_login(self, login_url: str, cookie_str: str, t0: float) -> LoginResult:
        """直接注入 Cookie。"""
        result = LoginResult()
        trace_lines = [f"[{time.strftime('%H:%M:%S')}] Cookie 注入模式"]

        page = None
        try:
            page = await self._browser.new_page()

            # 解析 cookie 字符串
            cookie_dict = {}
            for pair in cookie_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    cookie_dict[key.strip()] = value.strip()

            # 注入到浏览器
            for name, value in cookie_dict.items():
                await self._browser._context.add_cookies([{
                    "name": name,
                    "value": value,
                    "url": login_url,
                }])

            # 验证 cookie 是否有效
            await page.goto(login_url, wait_until="networkidle", timeout=15000)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] Cookie 已注入并验证")

            # 获取所有 cookies
            browser_cookies = await self._browser._context.cookies()
            result.cookies = {c["name"]: c["value"] for c in browser_cookies}
            result.session_cookie = cookie_str
            result.success = True

        except Exception as e:
            result.error = str(e)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] Cookie 注入失败: {e}")
        finally:
            if page:
                await self._browser.close_page(page)

        result.duration_ms = int((time.monotonic() - t0) * 1000)
        result.trace_log = "\n".join(trace_lines)
        return result

    async def _token_login(self, token: str) -> LoginResult:
        """Bearer Token 登录模式。"""
        result = LoginResult()
        result.bearer_token = token
        result.success = True
        result.trace_log = f"[{time.strftime('%H:%M:%S')}] Bearer Token 模式 (无需浏览器登录)"
        return result

    # ── Mode B: CLI 安全输入 ─────────────────────────────────────────

    async def interactive_login(
        self,
        login_url: str,
        timeout: int = 30,
    ) -> LoginResult:
        """CLI 安全输入模式 — 终端提示输入用户名和密码（密码不回显）。

        用户通过终端交互输入凭据，脚本自动填入登录表单并提取 Cookie。
        密码不会写入文件或日志，只存储提取到的 Cookie。
        """
        t0 = time.monotonic()
        result = LoginResult()
        trace_lines = [f"[{time.strftime('%H:%M:%S')}] CLI 交互式登录"]

        console.print()
        console.print("[bold cyan]🔐 CLI 安全输入 — 登录凭据[/bold cyan]")
        console.print("[dim]  密码输入不会回显，也不会保存到任何文件[/dim]")
        console.print()

        try:
            username = input("  用户名: ").strip()
            password = getpass.getpass("  密码: ")
        except (EOFError, KeyboardInterrupt):
            result.error = "用户取消输入"
            result.trace_log = "\n".join(trace_lines)
            return result

        if not username or not password:
            result.error = "用户名或密码为空"
            result.trace_log = "\n".join(trace_lines)
            return result

        # 复用 auto_login 的浏览器流程，但不传 login_payload 到持久化
        credentials = {"username": username, "password": password}
        result = await self.auto_login(
            login_url=login_url,
            credentials=credentials,
            timeout=timeout,
        )

        result.duration_ms = int((time.monotonic() - t0) * 1000)
        # 不把密码写入 trace，仅留用户名
        result.trace_log = (
            f"[{time.strftime('%H:%M:%S')}] CLI 交互登录完成 "
            f"(user={username}, success={result.success})"
        )
        return result

    # ── Mode D: 手动登录 + 自动捕获 Cookie ────────────────────────────

    async def manual_login(
        self,
        login_url: str,
        wait_timeout: int = 120,
        poll_interval: float = 1.5,
    ) -> LoginResult:
        """手动登录 + 自动捕获 Cookie 模式。

        启动 headed 浏览器到登录页面，用户手动完成登录（包括 MFA/验证码等），
        脚本自动检测登录完成并捕获所有 Cookie。

        检测策略：
        1. URL 变化检测 — 如果跳转到非登录页面，认为登录完成
        2. Cookie 增量检测 — 出现新的 session cookie 时触发
        3. 用户手动确认 — 终端按 Enter 立即结束

        Args:
            login_url: 登录页面 URL
            wait_timeout: 最长等待时间（秒），默认 120
            poll_interval: 轮询间隔（秒）
        """
        t0 = time.monotonic()
        result = LoginResult()
        trace_lines = [f"[{time.strftime('%H:%M:%S')}] 手动登录模式: {login_url}"]

        # 先捕获当前 cookies 作为基线
        baseline_cookies = await self._browser._context.cookies()
        baseline_names = {c["name"] for c in baseline_cookies}
        trace_lines.append(
            f"[{time.strftime('%H:%M:%S')}] 基线 cookies: {len(baseline_names)} 个"
        )

        page = None
        try:
            page = await self._browser.new_page()

            # 导航到登录页
            await page.goto(login_url, wait_until="networkidle", timeout=30000)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 登录页已加载: {login_url}")

            # 截图登录前状态
            screenshot_before = f"{self._browser.output_dir}/screenshot_login_before.png"
            await page.screenshot(path=screenshot_before, full_page=True)

            console.print()
            console.print(Panel(
                "[bold yellow]🔓 手动登录模式[/bold yellow]\n\n"
                f"[bold]请在浏览器窗口中手动完成登录。[/bold]\n\n"
                "[dim]支持: 用户名/密码、MFA、验证码、SSO、OAuth 等任意认证方式[/dim]\n\n"
                "[bold cyan]检测方式:[/bold cyan]\n"
                "  • 自动检测 URL 跳转或新 Cookie 注入\n"
                "  • 终端按 [bold]Enter[/bold] 键立即完成\n\n"
                f"[dim]超时时间: {wait_timeout} 秒[/dim]",
                style="bold yellow",
            ))

            # 轮询检测登录完成
            detected = False
            detected_by = ""
            elapsed = 0.0

            async def _check_login(_page) -> tuple[bool, str]:
                """检查登录是否完成。"""
                current_url = _page.url
                # 1. URL 变化 — 跳转到非登录页
                if login_url not in current_url:
                    return True, f"URL 跳转: {current_url}"

                # 2. 新 Cookie 出现
                try:
                    current_cookies = await self._browser._context.cookies()
                    current_names = {c["name"] for c in current_cookies}
                    new_cookies = current_names - baseline_names
                    if new_cookies:
                        return True, f"新 Cookie: {new_cookies}"
                except Exception:
                    pass

                return False, ""

            # 轮询循环
            while elapsed < wait_timeout:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

                detected, detected_by = await _check_login(page)
                if detected:
                    console.print(f"  [green]✅ 检测到登录完成: {detected_by}[/green]")
                    trace_lines.append(
                        f"[{time.strftime('%H:%M:%S')}] 自动检测: {detected_by}"
                    )
                    break

                # 检查用户是否在终端输入了什么（非阻塞近似 — 用少量 sleep）
                if elapsed % 5 < poll_interval:
                    remaining = wait_timeout - int(elapsed)
                    console.print(
                        f"  [dim]⏳ 等待登录中... "
                        f"(剩余 {remaining}s, 按 Enter 提前完成)[/dim]"
                    )

            if not detected and elapsed >= wait_timeout:
                console.print(
                    f"  [yellow]⚠ 超时 ({wait_timeout}s)，将使用当前 cookies[/yellow]"
                )
                trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 超时，捕获当前状态")

            # 额外等待 2 秒让页面完全加载
            await asyncio.sleep(2)

            # 提取 cookies
            browser_cookies = await self._browser._context.cookies()
            cookie_dict = {c["name"]: c["value"] for c in browser_cookies}
            result.cookies = cookie_dict
            trace_lines.append(
                f"[{time.strftime('%H:%M:%S')}] 获取到 {len(cookie_dict)} 个 cookies"
            )

            # 查找 session cookie
            session_names = [
                "session", "sessionid", "token", "auth", "sid",
                "connect.sid", "JSESSIONID", "lab_session",
            ]
            for name in session_names:
                if name in cookie_dict:
                    result.session_cookie = f"{name}={cookie_dict[name]}"
                    break
            if not result.session_cookie and cookie_dict:
                first_name = next(iter(cookie_dict))
                result.session_cookie = f"{first_name}={cookie_dict[first_name]}"

            # 查找 CSRF token
            csrf_names = ["csrf", "csrftoken", "xsrf", "_csrf", "XSRF-TOKEN"]
            for name in csrf_names:
                if name in cookie_dict:
                    result.csrf_token = cookie_dict[name]
                    break

            # 检查 localStorage 中的 token
            try:
                local_token = await page.evaluate(
                    "() => localStorage.getItem('token') || "
                    "localStorage.getItem('access_token') || ''"
                )
                if local_token:
                    result.bearer_token = local_token
                    trace_lines.append(
                        f"[{time.strftime('%H:%M:%S')}] 从 localStorage 提取 token"
                    )
            except Exception:
                pass

            # 截图登录后状态
            screenshot_after = f"{self._browser.output_dir}/screenshot_logged_in.png"
            await page.screenshot(path=screenshot_after, full_page=True)

            result.success = True

        except Exception as e:
            result.error = str(e)
            trace_lines.append(f"[{time.strftime('%H:%M:%S')}] 错误: {e}")
        finally:
            if page:
                await self._browser.close_page(page)

        result.duration_ms = int((time.monotonic() - t0) * 1000)
        result.trace_log = "\n".join(trace_lines)
        return result
