# -*- coding: utf-8 -*-
"""
阶段 3：浏览器导航

启动 Playwright 浏览器，注入已有凭据，导航到目标 URL。
增强：导航后若检测到登录页，自动填充用户名/密码（如已配置），
      并等待用户人工完成点击登录及二次验证（验证码/滑块/拼图）。
"""

from __future__ import annotations

import asyncio
import logging

from src.auth import fill_login_form
from src.browser_manager import BrowserManager
from src.dom import DOMDetector
from src.utils import truncate_error, wait_for_manual_login

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class NavigationStage(PipelineStage):
    """浏览器导航阶段"""

    name = "navigation"
    description = "启动浏览器并导航到目标"

    async def run(self, context: PipelineContext) -> StageResult:
        if context.target_type == "api":
            return StageResult(
                success=True,
                skipped=True,
                message="API 目标无需浏览器导航",
                data={},
            )

        headless = context.headless
        auth_profile = context.auth_profile
        storage_state = self._config(context, "storage_state") or self._config(context, "latest_storage_state")

        connection = self._config(context, "browser_connection", {})
        browser = BrowserManager(
            headless=headless,
            auth_profile=auth_profile,
            storage_state_path=storage_state,
            config=context.config,
        )
        await browser.start(url=context.target_url, connection=connection)

        context.browser_manager = browser
        context.page = browser.page

        page = browser.page
        if not page:
            return StageResult(success=False, message="页面未初始化")

        # 导航后立即检测登录页；若处于登录页则自动填充并等待人工完成登录
        spa_config = self._config(context, "spa_config", {})
        detector = DOMDetector(page, spa_config)
        is_login = await detector.is_login_page()

        if is_login:
            login_result = await self._handle_login_page(context, page, detector)
            if login_result:
                return login_result

        url = page.url
        title = await page.title()

        return StageResult(
            success=True,
            message=f"已导航到 {url}",
            data={"url": url, "title": title},
        )

    async def _handle_login_page(
        self,
        context: PipelineContext,
        page: Any,
        detector: DOMDetector,
    ) -> StageResult:
        """处理登录页：自动填充凭据并尝试自动点击登录，无验证码时实现全自动登录。"""
        username = self._config(context, "username", "")
        password = self._config(context, "password", "")
        has_creds = bool(username and password)

        if has_creds:
            try:
                fill_result = await fill_login_form(page, username, password, config=context.config)
                logger.info("Auto-filled login form: %s", fill_result)
            except Exception as exc:
                logger.warning("Failed to auto-fill login form: %s", truncate_error(str(exc), context.config))

            # 在未检测到验证码时，尝试自动点击登录按钮，实现全自动登录
            try:
                clicked = await self._try_auto_login_click(page, detector)
                if clicked:
                    logger.info("Auto-clicked login button")
                    # 给页面跳转/SSO 一点响应时间
                    await asyncio.sleep(2)
            except Exception as exc:
                logger.debug("Auto login click failed: %s", truncate_error(str(exc), context.config))

        wait_result = await wait_for_manual_login(
            page,
            detector,
            timeout_ms=self._spa_config(context, "manual_login_timeout_ms", 300000),
            poll_interval_ms=self._spa_config(context, "manual_login_poll_ms", 2000),
            require_enter=self._spa_config(context, "manual_login_require_enter", False),
            target_url=context.target_url,
            captcha_selectors=self._spa_config(context, "captcha_selectors", None),
            config=context.config,
        )
        context.config["_manual_login_wait_result"] = wait_result

        if not wait_result.get("login_resolved"):
            return StageResult(
                success=False,
                message="登录未完成或超时",
                data={"wait_result": wait_result},
            )

        # 重新检测，确认已离开登录页
        spa_config = self._config(context, "spa_config", {})
        detector = DOMDetector(context.page, spa_config)
        if await detector.is_login_page():
            return StageResult(
                success=False,
                message="登录后仍在登录页，请确认登录成功",
                data={"wait_result": wait_result},
            )

        return StageResult(
            success=True,
            message=f"登录完成，当前页面: {page.url}",
            data={"wait_result": wait_result},
        )

    async def _try_auto_login_click(self, page: Any, detector: DOMDetector) -> bool:
        """在未检测到验证码时尝试自动点击登录按钮。"""
        from src.utils.login_waiter import CAPTCHA_SELECTORS

        # 若存在验证码元素，则放弃自动点击，等待人工处理
        for selector in CAPTCHA_SELECTORS:
            try:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    logger.info("Captcha element detected, skipping auto-login click")
                    return False
            except Exception:
                continue

        login_button_selectors = [
            "button[type='submit']",
            "input[type='submit']",
            "button.login-btn",
            ".submit-btn",
            "button:has-text('登录')",
            "button:has-text('Login')",
            "button:has-text('Sign in')",
            "button:has-text('登 录')",
            "a:has-text('登录')",
            "div[role='button']:has-text('登录')",
        ]

        for selector in login_button_selectors:
            try:
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    await el.scroll_into_view_if_needed()
                    await el.click(timeout=5000)
                    return True
            except Exception:
                continue

        # 兜底：直接提交表单
        try:
            await page.evaluate("() => { const f = document.querySelector('form'); if (f) f.submit(); }")
            return True
        except Exception:
            return False
