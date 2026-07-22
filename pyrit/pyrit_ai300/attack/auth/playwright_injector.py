# -*- coding: utf-8 -*-
"""
AI-300 Framework - Playwright Auth Injector
将 AuthProfile 注入 Playwright 浏览器上下文

认证注入策略：
- Cookie 认证 → context.add_cookies()
- Bearer Token → page.set_extra_http_headers({"Authorization": "Bearer ..."})
- 组合认证 → 同时注入 Cookie 和 Header

设计原则：
- 复用 Playwright 原生 API，不修改浏览器行为
- 注入在导航前完成，确保首请求即带认证
- 支持静默模式（仅记录不输出）

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import os
import sys
import logging
from typing import TYPE_CHECKING

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

if TYPE_CHECKING:
    from playwright.async_api import Browser, BrowserContext, Page

    from .header_parser import AuthProfile

logger = logging.getLogger(__name__)


async def inject_auth(
    context: "BrowserContext",
    page: "Page",
    auth_profile: "AuthProfile",
) -> None:
    """
    将认证信息注入 Playwright 浏览器

    Args:
        context: Playwright 浏览器上下文
        page: Playwright 页面对象
        auth_profile: 认证配置文件

    Raises:
        RuntimeError: 注入失败时
    """
    if not auth_profile.has_auth():
        logger.debug("No auth info to inject")
        return

    try:
        # 1. 注入 Cookie（如果有）
        if auth_profile.cookies:
            await context.add_cookies(auth_profile.cookies)
            logger.debug("Injected %d cookies for %s", len(auth_profile.cookies), auth_profile.host)

        # 2. 注入 HTTP Headers（Authorization 等）
        if auth_profile.headers:
            await page.set_extra_http_headers(auth_profile.headers)
            logger.debug("Injected %d headers", len(auth_profile.headers))

        logger.info("Auth injected: %s", auth_profile.summary())

    except Exception as e:
        logger.error("Failed to inject auth: %s", str(e))
        raise RuntimeError(f"Auth injection failed: {str(e)}") from e


async def create_authenticated_context(
    browser: "Browser",
    auth_profile: "AuthProfile",
) -> "BrowserContext":
    """
    创建带认证状态的浏览器上下文

    Args:
        browser: Playwright 浏览器实例
        auth_profile: 认证配置文件

    Returns:
        已注入认证的浏览器上下文
    """
    context = await browser.new_context()

    # 注入 Cookie
    if auth_profile.cookies:
        await context.add_cookies(auth_profile.cookies)
        logger.debug("Injected %d cookies into new context", len(auth_profile.cookies))

    return context
