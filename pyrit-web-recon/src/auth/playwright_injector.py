# -*- coding: utf-8 -*-
"""
Playwright Auth Injector
========================

将 AuthProfile 注入 Playwright 浏览器上下文。

策略：
  - Cookie → context.add_cookies()
  - Authorization / 自定义头 → page.set_extra_http_headers()
  - 组合认证 → 同时注入 Cookie 和 Header
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page

    from .header_parser import AuthProfile

logger = logging.getLogger(__name__)


async def inject_auth(
    context: "BrowserContext",
    page: "Page",
    auth_profile: "AuthProfile",
) -> None:
    """将认证信息注入 Playwright 浏览器"""
    if not auth_profile.has_auth():
        logger.debug("No auth info to inject")
        return

    try:
        if auth_profile.cookies:
            await context.add_cookies(auth_profile.cookies)
            logger.debug("Injected %d cookies for %s", len(auth_profile.cookies), auth_profile.host)

        if auth_profile.headers:
            await page.set_extra_http_headers(auth_profile.headers)
            logger.debug("Injected %d headers", len(auth_profile.headers))

        logger.info("Auth injected: %s", auth_profile.summary())
    except Exception as e:
        logger.error("Failed to inject auth: %s", str(e))
        raise RuntimeError(f"Auth injection failed: {str(e)}") from e
