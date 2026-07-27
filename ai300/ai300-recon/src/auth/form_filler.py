# -*- coding: utf-8 -*-
"""
Login Form Filler
=================

在检测到登录页后，自动填充用户名和密码。

约束：
  - 仅执行填充操作，绝不点击登录按钮或提交表单。
  - 点击登录、短信/图片验证码、滑块/拼图等二次验证由用户人工完成。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from src.dom import LOGIN_PAGE_SELECTORS
from src.utils import truncate_error

logger = logging.getLogger(__name__)


async def fill_login_form(
    page: Any,
    username: str,
    password: str,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    自动填充登录表单。

    Args:
        page: Playwright Page 对象。
        username: 用户名/账号/手机号/学号。
        password: 密码。
        config: 全局配置，用于读取日志截断长度等参数。

    Returns:
        {
            "filled_username": bool,
            "filled_password": bool,
            "username_selector": str,
            "password_selector": str,
        }
    """
    username_selector = await _find_visible_selector(page, LOGIN_PAGE_SELECTORS["username"])
    password_selector = await _find_visible_selector(page, LOGIN_PAGE_SELECTORS["password"])

    filled_username = False
    filled_password = False

    if username_selector and username:
        try:
            await page.fill(username_selector, "")
            await page.fill(username_selector, username)
            filled_username = True
            logger.info("Filled username into: %s", username_selector)
        except Exception as exc:
            logger.warning("Failed to fill username into %s: %s", username_selector, truncate_error(str(exc), config))
    else:
        logger.debug("No visible username field found or username not provided")

    if password_selector and password:
        try:
            await page.fill(password_selector, "")
            await page.fill(password_selector, password)
            filled_password = True
            logger.info("Filled password into: %s", password_selector)
        except Exception as exc:
            logger.warning("Failed to fill password into %s: %s", password_selector, truncate_error(str(exc), config))
    else:
        logger.debug("No visible password field found or password not provided")

    return {
        "filled_username": filled_username,
        "filled_password": filled_password,
        "username_selector": username_selector,
        "password_selector": password_selector,
    }


async def _find_visible_selector(page: Any, selectors: list) -> str:
    """从选择器列表中找到第一个可见元素对应的选择器。"""
    for selector in selectors:
        try:
            el = await page.query_selector(selector)
            if el and await el.is_visible():
                return selector
        except Exception:
            continue
    return ""
