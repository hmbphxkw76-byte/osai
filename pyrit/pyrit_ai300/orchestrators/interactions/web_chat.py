# -*- coding: utf-8 -*-
"""
AI-300 Framework - Web Chat Interaction
Web 聊天界面交互函数：输入框 + 发送按钮 + 响应区

适用于大多数基于 Web 的聊天界面（包括 SPA 架构）。
通过参数化选择器适配不同站点，无需为每个站点编写新函数。

使用方式：
    # 在 target config 中声明选择器
    selectors:
      input: "#chat-input"
      send_button: "#send-btn"
      response: ".response-text"

    # 创建 interaction_func
    interaction_func = create_web_chat_interaction(selectors)

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import os
import sys
import logging
from typing import TYPE_CHECKING, Dict

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

if TYPE_CHECKING:
    from playwright.async_api import Page
    from pyrit.models import Message

logger = logging.getLogger(__name__)


def create_web_chat_interaction(
    selectors: Dict[str, str],
    wait_timeout: int = 10000,
    response_wait_delay: float = 1.0,
):
    """
    创建 Web 聊天界面交互函数（工厂模式）

    根据选择器配置生成针对特定站点的交互函数。
    同一交互模式的不同站点复用此函数，仅选择器不同。

    Args:
        selectors: 选择器配置
            - input: 输入框选择器
            - send_button: 发送按钮选择器
            - response: 响应区域选择器
        wait_timeout: 等待响应的超时时间（毫秒）
        response_wait_delay: 发送后等待响应开始的延迟（秒）

    Returns:
        交互函数 (page, message) -> str

    Example:
        interaction_func = create_web_chat_interaction({
            "input": "#chat-input",
            "send_button": "#send-btn",
            "response": ".ai-response",
        })
    """
    default_input = "textarea, input[type='text'], [contenteditable='true']"
    default_send = "button[type='submit'], .send-btn, [aria-label='Send']"
    default_response = ".response, .ai-message, .assistant-message"

    input_selector = selectors.get("input", default_input)
    send_selector = selectors.get("send_button", default_send)
    response_selector = selectors.get("response", default_response)

    async def web_chat_interaction(page: "Page", message: "Message") -> str:
        """
        Web 聊天界面交互函数

        Args:
            page: Playwright 页面对象
            message: PyRIT 消息对象

        Returns:
            响应文本
        """
        prompt = message.request_pieces[0].converted_value

        try:
            # 1. 等待输入框可用
            await page.wait_for_selector(input_selector, state="visible", timeout=wait_timeout)

            # 2. 清空输入框并填入 prompt
            await page.click(input_selector)
            await page.fill(input_selector, "")

            # 使用 type 模拟真实输入（某些 SPA 需要）
            await page.type(input_selector, prompt, delay=10)

            logger.debug("Filled prompt into %s", input_selector)

            # 3. 点击发送按钮
            await page.wait_for_selector(send_selector, state="visible", timeout=wait_timeout)
            await page.click(send_selector)

            logger.debug("Clicked send button: %s", send_selector)

            # 4. 等待响应出现
            await page.wait_for_selector(response_selector, state="visible", timeout=wait_timeout)

            # 额外等待确保响应完整渲染
            if response_wait_delay > 0:
                await page.wait_for_timeout(int(response_wait_delay * 1000))

            # 5. 提取响应文本
            response_text = await page.inner_text(response_selector)

            logger.debug("Got response: %d chars", len(response_text))
            return response_text.strip()

        except Exception as e:
            logger.error("Web chat interaction failed: %s", str(e))
            raise RuntimeError(f"Web chat interaction failed: {str(e)}") from e

    return web_chat_interaction


async def web_chat_interaction_default(page: "Page", message: "Message") -> str:
    """
    默认 Web 聊天界面交互函数（使用通用选择器）

    适用于标准聊天界面，无需配置选择器。
    作为 fallback 使用。
    """
    selectors = {
        "input": "textarea, input[type='text'], [contenteditable='true']",
        "send_button": "button[type='submit'], .send-btn",
        "response": ".response, .ai-message, .assistant-message",
    }
    interaction_func = create_web_chat_interaction(selectors)
    return await interaction_func(page, message)
