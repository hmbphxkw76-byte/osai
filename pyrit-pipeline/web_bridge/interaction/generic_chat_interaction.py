# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""通用聊天 UI 交互函数。.

提供从 TargetProfile.interaction 配置生成的 interaction_func 闭包,
符合 PlaywrightTarget.InteractionFunction Protocol 的签名:
  async def __call__(page: Page, message: Message) -> str

对齐 doc/code/targets/10_1_playwright_target.py 的交互模式:
  1. 记录当前 AI 消息数量
  2. 填充输入框
  3. 点击发送按钮
  4. 等待新消息出现
  5. 提取响应文本
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from web_bridge.targets.target_profile import InteractionConfig

if TYPE_CHECKING:
    from playwright.async_api import Page
    from pyrit.models import Message

logger = logging.getLogger(__name__)

# Type alias for the interaction function signature expected by PlaywrightTarget
InteractionFunc = Callable[["Page", "Message"], Awaitable[str]]


class GenericChatInteraction:
    """通用聊天 UI 交互函数生成器。.

    从 InteractionConfig 生成符合 PlaywrightTarget.InteractionFunction
    Protocol 的异步闭包。

    支持:
      - 多种输入框类型: textarea, contenteditable, input
      - 多种发送方式: 按钮点击, 键盘快捷键
      - 多种响应等待策略: new_element, text_stable, loading_gone
      - 响应文本提取: 从子选择器或整个容器提取
    """

    @staticmethod
    def create(interaction_config: InteractionConfig) -> InteractionFunc:
        """从配置创建 interaction_func 闭包。.

        Args:
            interaction_config: TargetProfile.interaction 配置。

        Returns:
            符合 InteractionFunction Protocol 的异步函数。
        """
        input_cfg = interaction_config.input
        send_cfg = interaction_config.send
        response_cfg = interaction_config.response
        extraction_cfg = interaction_config.extraction

        input_selector = input_cfg.selector
        input_type = input_cfg.type
        send_selector = send_cfg.selector
        keyboard_shortcut = send_cfg.keyboard_shortcut
        response_selector = response_cfg.selector
        wait_strategy = response_cfg.wait_strategy
        stability_threshold_ms = response_cfg.stability_threshold_ms
        loading_selector = response_cfg.loading_selector
        text_selector = extraction_cfg.text_selector

        async def interaction_func(page: Page, message: Message) -> str:
            # 1. 获取 prompt 文本
            prompt_text = message.message_pieces[0].converted_value
            logger.debug(f"GenericChatInteraction: sending prompt ({len(prompt_text)} chars)")

            # 2. 记录当前 AI 消息数量 (用于检测新消息)
            initial_count = len(await page.query_selector_all(response_selector))

            # 3. 等待输入框就绪
            await page.wait_for_selector(input_selector, state="visible")

            # 4. 填充输入框
            if input_type == "contenteditable":
                await page.click(input_selector)
                await page.type(input_selector, prompt_text)
            else:
                await page.fill(input_selector, prompt_text)

            # 5. 发送
            if keyboard_shortcut:
                await page.keyboard.press(keyboard_shortcut)
            else:
                await page.click(send_selector)

            # 6. 等待响应完成
            if wait_strategy == "new_element":
                await GenericChatInteraction._wait_for_new_element(page, response_selector, initial_count)
            elif wait_strategy == "text_stable":
                await GenericChatInteraction._wait_for_text_stable(page, response_selector, stability_threshold_ms)
            elif wait_strategy == "loading_gone":
                if loading_selector:
                    await page.wait_for_selector(loading_selector, state="hidden")
                # 还要等待新消息出现
                await GenericChatInteraction._wait_for_new_element(page, response_selector, initial_count)
            else:
                logger.warning(f"Unknown wait_strategy: {wait_strategy}, falling back to new_element")
                await GenericChatInteraction._wait_for_new_element(page, response_selector, initial_count)

            # 7. 提取响应文本
            last_response = await page.query_selector(f"{response_selector}:last-child")
            if last_response is None:
                logger.error(f"GenericChatInteraction: no response element found with selector '{response_selector}'")
                return ""

            if text_selector:
                text_el = await last_response.query_selector(text_selector)
                if text_el:
                    text = await text_el.text_content()
                    return text.strip() if text else ""
                else:
                    logger.warning(f"text_selector '{text_selector}' not found in response, using container text")

            text = await last_response.text_content()
            return text.strip() if text else ""

        return interaction_func

    @staticmethod
    async def _wait_for_new_element(
        page: Page,
        selector: str,
        initial_count: int,
        timeout_seconds: int = 120,
    ) -> None:
        """等待新消息出现 (对齐 doc/code/targets/10_1_playwright_target.py 的模式)。.

        使用 page.wait_for_function 检测消息数量增加。
        """
        # 转义 CSS 选择器中的特殊字符用于 JavaScript
        js_selector = selector.replace("'", "\\'")
        await page.wait_for_function(
            f"document.querySelectorAll('{js_selector}').length > {initial_count}",
            timeout=timeout_seconds * 1000,
        )

    @staticmethod
    async def _wait_for_text_stable(
        page: Page,
        selector: str,
        threshold_ms: int,
        timeout_seconds: int = 120,
    ) -> None:
        """等待文本内容稳定 (在 threshold_ms 内不再变化)。.

        适用于流式响应: AI 逐步生成文本, 等待文本不再变化后认为完成。
        """
        import time

        last_text = ""
        stable_since: float | None = None
        start = time.time()

        while time.time() - start < timeout_seconds:
            elements = await page.query_selector_all(selector)
            if elements:
                last_el = elements[-1]
                text = await last_el.text_content() or ""
                if text == last_text and text:
                    if stable_since is None:
                        stable_since = time.time()
                    elif (time.time() - stable_since) * 1000 >= threshold_ms:
                        return
                else:
                    stable_since = None
                    last_text = text
            await asyncio.sleep(0.5)

        logger.warning(f"_wait_for_text_stable: timed out after {timeout_seconds}s")
