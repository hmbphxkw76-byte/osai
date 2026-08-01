# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""InteractionFactory 单元测试。.

测试从 InteractionConfig 生成的 interaction_func 闭包行为。
使用 Mock Page 对象, 不需要真实浏览器。
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from web_redteam.interaction.interaction_factory import InteractionFactory
from web_redteam.targets.target_profile import (
    ExtractionConfig,
    InputConfig,
    InteractionConfig,
    ResponseConfig,
    SendConfig,
)


def _make_mock_message(text: str = "Hello") -> MagicMock:
    """创建 Mock Message 对象。."""
    piece = MagicMock()
    piece.converted_value = text
    message = MagicMock()
    message.message_pieces = [piece]
    return message


def _make_mock_page(
    input_selector: str = "textarea",
    response_selector: str = "div.response",
    initial_count: int = 0,
    response_text: str = "AI response",
) -> MagicMock:
    """创建 Mock Page 对象。."""
    page = MagicMock()

    # query_selector_all: 返回指定数量的元素
    elements = [MagicMock() for _ in range(initial_count)]
    page.query_selector_all = AsyncMock(return_value=elements)

    # wait_for_selector: 模拟等待
    page.wait_for_selector = AsyncMock()

    # fill: 模拟填充
    page.fill = AsyncMock()

    # click: 模拟点击
    page.click = AsyncMock()

    # type: 模拟输入
    page.type = AsyncMock()

    # keyboard: 模拟键盘
    page.keyboard = MagicMock()
    page.keyboard.press = AsyncMock()

    # wait_for_function: 模拟等待 JS 函数
    page.wait_for_function = AsyncMock()

    # query_selector: 返回最后一个响应元素
    response_element = MagicMock()
    response_element.text_content = AsyncMock(return_value=response_text)
    response_element.query_selector = AsyncMock(return_value=None)
    page.query_selector = AsyncMock(return_value=response_element)

    return page


class TestInteractionFactory:
    """InteractionFactory 测试。."""

    def test_create_returns_callable(self) -> None:
        """测试 create 返回可调用对象。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea#input", type="textarea"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(selector="div.response"),
            extraction=ExtractionConfig(),
        )
        func = InteractionFactory.create(config)
        assert callable(func)

    @pytest.mark.asyncio
    async def test_textarea_input_fill(self) -> None:
        """测试 textarea 类型输入框使用 fill。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea#input", type="textarea"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(selector="div.response", wait_strategy="new_element"),
            extraction=ExtractionConfig(),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page()
        message = _make_mock_message("Test prompt")

        await func(page, message)

        page.fill.assert_called_once_with("textarea#input", "Test prompt")
        page.click.assert_called_once_with("button#send")

    @pytest.mark.asyncio
    async def test_contenteditable_input_click_type(self) -> None:
        """测试 contenteditable 输入框使用 click + type。."""
        config = InteractionConfig(
            input=InputConfig(selector="div[contenteditable]", type="contenteditable"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(selector="div.response", wait_strategy="new_element"),
            extraction=ExtractionConfig(),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page()
        message = _make_mock_message("Test prompt")

        await func(page, message)

        page.click.assert_any_call("div[contenteditable]")
        page.type.assert_called_once_with("div[contenteditable]", "Test prompt")

    @pytest.mark.asyncio
    async def test_keyboard_shortcut_send(self) -> None:
        """测试键盘快捷键发送。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea", type="textarea"),
            send=SendConfig(selector="button#send", keyboard_shortcut="Enter"),
            response=ResponseConfig(selector="div.response", wait_strategy="new_element"),
            extraction=ExtractionConfig(),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page()
        message = _make_mock_message("Test prompt")

        await func(page, message)

        page.keyboard.press.assert_called_once_with("Enter")
        # 不应该点击 send button
        page.click.assert_not_called()

    @pytest.mark.asyncio
    async def test_response_extraction_default(self) -> None:
        """测试默认响应提取 (整个容器 text_content)。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea", type="textarea"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(selector="div.response", wait_strategy="new_element"),
            extraction=ExtractionConfig(text_selector=None),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page(response_text="Default response text")
        message = _make_mock_message("Test prompt")

        result = await func(page, message)

        assert result == "Default response text"

    @pytest.mark.asyncio
    async def test_response_extraction_with_text_selector(self) -> None:
        """测试使用 text_selector 提取响应文本。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea", type="textarea"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(selector="div.response", wait_strategy="new_element"),
            extraction=ExtractionConfig(text_selector="p.text"),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page()

        # 模拟 text_selector 子元素
        text_element = MagicMock()
        text_element.text_content = AsyncMock(return_value="Extracted text")
        response_element = MagicMock()
        response_element.text_content = AsyncMock(return_value="Full container text")
        response_element.query_selector = AsyncMock(return_value=text_element)
        page.query_selector = AsyncMock(return_value=response_element)

        message = _make_mock_message("Test prompt")

        result = await func(page, message)

        assert result == "Extracted text"

    @pytest.mark.asyncio
    async def test_new_element_wait_strategy(self) -> None:
        """测试 new_element 等待策略调用 wait_for_function。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea", type="textarea"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(selector="div.response", wait_strategy="new_element"),
            extraction=ExtractionConfig(),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page()
        message = _make_mock_message("Test prompt")

        await func(page, message)

        page.wait_for_function.assert_called_once()

    @pytest.mark.asyncio
    async def test_loading_gone_wait_strategy(self) -> None:
        """测试 loading_gone 等待策略。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea", type="textarea"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(
                selector="div.response",
                wait_strategy="loading_gone",
                loading_selector=".loading",
            ),
            extraction=ExtractionConfig(),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page()
        message = _make_mock_message("Test prompt")

        await func(page, message)

        # 应该等待 loading selector hidden
        page.wait_for_selector.assert_any_call(".loading", state="hidden")
        # 也应该等待新元素
        page.wait_for_function.assert_called_once()

    @pytest.mark.asyncio
    async def test_empty_response_returns_empty_string(self) -> None:
        """测试无响应元素时返回空字符串。."""
        config = InteractionConfig(
            input=InputConfig(selector="textarea", type="textarea"),
            send=SendConfig(selector="button#send"),
            response=ResponseConfig(selector="div.response", wait_strategy="new_element"),
            extraction=ExtractionConfig(),
        )
        func = InteractionFactory.create(config)

        page = _make_mock_page()
        page.query_selector = AsyncMock(return_value=None)  # 无响应元素

        message = _make_mock_message("Test prompt")

        result = await func(page, message)

        assert result == ""
