# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AuthDetector 单元测试。.

测试四种检测策略和 AuthDetector 轮询逻辑。
使用 Mock Page 对象, 不需要真实浏览器。
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from web_bridge.auth.auth_detector import (
    AuthDetector,
    AuthDetectorFactory,
    CookiePresenceStrategy,
    DOMElementStrategy,
    NetworkTokenStrategy,
    URLPatternStrategy,
)
from web_bridge.targets.target_profile import DetectionConfig


class TestURLPatternStrategy:
    """URL 模式匹配策略测试。."""

    @pytest.mark.asyncio
    async def test_url_matches_pattern(self) -> None:
        """测试 URL 匹配正则时返回 True。."""
        page = MagicMock()
        page.url = "https://example.com/chat"
        strategy = URLPatternStrategy(pattern=r"example\.com/chat")

        result = await strategy.is_auth_complete(page)
        assert result is True

    @pytest.mark.asyncio
    async def test_url_does_not_match_pattern(self) -> None:
        """测试 URL 不匹配正则时返回 False。."""
        page = MagicMock()
        page.url = "https://example.com/login"
        strategy = URLPatternStrategy(pattern=r"example\.com/chat")

        result = await strategy.is_auth_complete(page)
        assert result is False

    @pytest.mark.asyncio
    async def test_pattern_with_regex_groups(self) -> None:
        """测试带正则分组的模式。."""
        page = MagicMock()
        page.url = "https://example.com/dashboard"
        strategy = URLPatternStrategy(pattern=r"example\.com/(chat|home|dashboard)")

        result = await strategy.is_auth_complete(page)
        assert result is True


class TestDOMElementStrategy:
    """DOM 元素存在策略测试。."""

    @pytest.mark.asyncio
    async def test_element_found(self) -> None:
        """测试元素存在时返回 True。."""
        page = MagicMock()
        page.query_selector = AsyncMock(return_value=MagicMock())
        strategy = DOMElementStrategy(selector=".chat-container")

        result = await strategy.is_auth_complete(page)
        assert result is True

    @pytest.mark.asyncio
    async def test_element_not_found(self) -> None:
        """测试元素不存在时返回 False。."""
        page = MagicMock()
        page.query_selector = AsyncMock(return_value=None)
        strategy = DOMElementStrategy(selector=".chat-container")

        result = await strategy.is_auth_complete(page)
        assert result is False

    @pytest.mark.asyncio
    async def test_element_query_raises(self) -> None:
        """测试查询异常时返回 False。."""
        page = MagicMock()
        page.query_selector = AsyncMock(side_effect=Exception("timeout"))
        strategy = DOMElementStrategy(selector=".chat-container")

        result = await strategy.is_auth_complete(page)
        assert result is False


class TestCookiePresenceStrategy:
    """Cookie 存在策略测试。."""

    @pytest.mark.asyncio
    async def test_all_cookies_present(self) -> None:
        """测试所有 Cookie 存在时返回 True。."""
        page = MagicMock()
        page.context = MagicMock()
        page.context.cookies = AsyncMock(
            return_value=[
                {"name": "session_id", "value": "abc", "domain": "example.com"},
                {"name": "auth_token", "value": "xyz", "domain": "example.com"},
            ]
        )
        strategy = CookiePresenceStrategy(
            cookie_names=["session_id", "auth_token"],
            domain="example.com",
        )

        result = await strategy.is_auth_complete(page)
        assert result is True

    @pytest.mark.asyncio
    async def test_some_cookies_missing(self) -> None:
        """测试部分 Cookie 缺失时返回 False。."""
        page = MagicMock()
        page.context = MagicMock()
        page.context.cookies = AsyncMock(
            return_value=[
                {"name": "session_id", "value": "abc", "domain": "example.com"},
            ]
        )
        strategy = CookiePresenceStrategy(
            cookie_names=["session_id", "auth_token"],
            domain="example.com",
        )

        result = await strategy.is_auth_complete(page)
        assert result is False

    @pytest.mark.asyncio
    async def test_domain_filter(self) -> None:
        """测试域名过滤。."""
        page = MagicMock()
        page.context = MagicMock()
        page.context.cookies = AsyncMock(
            return_value=[
                {"name": "session_id", "value": "abc", "domain": "other.com"},
            ]
        )
        strategy = CookiePresenceStrategy(
            cookie_names=["session_id"],
            domain="example.com",
        )

        result = await strategy.is_auth_complete(page)
        assert result is False


class TestNetworkTokenStrategy:
    """网络 Token 拦截策略测试。."""

    @pytest.mark.asyncio
    async def test_token_not_captured(self) -> None:
        """测试未捕获到 Token 时返回 False。."""
        strategy = NetworkTokenStrategy()
        page = MagicMock()

        result = await strategy.is_auth_complete(page)
        assert result is False

    @pytest.mark.asyncio
    async def test_token_captured(self) -> None:
        """测试捕获到 Token 后返回 True。."""
        strategy = NetworkTokenStrategy()
        page = MagicMock()
        # 模拟捕获 Token
        strategy._captured_token = "fake_token_123"

        result = await strategy.is_auth_complete(page)
        assert result is True

    def test_attach_to_page(self) -> None:
        """测试附加响应处理器到 Page。."""
        strategy = NetworkTokenStrategy()
        page = MagicMock()
        page.on = MagicMock()

        strategy.attach_to_page(page)
        page.on.assert_called_once()
        args, kwargs = page.on.call_args
        assert args[0] == "response"
        assert callable(args[1])


class TestAuthDetector:
    """AuthDetector 轮询逻辑测试。."""

    @pytest.mark.asyncio
    async def test_immediate_success(self) -> None:
        """测试策略立即满足时快速返回。."""
        strategy = MagicMock()
        strategy.is_auth_complete = AsyncMock(return_value=True)
        strategy.check_immediate = AsyncMock(return_value=True)

        detector = AuthDetector(strategies=[strategy], poll_interval_seconds=0.1, timeout_seconds=5)
        page = MagicMock()

        result = await detector.wait_for_completion(page)
        assert result is True

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        """测试超时返回 False。."""
        strategy = MagicMock()
        strategy.is_auth_complete = AsyncMock(return_value=False)
        strategy.check_immediate = AsyncMock(return_value=False)

        detector = AuthDetector(strategies=[strategy], poll_interval_seconds=0.05, timeout_seconds=1)
        page = MagicMock()

        result = await detector.wait_for_completion(page)
        assert result is False

    @pytest.mark.asyncio
    async def test_eventual_success(self) -> None:
        """测试轮询多次后最终成功。."""
        call_count = 0

        class EventualStrategy:
            async def is_auth_complete(self, page: Any) -> bool:
                nonlocal call_count
                call_count += 1
                return call_count >= 3

            async def check_immediate(self, page: Any) -> bool:
                return await self.is_auth_complete(page)

        detector = AuthDetector(
            strategies=[EventualStrategy()],
            poll_interval_seconds=0.05,
            timeout_seconds=5,
        )
        page = MagicMock()

        result = await detector.wait_for_completion(page)
        assert result is True
        assert call_count >= 3

    @pytest.mark.asyncio
    async def test_multiple_strategies_or_logic(self) -> None:
        """测试多策略 OR 逻辑: 任一满足即返回 True。."""
        strategy1 = MagicMock()
        strategy1.is_auth_complete = AsyncMock(return_value=False)
        strategy1.check_immediate = AsyncMock(return_value=False)

        strategy2 = MagicMock()
        strategy2.is_auth_complete = AsyncMock(return_value=True)
        strategy2.check_immediate = AsyncMock(return_value=True)

        detector = AuthDetector(
            strategies=[strategy1, strategy2],
            poll_interval_seconds=0.1,
            timeout_seconds=5,
        )
        page = MagicMock()

        result = await detector.wait_for_completion(page)
        assert result is True

    @pytest.mark.asyncio
    async def test_check_immediate(self) -> None:
        """测试一次性检测。."""
        strategy = MagicMock()
        strategy.check_immediate = AsyncMock(return_value=True)

        detector = AuthDetector(strategies=[strategy])
        page = MagicMock()

        result = await detector.check_immediate(page)
        assert result is True

    def test_empty_strategies_raises(self) -> None:
        """测试空策略列表抛出异常。."""
        with pytest.raises(ValueError, match="at least one strategy"):
            AuthDetector(strategies=[])


class TestAuthDetectorFactory:
    """AuthDetectorFactory 测试。."""

    def test_from_configs_url_pattern(self) -> None:
        """测试从 url_pattern 配置创建策略。."""
        configs = [DetectionConfig(strategy="url_pattern", pattern="example\\.com/chat")]
        detector = AuthDetectorFactory.from_configs(configs)
        assert len(detector._strategies) == 1
        assert isinstance(detector._strategies[0], URLPatternStrategy)

    def test_from_configs_dom_element(self) -> None:
        """测试从 dom_element 配置创建策略。."""
        configs = [DetectionConfig(strategy="dom_element", selector=".chat")]
        detector = AuthDetectorFactory.from_configs(configs)
        assert isinstance(detector._strategies[0], DOMElementStrategy)

    def test_from_configs_cookie_presence(self) -> None:
        """测试从 cookie_presence 配置创建策略。."""
        configs = [DetectionConfig(strategy="cookie_presence", cookie_names=["sid"])]
        detector = AuthDetectorFactory.from_configs(configs)
        assert isinstance(detector._strategies[0], CookiePresenceStrategy)

    def test_from_configs_multiple(self) -> None:
        """测试多策略组合。."""
        configs = [
            DetectionConfig(strategy="url_pattern", pattern="test"),
            DetectionConfig(strategy="dom_element", selector=".chat"),
            DetectionConfig(strategy="cookie_presence", cookie_names=["sid"]),
        ]
        detector = AuthDetectorFactory.from_configs(configs)
        assert len(detector._strategies) == 3

    def test_from_configs_missing_pattern_skips(self) -> None:
        """测试缺少必填字段时跳过该策略。."""
        configs = [DetectionConfig(strategy="url_pattern")]  # 缺少 pattern
        with pytest.raises(ValueError, match="No valid detection strategies"):
            AuthDetectorFactory.from_configs(configs)

    def test_from_configs_unknown_strategy_skips(self) -> None:
        """测试未知策略类型时跳过。."""
        configs = [DetectionConfig(strategy="unknown_strategy")]
        with pytest.raises(ValueError, match="No valid detection strategies"):
            AuthDetectorFactory.from_configs(configs)
