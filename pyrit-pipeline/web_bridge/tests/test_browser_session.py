# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""BrowserSession 单元测试。.

测试浏览器会话管理器的配置和状态管理逻辑。
不启动真实浏览器, 只测试逻辑路径。
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from web_bridge.auth.browser_session import BrowserSession


class TestBrowserSession:
    """BrowserSession 测试。."""

    def test_init_default_state(self) -> None:
        """测试初始化默认状态。."""
        session = BrowserSession()
        assert session._playwright is None
        assert session._browser is None
        assert session._context is None
        assert session._page is None
        assert session._subprocess is None
        assert session._owns_browser is False

    @pytest.mark.asyncio
    async def test_close_no_resources(self) -> None:
        """测试无资源时 close 不报错。."""
        session = BrowserSession()
        await session.close()  # 不应该抛出异常

    @pytest.mark.asyncio
    async def test_close_with_resources(self) -> None:
        """测试有资源时 close 正确清理。."""
        session = BrowserSession()

        # Mock 资源
        session._page = MagicMock()
        session._page.close = AsyncMock()
        session._context = MagicMock()
        session._context.close = AsyncMock()
        session._browser = MagicMock()
        session._browser.close = AsyncMock()
        session._playwright = MagicMock()
        session._playwright.stop = AsyncMock()
        session._owns_browser = True

        await session.close()

        session._page.close.assert_called_once()
        session._context.close.assert_called_once()
        session._browser.close.assert_called_once()
        session._playwright.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_save_storage_state(self, tmp_path: Path) -> None:
        """测试保存认证状态。."""
        session = BrowserSession()

        context = MagicMock()
        context.storage_state = AsyncMock()

        path = str(tmp_path / "state.json")
        await session.save_storage_state(context, path)

        context.storage_state.assert_called_once()
        args, kwargs = context.storage_state.call_args
        assert path in kwargs.get("path", "") or path in str(args)

    @pytest.mark.asyncio
    async def test_restore_storage_state_file_not_found(self) -> None:
        """测试恢复不存在的文件时抛出异常。."""
        session = BrowserSession()

        with pytest.raises(FileNotFoundError, match="Storage state file not found"):
            await session.restore_storage_state("/nonexistent/path/state.json")

    @pytest.mark.asyncio
    async def test_navigate_cross_domain(self) -> None:
        """测试跨域导航。."""
        session = BrowserSession()

        page = MagicMock()
        page.goto = AsyncMock()
        page.url = "https://app.example.com/chat"
        page.on = MagicMock()
        page.remove_listener = MagicMock()

        # Mock framenavigated callback
        main_frame = MagicMock()
        page.main_frame = main_frame

        result = await session.navigate_cross_domain(
            page,
            "https://app.example.com/login",
            expected_final_domain="app.example.com",
            timeout_seconds=2,
        )

        page.goto.assert_called_once()
        page.on.assert_called_once()
        assert result == page

    @pytest.mark.asyncio
    async def test_navigate_cross_domain_timeout(self) -> None:
        """测试跨域导航超时 (未到达期望域名)。."""
        session = BrowserSession()

        page = MagicMock()
        page.goto = AsyncMock()
        page.url = "https://other.com/somepage"  # 不会匹配 expected_final_domain
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.main_frame = MagicMock()

        result = await session.navigate_cross_domain(
            page,
            "https://app.example.com/login",
            expected_final_domain="app.example.com",
            timeout_seconds=1,  # 短超时
        )

        # 应该返回 page (即使超时, 不报错)
        assert result == page


class TestBrowserExecutableDetection:
    """浏览器可执行文件检测测试。."""

    def test_find_browser_executable_returns_path(self) -> None:
        """测试 _find_browser_executable 返回路径 (或抛出异常)。."""
        # 这个测试不依赖真实浏览器, 只验证方法存在且可调用
        try:
            path = BrowserSession._find_browser_executable()
            assert isinstance(path, str)
            assert len(path) > 0
        except RuntimeError:
            # 如果系统上没有浏览器, 抛出 RuntimeError 是预期行为
            pass
