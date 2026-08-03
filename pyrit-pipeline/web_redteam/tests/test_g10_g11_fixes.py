# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""G10 + G11 修复验证测试。

G10: SameDomainAuthStrategy.execute() 在导航前调用 detector.attach_to_page()。
G11: AuthProbe._poll_url_during_settle() 捕获 SPA 客户端路由变化。
"""

from __future__ import annotations

import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from web_redteam.auth.auth_detector import AuthDetector
from web_redteam.auth.auth_probe import AuthProbe
from web_redteam.auth.auth_strategy import SameDomainAuthStrategy


class TestG10SameDomainAttachToPage:
    """G10: SameDomainAuthStrategy 导航前调用 attach_to_page。."""

    @pytest.mark.asyncio
    async def test_attach_to_page_called_before_authenticate(self) -> None:
        """验证 SameDomainAuthStrategy 在 authenticate 前调用 attach_to_page。."""
        strategy = SameDomainAuthStrategy()

        page = MagicMock()
        page.goto = AsyncMock()

        profile = MagicMock()
        profile.auth.type = "same_domain"
        profile.auth.login_url = "https://example.com/login"
        profile.auth.target_url = "https://example.com/chat"
        profile.auth.auto_fill = {}
        profile.auth.human_assisted_steps = []
        profile.auth.cross_domain.redirect_chain = []
        profile.get_detection_configs.return_value = []

        # Mock detector
        detector = MagicMock(spec=AuthDetector)
        detector.attach_to_page = AsyncMock()
        detector.wait_for_completion = AsyncMock(return_value=True)
        detector.check_immediate = AsyncMock(return_value=False)

        with (
            patch.object(strategy, "_create_detector", return_value=detector),
            patch.object(strategy._human_auth, "authenticate", new_callable=AsyncMock) as mock_auth,
        ):
            mock_auth.return_value = page
            await strategy.execute(page, profile)

        # G10: attach_to_page 必须在 authenticate 之前被调用
        detector.attach_to_page.assert_called_once_with(page)
        mock_auth.assert_called_once()


class TestG11AuthProbeSPARouting:
    """G11: AuthProbe SPA 客户端路由检测。."""

    @pytest.mark.asyncio
    async def test_poll_url_detects_spa_route(self) -> None:
        """验证 _poll_url_during_settle 捕获 SPA 路由变化。."""
        probe = AuthProbe(settle_wait_ms=600)

        page = MagicMock()
        # 模拟 SPA 路由: URL 在 settle 期间变化
        urls = [
            "https://app.com/chat",
            "https://app.com/chat",
            "https://sso.idp.com/login",  # SPA 路由跳转到 IdP
        ]
        url_iter = iter(urls)
        page.url = next(url_iter)

        # 每次 sleep 后更新 URL
        async def mock_sleep(seconds: float) -> None:
            with contextlib.suppress(StopIteration):
                page.url = next(url_iter)

        with patch("web_redteam.auth.auth_probe.asyncio.sleep", new=mock_sleep):
            domain_transitions = ["app.com"]
            await probe._poll_url_during_settle(page, domain_transitions)

        # 应该检测到 sso.idp.com 的域名变化
        assert "sso.idp.com" in domain_transitions

    @pytest.mark.asyncio
    async def test_poll_url_no_change(self) -> None:
        """验证 URL 不变时不添加重复域名。."""
        probe = AuthProbe(settle_wait_ms=400)

        page = MagicMock()
        page.url = "https://example.com/chat"

        with patch("web_redteam.auth.auth_probe.asyncio.sleep", new=AsyncMock()):
            domain_transitions = ["example.com"]
            await probe._poll_url_during_settle(page, domain_transitions)

        # 不应该有重复
        assert domain_transitions == ["example.com"]
