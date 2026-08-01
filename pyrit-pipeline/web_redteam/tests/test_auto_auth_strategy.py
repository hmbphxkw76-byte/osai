# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""NoAuthStrategy 和 AutoAuthStrategy 单元测试。.

测试内容:
  - NoAuthStrategy: 直接导航到 target_url, 无认证操作
  - AutoAuthStrategy: 探测 → 委托给具体策略
  - AuthStrategyFactory: 四种类型的工厂创建
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from web_redteam.auth.auth_probe import ProbeResult
from web_redteam.auth.auth_strategy import (
    AuthStrategyFactory,
    AutoAuthStrategy,
    CrossDomainAuthStrategy,
    NoAuthStrategy,
    SameDomainAuthStrategy,
)


class TestAuthStrategyFactory:
    """AuthStrategyFactory 测试。."""

    def test_create_auto(self) -> None:
        """测试创建 AutoAuthStrategy。."""
        strategy = AuthStrategyFactory.create("auto")
        assert isinstance(strategy, AutoAuthStrategy)

    def test_create_none(self) -> None:
        """测试创建 NoAuthStrategy。."""
        strategy = AuthStrategyFactory.create("none")
        assert isinstance(strategy, NoAuthStrategy)

    def test_create_same_domain(self) -> None:
        """测试创建 SameDomainAuthStrategy。."""
        strategy = AuthStrategyFactory.create("same_domain")
        assert isinstance(strategy, SameDomainAuthStrategy)

    def test_create_cross_domain(self) -> None:
        """测试创建 CrossDomainAuthStrategy。."""
        strategy = AuthStrategyFactory.create("cross_domain")
        assert isinstance(strategy, CrossDomainAuthStrategy)

    def test_create_invalid_type_raises(self) -> None:
        """测试无效类型抛出异常。."""
        with pytest.raises(ValueError, match="Unsupported auth type"):
            AuthStrategyFactory.create("invalid")


class TestNoAuthStrategy:
    """NoAuthStrategy 测试。."""

    @pytest.mark.asyncio
    async def test_navigate_to_target(self) -> None:
        """测试 NoAuthStrategy 直接导航到 target_url。."""
        strategy = NoAuthStrategy()

        page = MagicMock()
        page.goto = AsyncMock()

        profile = MagicMock()
        profile.auth.target_url = "https://example.com/open"

        result = await strategy.execute(page, profile)

        page.goto.assert_called_once_with("https://example.com/open", wait_until="domcontentloaded")
        assert result == page


class TestAutoAuthStrategy:
    """AutoAuthStrategy 测试。."""

    @pytest.mark.asyncio
    async def test_auto_delegates_to_none(self) -> None:
        """测试 auto 探测到 none 时直接返回 page。."""
        strategy = AutoAuthStrategy()

        # Mock AuthProbe.probe 返回 none 结果
        probe_result = ProbeResult(
            auth_type="none",
            target_domain="example.com",
            final_domain="example.com",
            final_url="https://example.com/chat",
            redirected=False,
            detection_reason="No redirect and no login form detected.",
        )

        page = MagicMock()
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        profile = MagicMock()
        profile.auth.target_url = "https://example.com/chat"
        profile.auth.login_url = ""
        profile.auth.same_domain.detection = []
        profile.auth.cross_domain.detection = []

        with patch.object(strategy._probe, "probe", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = probe_result
            result = await strategy.execute(page, profile)

        assert result == page
        # none 时不应该修改 profile
        assert profile.auth.login_url == ""

    @pytest.mark.asyncio
    async def test_auto_delegates_to_same_domain(self) -> None:
        """测试 auto 探测到 same_domain 时委托给 SameDomainAuthStrategy。."""
        strategy = AutoAuthStrategy()

        probe_result = ProbeResult(
            auth_type="same_domain",
            target_domain="example.com",
            final_domain="example.com",
            final_url="https://example.com/login",
            redirected=True,
            login_url_detected="https://example.com/login",
            detection_reason="Same-domain redirect to login path.",
        )

        page = MagicMock()
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        profile = MagicMock()
        profile.auth.target_url = "https://example.com/chat"
        profile.auth.login_url = ""  # 未配置, 应该被 patch
        profile.auth.same_domain.detection = []
        profile.auth.cross_domain.detection = []

        with patch.object(strategy._probe, "probe", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = probe_result

            # Mock SameDomainAuthStrategy.execute
            with patch.object(SameDomainAuthStrategy, "execute", new_callable=AsyncMock) as mock_execute:
                mock_execute.return_value = page
                await strategy.execute(page, profile)

        # 验证 login_url 被 patch
        assert profile.auth.login_url == "https://example.com/login"
        # 验证检测策略被生成
        assert len(profile.auth.same_domain.detection) > 0
        # 验证委托被调用
        mock_execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_auto_delegates_to_cross_domain(self) -> None:
        """测试 auto 探测到 cross_domain 时委托给 CrossDomainAuthStrategy。."""
        strategy = AutoAuthStrategy()

        probe_result = ProbeResult(
            auth_type="cross_domain",
            target_domain="app.example.com",
            final_domain="sso.idp.com",
            final_url="https://sso.idp.com/login",
            redirected=True,
            login_url_detected="https://sso.idp.com/login",
            domain_transitions=["app.example.com", "sso.idp.com"],
            detection_reason="Cross-domain redirect to IdP.",
        )

        page = MagicMock()
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        profile = MagicMock()
        profile.auth.target_url = "https://app.example.com/chat"
        profile.auth.login_url = ""
        profile.auth.same_domain.detection = []
        profile.auth.cross_domain.detection = []

        with patch.object(strategy._probe, "probe", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = probe_result

            with patch.object(CrossDomainAuthStrategy, "execute", new_callable=AsyncMock) as mock_execute:
                mock_execute.return_value = page
                await strategy.execute(page, profile)

        # 验证 login_url 被 patch
        assert profile.auth.login_url == "https://sso.idp.com/login"
        # 验证跨域检测策略被生成
        assert len(profile.auth.cross_domain.detection) > 0
        mock_execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_auto_does_not_overwrite_existing_login_url(self) -> None:
        """测试 auto 不覆盖 Profile 中已配置的 login_url。."""
        strategy = AutoAuthStrategy()

        probe_result = ProbeResult(
            auth_type="same_domain",
            target_domain="example.com",
            final_domain="example.com",
            final_url="https://example.com/login",
            redirected=True,
            login_url_detected="https://example.com/login",
            detection_reason="Same-domain redirect.",
        )

        page = MagicMock()
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        profile = MagicMock()
        profile.auth.target_url = "https://example.com/chat"
        profile.auth.login_url = "https://example.com/custom-login"  # 已配置
        profile.auth.same_domain.detection = []
        profile.auth.cross_domain.detection = []

        with patch.object(strategy._probe, "probe", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = probe_result

            with patch.object(SameDomainAuthStrategy, "execute", new_callable=AsyncMock) as mock_execute:
                mock_execute.return_value = page
                await strategy.execute(page, profile)

        # login_url 不应该被覆盖
        assert profile.auth.login_url == "https://example.com/custom-login"

    def test_patch_profile_none(self) -> None:
        """测试 _patch_profile 在 none 时不做修改。."""
        strategy = AutoAuthStrategy()
        profile = MagicMock()
        profile.auth.login_url = ""  # 初始值
        probe_result = ProbeResult(auth_type="none")

        strategy._patch_profile(profile, probe_result)

        # login_url 不应该被修改 (仍为空字符串)
        assert profile.auth.login_url == ""
