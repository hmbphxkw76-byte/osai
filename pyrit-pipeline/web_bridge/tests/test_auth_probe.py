# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AuthProbe 单元测试。.

测试自动认证探测器的三种判断场景:
  - none:         页面直接加载, 无重定向, 无登录表单
  - same_domain:  同域名重定向到登录页 / 页面有登录表单
  - cross_domain: 跨域名重定向到 IdP

使用 Mock Page 对象, 不需要真实浏览器。
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from web_bridge.auth.auth_probe import (
    AuthProbe,
    ProbeResult,
    _extract_domain,
    _is_login_path,
)


class TestHelperFunctions:
    """辅助函数测试。."""

    def test_extract_domain_normal(self) -> None:
        """测试正常 URL 提取域名。."""
        assert _extract_domain("https://example.com/chat") == "example.com"
        assert _extract_domain("http://localhost:5000") == "localhost:5000"
        assert _extract_domain("https://app.example.com:8080/path") == "app.example.com:8080"

    def test_extract_domain_empty(self) -> None:
        """测试空 URL。."""
        assert _extract_domain("") == ""

    def test_is_login_path_with_login_keyword(self) -> None:
        """测试包含 login 关键词的 URL。."""
        assert _is_login_path("https://example.com/login") is True
        assert _is_login_path("https://example.com/auth/signin") is True
        assert _is_login_path("https://example.com/account/login") is True

    def test_is_login_path_without_keyword(self) -> None:
        """测试不包含登录关键词的 URL。."""
        assert _is_login_path("https://example.com/chat") is False
        assert _is_login_path("https://example.com/dashboard") is False

    def test_is_login_path_with_sso(self) -> None:
        """测试 SSO/OAuth 关键词。."""
        assert _is_login_path("https://idp.example.com/sso/authorize") is True
        assert _is_login_path("https://example.com/oauth/callback") is True


class TestAuthProbeNone:
    """无需认证场景测试。."""

    @pytest.mark.asyncio
    async def test_no_redirect_no_login_form(self) -> None:
        """测试页面直接加载, 无重定向, 无登录表单 → none。."""
        probe = AuthProbe(settle_wait_ms=0)

        page = MagicMock()
        page.url = "https://example.com/chat"  # URL 未变
        page.main_frame = page
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)  # 无登录表单元素

        result = await probe.probe(page, "https://example.com/chat")

        assert result.auth_type == "none"
        assert result.target_domain == "example.com"
        assert result.final_domain == "example.com"
        assert result.redirected is False

    @pytest.mark.asyncio
    async def test_local_target_no_auth(self) -> None:
        """测试本地目标 (localhost) 无需认证。."""
        probe = AuthProbe(settle_wait_ms=0)

        page = MagicMock()
        page.url = "http://localhost:5000"
        page.main_frame = page
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        result = await probe.probe(page, "http://localhost:5000")

        assert result.auth_type == "none"


class TestAuthProbeSameDomain:
    """同域认证场景测试。."""

    @pytest.mark.asyncio
    async def test_same_domain_redirect_to_login(self) -> None:
        """测试同域名重定向到登录页 → same_domain。."""
        probe = AuthProbe(settle_wait_ms=0)

        page = MagicMock()
        # target_url 是 chat 页, 但重定向到了同域名的 login 页
        page.url = "https://example.com/login"
        page.main_frame = page
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)  # 不检查 DOM (URL 已判断)

        result = await probe.probe(page, "https://example.com/chat")

        assert result.auth_type == "same_domain"
        assert result.target_domain == "example.com"
        assert result.final_domain == "example.com"  # 同域名
        assert result.login_url_detected == "https://example.com/login"

    @pytest.mark.asyncio
    async def test_same_domain_login_form_on_page(self) -> None:
        """测试同域名页面有登录表单 (URL 可能未变) → same_domain。."""
        probe = AuthProbe(settle_wait_ms=0)

        page = MagicMock()
        page.url = "https://example.com/chat"  # URL 未变
        page.main_frame = page
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()

        # 模拟找到 password input
        password_element = MagicMock()
        page.query_selector = AsyncMock(return_value=password_element)

        result = await probe.probe(page, "https://example.com/chat")

        assert result.auth_type == "same_domain"
        assert result.login_url_detected == "https://example.com/chat"

    @pytest.mark.asyncio
    async def test_same_domain_signin_path(self) -> None:
        """测试重定向到 signin 路径 → same_domain。."""
        probe = AuthProbe(settle_wait_ms=0)

        page = MagicMock()
        page.url = "https://example.com/auth/signin"
        page.main_frame = page
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        result = await probe.probe(page, "https://example.com/app")

        assert result.auth_type == "same_domain"


class TestAuthProbeCrossDomain:
    """跨域认证场景测试。."""

    @pytest.mark.asyncio
    async def test_cross_domain_redirect_to_idp(self) -> None:
        """测试跨域名重定向到 IdP → cross_domain。."""
        probe = AuthProbe(settle_wait_ms=0)

        page = MagicMock()
        # target_url 在 app.com, 但重定向到了 sso.idp.com
        page.url = "https://sso.idp.example.com/auth?redirect=app.example.com"
        page.main_frame = page
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        result = await probe.probe(page, "https://app.example.com/chat")

        assert result.auth_type == "cross_domain"
        assert result.target_domain == "app.example.com"
        assert result.final_domain == "sso.idp.example.com"
        assert result.redirected is True
        assert result.login_url_detected == "https://sso.idp.example.com/auth?redirect=app.example.com"

    @pytest.mark.asyncio
    async def test_cross_domain_cas(self) -> None:
        """测试 CAS 单点登录跨域重定向。."""
        probe = AuthProbe(settle_wait_ms=0)

        page = MagicMock()
        page.url = "https://cas.university.edu/cas/login?service=https://app.university.edu/chat"
        page.main_frame = page
        page.goto = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.query_selector = AsyncMock(return_value=None)

        result = await probe.probe(page, "https://app.university.edu/chat")

        assert result.auth_type == "cross_domain"
        assert result.target_domain == "app.university.edu"
        assert result.final_domain == "cas.university.edu"


class TestProbeResult:
    """ProbeResult 数据类测试。."""

    def test_str_representation(self) -> None:
        """测试 ProbeResult 的字符串表示。."""
        result = ProbeResult(
            auth_type="cross_domain",
            target_domain="app.com",
            final_domain="idp.com",
            final_url="https://idp.com/login",
            redirected=True,
            login_url_detected="https://idp.com/login",
            domain_transitions=["app.com", "idp.com"],
            detection_reason="Cross-domain redirect",
        )
        s = str(result)
        assert "cross_domain" in s
        assert "app.com" in s
        assert "idp.com" in s
