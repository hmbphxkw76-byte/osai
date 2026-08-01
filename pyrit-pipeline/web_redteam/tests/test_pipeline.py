# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Pipeline 集成测试。.

测试 AuthStrategyFactory 和 HumanAssistedAuth 的逻辑路径。
不启动真实浏览器, 只验证控制流。
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from web_redteam.auth.auth_strategy import (
    AuthStrategyFactory,
    CrossDomainAuthStrategy,
    SameDomainAuthStrategy,
)
from web_redteam.auth.human_assisted_auth import HumanAssistedAuth
from web_redteam.targets.target_profile import TargetProfile

# ── 测试用 YAML ──

SAME_DOMAIN_YAML = """
target:
  name: "test_same"
auth:
  type: "same_domain"
  login_url: "https://example.com/login"
  target_url: "https://example.com/chat"
  same_domain:
    detection:
      - strategy: "url_pattern"
        pattern: 'example\\.com/chat'
  auto_fill:
    "#user": "testuser"
  human_assisted_steps:
    - "captcha"
interaction:
  input:
    selector: "textarea"
  send:
    selector: "button"
  response:
    selector: "div.response"
"""

CROSS_DOMAIN_YAML = """
target:
  name: "test_cross"
auth:
  type: "cross_domain"
  login_url: "https://app.test.com/login"
  target_url: "https://app.test.com/chat"
  cross_domain:
    redirect_chain:
      - domain: "app.test.com"
        auth_action: "redirect_to_idp"
      - domain: "sso.idp.com"
        auth_action: "login_form"
        human_steps: ["otp"]
      - domain: "app.test.com"
        auth_action: "callback"
    detection:
      - strategy: "url_pattern"
        pattern: 'app\\.test\\.com/chat'
interaction:
  input:
    selector: "textarea"
  send:
    selector: "button"
  response:
    selector: "div.response"
"""


class TestAuthStrategyFactory:
    """AuthStrategyFactory 测试。."""

    def test_create_same_domain(self) -> None:
        """测试创建同域策略。."""
        strategy = AuthStrategyFactory.create("same_domain")
        assert isinstance(strategy, SameDomainAuthStrategy)

    def test_create_cross_domain(self) -> None:
        """测试创建跨域策略。."""
        strategy = AuthStrategyFactory.create("cross_domain")
        assert isinstance(strategy, CrossDomainAuthStrategy)

    def test_create_invalid_type_raises(self) -> None:
        """测试无效类型抛出异常。."""
        with pytest.raises(ValueError, match="Unsupported auth type"):
            AuthStrategyFactory.create("invalid_type")


class TestSameDomainAuthStrategy:
    """SameDomainAuthStrategy 测试。."""

    @pytest.mark.asyncio
    async def test_execute_calls_human_auth(self, tmp_path) -> None:
        """测试同域策略调用 HumanAssistedAuth。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")
        profile = TargetProfile.from_yaml_file(yaml_file)

        strategy = SameDomainAuthStrategy()

        # Mock HumanAssistedAuth.authenticate
        strategy._human_auth = MagicMock()
        mock_page = MagicMock()
        returned_page = MagicMock()
        strategy._human_auth.authenticate = AsyncMock(return_value=returned_page)

        result = await strategy.execute(mock_page, profile)

        strategy._human_auth.authenticate.assert_called_once()
        assert result == returned_page


class TestCrossDomainAuthStrategy:
    """CrossDomainAuthStrategy 测试。."""

    @pytest.mark.asyncio
    async def test_execute_navigates_and_detects(self, tmp_path) -> None:
        """测试跨域策略导航和检测。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(CROSS_DOMAIN_YAML, encoding="utf-8")
        profile = TargetProfile.from_yaml_file(yaml_file)

        strategy = CrossDomainAuthStrategy()

        # Mock detector to return True immediately
        mock_detector = MagicMock()
        mock_detector.wait_for_completion = AsyncMock(return_value=True)
        strategy._create_detector = MagicMock(return_value=mock_detector)

        # Mock page
        page = MagicMock()
        page.goto = AsyncMock()
        page.wait_for_load_state = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.url = "https://app.test.com/chat"
        page.main_frame = page

        # Mock auto_fill
        strategy._human_auth = MagicMock()
        strategy._human_auth._auto_fill = AsyncMock()
        strategy._human_auth._print_human_instructions = MagicMock()

        result = await strategy.execute(page, profile)

        page.goto.assert_called()  # 导航到 login_url 和 target_url
        assert result == page

    @pytest.mark.asyncio
    async def test_execute_timeout_raises(self, tmp_path) -> None:
        """测试跨域策略超时抛出异常。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(CROSS_DOMAIN_YAML, encoding="utf-8")
        profile = TargetProfile.from_yaml_file(yaml_file)

        strategy = CrossDomainAuthStrategy()

        # Mock detector to return False immediately (simulating timeout)
        mock_detector = MagicMock()
        mock_detector.wait_for_completion = AsyncMock(return_value=False)
        strategy._create_detector = MagicMock(return_value=mock_detector)

        # Mock page
        page = MagicMock()
        page.goto = AsyncMock()
        page.wait_for_load_state = AsyncMock()
        page.on = MagicMock()
        page.remove_listener = MagicMock()
        page.url = "https://wrong.com/page"
        page.main_frame = page

        strategy._human_auth = MagicMock()
        strategy._human_auth._auto_fill = AsyncMock()
        strategy._human_auth._print_human_instructions = MagicMock()

        with pytest.raises(TimeoutError, match="Cross-domain authentication did not complete"):
            await strategy.execute(page, profile)


class TestHumanAssistedAuth:
    """HumanAssistedAuth 测试。."""

    @pytest.mark.asyncio
    async def test_authenticate_success(self, tmp_path) -> None:
        """测试认证成功流程。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")
        profile = TargetProfile.from_yaml_file(yaml_file)

        auth = HumanAssistedAuth()

        # Mock page
        page = MagicMock()
        page.goto = AsyncMock()
        page.fill = AsyncMock()
        page.query_selector = AsyncMock(return_value=MagicMock())  # 模拟元素存在

        # Mock detector (立即返回 True)
        detector = MagicMock()
        detector.wait_for_completion = AsyncMock(return_value=True)

        result = await auth.authenticate(page, profile, detector)

        page.goto.assert_any_call("https://example.com/login", wait_until="domcontentloaded")
        page.goto.assert_any_call("https://example.com/chat", wait_until="domcontentloaded")
        page.fill.assert_called_once_with("#user", "testuser")
        assert result == page

    @pytest.mark.asyncio
    async def test_authenticate_timeout_raises(self, tmp_path) -> None:
        """测试认证超时抛出异常。."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(SAME_DOMAIN_YAML, encoding="utf-8")
        profile = TargetProfile.from_yaml_file(yaml_file)

        auth = HumanAssistedAuth()

        page = MagicMock()
        page.goto = AsyncMock()

        detector = MagicMock()
        detector.wait_for_completion = AsyncMock(return_value=False)  # 超时

        with pytest.raises(TimeoutError, match="Authentication did not complete"):
            await auth.authenticate(page, profile, detector)

    def test_print_human_instructions(self) -> None:
        """测试人工操作提示打印。."""
        auth = HumanAssistedAuth()
        # 不抛出异常即可
        auth._print_human_instructions(["captcha", "slider", "qr_scan", "otp"])

    @pytest.mark.asyncio
    async def test_auto_fill_contenteditable_fallback(self) -> None:
        """测试 contenteditable 元素的 click+type 回退。."""
        auth = HumanAssistedAuth()

        page = MagicMock()
        page.query_selector = AsyncMock(return_value=MagicMock())  # 元素存在
        page.fill = AsyncMock(side_effect=Exception("not fillable"))
        page.click = AsyncMock()
        page.type = AsyncMock()

        await auth._auto_fill(page, {"#editor": "content"})

        page.click.assert_called_once_with("#editor")
        page.type.assert_called_once_with("#editor", "content")

    @pytest.mark.asyncio
    async def test_auto_fill_skips_empty_value(self) -> None:
        """测试空值跳过。."""
        auth = HumanAssistedAuth()

        page = MagicMock()
        page.query_selector = AsyncMock(return_value=MagicMock())
        page.fill = AsyncMock()

        await auth._auto_fill(page, {"#user": ""})

        page.fill.assert_not_called()
