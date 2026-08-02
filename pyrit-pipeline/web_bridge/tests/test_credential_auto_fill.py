# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""凭据自动填充测试。.

测试场景:
  1. .env 中设置了 TARGET_USERNAME/TARGET_PASSWORD → 动态 Profile 自动生成 auto_fill
  2. YAML Profile 中 auto_fill 使用 ${TARGET_USERNAME} → 加载时展开
  3. HumanAssistedAuth._auto_fill 多选择器场景: 匹配的填充, 不匹配的静默跳过
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from web_bridge.auth.human_assisted_auth import HumanAssistedAuth
from web_bridge.targets.dynamic_profile import (
    DEFAULT_PASSWORD_SELECTORS,
    DEFAULT_USERNAME_SELECTORS,
    _build_auto_fill_from_env,
    create_profile_from_url,
)
from web_bridge.targets.target_profile import TargetProfile


class TestEnvCredentialInjection:
    """环境变量凭据自动注入测试。."""

    def test_env_credentials_generate_auto_fill(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试 .env 中有凭据时, 动态 Profile 自动生成 auto_fill。."""
        monkeypatch.setenv("TARGET_USERNAME", "testuser123")
        monkeypatch.setenv("TARGET_PASSWORD", "testpass456")

        profile = create_profile_from_url("https://example.com/chat")

        assert len(profile.auth.auto_fill) > 0
        # 应该包含用户名选择器
        assert any(s in profile.auth.auto_fill for s in DEFAULT_USERNAME_SELECTORS)
        # 应该包含密码选择器
        assert any(s in profile.auth.auto_fill for s in DEFAULT_PASSWORD_SELECTORS)
        # 值应该是环境变量的值
        for selector in DEFAULT_USERNAME_SELECTORS:
            assert profile.auth.auto_fill[selector] == "testuser123"
        for selector in DEFAULT_PASSWORD_SELECTORS:
            assert profile.auth.auto_fill[selector] == "testpass456"

    def test_no_env_credentials_empty_auto_fill(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试 .env 中没有凭据时, auto_fill 为空。."""
        monkeypatch.delenv("TARGET_USERNAME", raising=False)
        monkeypatch.delenv("TARGET_PASSWORD", raising=False)

        profile = create_profile_from_url("https://example.com/chat")

        assert profile.auth.auto_fill == {}

    def test_only_username_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试只设置了用户名, 没有密码。."""
        monkeypatch.setenv("TARGET_USERNAME", "testuser")
        monkeypatch.delenv("TARGET_PASSWORD", raising=False)

        profile = create_profile_from_url("https://example.com/chat")

        # 只有用户名选择器
        assert any(s in profile.auth.auto_fill for s in DEFAULT_USERNAME_SELECTORS)
        # 没有密码选择器
        assert not any(s in profile.auth.auto_fill for s in DEFAULT_PASSWORD_SELECTORS)

    def test_build_auto_fill_from_env_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试 _build_auto_fill_from_env 函数。."""
        monkeypatch.setenv("TARGET_USERNAME", "admin")
        monkeypatch.setenv("TARGET_PASSWORD", "secret")

        auto_fill = _build_auto_fill_from_env()

        assert len(auto_fill) == len(DEFAULT_USERNAME_SELECTORS) + len(DEFAULT_PASSWORD_SELECTORS)
        assert "admin" in auto_fill.values()
        assert "secret" in auto_fill.values()


class TestYamlEnvVarExpansion:
    """YAML Profile 中 ${ENV_VAR} 展开测试。."""

    def test_yaml_auto_fill_env_expansion(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试 YAML Profile 中 ${TARGET_USERNAME} 被正确展开。."""
        monkeypatch.setenv("TARGET_USERNAME", "yaml_user")
        monkeypatch.setenv("TARGET_PASSWORD", "yaml_pass")

        yaml_content = """
target:
  name: "test_yaml_creds"
auth:
  type: "same_domain"
  login_url: "https://example.com/login"
  target_url: "https://example.com/chat"
  same_domain:
    detection:
      - strategy: "url_pattern"
        pattern: 'example\\.com/chat'
  auto_fill:
    "#username": "${TARGET_USERNAME}"
    "#password": "${TARGET_PASSWORD}"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert profile.auth.auto_fill["#username"] == "yaml_user"
        assert profile.auth.auto_fill["#password"] == "yaml_pass"

    def test_yaml_auto_fill_env_not_set_empty(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """测试环境变量未设置时, auto_fill 值为空字符串。."""
        monkeypatch.delenv("TARGET_USERNAME", raising=False)

        yaml_content = """
target:
  name: "test"
auth:
  type: "same_domain"
  login_url: "https://example.com/login"
  target_url: "https://example.com/chat"
  same_domain:
    detection:
      - strategy: "url_pattern"
        pattern: 'example'
  auto_fill:
    "#username": "${TARGET_USERNAME}"
interaction: {}
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        profile = TargetProfile.from_yaml_file(yaml_file)

        assert profile.auth.auto_fill["#username"] == ""


class TestAutoFillMultiSelector:
    """_auto_fill 多选择器场景测试。."""

    @pytest.mark.asyncio
    async def test_matching_selector_filled(self) -> None:
        """测试匹配到的选择器被填充。."""
        auth = HumanAssistedAuth()

        page = MagicMock()
        # 第一个选择器不存在, 第二个存在
        page.query_selector = AsyncMock(side_effect=[None, MagicMock()])
        page.fill = AsyncMock()

        config = {
            'input[name="username"]': "testuser",
            'input[type="email"]': "testuser",
        }

        await auth._auto_fill(page, config)

        # 应该只调用了一次 fill (第二个选择器匹配)
        page.fill.assert_called_once_with('input[type="email"]', "testuser")

    @pytest.mark.asyncio
    async def test_no_matching_selector_silent(self) -> None:
        """测试所有选择器都不匹配时, 静默跳过无报错。."""
        auth = HumanAssistedAuth()

        page = MagicMock()
        page.query_selector = AsyncMock(return_value=None)  # 所有选择器都不存在
        page.fill = AsyncMock()

        config = {
            'input[name="username"]': "testuser",
            'input[type="email"]': "testuser",
        }

        # 不应该抛异常
        await auth._auto_fill(page, config)

        # fill 不应该被调用
        page.fill.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_value_skipped(self) -> None:
        """测试空值被跳过。."""
        auth = HumanAssistedAuth()

        page = MagicMock()
        page.query_selector = AsyncMock(return_value=MagicMock())
        page.fill = AsyncMock()

        config = {
            "#username": "",  # 空值
            "#password": "secret",
        }

        await auth._auto_fill(page, config)

        # 只有 password 被填充
        page.fill.assert_called_once_with("#password", "secret")
