# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""APIAuthenticator + CredentialStore 单元测试。

测试覆盖:
  1. APIAuthenticator 认证 header 生成 (basic/bearer/cookie/none)
  2. APIAuthenticator 用户切换
  3. APIAuthenticator 从环境变量创建
  4. APIAuthenticator from_url 自动判别
  5. CredentialStore 凭据管理
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from web_redteam.auth.api_auth import APIAuthConfig, APIAuthenticator
from web_redteam.auth.credential_store import CredentialStore

# ──────────────────────────────────────────────────────────────────
# APIAuthenticator 测试
# ──────────────────────────────────────────────────────────────────


class TestAPIAuthenticator:
    """APIAuthenticator 测试。"""

    def test_basic_auth_headers(self) -> None:
        """Basic auth header 生成。"""
        import base64

        auth = APIAuthenticator(APIAuthConfig(
            auth_type="basic",
            username="alice",
            password="password123",
        ))
        headers = auth.get_headers()
        assert "Authorization" in headers
        expected = base64.b64encode(b"alice:password123").decode()
        assert headers["Authorization"] == f"Basic {expected}"
        assert auth.is_authenticated

    def test_bearer_auth_headers(self) -> None:
        """Bearer token header 生成。"""
        auth = APIAuthenticator(APIAuthConfig(
            auth_type="bearer",
            token="my-jwt-token",
        ))
        headers = auth.get_headers()
        assert headers["Authorization"] == "Bearer my-jwt-token"

    def test_cookie_auth_headers(self) -> None:
        """Cookie header 生成。"""
        auth = APIAuthenticator(APIAuthConfig(
            auth_type="cookie",
            cookie_name="session_id",
            cookie_value="abc123",
        ))
        headers = auth.get_headers()
        assert headers["Cookie"] == "session_id=abc123"

    def test_cookie_auth_cookies(self) -> None:
        """Cookie 字典生成。"""
        auth = APIAuthenticator(APIAuthConfig(
            auth_type="cookie",
            cookie_name="session_id",
            cookie_value="abc123",
        ))
        cookies = auth.get_cookies()
        assert cookies == {"session_id": "abc123"}

    def test_none_auth_empty_headers(self) -> None:
        """无认证时空 headers。"""
        auth = APIAuthenticator(APIAuthConfig(auth_type="none"))
        headers = auth.get_headers()
        assert headers == {}
        assert not auth.is_authenticated

    def test_extra_headers(self) -> None:
        """额外 headers。"""
        auth = APIAuthenticator(APIAuthConfig(
            auth_type="basic",
            username="admin",
            password="admin123",
            extra_headers={"X-Custom": "value"},
        ))
        headers = auth.get_headers()
        assert headers["X-Custom"] == "value"
        assert "Authorization" in headers

    def test_set_cookie(self) -> None:
        """设置 cookie。"""
        auth = APIAuthenticator(APIAuthConfig(auth_type="none"))
        auth.set_cookie("session_id", "new-session-456")
        assert auth.config.auth_type == "cookie"
        assert auth.config.cookie_name == "session_id"
        assert auth.config.cookie_value == "new-session-456"
        assert auth.is_authenticated

    def test_switch_user(self) -> None:
        """切换用户。"""
        auth = APIAuthenticator(APIAuthConfig(
            auth_type="basic",
            username="alice",
            password="password123",
        ))
        auth.switch_user("admin", "admin123", user_id=3)
        assert auth.config.username == "admin"
        assert auth.config.password == "admin123"
        assert auth.config.extra_headers is not None
        assert auth.config.extra_headers["X-User-ID"] == "3"

    def test_from_env(self) -> None:
        """从环境变量创建。"""
        with patch.dict("os.environ", {
            "TARGET_AUTH_TYPE": "basic",
            "TARGET_USERNAME": "testuser",
            "TARGET_PASSWORD": "testpass",
        }):
            auth = APIAuthenticator.from_env()
            assert auth.config.auth_type == "basic"
            assert auth.config.username == "testuser"
            assert auth.config.password == "testpass"

    def test_from_env_auto_bearer(self) -> None:
        """API_KEY 存在时自动切换 bearer。"""
        with patch.dict("os.environ", {
            "TARGET_AUTH_TYPE": "none",
            "API_KEY": "sk-test123",
        }):
            auth = APIAuthenticator.from_env()
            assert auth.config.auth_type == "bearer"
            assert auth.config.token == "sk-test123"

    def test_from_url_openai_compatible(self) -> None:
        """from_url: OpenAI 兼容端点。"""
        auth = APIAuthenticator.from_url(
            "https://api.example.com/v1/chat/completions",
            api_key="sk-test",
        )
        assert auth.config.auth_type == "bearer"
        assert auth.config.token == "sk-test"

    def test_from_url_ollama(self) -> None:
        """from_url: Ollama 端点。"""
        auth = APIAuthenticator.from_url("http://localhost:11434/api/chat")
        assert auth.config.auth_type == "none"

    def test_from_url_generic_bearer(self) -> None:
        """from_url: 通用端点 + api_key → Bearer。"""
        auth = APIAuthenticator.from_url(
            "https://custom.example.com/endpoint",
            api_key="my-key",
        )
        assert auth.config.auth_type == "bearer"
        assert auth.config.token == "my-key"

    def test_from_url_generic_none(self) -> None:
        """from_url: 通用端点无 api_key → none。"""
        auth = APIAuthenticator.from_url("https://custom.example.com/endpoint")
        assert auth.config.auth_type == "none"

    def test_for_openai_compatible(self) -> None:
        """for_openai_compatible 工厂方法。"""
        auth = APIAuthenticator.for_openai_compatible(
            "https://api.example.com/v1/chat/completions",
            api_key="sk-test",
        )
        assert auth.config.auth_type == "bearer"
        auth.get_headers()
        assert auth.is_authenticated

    def test_for_openai_compatible_no_key(self) -> None:
        """for_openai_compatible: 无 api_key → none。"""
        auth = APIAuthenticator.for_openai_compatible(
            "https://api.example.com/v1/chat/completions",
        )
        assert auth.config.auth_type == "none"
        assert not auth.is_authenticated

    def test_for_ollama_default(self) -> None:
        """for_ollama: 默认无认证。"""
        auth = APIAuthenticator.for_ollama()
        assert auth.config.auth_type == "none"

    def test_for_ollama_with_key(self) -> None:
        """for_ollama: 有 OLLAMA_API_KEY → Bearer。"""
        with patch.dict("os.environ", {"OLLAMA_API_KEY": "ollama-secret"}):
            auth = APIAuthenticator.for_ollama()
            assert auth.config.auth_type == "bearer"
            assert auth.config.token == "ollama-secret"


# ──────────────────────────────────────────────────────────────────
# CredentialStore 测试
# ──────────────────────────────────────────────────────────────────


class TestCredentialStore:
    """CredentialStore 测试。"""

    def test_get_credential(self) -> None:
        """获取环境变量凭据。"""
        with patch.dict("os.environ", {"MY_API_KEY": "sk-xxx"}):
            assert CredentialStore.get_credential("MY_API_KEY") == "sk-xxx"

    def test_get_credential_default(self) -> None:
        """默认值。"""
        assert CredentialStore.get_credential("NONEXISTENT", "fallback") == "fallback"

    def test_get_required_credential_missing(self) -> None:
        """必需凭据缺失报错。"""
        with pytest.raises(ValueError, match="Required credential"):
            CredentialStore.get_required_credential("DEFINITELY_NOT_SET_12345")

    def test_get_required_credential_exists(self) -> None:
        """必需凭据存在。"""
        with patch.dict("os.environ", {"REQUIRED_KEY": "value123"}):
            assert CredentialStore.get_required_credential("REQUIRED_KEY") == "value123"

    def test_load_from_env_prefix(self) -> None:
        """前缀过滤。"""
        with patch.dict("os.environ", {
            "TARGET_USER": "alice",
            "TARGET_PASS": "secret",
            "OTHER_VAR": "ignore",
        }):
            result = CredentialStore.load_from_env("TARGET_")
            assert "user" in result
            assert "pass" in result
            assert "other_var" not in result

    def test_load_from_env_no_prefix(self) -> None:
        """无前缀加载全部。"""
        with patch.dict("os.environ", {"LOAD_TEST_VAR": "value"}):
            result = CredentialStore.load_from_env()
            assert "LOAD_TEST_VAR" in result

    def test_from_args(self) -> None:
        """从 CLI 参数提取凭据。"""
        from argparse import Namespace

        args = Namespace(
            api_key="sk-test",
            api_oauth_client_id="client-id",
            api_oauth_client_secret="client-secret",
        )
        creds = CredentialStore.from_args(args)
        assert creds["api_key"] == "sk-test"
        assert creds["api_oauth_client_id"] == "client-id"
        assert creds["api_oauth_client_secret"] == "client-secret"
