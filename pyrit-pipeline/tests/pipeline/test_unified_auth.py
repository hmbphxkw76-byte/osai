# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""统一认证架构测试。

覆盖 AuthDataExtractor / APIAuthenticator URL 工厂 /
UnifiedAuthOrchestrator。

测试覆盖:
  1. AuthDataExtractor: cookies→headers 转换、localStorage token 提取
  2. APIAuthenticator.from_url: URL 自动判别认证方式
  3. APIAuthenticator.for_openai_compatible / for_ollama
  4. UnifiedAuthOrchestrator: API 认证流程 (mock)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ============================================================
# AuthDataExtractor 测试
# ============================================================


class TestAuthDataExtractorCookiesToHeaders:
    """AuthDataExtractor._cookies_to_headers 测试。"""

    def test_access_token_cookie_to_bearer(self):
        """access_token cookie → Authorization: Bearer header."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        cookies = [
            {"name": "access_token", "value": "eyJhbGciOiJIUzI1NiJ9..."},
            {"name": "session_id", "value": "abc123"},
        ]
        headers = AuthDataExtractor._cookies_to_headers(cookies)
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiJ9..."

    def test_jwt_cookie_to_bearer(self):
        """jwt_token cookie → Authorization: Bearer header."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        cookies = [{"name": "jwt_token", "value": "token123"}]
        headers = AuthDataExtractor._cookies_to_headers(cookies)
        assert headers.get("Authorization") == "Bearer token123"

    def test_bearer_cookie_to_bearer(self):
        """bearer cookie → Authorization: Bearer header."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        cookies = [{"name": "bearer", "value": "xyz789"}]
        headers = AuthDataExtractor._cookies_to_headers(cookies)
        assert headers.get("Authorization") == "Bearer xyz789"

    def test_no_auth_cookie(self):
        """无认证 cookie → headers 为空。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        cookies = [{"name": "theme", "value": "dark"}, {"name": "lang", "value": "en"}]
        headers = AuthDataExtractor._cookies_to_headers(cookies)
        assert "Authorization" not in headers

    def test_empty_cookies(self):
        """空 cookies 列表 → headers 为空。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        headers = AuthDataExtractor._cookies_to_headers([])
        assert headers == {}

    def test_cookie_with_empty_value(self):
        """cookie value 为空 → 跳过。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        cookies = [{"name": "access_token", "value": ""}]
        headers = AuthDataExtractor._cookies_to_headers(cookies)
        assert "Authorization" not in headers


class TestAuthDataExtractorAuthCookies:
    """AuthDataExtractor.extract_auth_cookies 测试。"""

    def test_extract_auth_cookies(self):
        """提取认证相关 cookies 为字典。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        cookies = [
            {"name": "session", "value": "abc"},
            {"name": "token", "value": "xyz"},
            {"name": "theme", "value": "dark"},
        ]
        result = AuthDataExtractor.extract_auth_cookies(cookies)
        assert "session" in result
        assert "token" in result
        assert "theme" not in result
        assert result["session"] == "abc"
        assert result["token"] == "xyz"

    def test_extract_auth_cookies_empty(self):
        """空 cookies → 空字典。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        result = AuthDataExtractor.extract_auth_cookies([])
        assert result == {}


class TestAuthDataExtractorExtractFromBrowserContext:
    """AuthDataExtractor.extract_from_browser_context 测试 (mock)。"""

    @pytest.mark.asyncio
    async def test_extract_with_cookies(self):
        """从 BrowserContext 提取 cookies (mock)。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        mock_context = AsyncMock()
        mock_context.cookies = AsyncMock(return_value=[
            {"name": "access_token", "value": "test_token_123"},
            {"name": "session_id", "value": "sess_456"},
        ])
        mock_context.storage_state = AsyncMock(return_value={"origins": []})

        auth_state = await AuthDataExtractor.extract_from_browser_context(
            context=mock_context,
            target_url="https://chat.example.com",
            auth_type="same_domain",
        )

        assert auth_state.auth_type == "same_domain"
        assert auth_state.target_url == "https://chat.example.com"
        assert len(auth_state.cookies) == 2
        assert "Authorization" in auth_state.headers
        assert auth_state.headers["Authorization"] == "Bearer test_token_123"
        assert "Cookie" in auth_state.headers
        assert auth_state.source == "pyrit_browser"

    @pytest.mark.asyncio
    async def test_extract_with_local_storage_token(self):
        """从 localStorage 提取 token (mock)。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        mock_context = AsyncMock()
        mock_context.cookies = AsyncMock(return_value=[])
        mock_context.storage_state = AsyncMock(return_value={
            "origins": [
                {
                    "origin": "https://chat.example.com",
                    "localStorage": [
                        {"name": "access_token", "value": "ls_token_789"},
                    ],
                }
            ]
        })

        auth_state = await AuthDataExtractor.extract_from_browser_context(
            context=mock_context,
            target_url="https://chat.example.com",
            auth_type="cross_domain",
        )

        assert "access_token" in auth_state.tokens
        assert auth_state.tokens["access_token"] == "ls_token_789"
        assert auth_state.headers.get("Authorization") == "Bearer ls_token_789"

    @pytest.mark.asyncio
    async def test_extract_no_auth_data(self):
        """无认证数据 → AuthState 仍创建 (none type)。."""
        from web_redteam.auth.auth_data_extractor import AuthDataExtractor

        mock_context = AsyncMock()
        mock_context.cookies = AsyncMock(return_value=[])
        mock_context.storage_state = AsyncMock(return_value={"origins": []})

        auth_state = await AuthDataExtractor.extract_from_browser_context(
            context=mock_context,
            target_url="https://example.com",
            auth_type="none",
        )

        assert auth_state.auth_type == "none"
        assert len(auth_state.headers) == 0
        assert len(auth_state.cookies) == 0


# ============================================================
# APIAuthenticator URL 工厂方法测试
# ============================================================


class TestAPIAuthenticatorFromUrl:
    """APIAuthenticator.from_url 测试。"""

    def test_openai_compatible_url(self):
        """OpenAI 兼容 URL → Bearer 认证。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.from_url(
            "https://api.longcat.chat/v1/chat/completions",
            api_key="sk-test123",
        )
        headers = auth.get_headers()
        assert "Authorization" in headers
        assert "Bearer sk-test123" in headers["Authorization"]
        assert auth.is_authenticated

    def test_ollama_url_no_key(self):
        """Ollama URL 无 key → 无认证。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.from_url("http://localhost:11434/v1/chat/completions")
        assert auth.config.auth_type == "none"
        assert not auth.is_authenticated

    def test_generic_url_with_key(self):
        """通用 URL + key → Bearer 认证。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.from_url("https://custom.example.com/api", api_key="key123")
        assert auth.config.auth_type == "bearer"
        assert auth.config.token == "key123"

    def test_generic_url_no_key(self):
        """通用 URL 无 key → 无认证。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.from_url("https://custom.example.com/api")
        assert auth.config.auth_type == "none"


class TestAPIAuthenticatorForOpenAICompatible:
    """APIAuthenticator.for_openai_compatible 测试。"""

    def test_with_api_key(self):
        """有 API key → Bearer。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.for_openai_compatible(
            "https://api.siliconflow.cn/v1",
            api_key="sk-sf-test",
        )
        assert auth.config.auth_type == "bearer"
        headers = auth.get_headers()
        assert "Bearer sk-sf-test" in headers["Authorization"]

    def test_without_api_key(self):
        """无 API key → none。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.for_openai_compatible("https://api.openai.com/v1")
        assert auth.config.auth_type == "none"


class TestAPIAuthenticatorForOllama:
    """APIAuthenticator.for_ollama 测试。"""

    def test_default_no_auth(self):
        """默认 Ollama 无认证。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.for_ollama()
        assert auth.config.auth_type == "none"

    def test_with_env_key(self):
        """环境变量 OLLAMA_API_KEY → Bearer。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        with patch.dict("os.environ", {"OLLAMA_API_KEY": "ollama-secret"}):
            auth = APIAuthenticator.for_ollama()
            assert auth.config.auth_type == "bearer"
            assert auth.config.token == "ollama-secret"

    def test_with_explicit_key(self):
        """显式传入 key → Bearer。."""
        from web_redteam.auth.api_auth import APIAuthenticator

        auth = APIAuthenticator.for_ollama(api_key="explicit-key")
        assert auth.config.auth_type == "bearer"
        assert auth.config.token == "explicit-key"


# ============================================================
# UnifiedAuthOrchestrator 测试
# ============================================================


class TestUnifiedAuthOrchestratorAPIFlow:
    """UnifiedAuthOrchestrator API 认证流程测试 (mock)。"""

    @pytest.mark.asyncio
    async def test_api_auth_flow_bearer(self):
        """API 认证流程 — Bearer token。."""
        from web_redteam.auth.unified_orchestrator import UnifiedAuthOrchestrator

        orchestrator = UnifiedAuthOrchestrator()

        # Mock _classify_target 返回 API platform
        mock_classification = MagicMock()
        mock_classification.target_type = "llm_api_platform"
        mock_classification.recommended_mode = "api"
        mock_classification.detection_reason = "JSON response"
        orchestrator._classify_target = AsyncMock(return_value=mock_classification)

        # Mock try_reuse_auth_state 返回 False
        with (
            patch(
                "web_redteam.auth.unified_orchestrator.try_reuse_auth_state",
                return_value=False,
            ),
            patch(
                "web_redteam.auth.unified_orchestrator.export_auth_state",
            ),
        ):
            mock_ctx = MagicMock()
            mock_ctx.metadata = {}
            mock_ctx.args = MagicMock()
            mock_ctx.args.api_key = "sk-test123"
            mock_ctx.args.target_profile = ""

            auth_state = await orchestrator.authenticate_and_route(
                url="https://api.longcat.chat/v1/chat/completions",
                ctx=mock_ctx,
                api_key="sk-test123",
            )

            assert auth_state.auth_type == "bearer"
            assert "Authorization" in auth_state.headers
            assert "Bearer sk-test123" in auth_state.headers["Authorization"]

    @pytest.mark.asyncio
    async def test_auth_failure_degradation(self):
        """认证失败 → 降级为无认证模式。."""
        from web_redteam.auth.unified_orchestrator import UnifiedAuthOrchestrator

        orchestrator = UnifiedAuthOrchestrator()

        # Mock _classify_target returns API platform
        mock_classification = MagicMock()
        mock_classification.target_type = "llm_api_platform"
        mock_classification.recommended_mode = "api"
        mock_classification.detection_reason = "JSON response"
        orchestrator._classify_target = AsyncMock(return_value=mock_classification)

        # Mock _api_auth_flow to raise exception
        orchestrator._api_auth_flow = AsyncMock(side_effect=Exception("Network error"))

        with (
            patch(
                "web_redteam.auth.unified_orchestrator.try_reuse_auth_state",
                return_value=False,
            ),
            patch(
                "web_redteam.auth.unified_orchestrator.export_auth_state",
            ),
        ):
            mock_ctx = MagicMock()
            mock_ctx.metadata = {}
            mock_ctx.args = MagicMock()
            mock_ctx.args.api_key = ""

            auth_state = await orchestrator.authenticate_and_route(
                url="https://unreachable.example.com",
                ctx=mock_ctx,
            )

            assert auth_state.auth_type == "none"
            assert auth_state.source == "pyrit_degraded"

    @pytest.mark.asyncio
    async def test_auth_state_reuse(self):
        """已有认证状态 → 复用, 不重新认证。."""
        from web_redteam.auth.unified_orchestrator import UnifiedAuthOrchestrator

        orchestrator = UnifiedAuthOrchestrator()

        mock_ctx = MagicMock()
        mock_ctx.metadata = {
            "auth_type": "bearer",
            "auth_headers": {"Authorization": "Bearer existing"},
            "auth_cookies": [],
            "auth_tokens": {},
        }

        with patch(
            "web_redteam.auth.unified_orchestrator.try_reuse_auth_state",
            return_value=True,
        ):
            auth_state = await orchestrator.authenticate_and_route(
                url="https://api.example.com/v1/chat/completions",
                ctx=mock_ctx,
            )

            # 复用已有认证
            assert auth_state.auth_type == "bearer"
            assert auth_state.source == "reused"
