"""L5 v48 侦察增强测试 — 认证管理 / 跨端口发现。

覆盖:
    - auth_state_manager: JWT 解码, 认证类型检测, CSRF 提取, 租户切换
    - port_expander: 主机提取, TLS 推断, 服务类型推断
    - rate_limited: 401/403 认证恢复分类

注: i18n_keywords 和 confidence_scorer 已精简合并到 capability_probe.py
    的内联布尔关键词匹配中 (移除过度工程化的贝叶斯评分系统)。

学术依据:
    - Heroux et al. (arXiv:2403.04206) §3.2
    - Greshake et al. (arXiv:2302.12173) §4
    - Zheng et al. (arXiv:2306.05685) §4.3
    - Arbis et al. (arXiv:2306.01943) §4.5
"""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# auth_state_manager
# ═══════════════════════════════════════════════════════


class TestAuthStateManager:
    """测试认证状态管理器."""

    def test_detect_bearer_auth(self):
        """检测 Bearer token 认证."""
        from pipeline.recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"authorization": "Bearer abc123xyz"}
        parsed.raw_headers = [("Authorization", "Bearer abc123xyz")]

        manager = AuthStateManager()
        # detect_auth_type is async
        import asyncio
        state = asyncio.run(manager.detect_auth_type(parsed))

        assert state.auth_type == "bearer"
        assert state.token_value == "abc123xyz"

    def test_detect_jwt_auth(self):
        """检测 JWT 认证 + exp 解码."""
        from pipeline.recon.auth_state_manager import AuthStateManager

        # 构造一个 JWT (header.payload.signature)
        # payload: {"exp": time.time() + 3600, "tenant_id": "org_001"}
        payload = {
            "exp": int(time.time()) + 3600,
            "tenant_id": "org_001",
            "sub": "user123",
        }
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        token = f"header.{payload_b64}.signature"

        parsed = MagicMock()
        parsed.headers = {"authorization": f"Bearer {token}"}
        parsed.raw_headers = [("Authorization", f"Bearer {token}")]

        manager = AuthStateManager()
        import asyncio
        state = asyncio.run(manager.detect_auth_type(parsed))

        assert state.auth_type == "jwt"
        assert state.token_value == token
        assert state.token_expiry is not None
        assert state.tenant_id == "org_001"

    def test_detect_cookie_auth(self):
        """检测 Cookie 认证."""
        from pipeline.recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"cookie": "session_id=abc123; JSESSIONID=xyz"}
        parsed.raw_headers = [("Cookie", "session_id=abc123; JSESSIONID=xyz")]

        manager = AuthStateManager()
        import asyncio
        state = asyncio.run(manager.detect_auth_type(parsed))

        assert state.auth_type == "cookie"
        assert state.token_value is not None

    def test_detect_api_key_auth(self):
        """检测 API Key 认证."""
        from pipeline.recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"x-api-key": "sk-12345"}
        parsed.raw_headers = [("X-API-Key", "sk-12345")]

        manager = AuthStateManager()
        import asyncio
        state = asyncio.run(manager.detect_auth_type(parsed))

        assert state.auth_type == "api_key"
        assert state.token_value == "sk-12345"

    def test_detect_no_auth(self):
        """无认证头."""
        from pipeline.recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {}
        parsed.raw_headers = []

        manager = AuthStateManager()
        import asyncio
        state = asyncio.run(manager.detect_auth_type(parsed))

        assert state.auth_type == "none"

    def test_detect_tenant_header(self):
        """检测租户 header."""
        from pipeline.recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {
            "authorization": "Bearer token123",
            "x-tenant-id": "acme_corp",
        }
        parsed.raw_headers = [
            ("Authorization", "Bearer token123"),
            ("X-Tenant-Id", "acme_corp"),
        ]

        manager = AuthStateManager()
        import asyncio
        state = asyncio.run(manager.detect_auth_type(parsed))

        assert state.tenant_header == "X-Tenant-Id"
        assert state.tenant_id == "acme_corp"

    def test_detect_csrf_header(self):
        """检测 CSRF token header."""
        from pipeline.recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {
            "authorization": "Bearer token123",
            "x-csrf-token": "csrf_abc",
        }
        parsed.raw_headers = [
            ("Authorization", "Bearer token123"),
            ("X-CSRF-Token", "csrf_abc"),
        ]

        manager = AuthStateManager()
        import asyncio
        state = asyncio.run(manager.detect_auth_type(parsed))

        assert state.csrf_header == "X-CSRF-Token"
        assert state.csrf_token == "csrf_abc"

    def test_tenant_switch_numeric(self):
        """租户 ID 数字递增切换."""
        from pipeline.recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="jwt",
            tenant_id="org_001",
            tenant_header="X-Tenant-Id",
            raw_headers=[("X-Tenant-Id", "org_001")],
        )

        manager = AuthStateManager()
        import asyncio
        new_state = asyncio.run(manager.try_tenant_switch(state))

        assert new_state is not None
        assert new_state.tenant_id == "org_002"

    def test_tenant_switch_no_numeric(self):
        """无数字部分的租户 ID 无法枚举."""
        from pipeline.recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="jwt",
            tenant_id="acme_corp",
            tenant_header="X-Tenant-Id",
            raw_headers=[("X-Tenant-Id", "acme_corp")],
        )

        manager = AuthStateManager()
        import asyncio
        new_state = asyncio.run(manager.try_tenant_switch(state))

        assert new_state is None

    def test_csrf_update_from_header(self):
        """从响应 header 更新 CSRF token."""
        from pipeline.recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="cookie",
            csrf_header="X-CSRF-Token",
            csrf_token="old_token",
        )

        manager = AuthStateManager()
        updated = manager.update_csrf_token(
            state,
            {"X-CSRF-Token": "new_token_123"},
        )

        assert updated.csrf_token == "new_token_123"

    def test_csrf_update_from_set_cookie(self):
        """从 Set-Cookie 更新 CSRF token."""
        from pipeline.recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(auth_type="cookie")

        manager = AuthStateManager()
        updated = manager.update_csrf_token(
            state,
            {"set-cookie": "csrf=cookie_csrf_token; Path=/"},
        )

        assert updated.csrf_token == "cookie_csrf_token"

    def test_csrf_update_from_json_body(self):
        """从 JSON 响应体更新 CSRF token."""
        from pipeline.recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(auth_type="cookie")

        manager = AuthStateManager()
        updated = manager.update_csrf_token(
            state,
            {},
            json.dumps({"csrf_token": "json_csrf_123"}),
        )

        assert updated.csrf_token == "json_csrf_123"

    def test_build_auth_headers_bearer(self):
        """重建 Bearer 认证 headers."""
        from pipeline.recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="bearer",
            token_value="new_token_456",
            raw_headers=[("Authorization", "Bearer old_token"), ("Content-Type", "application/json")],
        )

        manager = AuthStateManager()
        headers = manager.build_auth_headers(state)

        # 应该包含更新后的 Authorization
        auth_header = [v for k, v in headers if k.lower() == "authorization"][0]
        assert auth_header == "Bearer new_token_456"

    def test_is_token_expired(self):
        """Token 过期检查."""
        from pipeline.recon.auth_state_manager import AuthState, AuthStateManager

        manager = AuthStateManager()

        # 未过期
        state_future = AuthState(token_expiry=time.time() + 3600)
        assert not manager.is_token_expired(state_future)

        # 已过期
        state_past = AuthState(token_expiry=time.time() - 100)
        assert manager.is_token_expired(state_past)

        # 无过期时间
        state_none = AuthState(token_expiry=None)
        assert not manager.is_token_expired(state_none)

    def test_jwt_decode_invalid(self):
        """无效 JWT 解码返回 None."""
        from pipeline.recon.auth_state_manager import _decode_jwt_payload

        assert _decode_jwt_payload("not.a.jwt") is None
        assert _decode_jwt_payload("too-short") is None
        assert _decode_jwt_payload("") is None


# ═══════════════════════════════════════════════════════
# port_expander
# ═══════════════════════════════════════════════════════


class TestPortExpander:
    """测试跨端口端点发现."""

    def test_extract_host_from_parsed(self):
        """从 ParsedBurpRequest 提取 host."""
        from pipeline.recon.port_expander import _extract_host

        parsed = MagicMock()
        parsed.host = "example.com"
        parsed.headers = {}
        parsed.raw_request = ""

        assert _extract_host(parsed) == "example.com"

    def test_extract_host_with_port(self):
        """提取 host 时去除端口号."""
        from pipeline.recon.port_expander import _extract_host

        parsed = MagicMock()
        parsed.host = "example.com:8080"
        parsed.headers = {}
        parsed.raw_request = ""

        assert _extract_host(parsed) == "example.com"

    def test_extract_host_from_header(self):
        """从 Host header 提取."""
        from pipeline.recon.port_expander import _extract_host

        parsed = MagicMock()
        parsed.host = None
        parsed.headers = {"host": "api.target.com:443"}
        parsed.raw_request = ""

        assert _extract_host(parsed) == "api.target.com"

    def test_extract_tls_from_parsed(self):
        """从 parsed 属性提取 TLS."""
        from pipeline.recon.port_expander import _extract_tls

        parsed = MagicMock()
        parsed.use_tls = True
        parsed.raw_request = ""

        assert _extract_tls(parsed) is True

    def test_extract_tls_from_raw_request(self):
        """从 raw_request 推断 TLS."""
        from pipeline.recon.port_expander import _extract_tls

        parsed = MagicMock()
        parsed.use_tls = None
        parsed.is_https = None
        parsed.tls = None
        parsed.raw_request = "POST https://api.example.com/v1/chat HTTP/1.1\r\nHost: api.example.com"
        parsed.port = None

        assert _extract_tls(parsed) is True

    def test_infer_service_type_mcp(self):
        """推断 MCP 服务类型."""
        from pipeline.recon.port_expander import _infer_service_type

        service = _infer_service_type(
            200,
            "application/json",
            '{"jsonrpc": "2.0", "result": {"tools": []}}',
        )
        assert service == "mcp"

    def test_infer_service_type_a2a(self):
        """推断 A2A 服务类型."""
        from pipeline.recon.port_expander import _infer_service_type

        service = _infer_service_type(
            200,
            "application/json",
            '{"capabilities": ["chat"], "skills": ["search"]}',
        )
        assert service == "a2a"

    def test_infer_service_type_llm_api(self):
        """推断 LLM API 服务类型."""
        from pipeline.recon.port_expander import _infer_service_type

        service = _infer_service_type(
            200,
            "application/json",
            '{"models": ["gpt-4o"], "completion": "..."}',
        )
        assert service == "llm_api"

    def test_infer_service_type_unknown(self):
        """推断未知服务类型."""
        from pipeline.recon.port_expander import _infer_service_type

        service = _infer_service_type(
            200,
            "text/html",
            "<html><body>Hello</body></html>",
        )
        assert service == "unknown"

    def test_build_port_parsed_request(self):
        """构建端口请求参数."""
        from pipeline.recon.port_expander import (
            DiscoveredPortEndpoint,
            build_port_parsed_request,
        )

        original = MagicMock()
        original.host = "example.com"
        original.headers = {
            "authorization": "Bearer token123",
            "content-type": "application/json",
            "host": "example.com",
        }

        endpoint = DiscoveredPortEndpoint(
            port=3001,
            path="/mcp",
            status_code=200,
            content_type="application/json",
            response_preview='{"jsonrpc": "2.0"}',
            service_type="mcp",
            use_tls=True,
        )

        params = build_port_parsed_request(original, endpoint)

        assert params["host"] == "example.com"
        assert params["port"] == 3001
        assert params["path"] == "/mcp"
        assert params["use_tls"] is True
        assert params["method"] == "GET"
        assert "authorization" in params["headers"]
        assert "host" not in params["headers"]


# ═══════════════════════════════════════════════════════
# rate_limited: 401/403 认证恢复分类
# ═══════════════════════════════════════════════════════


class TestRateLimitedAuthRecovery:
    """测试 RateLimitedTarget 的 401/403 认证恢复分类."""

    def test_401_is_auth_recoverable(self):
        """401 应标记为 auth_recoverable."""
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 401 Unauthorized")
        info = _classify_error(exc)

        assert info["auth_recoverable"] is True
        assert info["retryable"] is False  # 不做普通重试
        assert "401" in info["type"]

    def test_403_is_auth_recoverable(self):
        """403 应标记为 auth_recoverable."""
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 403 Forbidden")
        info = _classify_error(exc)

        assert info["auth_recoverable"] is True
        assert info["retryable"] is False

    def test_400_not_auth_recoverable(self):
        """400 不应标记为 auth_recoverable."""
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 400 Bad Request")
        info = _classify_error(exc)

        assert info["auth_recoverable"] is False
        assert info["retryable"] is False

    def test_429_not_auth_recoverable(self):
        """429 不应标记为 auth_recoverable."""
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 429 Too Many Requests")
        info = _classify_error(exc)

        assert info["auth_recoverable"] is False
        assert info["retryable"] is True

    def test_timeout_not_auth_recoverable(self):
        """超时不应标记为 auth_recoverable."""
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("asyncio.TimeoutError")
        info = _classify_error(exc)

        assert info["auth_recoverable"] is False
        assert info["retryable"] is True
        assert info["is_timeout"] is True

    def test_404_not_auth_recoverable(self):
        """404 不应标记为 auth_recoverable."""
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 404 Not Found")
        info = _classify_error(exc)

        assert info["auth_recoverable"] is False
        assert info["retryable"] is False
