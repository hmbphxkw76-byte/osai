# arXiv:2403.04206 — Auth recovery strategy
"""Tests for recon/auth_state_manager.py — authentication state management.

Covers:
    - detect_auth_type: JWT/Bearer/Cookie/API key detection
    - try_recover_auth: auth recovery (anonymous fallback)
    - try_tenant_switch: multi-tenant ID enumeration
    - update_csrf_token: CSRF token rotation from response
    - build_auth_headers: auth header reconstruction
    - is_token_expired: token expiry check
    - _decode_jwt_payload: JWT payload decoding (no signature verification)

学术依据:
    - Heroux et al. (arXiv:2403.04206) §3.2 — 认证失效恢复策略
    - RFC 7519 §4.1.4 — JWT exp claim
    - OWASP WSTG-ATHN-01 — 认证绕过测试标准
"""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def _make_jwt(payload: dict) -> str:
    """Create a test JWT (unsigned, for testing only)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}.signature"


class TestDetectAuthType:
    """Test detect_auth_type — authentication type detection."""

    @pytest.mark.asyncio
    async def test_bearer_token_detection(self):
        """Bearer token should be detected."""
        from recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"authorization": "Bearer abc123token"}
        parsed.raw_headers = [("Authorization", "Bearer abc123token")]

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.auth_type == "bearer"
        assert state.token_value == "abc123token"

    @pytest.mark.asyncio
    async def test_jwt_detection_with_exp(self):
        """JWT should be detected with expiry."""
        from recon.auth_state_manager import AuthStateManager

        exp = int(time.time()) + 3600  # 1 hour from now
        jwt_token = _make_jwt({"exp": exp, "sub": "test"})
        parsed = MagicMock()
        parsed.headers = {"authorization": f"Bearer {jwt_token}"}
        parsed.raw_headers = [("Authorization", f"Bearer {jwt_token}")]

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.auth_type == "jwt"
        assert state.token_value == jwt_token
        assert state.token_expiry is not None
        # Should be 60s before exp
        assert state.token_expiry == float(exp) - 60.0

    @pytest.mark.asyncio
    async def test_jwt_tenant_extraction(self):
        """Tenant ID should be extracted from JWT payload."""
        from recon.auth_state_manager import AuthStateManager

        jwt_token = _make_jwt({"sub": "test", "tenant_id": "org_001"})
        parsed = MagicMock()
        parsed.headers = {"authorization": f"Bearer {jwt_token}"}
        parsed.raw_headers = [("Authorization", f"Bearer {jwt_token}")]

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.tenant_id == "org_001"

    @pytest.mark.asyncio
    async def test_cookie_session_detection(self):
        """Cookie-based auth should be detected."""
        from recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"cookie": "session_id=abc123; theme=dark"}
        parsed.raw_headers = [("Cookie", "session_id=abc123; theme=dark")]

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.auth_type == "cookie"
        assert state.token_value == "session_id=abc123; theme=dark"

    @pytest.mark.asyncio
    async def test_api_key_detection(self):
        """API key auth should be detected."""
        from recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"x-api-key": "sk-test-key-12345"}
        parsed.raw_headers = [("X-API-Key", "sk-test-key-12345")]

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.auth_type == "api_key"
        assert state.token_value == "sk-test-key-12345"

    @pytest.mark.asyncio
    async def test_no_auth_anonymous(self):
        """No auth headers should yield 'none' type."""
        from recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {}
        parsed.raw_headers = []

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.auth_type == "none"

    @pytest.mark.asyncio
    async def test_tenant_header_detection(self):
        """Tenant header should be detected from raw_headers."""
        from recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"authorization": "Bearer token123"}
        parsed.raw_headers = [
            ("Authorization", "Bearer token123"),
            ("X-Tenant-Id", "acme-corp"),
        ]

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.tenant_header == "X-Tenant-Id"
        assert state.tenant_id == "acme-corp"

    @pytest.mark.asyncio
    async def test_csrf_header_detection(self):
        """CSRF token header should be detected."""
        from recon.auth_state_manager import AuthStateManager

        parsed = MagicMock()
        parsed.headers = {"x-csrf-token": "csrf-abc-123"}
        parsed.raw_headers = [("X-CSRF-Token", "csrf-abc-123")]

        manager = AuthStateManager()
        state = await manager.detect_auth_type(parsed)
        assert state.csrf_header == "X-CSRF-Token"
        assert state.csrf_token == "csrf-abc-123"


class TestTryRecoverAuth:
    """Test try_recover_auth — authentication recovery."""

    @pytest.mark.asyncio
    async def test_anonymous_fallback(self):
        """All strategies fail → anonymous fallback."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        manager = AuthStateManager(max_refreshes=3)
        state = AuthState(auth_type="bearer", token_value="expired")
        recovered = await manager.try_recover_auth(state, host="example.com")
        assert recovered is True
        assert state.auth_type == "none"
        assert state.token_value is None

    @pytest.mark.asyncio
    async def test_max_refreshes_exhausted(self):
        """Should return False when max refreshes exhausted."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        manager = AuthStateManager(max_refreshes=2)
        state = AuthState(auth_type="bearer", token_value="token", max_refreshes=2)
        state.refresh_count = 2  # Already exhausted

        recovered = await manager.try_recover_auth(state)
        assert recovered is False


class TestTryTenantSwitch:
    """Test try_tenant_switch — multi-tenant enumeration."""

    @pytest.mark.asyncio
    async def test_numeric_tenant_enumeration(self):
        """Numeric tenant ID should auto-increment."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="bearer",
            tenant_header="X-Tenant-Id",
            tenant_id="org_001",
            raw_headers=[("X-Tenant-Id", "org_001")],
        )
        manager = AuthStateManager()
        new_state = await manager.try_tenant_switch(state)
        assert new_state is not None
        assert new_state.tenant_id == "org_002"

    @pytest.mark.asyncio
    async def test_explicit_tenant_id(self):
        """Explicit tenant ID should be used."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="bearer",
            tenant_header="X-Org-Id",
            tenant_id="org_001",
            raw_headers=[("X-Org-Id", "org_001")],
        )
        manager = AuthStateManager()
        new_state = await manager.try_tenant_switch(state, new_tenant_id="acme-corp")
        assert new_state is not None
        assert new_state.tenant_id == "acme-corp"

    @pytest.mark.asyncio
    async def test_no_tenant_header_returns_none(self):
        """No tenant header → None."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(auth_type="bearer")
        manager = AuthStateManager()
        new_state = await manager.try_tenant_switch(state)
        assert new_state is None

    @pytest.mark.asyncio
    async def test_non_numeric_tenant_returns_none(self):
        """Non-numeric tenant ID without explicit ID → None."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="bearer",
            tenant_header="X-Tenant-Id",
            tenant_id="acme-corp",
            raw_headers=[("X-Tenant-Id", "acme-corp")],
        )
        manager = AuthStateManager()
        new_state = await manager.try_tenant_switch(state)
        assert new_state is None


class TestUpdateCsrfToken:
    """Test update_csrf_token — CSRF token rotation."""

    def test_from_response_header(self):
        """CSRF token from response header should update state."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState()
        manager = AuthStateManager()
        result = manager.update_csrf_token(
            state,
            {"X-CSRF-Token": "new-csrf-456"},
        )
        assert result.csrf_token == "new-csrf-456"
        assert result.csrf_header == "X-CSRF-Token"

    def test_from_set_cookie(self):
        """CSRF token from Set-Cookie should be extracted."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState()
        manager = AuthStateManager()
        result = manager.update_csrf_token(
            state,
            {"set-cookie": "csrf=cookie-csrf-789; Path=/"},
        )
        assert result.csrf_token == "cookie-csrf-789"

    def test_from_json_body(self):
        """CSRF token from JSON body should be extracted."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState()
        manager = AuthStateManager()
        body = json.dumps({"csrf_token": "json-csrf-999"})
        result = manager.update_csrf_token(state, {}, body)
        assert result.csrf_token == "json-csrf-999"

    def test_no_csrf_in_response(self):
        """No CSRF in response → unchanged state."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(csrf_token="existing-token")
        manager = AuthStateManager()
        result = manager.update_csrf_token(state, {})
        assert result.csrf_token == "existing-token"


class TestBuildAuthHeaders:
    """Test build_auth_headers — auth header reconstruction."""

    def test_bearer_header_rebuilt(self):
        """Bearer header should be rebuilt with new token."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="bearer",
            token_value="new-token-123",
            raw_headers=[("Authorization", "Bearer old-token")],
        )
        manager = AuthStateManager()
        headers = manager.build_auth_headers(state)
        auth_header = [v for k, v in headers if k.lower() == "authorization"][0]
        assert auth_header == "Bearer new-token-123"

    def test_tenant_header_replaced(self):
        """Tenant header should be replaced with new value."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="bearer",
            token_value="token",
            tenant_header="X-Tenant-Id",
            tenant_id="org_002",
            raw_headers=[
                ("Authorization", "Bearer token"),
                ("X-Tenant-Id", "org_001"),
            ],
        )
        manager = AuthStateManager()
        headers = manager.build_auth_headers(state)
        tenant_header = [v for k, v in headers if k.lower() == "x-tenant-id"][0]
        assert tenant_header == "org_002"

    def test_csrf_header_appended(self):
        """CSRF header should be appended if not in raw_headers."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(
            auth_type="none",
            csrf_header="X-CSRF-Token",
            csrf_token="csrf-123",
            raw_headers=[("User-Agent", "test")],
        )
        manager = AuthStateManager()
        headers = manager.build_auth_headers(state)
        csrf_values = [v for k, v in headers if k.lower() == "x-csrf-token"]
        assert len(csrf_values) == 1
        assert csrf_values[0] == "csrf-123"


class TestIsTokenExpired:
    """Test is_token_expired — token expiry check."""

    def test_expired_token(self):
        """Past expiry should return True."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(token_expiry=time.time() - 100)
        manager = AuthStateManager()
        assert manager.is_token_expired(state) is True

    def test_valid_token(self):
        """Future expiry should return False."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(token_expiry=time.time() + 3600)
        manager = AuthStateManager()
        assert manager.is_token_expired(state) is False

    def test_no_expiry(self):
        """None expiry should return False."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        state = AuthState(token_expiry=None)
        manager = AuthStateManager()
        assert manager.is_token_expired(state) is False

    def test_ahead_parameter(self):
        """Ahead parameter should trigger early."""
        from recon.auth_state_manager import AuthState, AuthStateManager

        # Token expires in 30s, ahead=60 → should be expired
        state = AuthState(token_expiry=time.time() + 30)
        manager = AuthStateManager()
        assert manager.is_token_expired(state, ahead=60) is True


class TestDecodeJwtPayload:
    """Test _decode_jwt_payload — JWT payload decoding."""

    def test_valid_jwt(self):
        """Valid JWT should decode payload."""
        from recon.auth_state_manager import _decode_jwt_payload

        jwt = _make_jwt({"sub": "user123", "exp": 1234567890})
        payload = _decode_jwt_payload(jwt)
        assert payload is not None
        assert payload["sub"] == "user123"
        assert payload["exp"] == 1234567890

    def test_non_jwt_returns_none(self):
        """Non-JWT string should return None."""
        from recon.auth_state_manager import _decode_jwt_payload

        assert _decode_jwt_payload("not.a.jwt") is None
        assert _decode_jwt_payload("plain text") is None
        assert _decode_jwt_payload("") is None

    def test_invalid_base64_returns_none(self):
        """Invalid base64 should return None."""
        from recon.auth_state_manager import _decode_jwt_payload

        assert _decode_jwt_payload("header.@@@.signature") is None
