# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""SSEChatTarget + RuleBasedTarget + AuthManager 单元测试。.

测试覆盖:
  1. SSE 流解析 (meta/content/mcp_result 事件)
  2. SSEChatTarget 属性和方法
  3. RuleBasedTarget 属性和方法
  4. AuthManager 认证 header 生成
  5. AuthManager 用户切换
  6. AuthManager 从环境变量创建
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pipeline.integrations.auth_manager import AuthConfig, AuthManager
from pipeline.targets.rule_based_target import RuleBasedResponse, RuleBasedTarget
from pipeline.targets.sse_chat_target import (
    SSEChatTarget,
    SSEMCPResult,
    SSEMetaEvent,
    SSEResponse,
)


# ──────────────────────────────────────────────────────────────────
# SSE 流解析测试
# ──────────────────────────────────────────────────────────────────


class TestSSEParsing:
    """SSE 流解析测试。"""

    def test_parse_simple_content(self) -> None:
        """解析普通内容流。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01")
        raw = (
            'data: {"content":"Hello "}\n'
            'data: {"content":"world"}\n'
        )
        resp = target.parse_sse_stream(raw)
        assert resp.content == "Hello world"
        assert resp.meta is None
        assert resp.mcp_result is None

    def test_parse_meta_event(self) -> None:
        """解析 meta 事件。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01")
        meta_data = json.dumps({"request_id": "abc-123", "lab_id": "PI_01", "phase": 1, "control_mode": "off"})
        raw = f"event: meta\ndata: {meta_data}\n"
        resp = target.parse_sse_stream(raw)
        assert resp.meta is not None
        assert resp.meta.request_id == "abc-123"
        assert resp.meta.lab_id == "PI_01"
        assert resp.meta.phase == 1
        assert resp.meta.control_mode == "off"

    def test_parse_mcp_result_event(self) -> None:
        """解析 mcp_result 事件。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="MCP_01")
        mcp_data = json.dumps({
            "tool_result": "token=sk-abc",
            "mcp_telemetry": {"exploit_success": True, "attack_class": "token_leak"},
        })
        raw = f"event: mcp_result\ndata: {mcp_data}\n"
        resp = target.parse_sse_stream(raw)
        assert resp.mcp_result is not None
        assert resp.mcp_result.tool_result == "token=sk-abc"
        assert resp.mcp_result.exploit_success is True

    def test_parse_full_stream(self) -> None:
        """解析完整 SSE 流 (meta + content + mcp_result)。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="MCP_05")
        meta_data = json.dumps({"request_id": "req-1", "lab_id": "MCP_05", "phase": 4, "control_mode": "off"})
        mcp_data = json.dumps({
            "tool_result": "SECRET_ENV=sk-test",
            "mcp_telemetry": {"exploit_success": True},
        })
        raw = (
            f"event: meta\ndata: {meta_data}\n\n"
            'data: {"content":"Calling tool..."}\n\n'
            f"event: mcp_result\ndata: {mcp_data}\n\n"
        )
        resp = target.parse_sse_stream(raw)
        assert resp.meta is not None
        assert resp.meta.phase == 4
        assert resp.content == "Calling tool..."
        assert resp.mcp_result is not None
        assert resp.mcp_result.exploit_success is True
        assert "meta" in resp.raw_events
        assert "mcp_result" in resp.raw_events

    def test_parse_invalid_json_skipped(self) -> None:
        """无效 JSON 行被跳过。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01")
        raw = 'data: {invalid json}\ndata: {"content":"ok"}\n'
        resp = target.parse_sse_stream(raw)
        assert resp.content == "ok"

    def test_parse_empty_lines(self) -> None:
        """空行被跳过。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01")
        raw = '\n\n  \ndata: {"content":"x"}\n\n'
        resp = target.parse_sse_stream(raw)
        assert resp.content == "x"


# ──────────────────────────────────────────────────────────────────
# SSEChatTarget 属性测试
# ──────────────────────────────────────────────────────────────────


class TestSSEChatTargetProperties:
    """SSEChatTarget 属性测试。"""

    def test_endpoint_url(self) -> None:
        """端点 URL 正确。"""
        target = SSEChatTarget(base_url="http://localhost:8000/", lab_id="PI_01")
        assert target.endpoint == "http://localhost:8000/api/labs/PI_01/chat"

    def test_endpoint_url_no_trailing_slash(self) -> None:
        """基础 URL 无尾部斜杠。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="DE_05")
        assert target.base_url == "http://localhost:8000"

    def test_control_mode_property(self) -> None:
        """控制模式属性。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01", control_mode="mitigate")
        assert target.control_mode == "mitigate"

    def test_session_cookie_setter(self) -> None:
        """Session cookie 设置器。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01")
        assert target.session_cookie is None
        target.session_cookie = "test-sid-123"
        assert target.session_cookie == "test-sid-123"

    def test_rpm_compatibility(self) -> None:
        """RPM 属性兼容 RateLimitedTarget。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01")
        target._max_requests_per_minute = 60
        assert target._max_requests_per_minute == 60

    @pytest.mark.asyncio
    async def test_validate_secret_async(self) -> None:
        """Secret 验证 (mock)。"""
        target = SSEChatTarget(base_url="http://localhost:8000", lab_id="PI_01")

        mock_resp = MagicMock()
        mock_resp.json = AsyncMock(return_value={"success": True, "message": "Correct!"})

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_ctx)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await target.validate_secret_async("sk-test123")
            assert result is True


# ──────────────────────────────────────────────────────────────────
# RuleBasedTarget 属性测试
# ──────────────────────────────────────────────────────────────────


class TestRuleBasedTargetProperties:
    """RuleBasedTarget 属性测试。"""

    def test_endpoint_url(self) -> None:
        """端点 URL 正确。"""
        target = RuleBasedTarget(base_url="http://localhost:8000", username="alice", password="password123")
        assert target.endpoint == "http://localhost:8000/chat"

    def test_session_id_setter(self) -> None:
        """Session ID 设置器。"""
        target = RuleBasedTarget(base_url="http://localhost:8000", username="alice", password="password123")
        assert target.session_id is None
        target.session_id = 42
        assert target.session_id == 42

    def test_rpm_compatibility(self) -> None:
        """RPM 属性兼容。"""
        target = RuleBasedTarget(base_url="http://localhost:8000", username="alice", password="password123")
        target._max_requests_per_minute = 30
        assert target._max_requests_per_minute == 30

    @pytest.mark.asyncio
    async def test_send_prompt_async_mock(self) -> None:
        """send_prompt_async (mock)。"""
        target = RuleBasedTarget(base_url="http://localhost:8000", username="alice", password="password123")

        mock_resp = MagicMock()
        mock_resp.json = AsyncMock(return_value={
            "response": "Rome is the capital of Italy.",
            "session_id": 1,
            "tokens_used": 7,
            "vulnerability_detected": None,
        })

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_ctx)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await target.send_prompt_async(prompt="What is the capital of Italy?")
            assert target.last_response is not None
            assert target.last_response.response == "Rome is the capital of Italy."
            assert target.last_response.session_id == 1
            assert target.last_response.vulnerability_detected is None


# ──────────────────────────────────────────────────────────────────
# AuthManager 测试
# ──────────────────────────────────────────────────────────────────


class TestAuthManager:
    """AuthManager 测试。"""

    def test_basic_auth_headers(self) -> None:
        """Basic auth header 生成。"""
        import base64

        manager = AuthManager(AuthConfig(
            auth_type="basic",
            username="alice",
            password="password123",
        ))
        headers = manager.get_headers()
        assert "Authorization" in headers
        expected = base64.b64encode(b"alice:password123").decode()
        assert headers["Authorization"] == f"Basic {expected}"
        assert manager.is_authenticated

    def test_bearer_auth_headers(self) -> None:
        """Bearer token header 生成。"""
        manager = AuthManager(AuthConfig(
            auth_type="bearer",
            token="my-jwt-token",
        ))
        headers = manager.get_headers()
        assert headers["Authorization"] == "Bearer my-jwt-token"

    def test_cookie_auth_headers(self) -> None:
        """Cookie header 生成。"""
        manager = AuthManager(AuthConfig(
            auth_type="cookie",
            cookie_name="aivp_sid",
            cookie_value="abc123",
        ))
        headers = manager.get_headers()
        assert headers["Cookie"] == "aivp_sid=abc123"

    def test_cookie_auth_cookies(self) -> None:
        """Cookie 字典生成。"""
        manager = AuthManager(AuthConfig(
            auth_type="cookie",
            cookie_name="aivp_sid",
            cookie_value="abc123",
        ))
        cookies = manager.get_cookies()
        assert cookies == {"aivp_sid": "abc123"}

    def test_none_auth_empty_headers(self) -> None:
        """无认证时空 headers。"""
        manager = AuthManager(AuthConfig(auth_type="none"))
        headers = manager.get_headers()
        assert headers == {}
        assert not manager.is_authenticated

    def test_extra_headers(self) -> None:
        """额外 headers。"""
        manager = AuthManager(AuthConfig(
            auth_type="basic",
            username="admin",
            password="admin123",
            extra_headers={"X-Custom": "value"},
        ))
        headers = manager.get_headers()
        assert headers["X-Custom"] == "value"
        assert "Authorization" in headers

    def test_set_cookie(self) -> None:
        """设置 cookie。"""
        manager = AuthManager(AuthConfig(auth_type="none"))
        manager.set_cookie("aivp_sid", "new-session-456")
        assert manager.config.auth_type == "cookie"
        assert manager.config.cookie_name == "aivp_sid"
        assert manager.config.cookie_value == "new-session-456"
        assert manager.is_authenticated

    def test_switch_user(self) -> None:
        """切换用户。"""
        manager = AuthManager(AuthConfig(
            auth_type="basic",
            username="alice",
            password="password123",
        ))
        manager.switch_user("admin", "admin123", user_id=3)
        assert manager.config.username == "admin"
        assert manager.config.password == "admin123"
        assert manager.config.extra_headers is not None
        assert manager.config.extra_headers["X-User-ID"] == "3"

    def test_switch_to_donkai_user(self) -> None:
        """切换到预定义 DonkAI 用户。"""
        manager = AuthManager()
        user, pwd, uid = manager.switch_to_donkai_user("admin")
        assert user == "admin"
        assert pwd == "admin123"
        assert uid == 3
        assert manager.is_authenticated

    def test_switch_to_donkai_user_invalid(self) -> None:
        """无效用户名报错。"""
        manager = AuthManager()
        with pytest.raises(ValueError, match="Unknown DonkAI user"):
            manager.switch_to_donkai_user("hacker")

    def test_for_aivp(self) -> None:
        """AIVP 认证管理器。"""
        manager = AuthManager.for_aivp("http://localhost:8000")
        assert manager.config.auth_type == "cookie"
        assert manager.config.cookie_name == "aivp_sid"

    def test_for_donkai(self) -> None:
        """DonkAI 认证管理器。"""
        manager = AuthManager.for_donkai("alice")
        assert manager.config.auth_type == "basic"
        assert manager.config.username == "alice"
        assert manager.config.password == "password123"
        assert manager.is_authenticated

    def test_for_donkai_admin(self) -> None:
        """DonkAI admin 用户。"""
        manager = AuthManager.for_donkai("admin")
        assert manager.config.username == "admin"
        assert manager.config.password == "admin123"

    def test_from_env(self) -> None:
        """从环境变量创建。"""
        with patch.dict("os.environ", {
            "TARGET_AUTH_TYPE": "basic",
            "TARGET_USERNAME": "testuser",
            "TARGET_PASSWORD": "testpass",
        }):
            manager = AuthManager.from_env()
            assert manager.config.auth_type == "basic"
            assert manager.config.username == "testuser"
            assert manager.config.password == "testpass"
