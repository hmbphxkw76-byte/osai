# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""V-65~V-70 Agent Proxy Bridge 测试.

测试覆盖:
  - V-66: CapabilityAdapter (build_multi_turn_configuration / apply_multi_turn_capability)
  - V-67: MultiTurnConversationBridge (创建会话 / 添加轮次 / 历史注入 / 清除)
  - V-68: detect_agent_capability_from_burp (Agent 特征检测)
  - V-69: _can_use_agent_proxy (自动检测条件)
  - V-65: _bridge_agent_proxy (端到端桥接 — Mock)
  - 路由优先级 (tool_calling > agent_proxy > burp_api)

> **日期**: 2026-8-16
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ============================================================
# V-66: CapabilityAdapter
# ============================================================


class TestCapabilityAdapter:
    """V-66: CapabilityAdapter 非侵入式能力声明."""

    def test_build_multi_turn_configuration(self) -> None:
        """build_multi_turn_configuration 应返回含 supports_multi_turn=True 的配置."""
        from pipeline.targets.capability_adapter import build_multi_turn_configuration

        config = build_multi_turn_configuration()
        # 可能因 PyRIT 版本差异返回 None
        if config is not None:
            capabilities = config.capabilities
            assert capabilities.supports_multi_turn is True
            assert capabilities.supports_editable_history is True

    def test_build_multi_turn_configuration_immutability(self) -> None:
        """多次调用应返回独立配置实例 (不共享引用)."""
        from pipeline.targets.capability_adapter import build_multi_turn_configuration

        config1 = build_multi_turn_configuration()
        config2 = build_multi_turn_configuration()
        if config1 is not None and config2 is not None:
            assert config1 is not config2

    def test_apply_multi_turn_capability_to_mock_target(self) -> None:
        """apply_multi_turn_capability 应为 Mock Target 设置 _custom_configuration."""
        from pipeline.targets.capability_adapter import apply_multi_turn_capability

        mock_target = MagicMock()
        result = apply_multi_turn_capability(mock_target)
        # 如果 PyRIT 原生导入成功, 应返回 True
        if result:
            assert hasattr(mock_target, "_custom_configuration")
            assert mock_target._custom_configuration is not None


# ============================================================
# V-67: MultiTurnConversationBridge
# ============================================================


class TestMultiTurnConversationBridge:
    """V-67: MultiTurnConversationBridge 多轮对话历史管理."""

    def test_create_session(self) -> None:
        """create_session 应返回唯一 session ID."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge()
        session1 = bridge.create_session()
        session2 = bridge.create_session()
        assert session1 != session2
        assert bridge.session_count == 2

    def test_add_turn_and_retrieve(self) -> None:
        """add_turn 后应能通过 inject_history 获取历史."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge()
        session_id = bridge.create_session()

        bridge.add_turn(session_id, role="user", content="Hello")
        bridge.add_turn(session_id, role="assistant", content="Hi there")

        body = '{"prompt":"{PROMPT}"}'
        result = bridge.inject_history(body, session_id=session_id, current_prompt="Next attack")

        # 历史应出现在结果中
        assert "Hello" in result
        assert "Hi there" in result
        assert "Next attack" in result

    def test_inject_history_openai_messages_format(self) -> None:
        """OpenAI messages 格式: 历史应追加到 messages 数组."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge()
        session_id = bridge.create_session()

        bridge.add_turn(session_id, role="user", content="Round 1 user")
        bridge.add_turn(session_id, role="assistant", content="Round 1 assistant")

        body = json.dumps({
            "messages": [
                {"role": "system", "content": "You are a test assistant."},
                {"role": "user", "content": "{PROMPT}"},
            ]
        })
        result = bridge.inject_history(body, session_id=session_id, current_prompt="Round 2 attack")

        data = json.loads(result)
        messages = data["messages"]
        # 应包含: system + history(2) + current(1) = 4 messages
        assert len(messages) == 4
        assert messages[0]["role"] == "system"
        assert messages[1]["content"] == "Round 1 user"
        assert messages[2]["content"] == "Round 1 assistant"
        assert messages[3]["content"] == "Round 2 attack"

    def test_inject_history_no_history(self) -> None:
        """无历史时, {PROMPT} 直接替换为 current_prompt."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge()
        session_id = bridge.create_session()

        body = '{"messages":[{"role":"user","content":"{PROMPT}"}]}'
        result = bridge.inject_history(body, session_id=session_id, current_prompt="First attack")

        data = json.loads(result)
        assert data["messages"][0]["content"] == "First attack"

    def test_max_history_turns_truncation(self) -> None:
        """超过 max_history_turns 时应截断旧历史."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge(max_history_turns=2)
        session_id = bridge.create_session()

        # 添加 5 轮 (10 条消息)
        for i in range(5):
            bridge.add_turn(session_id, role="user", content=f"User turn {i}")
            bridge.add_turn(session_id, role="assistant", content=f"Assistant turn {i}")

        body = '{"prompt":"{PROMPT}"}'
        result = bridge.inject_history(body, session_id=session_id, current_prompt="Current")

        # 应只保留最后 2 轮 (4 条消息)
        assert "User turn 0" not in result  # 已截断
        assert "User turn 3" in result  # 保留
        assert "User turn 4" in result  # 保留
        assert "Current" in result

    def test_clear_session(self) -> None:
        """clear_session 后历史应为空."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge()
        session_id = bridge.create_session()

        bridge.add_turn(session_id, role="user", content="Test")
        bridge.clear_session(session_id)

        body = '{"prompt":"{PROMPT}"}'
        result = bridge.inject_history(body, session_id=session_id, current_prompt="After clear")
        assert "Test" not in result
        assert "After clear" in result

    def test_clear_all(self) -> None:
        """clear_all 应清除所有会话."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge()
        s1 = bridge.create_session()
        s2 = bridge.create_session()

        bridge.add_turn(s1, role="user", content="Session 1")
        bridge.add_turn(s2, role="user", content="Session 2")

        bridge.clear_all()
        assert bridge.session_count == 0


# ============================================================
# V-68: detect_agent_capability_from_burp
# ============================================================


class TestDetectAgentCapability:
    """V-68: 从 Burp 请求检测 Agent 能力."""

    def test_detect_tools_field(self) -> None:
        """请求体含 tools 字段 → Agent."""
        from pipeline.targets.capability_adapter import detect_agent_capability_from_burp

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","name":"read_file"}]}'
        )
        assert detect_agent_capability_from_burp(request) is True

    def test_detect_functions_field(self) -> None:
        """请求体含 functions 字段 → Agent."""
        from pipeline.targets.capability_adapter import detect_agent_capability_from_burp

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"functions":[{"name":"send_email"}]}'
        )
        assert detect_agent_capability_from_burp(request) is True

    def test_detect_tool_calls_in_messages(self) -> None:
        """请求体 messages 含 tool_calls → Agent."""
        from pipeline.targets.capability_adapter import detect_agent_capability_from_burp

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"call_1"}]}]}'
        )
        assert detect_agent_capability_from_burp(request) is True

    def test_detect_simple_llm_app(self) -> None:
        """简单 LLM 应用 (仅 prompt 字段) → 非 Agent."""
        from pipeline.targets.capability_adapter import detect_agent_capability_from_burp

        request = (
            "POST /api/labs/DE_02/chat HTTP/1.1\r\n"
            "Host: 192.168.18.14\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"introduce yourself"}'
        )
        assert detect_agent_capability_from_burp(request) is False

    def test_detect_non_json_body(self) -> None:
        """非 JSON 请求体 → 非 Agent."""
        from pipeline.targets.capability_adapter import detect_agent_capability_from_burp

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            "plain text body"
        )
        assert detect_agent_capability_from_burp(request) is False

    def test_detect_empty_body(self) -> None:
        """空请求体 → 非 Agent."""
        from pipeline.targets.capability_adapter import detect_agent_capability_from_burp

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
        )
        assert detect_agent_capability_from_burp(request) is False


# ============================================================
# V-69: _can_use_agent_proxy
# ============================================================


class TestCanUseAgentProxy:
    """V-69: Agent Proxy Bridge 自动检测条件."""

    def test_auto_detect_with_burp_and_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """有 --burp-request + .env 有 OPENAI_CHAT_ENDPOINT → True."""
        from pipeline.stages.stage_target_classify import _can_use_agent_proxy

        args = MagicMock()
        args.burp_request = "data/burp/request.txt"
        args.tool_calling = False
        args.target_url = "http://example.com/api/chat"

        ctx = MagicMock()
        ctx.args = args

        monkeypatch.setenv("OPENAI_CHAT_ENDPOINT", "https://api.example.com/v1")

        assert _can_use_agent_proxy(ctx) is True

    def test_auto_detect_without_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """有 --burp-request 但 .env 无 OPENAI_CHAT_ENDPOINT → False."""
        from pipeline.stages.stage_target_classify import _can_use_agent_proxy

        args = MagicMock()
        args.burp_request = "data/burp/request.txt"
        args.tool_calling = False
        args.target_url = "http://example.com/api/chat"

        ctx = MagicMock()
        ctx.args = args

        monkeypatch.delenv("OPENAI_CHAT_ENDPOINT", raising=False)

        assert _can_use_agent_proxy(ctx) is False

    def test_auto_detect_with_tool_calling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """指定 --tool-calling → False (tool-calling 优先级更高)."""
        from pipeline.stages.stage_target_classify import _can_use_agent_proxy

        args = MagicMock()
        args.burp_request = "data/burp/request.txt"
        args.tool_calling = True
        args.target_url = "http://example.com/api/chat"

        ctx = MagicMock()
        ctx.args = args

        monkeypatch.setenv("OPENAI_CHAT_ENDPOINT", "https://api.example.com/v1")

        assert _can_use_agent_proxy(ctx) is False

    def test_auto_detect_without_burp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无 --burp-request → False."""
        from pipeline.stages.stage_target_classify import _can_use_agent_proxy

        args = MagicMock()
        args.burp_request = None
        args.tool_calling = False
        args.target_url = "http://example.com/api/chat"

        ctx = MagicMock()
        ctx.args = args

        monkeypatch.setenv("OPENAI_CHAT_ENDPOINT", "https://api.example.com/v1")

        # 无 burp_request, 且自动发现失败 → False
        with patch("pipeline.stages.stage_target_classify._discover_burp_request_file", return_value=None):
            assert _can_use_agent_proxy(ctx) is False


# ============================================================
# V-65: _bridge_agent_proxy (端到端 Mock)
# ============================================================


class TestBridgeAgentProxy:
    """V-65: Agent Proxy Bridge 端到端桥接测试."""

    @pytest.mark.asyncio
    async def test_bridge_agent_proxy_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
        """成功桥接: Burp 请求 + .env 配置 → 三角色分离注册."""
        # 创建临时 Burp 请求文件
        import tempfile

        import pipeline.stages.stage_target_classify as stage_mod
        from pipeline.context import PipelineContext
        tmpdir = tempfile.mkdtemp()
        burp_file = f"{tmpdir}/request.txt"
        with open(burp_file, "w", encoding="utf-8") as f:
            f.write(
                "POST /api/chat HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Content-Type: application/json\r\n"
                "\r\n"
                '{"messages":[{"role":"user","content":"{PROMPT}"}]}'
            )

        # Mock args
        args = MagicMock()
        args.rate_limit = 3
        args.rate_limit_retries = 3
        args.api_response_path = "choices[0].message.content"
        args.tool_calling = False

        ctx = MagicMock(spec=PipelineContext)
        ctx.args = args
        ctx.metadata = {}
        ctx.target_type = ""

        # Mock .env
        monkeypatch.setenv("OPENAI_CHAT_ENDPOINT", "https://api.example.com/v1")
        monkeypatch.setenv("OPENAI_CHAT_MODEL", "test-model")
        monkeypatch.setenv("OBJECTIVE_SCORER_CHAT_ENDPOINT", "https://scorer.example.com/v1")
        monkeypatch.setenv("OBJECTIVE_SCORER_CHAT_MODEL", "scorer-model")

        # Mock PyRIT HTTPTarget
        mock_http_target = MagicMock()

        # Mock functions that _bridge_agent_proxy calls
        monkeypatch.setattr(stage_mod, "_detect_sse_from_request", lambda x: False)
        monkeypatch.setattr(stage_mod, "_detect_tls_from_request", lambda x: False)
        monkeypatch.setattr(stage_mod, "_build_non_stream_variant", lambda x: None)
        monkeypatch.setattr(stage_mod, "_build_burp_callback", lambda **kw: MagicMock())
        monkeypatch.setattr(stage_mod, "_fix_content_length", lambda x: x)
        monkeypatch.setattr(stage_mod, "_inject_dynamic_session_fields", lambda x: x)

        async def mock_probe(*args, **kwargs):
            return {"response_path": "content", "is_sse": False}

        monkeypatch.setattr(stage_mod, "_burp_pre_flight_probe", mock_probe)

        async def mock_probe_caps(*args, **kwargs):
            pass

        monkeypatch.setattr(stage_mod, "_probe_and_record_capabilities", mock_probe_caps)

        # Mock HTTPTarget constructor
        with (
            patch("pyrit.prompt_target.HTTPTarget", return_value=mock_http_target),
            patch("pyrit.registry.TargetRegistry") as mock_reg_cls,
        ):
            mock_registry = MagicMock()
            mock_reg_cls.get_registry_singleton.return_value = mock_registry

            result = await stage_mod._bridge_agent_proxy(
                ctx, "http://example.com/api/chat", burp_file, MagicMock()
            )

        assert result is True
        assert ctx.metadata.get("agent_proxy_mode") is True
        assert ctx.http_target_configured is True
        # 三角色分离: 应注册 agent_proxy_objective_target (不覆盖 default)
        mock_registry.instances.register.assert_called()
