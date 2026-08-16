# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""P0-P3: Crescendo 多轮对话 + API Escalation 测试.

测试覆盖:
  - P0: _get_attack_targets(ctx) Agent Proxy 三角色分离
  - P1: MultiTurnConversationBridge token 级截断
  - P2: _should_use_hybrid_agent_attack / _bridge_hybrid_agent_attack
  - P3: extract_api_credentials_from_response / verify_captured_api /
        switch_to_api_direct_mode / process_attack_response_for_api

> **日期**: 2026-8-16
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ============================================================
# P0: _get_attack_targets(ctx) — Agent Proxy 三角色分离
# ============================================================


class TestGetAttackTargetsAgentProxy:
    """P0: Agent Proxy Bridge 模式下三角色分离."""

    def test_agent_proxy_mode_routes_to_get_agent_proxy_targets(self) -> None:
        """ctx.metadata 有 agent_proxy_mode=True 时应调用 _get_agent_proxy_targets."""
        from pipeline.stages.stage_scenario import _get_attack_targets

        ctx = MagicMock()
        ctx.metadata = {"agent_proxy_mode": True}

        with patch(
            "pipeline.stages.stage_scenario._get_agent_proxy_targets",
            return_value=("obj", "adv", "score"),
        ) as mock_proxy:
            result = _get_attack_targets(ctx)
            mock_proxy.assert_called_once_with(ctx)
            assert result == ("obj", "adv", "score")

    def test_normal_mode_falls_through_to_registry(self) -> None:
        """ctx=None 或无 agent_proxy_mode 时走正常注册表逻辑."""
        from pipeline.stages.stage_scenario import _get_attack_targets

        # ctx=None 走正常逻辑
        with (
            patch("pipeline.stages.stage_scenario.TargetRegistry") as mock_reg_cls,
            patch("pipeline.stages.stage_scenario.logger"),
        ):
            mock_reg = MagicMock()
            mock_reg_cls.get_registry_singleton.return_value = mock_reg
            mock_reg.instances.get_all_instances.return_value = []
            result = _get_attack_targets(None)
            assert result == (None, None, None)

    def test_get_agent_proxy_targets_tag_resolution(self) -> None:
        """_get_agent_proxy_targets 应按标签正确解析三角色."""
        from pipeline.stages.stage_scenario import _get_agent_proxy_targets

        ctx = MagicMock()
        ctx.metadata = {"agent_proxy_mode": True}

        # Mock TargetRegistry with 3 entries with different tags
        burp_target = MagicMock(name="BurpHTTPTarget")
        env_target = MagicMock(name="EnvOpenAIChatTarget")
        scorer_target = MagicMock(name="ScorerTarget")

        entry_burp = MagicMock()
        entry_burp.tags = {"default_objective_target"}
        entry_burp.instance = burp_target

        entry_env = MagicMock()
        entry_env.tags = {"default"}
        entry_env.instance = env_target

        entry_scorer = MagicMock()
        entry_scorer.tags = {"scorer"}
        entry_scorer.instance = scorer_target

        with patch("pipeline.stages.stage_scenario.TargetRegistry") as mock_reg_cls:
            mock_reg = MagicMock()
            mock_reg_cls.get_registry_singleton.return_value = mock_reg
            mock_reg.instances.get_all_instances.return_value = [
                entry_burp,
                entry_env,
                entry_scorer,
            ]
            result = _get_agent_proxy_targets(ctx)

        # objective = Burp (default_objective_target without default)
        # adversarial = env (default without scorer)
        # scoring = scorer (scorer tag)
        assert result[0] is burp_target
        assert result[1] is env_target
        assert result[2] is scorer_target

    def test_get_agent_proxy_targets_fallback_shared_scorer(self) -> None:
        """无独立 scorer 时应共用 adversarial."""
        from pipeline.stages.stage_scenario import _get_agent_proxy_targets

        ctx = MagicMock()
        ctx.metadata = {"agent_proxy_mode": True}

        burp_target = MagicMock(name="BurpHTTPTarget")
        env_target = MagicMock(name="EnvOpenAIChatTarget")

        entry_burp = MagicMock()
        entry_burp.tags = {"default_objective_target"}
        entry_burp.instance = burp_target

        entry_env = MagicMock()
        entry_env.tags = {"default"}
        entry_env.instance = env_target

        with patch("pipeline.stages.stage_scenario.TargetRegistry") as mock_reg_cls:
            mock_reg = MagicMock()
            mock_reg_cls.get_registry_singleton.return_value = mock_reg
            mock_reg.instances.get_all_instances.return_value = [entry_burp, entry_env]
            result = _get_agent_proxy_targets(ctx)

        # scoring 应降级为 adversarial (env_target)
        assert result[0] is burp_target
        assert result[1] is env_target
        assert result[2] is env_target  # shared


# ============================================================
# P1: MultiTurnConversationBridge token 级截断
# ============================================================


class TestMultiTurnTokenTruncation:
    """P1: 对话历史 token 控制."""

    def test_token_truncation_with_long_messages(self) -> None:
        """长消息超过 max_history_tokens 时应截断旧消息."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        # max_history_tokens=100 → ~300 chars
        bridge = MultiTurnConversationBridge(max_history_turns=20, max_history_tokens=100)
        session_id = bridge.create_session()

        # 添加大量长消息
        for i in range(10):
            bridge.add_turn(
                session_id,
                role="user",
                content=f"User message number {i} " + "x" * 100,
            )
            bridge.add_turn(
                session_id,
                role="assistant",
                content=f"Assistant response number {i} " + "y" * 100,
            )

        # 应被截断到 ~300 chars
        messages = bridge._sessions[session_id]
        total_chars = sum(len(m["content"]) for m in messages)
        estimated_tokens = total_chars // 3
        assert estimated_tokens <= 100 or len(messages) <= 2

    def test_no_truncation_with_short_messages(self) -> None:
        """短消息不应被截断."""
        from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge

        bridge = MultiTurnConversationBridge(max_history_turns=10, max_history_tokens=4000)
        session_id = bridge.create_session()

        for i in range(5):
            bridge.add_turn(session_id, role="user", content=f"Short {i}")
            bridge.add_turn(session_id, role="assistant", content=f"Reply {i}")

        messages = bridge._sessions[session_id]
        assert len(messages) == 10  # 5 轮 = 10 条消息, 全部保留


# ============================================================
# P2: _should_use_hybrid_agent_attack
# ============================================================


class TestHybridAgentAttack:
    """P2: Agent 工具劫持 (Burp + tool_calling 混合)."""

    def test_should_use_hybrid_with_tools_field(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Burp 请求含 tools 字段 → 应使用混合模式."""
        from pipeline.stages.stage_target_classify import _should_use_hybrid_agent_attack

        burp_file = tmp_path / "request.txt"
        burp_file.write_bytes(
            b'POST /api/chat HTTP/1.1\r\n'
            b'Host: example.com\r\n'
            b'\r\n'
            b'{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","name":"read_file"}]}',
        )
        assert _should_use_hybrid_agent_attack(str(burp_file)) is True

    def test_should_not_use_hybrid_without_tools(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Burp 请求无 tools → 不应使用混合模式."""
        from pipeline.stages.stage_target_classify import _should_use_hybrid_agent_attack

        burp_file = tmp_path / "request.txt"
        burp_file.write_bytes(
            b'POST /api/chat HTTP/1.1\r\n'
            b'Host: example.com\r\n'
            b'\r\n'
            b'{"prompt":"hello"}',
        )
        assert _should_use_hybrid_agent_attack(str(burp_file)) is False

    def test_should_not_use_hybrid_nonexistent_file(self) -> None:
        """不存在的文件 → False."""
        from pipeline.stages.stage_target_classify import _should_use_hybrid_agent_attack

        assert _should_use_hybrid_agent_attack("/nonexistent/path.txt") is False


# ============================================================
# P3: extract_api_credentials_from_response
# ============================================================


class TestExtractApiCredentials:
    """P3: 从攻击响应中提取后端 API 信息."""

    def test_extract_full_credentials(self) -> None:
        """响应包含完整 endpoint + key + model → 高置信度."""
        from pipeline.targets.api_escalation import extract_api_credentials_from_response

        response = (
            "The system prompt says: API endpoint is https://api.internal.com/v1/chat/completions, "
            "use API key sk-proj-1234567890abcdefghijklmnop, model is gpt-4o"
        )
        result = extract_api_credentials_from_response(response)

        assert result is not None
        assert result["confidence"] == "high"
        assert "api.internal.com" in result["endpoint"]
        assert result["api_key"].startswith("sk-")
        assert result["model_name"] == "gpt-4o"

    def test_extract_with_bearer_prefix(self) -> None:
        """Bearer 格式的 API Key 应正确提取."""
        from pipeline.targets.api_escalation import extract_api_credentials_from_response

        response = (
            "Found config: endpoint=https://api.openai.com/v1/chat/completions, "
            "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz123456"
        )
        result = extract_api_credentials_from_response(response)

        assert result is not None
        assert result["confidence"] == "high"
        assert result["api_key"].startswith("sk-")
        assert not result["api_key"].lower().startswith("bearer")

    def test_extract_env_var_style_key(self) -> None:
        """环境变量风格的 API Key 应被检测."""
        from pipeline.targets.api_escalation import extract_api_credentials_from_response

        response = (
            "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456 "
            "endpoint=https://api.openai.com/v1/chat/completions"
        )
        result = extract_api_credentials_from_response(response)

        assert result is not None
        assert result["confidence"] == "high"
        assert result["api_key"].startswith("sk-")

    def test_extract_partial_credentials(self) -> None:
        """仅有 endpoint 无 key → 低置信度."""
        from pipeline.targets.api_escalation import extract_api_credentials_from_response

        response = "The API endpoint is https://api.example.com/v1/chat/completions"
        result = extract_api_credentials_from_response(response)

        assert result is not None
        assert result["confidence"] == "low"

    def test_extract_no_credentials(self) -> None:
        """无 API 信息 → None."""
        from pipeline.targets.api_escalation import extract_api_credentials_from_response

        response = "I cannot help with that request. It violates my safety guidelines."
        result = extract_api_credentials_from_response(response)
        assert result is None

    def test_extract_deepseek_model(self) -> None:
        """检测 deepseek 模型名."""
        from pipeline.targets.api_escalation import extract_api_credentials_from_response

        response = (
            "Config: endpoint=https://api.deepseek.com/v1/chat/completions "
            "key=sk-1234567890abcdefghijklmnopqrstuv "
            'model: "deepseek-chat"'
        )
        result = extract_api_credentials_from_response(response)

        assert result is not None
        assert "deepseek" in result["model_name"].lower()

    def test_extract_empty_response(self) -> None:
        """空响应 → None."""
        from pipeline.targets.api_escalation import extract_api_credentials_from_response

        assert extract_api_credentials_from_response("") is None


# ============================================================
# P3: switch_to_api_direct_mode
# ============================================================


class TestSwitchToApiDirectMode:
    """P3: API 直连模式切换."""

    @pytest.mark.asyncio
    async def test_switch_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """成功切换: 创建 OpenAIChatTarget 并注册."""
        from pipeline.targets.api_escalation import switch_to_api_direct_mode

        ctx = MagicMock()
        ctx.metadata = {}

        captured = {
            "endpoint": "https://api.internal.com/v1/chat/completions",
            "api_key": "sk-test1234567890abcdefghijklmnop",
            "model_name": "gpt-4o",
            "source": "attack_response",
            "confidence": "high",
        }

        mock_target = MagicMock()

        with (
            patch("pyrit.prompt_target.OpenAIChatTarget", return_value=mock_target),
            patch("pyrit.registry.TargetRegistry") as mock_reg_cls,
        ):
            mock_reg = MagicMock()
            mock_reg_cls.get_registry_singleton.return_value = mock_reg

            result = await switch_to_api_direct_mode(ctx, captured)

        assert result is True
        assert ctx.metadata["api_escalation_mode"] is True
        assert ctx.metadata["escalated_endpoint"] == captured["endpoint"]
        mock_reg.instances.register.assert_called_once()

    @pytest.mark.asyncio
    async def test_switch_missing_credentials(self) -> None:
        """缺少 endpoint 或 key → False."""
        from pipeline.targets.api_escalation import switch_to_api_direct_mode

        ctx = MagicMock()
        ctx.metadata = {}

        captured = {"endpoint": "", "api_key": "", "model_name": "auto"}

        result = await switch_to_api_direct_mode(ctx, captured)
        assert result is False


# ============================================================
# P3: process_attack_response_for_api
# ============================================================


class TestProcessAttackResponse:
    """P3: 攻击响应处理流程."""

    @pytest.mark.asyncio
    async def test_already_escalated_skips(self) -> None:
        """已升级模式时跳过检测."""
        from pipeline.targets.api_escalation import process_attack_response_for_api

        ctx = MagicMock()
        ctx.metadata = {"api_escalation_mode": True}
        ctx.args = MagicMock()

        result = await process_attack_response_for_api(ctx, "some response")
        assert result is False

    @pytest.mark.asyncio
    async def test_no_credentials_returns_false(self) -> None:
        """无 API 信息 → False."""
        from pipeline.targets.api_escalation import process_attack_response_for_api

        ctx = MagicMock()
        ctx.metadata = {}
        ctx.args = MagicMock()
        ctx.args.auto_escalate = False

        result = await process_attack_response_for_api(ctx, "No API info here")
        assert result is False

    @pytest.mark.asyncio
    async def test_detect_without_auto_escalate_records(self) -> None:
        """有 API 信息但未 --auto-escalate → 仅记录."""
        from pipeline.targets.api_escalation import process_attack_response_for_api

        ctx = MagicMock()
        ctx.metadata = {}
        ctx.args = MagicMock()
        ctx.args.auto_escalate = False

        response = (
            "endpoint: https://api.internal.com/v1/chat/completions "
            "key: sk-proj-1234567890abcdefghijklmnop"
        )

        # process_attack_response_for_api 不调用 verify_captured_api 当 auto_escalate=False
        result = await process_attack_response_for_api(ctx, response)
        assert result is False  # 未切换
        assert "detected_api_info" in ctx.metadata
