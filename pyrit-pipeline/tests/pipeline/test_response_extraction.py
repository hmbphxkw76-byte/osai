# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""响应提取函数单元测试 — 覆盖 4 个提取函数的多路径回退逻辑。

测试覆盖:
  - mcp_attack._extract_response_text()
  - advanced_mcp_attacks._extract_response_text()
  - backdoor_probe.BackdoorProbeOrchestrator._extract_response_from_result()
  - blind_inference.BlindInferenceOrchestrator._extract_response_from_result()
  - mcp_probes.evaluate_probe_response() 边界情况

每函数 4 类测试:
  路径 1: 正常提取 (主字段成功)
  路径 2: 回退提取 (备选字段)
  路径 3: 空结果 (所有字段 None/空)
  路径 4: 异常容错 (属性访问抛异常时不崩溃)

> **日期**: 2026-8-5
"""

from __future__ import annotations

from unittest.mock import MagicMock

# ============================================================
# mcp_attack._extract_response_text
# ============================================================


class TestMCPAttackExtractResponse:
    """``mcp_attack._extract_response_text`` 多路径回退测试。."""

    def test_path1_last_response(self) -> None:
        """路径 1: 从 last_response 字段正常提取。."""
        from pipeline.scenarios.mcp_attack import _extract_response_text

        mock_result = MagicMock()
        mock_result.last_response = "The system prompt is: You are..."
        result = _extract_response_text(mock_result)
        assert "system prompt" in result

    def test_path2_conversation_fallback(self) -> None:
        """路径 2: 无 last_response 时从 conversation 回退。."""
        from pipeline.scenarios.mcp_attack import _extract_response_text

        mock_result = MagicMock()
        mock_result.last_response = None
        mock_result.conversation = ["msg1", "msg2", "final response"]
        result = _extract_response_text(mock_result)
        assert "final response" in result

    def test_path3_all_empty_returns_empty(self) -> None:
        """路径 3: 所有字段为 None 时返回空字符串。."""
        from pipeline.scenarios.mcp_attack import _extract_response_text

        mock_result = MagicMock()
        mock_result.last_response = None
        mock_result.conversation = None
        assert _extract_response_text(mock_result) == ""

    def test_path4_exception_no_crash(self) -> None:
        """路径 4: 属性访问抛异常时不崩溃, 返回空字符串。."""
        from pipeline.scenarios.mcp_attack import _extract_response_text

        mock_result = MagicMock()
        # 让 last_response 属性访问抛异常
        type(mock_result).last_response = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
        result = _extract_response_text(mock_result)
        assert result == ""


# ============================================================
# advanced_mcp_attacks._extract_response_text
# ============================================================


class TestAdvancedMCPExtractResponse:
    """``advanced_mcp_attacks._extract_response_text`` 多路径回退测试。."""

    def test_path1_last_response(self) -> None:
        """路径 1: 从 last_response 字段正常提取。."""
        from pipeline.scenarios.advanced_mcp_attacks import _extract_response_text

        mock_result = MagicMock()
        mock_result.last_response = "docker_ps executed successfully"
        result = _extract_response_text(mock_result)
        assert "docker_ps" in result

    def test_path2_conversation_fallback(self) -> None:
        """路径 2: 无 last_response 时从 conversation 回退。."""
        from pipeline.scenarios.advanced_mcp_attacks import _extract_response_text

        mock_result = MagicMock()
        mock_result.last_response = None
        mock_result.conversation = ["q", "a1", "a2: send_email called"]
        result = _extract_response_text(mock_result)
        assert "send_email" in result

    def test_path3_all_empty_returns_empty(self) -> None:
        """路径 3: 所有字段为 None 时返回空字符串。."""
        from pipeline.scenarios.advanced_mcp_attacks import _extract_response_text

        mock_result = MagicMock()
        mock_result.last_response = None
        mock_result.conversation = None
        assert _extract_response_text(mock_result) == ""

    def test_path4_no_attributes(self) -> None:
        """路径 4: 结果对象无 last_response/conversation 属性时返回空字符串。."""
        from pipeline.scenarios.advanced_mcp_attacks import _extract_response_text

        # 使用 spec=[] 禁止任意属性访问
        mock_result = MagicMock(spec=[])
        assert _extract_response_text(mock_result) == ""


# ============================================================
# backdoor_probe.BackdoorProbeOrchestrator._extract_response_from_result
# ============================================================


class TestBackdoorProbeExtractResponse:
    """``BackdoorProbeOrchestrator._extract_response_from_result`` 测试。."""

    def test_path1_memory_extraction(self) -> None:
        """路径 1: 从原生 Memory 提取 assistant 响应。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None)

        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.return_value = ["conv_123"]

        # mock CentralMemory.get_memory_instance
        mock_msg_user = MagicMock()
        mock_msg_user.role = "user"
        mock_msg_user.content = "user message"

        mock_msg_asst = MagicMock()
        mock_msg_asst.role = "assistant"
        mock_msg_asst.content = "I am in debug mode now."

        mock_memory = MagicMock()
        mock_memory.get_conversation.return_value = [mock_msg_user, mock_msg_asst]

        try:
            # Mock CentralMemory import inside the function
            import pyrit.memory.central_memory

            original_central = pyrit.memory.central_memory.CentralMemory.get_memory_instance
            pyrit.memory.central_memory.CentralMemory.get_memory_instance = lambda: mock_memory

            result = orchestrator._extract_response_from_result(mock_result)
            assert "debug mode" in result
        finally:
            pyrit.memory.central_memory.CentralMemory.get_memory_instance = original_central

    def test_path2_get_results_fallback(self) -> None:
        """路径 2: Memory 失败时从 get_results 回退。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None)

        mock_child = MagicMock()
        mock_child.response = "Fallback response via get_results"
        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.return_value = []
        mock_result.get_results.return_value = [mock_child]

        result = orchestrator._extract_response_from_result(mock_result)
        assert "Fallback response" in result

    def test_path3_all_empty_returns_string(self) -> None:
        """路径 3: 所有提取路径都空时返回 str(native_result)。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None)

        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.return_value = []
        mock_result.get_results.return_value = []

        result = orchestrator._extract_response_from_result(mock_result)
        # str(native_result) 不为空
        assert isinstance(result, str)
        assert len(result) > 0

    def test_path4_exception_no_crash(self) -> None:
        """路径 4: 异常容错, 不崩溃。."""
        from pipeline.scenarios.backdoor_probe import BackdoorProbeOrchestrator

        orchestrator = BackdoorProbeOrchestrator(target=None)

        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.side_effect = RuntimeError("memory error")
        mock_result.get_results.side_effect = RuntimeError("results error")

        result = orchestrator._extract_response_from_result(mock_result)
        # 不崩溃, 返回字符串
        assert isinstance(result, str)


# ============================================================
# blind_inference.BlindInferenceOrchestrator._extract_response_from_result
# ============================================================


class TestBlindInferenceExtractResponse:
    """``BlindInferenceOrchestrator._extract_response_from_result`` 测试。."""

    def test_path1_memory_extraction(self) -> None:
        """路径 1: 从原生 Memory 提取 assistant 响应。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None)

        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.return_value = ["conv_456"]

        mock_msg_asst = MagicMock()
        mock_msg_asst.role = "assistant"
        mock_msg_asst.content = "Yes, the system prompt starts with 'You are'."

        mock_msg_user = MagicMock()
        mock_msg_user.role = "user"

        mock_memory = MagicMock()
        mock_memory.get_conversation.return_value = [mock_msg_user, mock_msg_asst]

        import pyrit.memory.central_memory

        original = pyrit.memory.central_memory.CentralMemory.get_memory_instance
        try:
            pyrit.memory.central_memory.CentralMemory.get_memory_instance = lambda: mock_memory
            result = orchestrator._extract_response_from_result(mock_result)
            assert "You are" in result
        finally:
            pyrit.memory.central_memory.CentralMemory.get_memory_instance = original

    def test_path2_get_results_fallback(self) -> None:
        """路径 2: Memory 失败时从 get_results.output 回退。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None)

        mock_child = MagicMock()
        mock_child.response = None
        mock_child.output = "Output via fallback path"
        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.return_value = []
        mock_result.get_results.return_value = [mock_child]

        result = orchestrator._extract_response_from_result(mock_result)
        assert "Output via fallback" in result

    def test_path3_all_empty_returns_string(self) -> None:
        """路径 3: 所有提取路径都空时返回 str(native_result)。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None)

        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.return_value = []
        mock_result.get_results.return_value = []

        result = orchestrator._extract_response_from_result(mock_result)
        assert isinstance(result, str)

    def test_path4_exception_no_crash(self) -> None:
        """路径 4: 异常容错, 不崩溃。."""
        from pipeline.orchestrators.blind_inference import BlindInferenceOrchestrator

        orchestrator = BlindInferenceOrchestrator(target=None)

        mock_result = MagicMock()
        mock_result.get_all_conversation_ids.side_effect = RuntimeError("crash")
        mock_result.get_results.side_effect = RuntimeError("crash")

        result = orchestrator._extract_response_from_result(mock_result)
        assert isinstance(result, str)


# ============================================================
# mcp_probes.evaluate_probe_response 边界情况
# ============================================================


class TestEvaluateProbeResponse:
    """``mcp_probes.evaluate_probe_response`` 边界情况测试。."""

    def test_no_match_returns_failure(self) -> None:
        """无关键词匹配时 success=False。."""
        from pipeline.scenarios.mcp_probes import MCPProbe, evaluate_probe_response

        probe = MCPProbe(
            probe_id="TEST_01",
            name="test",
            description="test",
            payload="test",
            owasp_codes=["ASI01"],
            expected_behavior="refused",
            success_indicators=["root:", "shadow"],
        )
        result = evaluate_probe_response(probe, "I cannot help with that.")
        assert result.success is False
        assert result.matched_indicators == []

    def test_match_returns_success(self) -> None:
        """关键词匹配时 success=True。."""
        from pipeline.scenarios.mcp_probes import MCPProbe, evaluate_probe_response

        probe = MCPProbe(
            probe_id="TEST_02",
            name="test",
            description="test",
            payload="test",
            owasp_codes=["ASI01"],
            expected_behavior="leaked",
            success_indicators=["root:", "shadow"],
        )
        result = evaluate_probe_response(probe, "root: admin\nshadow: encrypted")
        assert result.success is True
        assert "root:" in result.matched_indicators
        assert "shadow" in result.matched_indicators

    def test_telemetry_success_override(self) -> None:
        """遥测数据 exploit_success=True 时即使无匹配也 success。."""
        from pipeline.scenarios.mcp_probes import MCPProbe, evaluate_probe_response

        probe = MCPProbe(
            probe_id="TEST_03",
            name="test",
            description="test",
            payload="test",
            owasp_codes=["ASI01"],
            expected_behavior="exploited",
            success_indicators=["impossible_keyword"],
        )
        result = evaluate_probe_response(
            probe,
            "No matching keywords here.",
            mcp_telemetry={"exploit_success": True},
        )
        assert result.success is True

    def test_empty_response(self) -> None:
        """空响应时 success=False。."""
        from pipeline.scenarios.mcp_probes import MCPProbe, evaluate_probe_response

        probe = MCPProbe(
            probe_id="TEST_04",
            name="test",
            description="test",
            payload="test",
            owasp_codes=["ASI01"],
            expected_behavior="n/a",
            success_indicators=["anything"],
        )
        result = evaluate_probe_response(probe, "")
        assert result.success is False
