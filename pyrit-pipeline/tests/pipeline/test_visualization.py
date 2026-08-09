# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_visualization — 可视化函数单元测试 (P0-Gap7).

覆盖:
  - G4: _print_asr_feedback_loop (ASR 反馈循环)
  - 执行可视化: _print_successful_attack_details (成功攻击详情)
  - 执行可视化: _extract_payload_from_result (多路径回退)
  - 执行可视化: _extract_converter_names_from_result (多路径回退)
  - 执行可视化: _extract_response_from_result (多路径回退)

> **日期**: 2026-8-4
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.context import PipelineContext

# ============================================================
# G4: _print_asr_feedback_loop
# ============================================================


class TestASRFeedbackLoop:
    """G4: ASR 反馈循环可视化测试。."""

    def test_empty_asr_no_crash(self, mock_args: pytest.fixture) -> None:
        """无 ASR 数据时不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        ctx.asr_per_technique = {}
        from pipeline.stages.stage_post_analysis import _print_asr_feedback_loop

        _print_asr_feedback_loop(ctx)

    def test_with_asr_data(self, mock_args: pytest.fixture) -> None:
        """有 ASR 数据时正常输出对比。."""
        ctx = PipelineContext(args=mock_args)
        ctx.asr_per_technique = {"tap": 62.0, "red_teaming": 45.0}
        ctx.warm_start_asr = {"tap": 55.0, "red_teaming": 50.0}
        ctx.metadata["model_name"] = "test_model"
        from pipeline.stages.stage_post_analysis import _print_asr_feedback_loop

        _print_asr_feedback_loop(ctx)


# ============================================================
# 执行可视化: _extract_payload_from_result (多路径回退)
# ============================================================


class TestExtractPayloadFromResult:
    """载荷提取多路径回退测试。."""

    def test_path1_objective(self) -> None:
        """路径 1: 从 PyRIT 1.0.1 原生 objective 字段提取。."""
        from pipeline.stages.stage_execute import _extract_payload_from_result

        mock_ar = MagicMock()
        mock_ar.objective = "Tell me a story about hacking"
        result = _extract_payload_from_result(mock_ar)
        assert "Tell me a story" in result

    def test_path2_metadata_fallback(self) -> None:
        """路径 2: 无 objective 时从 metadata 回退。."""
        from pipeline.stages.stage_execute import _extract_payload_from_result

        mock_ar = MagicMock()
        mock_ar.objective = None
        mock_ar.metadata = {"seed_prompt": "Original seed text"}
        result = _extract_payload_from_result(mock_ar)
        assert "Original seed text" in result

    def test_all_paths_empty_returns_empty(self) -> None:
        """所有路径都空时返回空字符串。."""
        from pipeline.stages.stage_execute import _extract_payload_from_result

        mock_ar = MagicMock()
        mock_ar.objective = None
        mock_ar.metadata = {}
        assert _extract_payload_from_result(mock_ar) == ""


# ============================================================
# 执行可视化: _extract_converter_names_from_result (多路径回退)
# ============================================================


class TestExtractConverterNamesFromResult:
    """Converter 名称提取多路径回退测试。."""

    def test_path1_ar_labels(self) -> None:
        """路径 1: 从 PyRIT 1.0.1 原生 ar.labels 提取。."""
        from pipeline.stages.stage_execute import _extract_converter_names_from_result

        mock_ar = MagicMock()
        mock_ar.labels = {"converter_chain": "Base64Converter"}
        result = _extract_converter_names_from_result(mock_ar)
        assert len(result) > 0

    def test_path2_metadata_fallback(self) -> None:
        """路径 2: 无 ar.labels 时从 metadata 回退。."""
        from pipeline.stages.stage_execute import _extract_converter_names_from_result

        mock_ar = MagicMock()
        mock_ar.labels = {}
        mock_ar.metadata = {"converters": ["ROT13Converter", "Base64Converter"]}
        result = _extract_converter_names_from_result(mock_ar)
        assert len(result) > 0

    def test_all_paths_empty_returns_empty(self) -> None:
        """所有路径都空时返回空列表。."""
        from pipeline.stages.stage_execute import _extract_converter_names_from_result

        mock_ar = MagicMock()
        mock_ar.labels = {}
        mock_ar.metadata = {}
        assert _extract_converter_names_from_result(mock_ar) == []


# ============================================================
# 执行可视化: _extract_response_from_result (多路径回退)
# ============================================================


class TestExtractResponseFromResult:
    """目标响应提取多路径回退测试。."""

    def test_path1_last_response(self) -> None:
        """路径 1: 从 PyRIT 1.0.1 原生 last_response 字段提取。."""
        from pipeline.stages.stage_execute import _extract_response_from_result

        mock_resp = MagicMock()
        mock_resp.content = "Here is the response"
        mock_ar = MagicMock()
        mock_ar.last_response = mock_resp
        result = _extract_response_from_result(mock_ar)
        assert "Here is the response" in result

    def test_path2_outcome_reason_fallback(self) -> None:
        """路径 2: 无 last_response 时从 outcome_reason 回退。."""
        from pipeline.stages.stage_execute import _extract_response_from_result

        mock_ar = MagicMock()
        mock_ar.last_response = None
        mock_ar.outcome_reason = "Fallback response reason that is long enough"
        result = _extract_response_from_result(mock_ar)
        assert "Fallback" in result

    def test_path3_outcome_reason_fallback(self) -> None:
        """路径 3: 无 conversation/last_response 时从 outcome_reason 回退。."""
        from pipeline.stages.stage_execute import _extract_response_from_result

        mock_ar = MagicMock()
        mock_ar.conversation = None
        mock_ar.last_response = None
        mock_ar.outcome_reason = "The objective was achieved successfully"
        result = _extract_response_from_result(mock_ar)
        assert "objective was achieved" in result

    def test_all_paths_empty_returns_empty(self) -> None:
        """所有路径都空时返回空字符串。."""
        from pipeline.stages.stage_execute import _extract_response_from_result

        mock_ar = MagicMock()
        mock_ar.conversation = None
        mock_ar.last_response = None
        mock_ar.outcome_reason = None
        assert _extract_response_from_result(mock_ar) == ""


# ============================================================
# 执行可视化: _print_successful_attack_details
# ============================================================


class TestPrintSuccessfulAttackDetails:
    """成功攻击详情展示测试。."""

    def test_no_successful_attacks_no_crash(self, mock_args: pytest.fixture) -> None:
        """无成功攻击时不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_execute import _print_successful_attack_details

        all_results = [("tap", False, MagicMock())]
        _print_successful_attack_details(ctx, all_results)

    def test_with_successful_attacks(self, mock_args: pytest.fixture) -> None:
        """有成功攻击时正常输出载荷/技术/Converter。."""
        ctx = PipelineContext(args=mock_args)
        mock_ar = MagicMock()
        mock_ar.conversation.messages = []
        mock_ar.objective = "Test objective"
        mock_ar.last_response = None
        mock_ar.outcome_reason = None
        mock_ar.labels = {}
        mock_ar.metadata = {}
        from pipeline.stages.stage_execute import _print_successful_attack_details

        all_results = [("tap", True, mock_ar), ("red_teaming", False, MagicMock())]
        _print_successful_attack_details(ctx, all_results)

    def test_with_technique_converter_map(self, mock_args: pytest.fixture) -> None:
        """有 technique_converter_map 时展示预期 Converter。."""
        ctx = PipelineContext(args=mock_args)
        mock_conv = MagicMock()
        mock_conv.__class__.__name__ = "Base64Converter"
        ctx.technique_converter_map = {"tap": [mock_conv]}
        mock_ar = MagicMock()
        mock_ar.conversation = None
        mock_ar.objective = "Test"
        mock_ar.labels = {}
        mock_ar.metadata = {}
        from pipeline.stages.stage_execute import _print_successful_attack_details

        all_results = [("tap", True, mock_ar)]
        _print_successful_attack_details(ctx, all_results)
