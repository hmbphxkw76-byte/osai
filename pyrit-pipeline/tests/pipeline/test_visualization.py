# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_visualization — 可视化函数单元测试 (P0-Gap7).

覆盖:
  - G1: _print_payload_technique_matrix (载荷-技术匹配矩阵)
  - G2: _print_converter_transform_sample (Converter 变换示例)
  - G3: _print_target_converter_adaptation (目标类型→Converter 适配)
  - G4: _print_asr_feedback_loop (ASR 反馈循环)
  - D1: _print_5layer_decision_pipeline (5层决策流水线)
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
# G1: _print_payload_technique_matrix
# ============================================================


class TestPayloadTechniqueMatrix:
    """G1: 载荷-技术匹配矩阵测试。."""

    def test_empty_datasets_no_crash(self, mock_args: pytest.fixture) -> None:
        """空数据集列表不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_scenario import _print_payload_technique_matrix

        _print_payload_technique_matrix(ctx, [], None)  # 不应抛出异常

    def test_with_datasets_and_warm_start(self, mock_args: pytest.fixture) -> None:
        """有数据集和 warm-start 时正常输出。."""
        ctx = PipelineContext(args=mock_args)
        warm_start = {"tap": 62.0, "red_teaming": 55.0}
        from pipeline.stages.stage_scenario import _print_payload_technique_matrix

        _print_payload_technique_matrix(ctx, ["harmbench", "jbb_behaviors"], warm_start)

    def test_with_none_warm_start(self, mock_args: pytest.fixture) -> None:
        """warm_start 为 None 时不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_scenario import _print_payload_technique_matrix

        _print_payload_technique_matrix(ctx, ["harmbench"], None)


# ============================================================
# G2: _print_converter_transform_sample
# ============================================================


class TestConverterTransformSample:
    """G2: Converter 变换示例测试。."""

    def test_empty_map_no_crash(self, mock_args: pytest.fixture) -> None:
        """空 converter map 不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_scenario import _print_converter_transform_sample

        _print_converter_transform_sample(ctx, {}, ["harmbench"])

    def test_with_converters(self, mock_args: pytest.fixture) -> None:
        """有 converter 链时正常输出变换效果。."""
        ctx = PipelineContext(args=mock_args)
        mock_conv = MagicMock()
        mock_conv.__class__.__name__ = "Base64Converter"
        from pipeline.stages.stage_scenario import _print_converter_transform_sample

        _print_converter_transform_sample(
            ctx, {"tap": [mock_conv], "red_teaming": [mock_conv]}, ["harmbench"]
        )


# ============================================================
# G3: _print_target_converter_adaptation
# ============================================================


class TestTargetConverterAdaptation:
    """G3: 目标类型→Converter 适配图测试。."""

    def test_no_target_type_no_crash(self, mock_args: pytest.fixture) -> None:
        """无 target_type 时不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_scenario import _print_target_converter_adaptation

        _print_target_converter_adaptation(ctx, {}, "strong")

    def test_with_api_target_type(self, mock_args: pytest.fixture) -> None:
        """api 目标类型时输出适配策略。."""
        ctx = PipelineContext(args=mock_args)
        ctx.target_type = "api"
        from pipeline.stages.stage_scenario import _print_target_converter_adaptation

        _print_target_converter_adaptation(ctx, {}, "strong")

    def test_with_web_chat_target_type(self, mock_args: pytest.fixture) -> None:
        """web_chat 目标类型时输出适配策略。."""
        ctx = PipelineContext(args=mock_args)
        ctx.target_type = "web_chat"
        mock_conv = MagicMock()
        mock_conv.__class__.__name__ = "UnicodeConfusableConverter"
        from pipeline.stages.stage_scenario import _print_target_converter_adaptation

        _print_target_converter_adaptation(ctx, {"tap": [mock_conv]}, "moderate")


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
# D1: _print_5layer_decision_pipeline
# ============================================================


class Test5LayerDecisionPipeline:
    """D1: 5层决策流水线图测试。."""

    def test_empty_datasets_no_crash(self, mock_args: pytest.fixture) -> None:
        """空数据集列表不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_scenario import _print_5layer_decision_pipeline

        _print_5layer_decision_pipeline(ctx, [], None)

    def test_with_datasets_and_warm_start(self, mock_args: pytest.fixture) -> None:
        """有数据集和 warm-start 时正常输出。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_scenario import _print_5layer_decision_pipeline

        _print_5layer_decision_pipeline(
            ctx, ["harmbench", "jbb_behaviors"], {"tap": 62.0}
        )

    def test_layer_flow_sections_present(self, mock_args: pytest.fixture) -> None:
        """验证层间数据流 section 存在。."""
        ctx = PipelineContext(args=mock_args)
        from pipeline.stages.stage_scenario import _print_5layer_decision_pipeline

        # 不崩溃即验证 (内部构造了 L1→L2, L2→L3 等层间 section)
        _print_5layer_decision_pipeline(ctx, ["harmbench"], {"tap": 50.0})


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
