# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_stage_execute — Stage 4 场景执行单元测试。.

覆盖:
  - ASR 计算 (空数据保护)
  - ASR 排行榜展示

> **日期**: 2026-8-1
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.context import PipelineContext


class TestComputeASR:
    """_print_attack_summary ASR 计算单元测试 (原 _compute_asr 已内联)。."""

    def test_none_result_no_crash(self, mock_args: pytest.fixture) -> None:
        """Result 为 None 时不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        ctx.result = None

        from pipeline.stages.stage_execute import _print_attack_summary

        _print_attack_summary(ctx, {})
        assert ctx.asr_per_technique == {}
        assert ctx.overall_asr == 0

    def test_empty_attack_results(self, mock_args: pytest.fixture) -> None:
        """空 attack_results 不崩溃。."""
        ctx = PipelineContext(args=mock_args)
        ctx.result = MagicMock()
        ctx.result.attack_results = {}
        ctx.result.get_display_groups = MagicMock(return_value={})
        ctx.result.objective_achieved_rate = MagicMock(return_value=0)

        from pipeline.stages.stage_execute import _print_attack_summary

        _print_attack_summary(ctx, {})
        assert ctx.asr_per_technique == {}
        assert ctx.overall_asr == 0

    def test_with_results(self, mock_args: pytest.fixture) -> None:
        """有结果时正确计算 ASR。."""
        from pyrit.models import AttackOutcome

        # 模拟 3 个成功 + 2 个失败
        # 设置 strategy identifier 以提取技术名 (否则回退为 "unknown")
        def _make_result(outcome: AttackOutcome) -> MagicMock:
            r = MagicMock()
            r.outcome = outcome
            identifier = MagicMock()
            identifier.name = None  # extract_technique_name 先检查 name, None 时回退到 class_name
            identifier.class_name = "many_shot"
            r.get_attack_strategy_identifier = MagicMock(return_value=identifier)
            return r

        success_results = [_make_result(AttackOutcome.SUCCESS) for _ in range(3)]
        failure_results = [_make_result(AttackOutcome.FAILURE) for _ in range(2)]

        ctx = PipelineContext(args=mock_args)
        ctx.result = MagicMock()
        ctx.result.get_display_groups = MagicMock(
            return_value={
                "many_shot": success_results + failure_results,
            }
        )
        ctx.result.objective_achieved_rate = MagicMock(return_value=60)

        from pipeline.stages.stage_execute import _print_attack_summary

        _print_attack_summary(ctx, {})
        assert "many_shot" in ctx.asr_per_technique
        assert ctx.asr_per_technique["many_shot"] == pytest.approx(60.0)  # 3/5 * 100
        assert ctx.overall_asr == 60

    def test_empty_group_skipped(self, mock_args: pytest.fixture) -> None:
        """空 display_group 被跳过。."""
        ctx = PipelineContext(args=mock_args)
        ctx.result = MagicMock()
        ctx.result.get_display_groups = MagicMock(
            return_value={
                "empty_group": [],
            }
        )
        ctx.result.objective_achieved_rate = MagicMock(return_value=0)

        from pipeline.stages.stage_execute import _print_attack_summary

        _print_attack_summary(ctx, {})
        assert "empty_group" not in ctx.asr_per_technique
