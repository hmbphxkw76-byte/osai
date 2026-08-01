# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_stage_initialize — Stage 3 场景初始化单元测试。.

覆盖:
  - 同次运行 ASR 反馈闭环
  - ASR 智能调度

> **日期**: 2026-8-1
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pipeline.context import PipelineContext


class TestFeedbackCurrentRunASR:
    """_feedback_current_run_asr 单元测试。."""

    def test_no_resume_id(self, mock_args: pytest.fixture) -> None:
        """无 resume ID 时设置空 metadata。."""
        ctx = PipelineContext(args=mock_args)
        # scenario_result_id 为 None (args.resume = None)

        from pipeline.stages.stage_initialize import _feedback_current_run_asr

        _feedback_current_run_asr(ctx)
        assert ctx.metadata["current_run_asr"] == {}

    def test_with_resume_id_no_results(self, mock_args: pytest.fixture) -> None:
        """有 resume ID 但无已完成结果时设置空 metadata。."""
        mock_args.resume = "run-123"
        ctx = PipelineContext(args=mock_args)

        with patch("pipeline.stages.stage_initialize.query_current_run_asr_by_technique", return_value={}):
            from pipeline.stages.stage_initialize import _feedback_current_run_asr

            _feedback_current_run_asr(ctx)
            assert ctx.metadata["current_run_asr"] == {}

    def test_with_resume_id_and_results(self, mock_args: pytest.fixture) -> None:
        """有 resume ID 且有已完成结果时写入 metadata。."""
        from pipeline.asr.optimizer import compute_stats

        mock_args.resume = "run-123"
        ctx = PipelineContext(args=mock_args)

        asr_data = {"many_shot": compute_stats(successes=5, failures=5, undetermined=0, errors=0)}
        with (
            patch("pipeline.stages.stage_initialize.query_current_run_asr_by_technique", return_value=asr_data),
            patch("pipeline.stages.stage_initialize.query_historical_asr_by_technique", return_value={}),
        ):
            from pipeline.stages.stage_initialize import _feedback_current_run_asr

            _feedback_current_run_asr(ctx)
            assert "current_run_asr" in ctx.metadata
            assert "many_shot" in ctx.metadata["current_run_asr"]


class TestReorderByASR:
    """_reorder_attacks_by_asr 单元测试。."""

    def test_no_atomic_attacks(self, mock_args: pytest.fixture) -> None:
        """无 _atomic_attacks 时直接返回。."""
        ctx = PipelineContext(args=mock_args)
        ctx.scenario = MagicMock()
        ctx.scenario._atomic_attacks = None

        from pipeline.stages.stage_initialize import _reorder_attacks_by_asr

        _reorder_attacks_by_asr(ctx)  # 不应崩溃

    def test_single_attack_no_reorder(self, mock_args: pytest.fixture) -> None:
        """仅 1 个 AtomicAttack 时不重排。."""
        ctx = PipelineContext(args=mock_args)
        attack = MagicMock()
        attack.atomic_attack_name = "attack_1"
        attack.display_group = "many_shot"
        ctx.scenario = MagicMock()
        ctx.scenario._atomic_attacks = [attack]

        with patch("pipeline.stages.stage_initialize.query_historical_asr_by_technique", return_value={}):
            from pipeline.stages.stage_initialize import _reorder_attacks_by_asr

            _reorder_attacks_by_asr(ctx)
            assert len(ctx.scenario._atomic_attacks) == 1

    def test_reorder_by_asr(self, mock_args: pytest.fixture) -> None:
        """按 ASR 降序重排。."""
        from pipeline.asr.optimizer import compute_stats

        asr_data = {
            "low_asr_tech": compute_stats(successes=1, failures=9, undetermined=0, errors=0),  # 10% ASR
            "high_asr_tech": compute_stats(successes=9, failures=1, undetermined=0, errors=0),  # 90% ASR
        }

        attack_low = MagicMock()
        attack_low.atomic_attack_name = "attack_low"
        attack_low.display_group = "low_asr_tech"

        attack_high = MagicMock()
        attack_high.atomic_attack_name = "attack_high"
        attack_high.display_group = "high_asr_tech"

        ctx = PipelineContext(args=mock_args)
        ctx.scenario = MagicMock()
        ctx.scenario._atomic_attacks = [attack_low, attack_high]  # low 在前

        with patch("pipeline.stages.stage_initialize.query_historical_asr_by_technique", return_value=asr_data):
            from pipeline.stages.stage_initialize import _reorder_attacks_by_asr

            _reorder_attacks_by_asr(ctx)
            # high ASR 应在前
            assert ctx.scenario._atomic_attacks[0].atomic_attack_name == "attack_high"
            assert ctx.scenario._atomic_attacks[1].atomic_attack_name == "attack_low"
