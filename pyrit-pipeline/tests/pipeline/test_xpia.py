# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tests for xpia.py — XPIA 工作流编排.

测试覆盖:
  - run_xpia: 函数签名、参数传递、错误处理
  - run_xpia_workflow_async: 原生 API 封装
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pipeline.context import PipelineContext
from pipeline.workflows.xpia import run_xpia


class TestRunXpia:
    """run_xpia 单元测试."""

    @pytest.mark.asyncio
    async def test_run_xpia_insufficient_targets(self) -> None:
        """Target 数量不足时打印错误并返回."""
        ctx = PipelineContext()
        ctx.args = MagicMock()

        with patch("pyrit.registry.TargetRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_registry_singleton.return_value.instances.get_all_instances.return_value = []
            mock_registry_cls.get_registry_singleton = mock_registry.get_registry_singleton

            # 不应该抛出异常，只是打印错误
            await run_xpia(ctx)

    @pytest.mark.asyncio
    async def test_run_xpia_default_attack_content(self) -> None:
        """默认攻击内容."""
        ctx = PipelineContext()
        ctx.args = MagicMock()
        ctx.args.xpia_attack_content = None

        mock_target1 = MagicMock()
        mock_target2 = MagicMock()
        mock_scorer_entry = MagicMock()
        mock_scorer_entry.instance = MagicMock()

        with (
            patch("pyrit.registry.TargetRegistry") as mock_target_reg,
            patch("pyrit.registry.ScorerRegistry") as mock_scorer_reg,
            patch("pipeline.workflows.xpia.run_xpia_workflow_async", new_callable=AsyncMock) as mock_run,
        ):
            mock_target_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = [
                MagicMock(instance=mock_target1),
                MagicMock(instance=mock_target2),
            ]
            mock_scorer_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = [
                mock_scorer_entry,
            ]

            mock_result = MagicMock()
            mock_result.status = "success"
            mock_result.processing_response = "test response"
            mock_result.score = None
            mock_run.return_value = mock_result

            await run_xpia(ctx)

            # 验证使用了默认攻击内容
            call_kwargs = mock_run.call_args.kwargs
            assert "Ignore all previous instructions" in call_kwargs["attack_content"]

    @pytest.mark.asyncio
    async def test_run_xpia_custom_attack_content(self) -> None:
        """自定义攻击内容."""
        ctx = PipelineContext()
        ctx.args = MagicMock()
        ctx.args.xpia_attack_content = "Custom attack payload"

        mock_target1 = MagicMock()
        mock_target2 = MagicMock()

        with (
            patch("pyrit.registry.TargetRegistry") as mock_target_reg,
            patch("pyrit.registry.ScorerRegistry") as mock_scorer_reg,
            patch("pipeline.workflows.xpia.run_xpia_workflow_async", new_callable=AsyncMock) as mock_run,
        ):
            mock_target_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = [
                MagicMock(instance=mock_target1),
                MagicMock(instance=mock_target2),
            ]
            mock_scorer_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = []

            mock_result = MagicMock()
            mock_result.status = "success"
            mock_result.processing_response = "response"
            mock_result.score = None
            mock_run.return_value = mock_result

            await run_xpia(ctx)

            call_kwargs = mock_run.call_args.kwargs
            assert call_kwargs["attack_content"] == "Custom attack payload"

    @pytest.mark.asyncio
    async def test_run_xpia_with_output_manager(self) -> None:
        """有 output_manager 时保存报告."""
        import tempfile
        from pathlib import Path

        tmpdir = Path(tempfile.mkdtemp())
        ctx = PipelineContext()
        ctx.args = MagicMock()
        ctx.args.xpia_attack_content = "test"

        # Mock output_manager with real Path
        mock_output_mgr = MagicMock()
        mock_output_mgr.reports_dir = tmpdir
        mock_output_mgr.timestamp = "20260802_120000"
        ctx._output_manager = mock_output_mgr
        # PipelineContext uses dataclass field, set it directly
        ctx.output_manager = mock_output_mgr

        mock_target1 = MagicMock()
        mock_target2 = MagicMock()
        mock_scorer_entry = MagicMock()
        mock_scorer_entry.instance = MagicMock()

        with (
            patch("pyrit.registry.TargetRegistry") as mock_target_reg,
            patch("pyrit.registry.ScorerRegistry") as mock_scorer_reg,
            patch("pipeline.workflows.xpia.run_xpia_workflow_async", new_callable=AsyncMock) as mock_run,
        ):
            mock_target_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = [
                MagicMock(instance=mock_target1),
                MagicMock(instance=mock_target2),
            ]
            mock_scorer_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = [
                mock_scorer_entry,
            ]

            mock_result = MagicMock()
            mock_result.status = "success"
            mock_result.processing_response = "test response"
            mock_result.score = MagicMock()
            mock_result.score.score_value = "True"
            mock_result.score.score_rationale = "injection succeeded"
            mock_run.return_value = mock_result

            await run_xpia(ctx)

            # 验证报告文件被创建
            report_files = list(tmpdir.glob("xpia_*_report.md"))
            assert len(report_files) == 1
            content = report_files[0].read_text(encoding="utf-8")
            assert "XPIA Report" in content
            assert "success" in content
