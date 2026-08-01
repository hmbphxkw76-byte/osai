# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_stage_scenario — Stage 2 场景配置单元测试。.

覆盖:
  - set_params_from_args 异常处理
  - 评分器 fallback 链
  - converter 路由

> **日期**: 2026-8-1
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pipeline.context import PipelineContext


@pytest.mark.asyncio
class TestStageScenario:
    """Stage 2: stage_scenario.run 单元测试。."""

    async def test_set_params_failure_raises(self, mock_args: pytest.fixture) -> None:
        """set_params_from_args 失败时引发异常。."""
        ctx = PipelineContext(args=mock_args)

        with (
            patch("pipeline.stages.stage_scenario.query_historical_asr_by_category", return_value={}),
            patch("pipeline.stages.stage_scenario.query_historical_asr_by_technique", return_value={}),
            patch("pipeline.stages.stage_scenario.sort_datasets_by_asr", return_value=mock_args.datasets),
            patch("pipeline.stages.stage_scenario.get_asr_summary", return_value=""),
            patch("pipeline.stages.stage_scenario.get_technique_asr_summary", return_value=""),
            patch("pipeline.stages.stage_scenario.TextAdaptive") as mock_text_adaptive_cls,
            patch("pipeline.stages.stage_scenario.CompoundDatasetAttackConfiguration"),
            patch("pipeline.stages.stage_scenario.FailureTypeRoutingSelector"),
            patch("pipeline.stages.stage_scenario.SelectorScope"),
            patch("pipeline.stages.stage_scenario._get_objective_scorer", return_value=None),
        ):
            mock_scenario = MagicMock()
            mock_scenario.set_params_from_args = MagicMock(side_effect=RuntimeError("Invalid params"))
            mock_text_adaptive_cls.return_value = mock_scenario

            from pipeline.stages.stage_scenario import run as stage_scenario

            with pytest.raises(RuntimeError, match="Invalid params"):
                await stage_scenario(ctx)

    async def test_converter_failure_handled(self, mock_args: pytest.fixture) -> None:
        """Converter 路由失败时优雅处理, 不中断流程。."""
        mock_args.converters = ["unknown_converter"]
        ctx = PipelineContext(args=mock_args)

        with (
            patch("pipeline.stages.stage_scenario.query_historical_asr_by_category", return_value={}),
            patch("pipeline.stages.stage_scenario.sort_datasets_by_asr", return_value=mock_args.datasets),
            patch("pipeline.stages.stage_scenario.get_asr_summary", return_value=""),
            patch("pipeline.stages.stage_scenario.get_technique_asr_summary", return_value=""),
            patch("pipeline.stages.stage_scenario.query_historical_asr_by_technique", return_value={}),
            patch("pipeline.stages.stage_scenario.TextAdaptive") as mock_text_adaptive_cls,
            patch("pipeline.stages.stage_scenario.CompoundDatasetAttackConfiguration"),
            patch("pipeline.stages.stage_scenario.FailureTypeRoutingSelector"),
            patch("pipeline.stages.stage_scenario.SelectorScope"),
            patch("pipeline.stages.stage_scenario._get_objective_scorer", return_value=None),
            patch("pipeline.stages.stage_scenario.AttackTechniqueRegistry"),
        ):
            mock_scenario = MagicMock()
            mock_scenario.set_params_from_args = MagicMock()
            mock_text_adaptive_cls.return_value = mock_scenario

            from pipeline.stages.stage_scenario import run as stage_scenario

            # 不应引发异常, converter 失败被捕获
            await stage_scenario(ctx)
            assert ctx.scenario is mock_scenario


class TestGetObjectiveScorer:
    """_get_objective_scorer 单元测试 (三级 fallback)。."""

    def test_first_fallback_default_tag(self) -> None:
        """优先从 default_objective_scorer 标签获取。."""
        mock_scorer = MagicMock()
        mock_registry = MagicMock()
        mock_entry = MagicMock()
        mock_entry.instance = mock_scorer
        mock_registry.get_registry_singleton.return_value.instances.get_by_tag.return_value = [mock_entry]

        with patch("pipeline.stages.stage_scenario.ScorerRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_objective_scorer

            result = _get_objective_scorer()
            assert result is mock_scorer

    def test_final_fallback_none(self) -> None:
        """全部 fallback 失败时返回 None。."""
        mock_registry = MagicMock()
        mock_registry.get_registry_singleton.return_value.instances.get_by_tag.return_value = []
        mock_registry.get_registry_singleton.return_value.instances.get_entry.return_value = None
        mock_registry.get_registry_singleton.return_value.instances.get_all_instances.return_value = []

        with patch("pipeline.stages.stage_scenario.ScorerRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_objective_scorer

            result = _get_objective_scorer()
            assert result is None


# ──────────────────────────────────────────────────────────────────
#  _get_converter_target (v8.0 P5-2 单元测试)
# ──────────────────────────────────────────────────────────────────


class TestGetConverterTarget:
    """_get_converter_target 单元测试 (4 级 fallback)。.

    测试从 TargetRegistry 获取 LLM 辅助 Converter 链所需目标实例。
    优先级:
      1. adversarial_chat 标签
      2. converter_target 标签
      3. objective_scorer_chat 名称
      4. 第一个非 default_objective_target 的目标
      5. None
    """

    def test_priority_1_adversarial_chat_tag(self) -> None:
        """优先级 1: 从 adversarial_chat 标签获取。."""
        mock_target = MagicMock()
        mock_registry = self._build_registry(
            by_tag_results={
                "adversarial_chat": [self._entry("adv_chat", mock_target)],
            },
        )
        with patch("pipeline.stages.stage_scenario.TargetRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_converter_target

            result = _get_converter_target()
            assert result is mock_target

    def test_priority_2_converter_target_tag(self) -> None:
        """优先级 2: 无 adversarial_chat 时从 converter_target 标签获取。."""
        mock_target = MagicMock()
        mock_registry = self._build_registry(
            by_tag_results={
                "adversarial_chat": [],
                "converter_target": [self._entry("conv_target", mock_target)],
            },
        )
        with patch("pipeline.stages.stage_scenario.TargetRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_converter_target

            result = _get_converter_target()
            assert result is mock_target

    def test_priority_3_objective_scorer_chat_name(self) -> None:
        """优先级 3: 无前两个标签时从 objective_scorer_chat 名称获取。."""
        mock_target = MagicMock()
        mock_registry = self._build_registry(
            by_tag_results={
                "adversarial_chat": [],
                "converter_target": [],
            },
            get_entry_result=self._entry("objective_scorer_chat", mock_target),
        )
        with patch("pipeline.stages.stage_scenario.TargetRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_converter_target

            result = _get_converter_target()
            assert result is mock_target

    def test_priority_4_first_non_objective_target(self) -> None:
        """优先级 4: 取第一个非 default_objective_target 的目标。."""
        objective_target = MagicMock()
        other_target = MagicMock()
        mock_registry = self._build_registry(
            by_tag_results={
                "adversarial_chat": [],
                "converter_target": [],
                "default_objective_target": [self._entry("obj", objective_target)],
            },
            get_entry_result=None,
            all_instances=[
                self._entry("obj", objective_target),
                self._entry("other", other_target),
            ],
        )
        with patch("pipeline.stages.stage_scenario.TargetRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_converter_target

            result = _get_converter_target()
            assert result is other_target

    def test_priority_5_all_empty_returns_none(self) -> None:
        """优先级 5: 全部 fallback 失败时返回 None。."""
        mock_registry = self._build_registry(
            by_tag_results={
                "adversarial_chat": [],
                "converter_target": [],
                "default_objective_target": [],
            },
            get_entry_result=None,
            all_instances=[],
        )
        with patch("pipeline.stages.stage_scenario.TargetRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_converter_target

            result = _get_converter_target()
            assert result is None

    # ── 辅助方法 ──

    @staticmethod
    def _entry(name: str, instance: MagicMock) -> MagicMock:
        """构建模拟 registry entry。."""
        entry = MagicMock()
        entry.name = name
        entry.instance = instance
        return entry

    @staticmethod
    def _build_registry(
        by_tag_results: dict | None = None,
        get_entry_result: MagicMock | None = None,
        all_instances: list | None = None,
    ) -> MagicMock:
        """构建模拟 TargetRegistry。.

        Args:
            by_tag_results: {tag: [entries]} 映射, 用于 get_by_tag 返回值
            get_entry_result: get_entry 返回值 (单个 entry 或 None)
            all_instances: get_all_instances 返回值 (entry 列表)
        """
        mock_registry = MagicMock()
        instances = MagicMock()

        # get_by_tag: 根据 tag 参数返回对应列表
        tag_map = by_tag_results or {}
        instances.get_by_tag.side_effect = lambda tag: tag_map.get(tag, [])

        # get_entry: 返回指定 entry 或 None
        instances.get_entry.return_value = get_entry_result

        # get_all_instances: 返回全部 entry 列表
        instances.get_all_instances.return_value = all_instances or []

        mock_registry.get_registry_singleton.return_value.instances = instances
        return mock_registry
