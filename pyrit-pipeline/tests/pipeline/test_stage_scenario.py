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
            patch("pipeline.stages.stage_scenario._get_objective_scorer", return_value=(None, "default")),
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
            patch("pipeline.stages.stage_scenario._get_objective_scorer", return_value=(None, "default")),
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
            assert result[0] is mock_scorer

    def test_final_fallback_none(self) -> None:
        """全部 fallback 失败时返回 None。."""
        mock_registry = MagicMock()
        mock_registry.get_registry_singleton.return_value.instances.get_by_tag.return_value = []
        mock_registry.get_registry_singleton.return_value.instances.get_entry.return_value = None
        mock_registry.get_registry_singleton.return_value.instances.get_all_instances.return_value = []

        with patch("pipeline.stages.stage_scenario.ScorerRegistry", mock_registry):
            from pipeline.stages.stage_scenario import _get_objective_scorer

            result = _get_objective_scorer()
            assert result[0] is None


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


# ============================================================
# v25.0 P0-P2 攻击载荷决策优化测试
# ============================================================


class TestBuildAdaptiveDatasetConfig:
    """P2-⑤: ASR 加权自适应预算分配测试."""

    def test_no_asr_data_fallback_to_uniform(self):
        """无 ASR 数据时回退到原生均匀 per_dataset."""
        from pipeline.stages.stage_scenario import _build_adaptive_dataset_config

        config = _build_adaptive_dataset_config(
            sorted_datasets=["owasp/asi01", "owasp/asi02"],
            max_dataset_size=5,
            dataset_level_asr=None,
        )
        assert config is not None
        assert len(config._configurations) == 2

    def test_high_asr_gets_more_budget(self):
        """高 ASR 数据集获得更多种子预算."""
        from pipeline.stages.stage_scenario import _build_adaptive_dataset_config

        dataset_asr = {
            "owasp/asi01": {"asr": 0.50, "total": 10},
            "owasp/asi02": {"asr": 0.05, "total": 10},
        }
        config = _build_adaptive_dataset_config(
            sorted_datasets=["owasp/asi01", "owasp/asi02"],
            max_dataset_size=5,
            dataset_level_asr=dataset_asr,
        )
        budgets = [c.max_dataset_size for c in config._configurations]
        assert budgets[0] > budgets[1]  # 高 ASR > 低 ASR

    def test_low_asr_minimum_budget(self):
        """低 ASR 数据集预算不低于 2."""
        from pipeline.stages.stage_scenario import _build_adaptive_dataset_config

        dataset_asr = {
            "owasp/asi01": {"asr": 0.01, "total": 10},
        }
        config = _build_adaptive_dataset_config(
            sorted_datasets=["owasp/asi01"],
            max_dataset_size=3,
            dataset_level_asr=dataset_asr,
        )
        assert config._configurations[0].max_dataset_size >= 2

    def test_medium_asr_default_budget(self):
        """中 ASR 数据集保持默认预算."""
        from pipeline.stages.stage_scenario import _build_adaptive_dataset_config

        dataset_asr = {
            "owasp/asi01": {"asr": 0.15, "total": 10},
        }
        config = _build_adaptive_dataset_config(
            sorted_datasets=["owasp/asi01"],
            max_dataset_size=5,
            dataset_level_asr=dataset_asr,
        )
        assert config._configurations[0].max_dataset_size == 5


class TestExtractHarmCategoryFromItem:
    """P2-⑥: harm category 提取测试."""

    def test_extract_from_metadata(self):
        """从 item.metadata 提取 harm_category."""
        from pipeline.stages.stage_scenario import _extract_harm_category_from_item

        item = MagicMock()
        item.metadata = {"harm_category": "cybercrime"}
        assert _extract_harm_category_from_item(item) == "cybercrime"

    def test_extract_from_category_key(self):
        """从 item.metadata 的 category 键提取."""
        from pipeline.stages.stage_scenario import _extract_harm_category_from_item

        item = MagicMock()
        item.metadata = {"category": "harassment"}
        assert _extract_harm_category_from_item(item) == "harassment"

    def test_extract_empty_when_no_metadata(self):
        """无 metadata 时返回空字符串."""
        from pipeline.stages.stage_scenario import _extract_harm_category_from_item

        item = MagicMock()
        item.metadata = None
        assert _extract_harm_category_from_item(item) == ""

    def test_extract_from_seed_metadata(self):
        """从 seeds[0].metadata 提取 harm_category."""
        from pipeline.stages.stage_scenario import _extract_harm_category_from_item

        item = MagicMock()
        item.metadata = {}
        seed = MagicMock()
        seed.metadata = {"harm_category": "deception"}
        item.seeds = [seed]
        assert _extract_harm_category_from_item(item) == "deception"


class TestColdStartConverterChains:
    """P2-⑦: 冷启动 Converter 链预生成测试."""

    def test_weak_tier_skipped(self):
        """小模型跳过冷启动 Converter 预生成."""
        from pipeline.stages.stage_scenario import _build_cold_start_converter_chains

        result = _build_cold_start_converter_chains(
            technique_names=["prompt_sending"],
            model_tier="weak",
        )
        assert result == {}

    def test_unknown_technique_gets_default_chain(self):
        """未知技术获得默认说服策略链."""
        from pipeline.stages.stage_scenario import _build_cold_start_converter_chains

        with patch("pipeline.converters.chains.build_converters_from_chain_names") as mock:
            mock.return_value = [MagicMock()]
            result = _build_cold_start_converter_chains(
                technique_names=["unknown_technique"],
                model_tier="strong",
            )
            assert "unknown_technique" in result

    def test_known_technique_gets_mapped_chain(self):
        """已知技术获得映射的 Converter 链."""
        from pipeline.stages.stage_scenario import _build_cold_start_converter_chains

        with patch("pipeline.converters.chains.build_converters_from_chain_names") as mock:
            mock.return_value = [MagicMock()]
            result = _build_cold_start_converter_chains(
                technique_names=["crescendo"],
                model_tier="strong",
            )
            assert "crescendo" in result
            # 验证调用了 persuasion_authority 链
            mock.assert_called_with(["persuasion_authority"])

    def test_build_failure_handled_gracefully(self):
        """Converter 构建失败时优雅降级."""
        from pipeline.stages.stage_scenario import _build_cold_start_converter_chains

        with patch("pipeline.converters.chains.build_converters_from_chain_names") as mock:
            mock.side_effect = Exception("build failed")
            result = _build_cold_start_converter_chains(
                technique_names=["crescendo"],
                model_tier="strong",
            )
            assert result == {}


class TestDatasetLevelAsrAutoCollect:
    """P0-②: dataset_level ASR 自动收集测试."""

    def test_auto_collect_when_file_missing(self):
        """当 dataset_level ASR 文件不存在时, 自动从 CentralMemory 收集."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_init import _apply_dataset_level_asr_prioritization

        ctx = PipelineContext()
        ctx.args = MagicMock()
        ctx.args.model = "test-model"
        ctx.args.datasets = ["owasp/asi01", "owasp/asi02"]

        with patch("pipeline.asr.optimizer.load_dataset_level_asr", return_value=None), \
             patch("pipeline.asr.optimizer.collect_dataset_level_asr_from_memory") as mock_collect:
            mock_collect.return_value = {
                "owasp/asi01": {"asr": 0.30, "total": 5},
                "owasp/asi02": {"asr": 0.10, "total": 5},
            }
            _apply_dataset_level_asr_prioritization(ctx)
            assert ctx.metadata.get("dataset_level_asr") is not None
            mock_collect.assert_called_once()

    def test_skip_auto_collect_when_file_exists(self):
        """当 dataset_level ASR 文件存在时, 不触发自动收集."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_init import _apply_dataset_level_asr_prioritization

        ctx = PipelineContext()
        ctx.args = MagicMock()
        ctx.args.model = "test-model"
        ctx.args.datasets = ["owasp/asi01"]

        existing_data = {"owasp/asi01": {"asr": 0.50, "total": 10}}
        with patch("pipeline.asr.optimizer.load_dataset_level_asr", return_value=existing_data), \
             patch("pipeline.asr.optimizer.collect_dataset_level_asr_from_memory") as mock_collect:
            _apply_dataset_level_asr_prioritization(ctx)
            assert ctx.metadata.get("dataset_level_asr") == existing_data
            mock_collect.assert_not_called()
