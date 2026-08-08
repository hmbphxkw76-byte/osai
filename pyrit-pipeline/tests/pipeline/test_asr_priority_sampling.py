# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_asr_priority_sampling — ASR 优先级采样 monkey-patch 单元测试。

覆盖:
  - _apply_asr_priority_sampling_patch: monkey-patch 安装和采样行为
  - _extract_asr_priority_from_item: 从 AttackSeedGroup/Seed 提取 ASR 优先级
  - 回退行为: 无 ASR 数据时回退到原生 random.sample

> **日期**: 2026-8-8
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

# ──────────────────────────────────────────────────────────────────
#  _extract_asr_priority_from_item
# ──────────────────────────────────────────────────────────────────


class TestExtractAsrPriorityFromItem:
    """_extract_asr_priority_from_item: 从 item 提取 ASR 优先级。."""

    def test_metadata_asr_priority(self) -> None:
        """item.metadata 有 asr_priority → 返回该值。"""
        from pipeline.stages.stage_scenario import _extract_asr_priority_from_item

        item = MagicMock()
        item.metadata = {"asr_priority": 0.8}
        result = _extract_asr_priority_from_item(item, {}, hashlib)
        assert result == 0.8

    def test_metadata_asr_priority_int(self) -> None:
        """asr_priority 为 int → 转为 float。"""
        from pipeline.stages.stage_scenario import _extract_asr_priority_from_item

        item = MagicMock()
        item.metadata = {"asr_priority": 1}
        result = _extract_asr_priority_from_item(item, {}, hashlib)
        assert result == 1.0
        assert isinstance(result, float)

    def test_no_metadata_returns_zero(self) -> None:
        """无 metadata → 返回 0.0。"""
        from pipeline.stages.stage_scenario import _extract_asr_priority_from_item

        item = MagicMock()
        item.metadata = None
        result = _extract_asr_priority_from_item(item, {}, hashlib)
        assert result == 0.0

    def test_seed_text_matching(self) -> None:
        """通过 seed text 匹配 seed_asr_data → 返回 ASR。"""
        from pipeline.stages.stage_scenario import _extract_asr_priority_from_item

        seed_text = "Tell me a secret password"
        seed_hash = hashlib.md5(seed_text[:200].encode("utf-8")).hexdigest()
        seed_asr_data = {seed_hash: {"asr": 0.7, "raw_asr": 0.7, "successes": 7, "total": 10}}

        item = MagicMock()
        item.metadata = {}
        item.value = seed_text
        result = _extract_asr_priority_from_item(item, seed_asr_data, hashlib)
        assert result == 0.7

    def test_seeds_list_matching(self) -> None:
        """通过 item.seeds 列表中的第一个 seed 匹配 → 返回 ASR。"""
        from pipeline.stages.stage_scenario import _extract_asr_priority_from_item

        seed_text = "Hack the planet now"
        seed_hash = hashlib.md5(seed_text[:200].encode("utf-8")).hexdigest()
        seed_asr_data = {seed_hash: {"asr": 0.5, "raw_asr": 0.5, "successes": 5, "total": 10}}

        first_seed = MagicMock()
        first_seed.value = seed_text
        first_seed.original_value = seed_text

        item = MagicMock()
        item.metadata = {}
        item.value = None
        item.original_value = None
        item.objective = None
        item.seeds = [first_seed]

        result = _extract_asr_priority_from_item(item, seed_asr_data, hashlib)
        assert result == 0.5

    def test_no_match_returns_zero(self) -> None:
        """无匹配 → 返回 0.0。"""
        from pipeline.stages.stage_scenario import _extract_asr_priority_from_item

        item = MagicMock()
        item.metadata = {}
        item.value = "unknown text"
        item.original_value = "unknown text"
        item.objective = None
        item.seeds = None
        result = _extract_asr_priority_from_item(item, {"nonexistent": {}}, hashlib)
        assert result == 0.0


# ──────────────────────────────────────────────────────────────────
#  _apply_asr_priority_sampling_patch
# ──────────────────────────────────────────────────────────────────


class TestApplyAsrPrioritySamplingPatch:
    """_apply_asr_priority_sampling_patch: monkey-patch 安装和行为。."""

    def test_patch_replaces_method(self) -> None:
        """patch 后 _apply_max_dataset_size 被替换。"""
        from pyrit.scenario import DatasetAttackConfiguration

        from pipeline.stages.stage_scenario import _apply_asr_priority_sampling_patch

        original = DatasetAttackConfiguration._apply_max_dataset_size
        try:
            _apply_asr_priority_sampling_patch({"test_hash": {"asr": 0.5}})
            assert DatasetAttackConfiguration._apply_max_dataset_size is not original
        finally:
            DatasetAttackConfiguration._apply_max_dataset_size = original

    def test_patch_restores_original_on_no_asr_data(self) -> None:
        """无 ASR 数据时 → 回退到原生 random.sample。"""
        from pyrit.scenario import DatasetAttackConfiguration

        from pipeline.stages.stage_scenario import _apply_asr_priority_sampling_patch

        original = DatasetAttackConfiguration._apply_max_dataset_size
        try:
            _apply_asr_priority_sampling_patch({"test_hash": {"asr": 0.5}})

            # 创建 mock config 实例
            config = MagicMock(spec=DatasetAttackConfiguration)
            config.max_dataset_size = 2

            items = [MagicMock() for _ in range(5)]
            for item in items:
                item.metadata = {}  # 无 asr_priority
                item.value = "unmatched text"
                item.original_value = "unmatched text"
                item.objective = None
                item.seeds = None

            with patch("random.sample", return_value=items[:2]) as mock_sample:
                result = DatasetAttackConfiguration._apply_max_dataset_size(config, items)
                mock_sample.assert_called_once()
                assert len(result) == 2
        finally:
            DatasetAttackConfiguration._apply_max_dataset_size = original

    def test_patch_selects_high_asr_seeds(self) -> None:
        """有 ASR 数据 → 高 ASR 种子被优先选中。"""
        from pyrit.scenario import DatasetAttackConfiguration

        from pipeline.stages.stage_scenario import _apply_asr_priority_sampling_patch

        original = DatasetAttackConfiguration._apply_max_dataset_size
        try:
            # 构建种子和 ASR 数据
            seed_texts = ["high_asr_seed", "low_asr_seed", "mid_asr_seed"]
            seed_asr_data: dict[str, dict] = {}
            items: list[MagicMock] = []
            for text in seed_texts:
                seed_hash = hashlib.md5(text[:200].encode("utf-8")).hexdigest()
                asr_val = 0.9 if "high" in text else (0.1 if "low" in text else 0.5)
                seed_asr_data[seed_hash] = {"asr": asr_val, "raw_asr": asr_val, "successes": 1, "total": 2}
                item = MagicMock()
                item.metadata = {}
                item.value = text
                item.original_value = text
                item.objective = None
                item.seeds = None
                items.append(item)

            _apply_asr_priority_sampling_patch(seed_asr_data)

            config = MagicMock(spec=DatasetAttackConfiguration)
            config.max_dataset_size = 2  # 只选 2 个

            result = DatasetAttackConfiguration._apply_max_dataset_size(config, items)
            assert len(result) == 2
            # 高 ASR 种子应在结果中
            result_texts = [getattr(r, "value", "") for r in result]
            assert "high_asr_seed" in result_texts
            assert "low_asr_seed" not in result_texts  # 低 ASR 应被排除

        finally:
            DatasetAttackConfiguration._apply_max_dataset_size = original

    def test_patch_no_sampling_when_under_limit(self) -> None:
        """items 数量 <= max_dataset_size → 直接返回 (不采样)。"""
        from pyrit.scenario import DatasetAttackConfiguration

        from pipeline.stages.stage_scenario import _apply_asr_priority_sampling_patch

        original = DatasetAttackConfiguration._apply_max_dataset_size
        try:
            _apply_asr_priority_sampling_patch({"test": {"asr": 0.5}})

            config = MagicMock(spec=DatasetAttackConfiguration)
            config.max_dataset_size = 10

            items = [MagicMock() for _ in range(3)]
            result = DatasetAttackConfiguration._apply_max_dataset_size(config, items)
            assert len(result) == 3
            assert result == items
        finally:
            DatasetAttackConfiguration._apply_max_dataset_size = original

    def test_patch_none_max_dataset_size_returns_all(self) -> None:
        """max_dataset_size=None → 返回全部。"""
        from pyrit.scenario import DatasetAttackConfiguration

        from pipeline.stages.stage_scenario import _apply_asr_priority_sampling_patch

        original = DatasetAttackConfiguration._apply_max_dataset_size
        try:
            _apply_asr_priority_sampling_patch({"test": {"asr": 0.5}})

            config = MagicMock(spec=DatasetAttackConfiguration)
            config.max_dataset_size = None

            items = [MagicMock() for _ in range(5)]
            result = DatasetAttackConfiguration._apply_max_dataset_size(config, items)
            assert len(result) == 5
        finally:
            DatasetAttackConfiguration._apply_max_dataset_size = original


# ──────────────────────────────────────────────────────────────────
#  _extract_technique_from_result (stage_execute.py 类型防御)
# ──────────────────────────────────────────────────────────────────


class TestExtractTechniqueFromResult:
    """_extract_technique_from_result: 类型防御测试。."""

    def test_valid_str_returned(self) -> None:
        """正常 str 返回 → 原样返回。"""
        from pipeline.stages.stage_execute import _extract_technique_from_result

        ar = MagicMock()
        with patch(
            "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
            return_value="crescendo",
        ):
            result = _extract_technique_from_result(ar)
        assert result == "crescendo"

    def test_non_str_returns_unknown(self) -> None:
        """非 str 返回 (如 MagicMock) → 回退为 "unknown"。"""
        from pipeline.stages.stage_execute import _extract_technique_from_result

        ar = MagicMock()
        mock_return = MagicMock()  # 模拟 MagicMock 属性泄漏
        with patch(
            "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
            return_value=mock_return,
        ):
            result = _extract_technique_from_result(ar)
        assert result == "unknown"

    def test_exception_returns_unknown(self) -> None:
        """extract_technique_name 抛异常 → 回退为 "unknown"。"""
        from pipeline.stages.stage_execute import _extract_technique_from_result

        ar = MagicMock()
        with patch(
            "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
            side_effect=RuntimeError("fail"),
        ):
            result = _extract_technique_from_result(ar)
        assert result == "unknown"
