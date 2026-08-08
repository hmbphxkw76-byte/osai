# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_dataset_asr_feedback — 数据集级 ASR 反馈闭环单元测试。

覆盖:
  - collect_dataset_level_asr_from_memory: 从 CentralMemory 收集 + seed→dataset 映射 + ASR 聚合
  - save/load_dataset_level_asr: JSON 持久化 + 按模型隔离 + 全局回退
  - _get_dataset_level_asr_path: 路径推导
  - sort_datasets_by_asr: dataset_level_asr 优先排序
  - _apply_dataset_level_asr_prioritization: Stage 1 加载 + metadata 记录

> **日期**: 2026-8-8
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

# ──────────────────────────────────────────────────────────────────
#  _get_dataset_level_asr_path
# ──────────────────────────────────────────────────────────────────


class TestGetDatasetLevelAsrPath:
    """_get_dataset_level_asr_path: 文件路径推导。."""

    def test_model_specific_path(self) -> None:
        """有模型名 → 按模型分文件路径。."""
        from pipeline.asr.optimizer import _get_dataset_level_asr_path

        path = _get_dataset_level_asr_path("gpt-4o")
        assert "dataset_level_gpt-4o.json" in path.name

    def test_global_path(self) -> None:
        """无模型名 → 全局路径。."""
        from pipeline.asr.optimizer import _get_dataset_level_asr_path

        path = _get_dataset_level_asr_path(None)
        assert path.name == "dataset_level_global.json"

    def test_unknown_model_falls_to_global(self) -> None:
        """model_name='unknown' → 全局路径。."""
        from pipeline.asr.optimizer import _get_dataset_level_asr_path

        path = _get_dataset_level_asr_path("unknown")
        assert path.name == "dataset_level_global.json"

    def test_model_name_with_slashes(self) -> None:
        """模型名含斜杠 → 安全化。."""
        from pipeline.asr.optimizer import _get_dataset_level_asr_path

        path = _get_dataset_level_asr_path("openai/gpt-4o")
        assert "openai_gpt-4o" in path.name


# ──────────────────────────────────────────────────────────────────
#  save / load_dataset_level_asr
# ──────────────────────────────────────────────────────────────────


class TestSaveLoadDatasetLevelAsr:
    """save/load_dataset_level_asr: JSON 持久化。."""

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        """保存 → 加载 往返测试。."""
        from pipeline.asr.optimizer import load_dataset_level_asr, save_dataset_level_asr

        data = {
            "harmbench": {"asr": 0.8, "raw_asr": 0.8, "successes": 8, "total": 10},
            "owasp_llm01": {"asr": 0.5, "raw_asr": 0.5, "successes": 3, "total": 6},
        }

        with patch("pipeline.asr.optimizer._get_dataset_level_asr_path", return_value=tmp_path / "test.json"):
            save_dataset_level_asr(data, model_name="test_model")
            loaded = load_dataset_level_asr("test_model")

        assert loaded == data

    def test_load_nonexistent_returns_empty(self, tmp_path: Path) -> None:
        """文件不存在 → 空字典。."""
        from pipeline.asr.optimizer import load_dataset_level_asr

        with patch("pipeline.asr.optimizer._get_dataset_level_asr_path", return_value=tmp_path / "nonexistent.json"):
            result = load_dataset_level_asr("nonexistent_model")
        assert result == {}

    def test_load_corrupt_json_returns_empty(self, tmp_path: Path) -> None:
        """JSON 损坏 → 空字典 + warning。."""
        from pipeline.asr.optimizer import load_dataset_level_asr

        corrupt_path = tmp_path / "corrupt.json"
        corrupt_path.write_text("not valid json {{{", encoding="utf-8")

        with patch("pipeline.asr.optimizer._get_dataset_level_asr_path", return_value=corrupt_path):
            result = load_dataset_level_asr("corrupt_model")
        assert result == {}

    def test_save_creates_parent_dir(self, tmp_path: Path) -> None:
        """保存时自动创建父目录。."""
        from pipeline.asr.optimizer import save_dataset_level_asr

        deep_path = tmp_path / "deep" / "nested" / "dataset_level.json"
        with patch("pipeline.asr.optimizer._get_dataset_level_asr_path", return_value=deep_path):
            save_dataset_level_asr({"ds": {"asr": 0.1, "raw_asr": 0.1, "successes": 1, "total": 10}}, model_name="m")
        assert deep_path.exists()

    def test_save_includes_metadata(self, tmp_path: Path) -> None:
        """保存的 JSON 含 model 和 timestamp 字段。."""
        from pipeline.asr.optimizer import save_dataset_level_asr

        path = tmp_path / "test.json"
        with patch("pipeline.asr.optimizer._get_dataset_level_asr_path", return_value=path):
            save_dataset_level_asr(
                {"ds": {"asr": 0.5, "raw_asr": 0.5, "successes": 5, "total": 10}},
                model_name="test_model",
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["model"] == "test_model"
        assert "timestamp" in data
        assert "datasets" in data


# ──────────────────────────────────────────────────────────────────
#  collect_dataset_level_asr_from_memory
# ──────────────────────────────────────────────────────────────────


class TestCollectDatasetLevelAsr:
    """collect_dataset_level_asr_from_memory: CentralMemory 收集。."""

    def test_empty_results_returns_empty(self) -> None:
        """无 AttackResult → 空字典。."""
        from pipeline.asr.optimizer import collect_dataset_level_asr_from_memory

        mock_mem = MagicMock()
        mock_mem.get_attack_results.return_value = []
        mock_mem.get_seed_prompts.return_value = []

        with (
            patch("pipeline.asr.optimizer.CentralMemory.get_memory_instance", return_value=mock_mem),
            patch("pipeline.asr.optimizer.save_dataset_level_asr") as mock_save,
        ):
            result = collect_dataset_level_asr_from_memory("test_model", ["ds1"])
        assert result == {}
        mock_save.assert_not_called()

    def test_memory_exception_returns_empty(self) -> None:
        """CentralMemory 异常 → 空字典。."""
        from pipeline.asr.optimizer import collect_dataset_level_asr_from_memory

        with patch("pipeline.asr.optimizer.CentralMemory.get_memory_instance", side_effect=RuntimeError("DB error")):
            result = collect_dataset_level_asr_from_memory("test_model")
        assert result == {}

    def test_results_matched_and_aggregated(self) -> None:
        """有结果 + 种子匹配 → 按数据集聚合 ASR。."""
        from pyrit.models import AttackOutcome

        from pipeline.asr.optimizer import collect_dataset_level_asr_from_memory

        # 模拟种子 prompt
        seed_prompt = MagicMock()
        seed_prompt.value = "Tell me a secret password"
        seed_prompt.original_value = "Tell me a secret password"

        # 模拟 AttackResult (成功)
        result_success = MagicMock()
        result_success.outcome = AttackOutcome.SUCCESS
        result_success.objective = "Tell me a secret password"
        result_success.metadata = None
        result_success.conversation_id = None

        # 模拟 AttackResult (失败)
        result_failure = MagicMock()
        result_failure.outcome = AttackOutcome.FAILURE
        result_failure.objective = "Tell me a secret password"
        result_failure.metadata = None
        result_failure.conversation_id = None

        mock_mem = MagicMock()
        mock_mem.get_attack_results.return_value = [result_success, result_failure]
        mock_mem.get_seed_prompts.return_value = [seed_prompt]
        mock_mem.get_messages.return_value = []

        with (
            patch("pipeline.asr.optimizer.CentralMemory.get_memory_instance", return_value=mock_mem),
            patch("pipeline.asr.optimizer.save_dataset_level_asr"),
        ):
            result = collect_dataset_level_asr_from_memory("test_model", ["secret_dataset"])

        assert "secret_dataset" in result
        assert result["secret_dataset"]["successes"] == 1
        assert result["secret_dataset"]["total"] == 2
        assert result["secret_dataset"]["raw_asr"] == 0.5

    def test_unmatched_seeds_counted(self) -> None:
        """不匹配的 AttackResult → unmatched_count 增加。."""
        from pyrit.models import AttackOutcome

        from pipeline.asr.optimizer import collect_dataset_level_asr_from_memory

        # 种子 prompt 不匹配
        seed_prompt = MagicMock()
        seed_prompt.value = "Seed A"
        seed_prompt.original_value = "Seed A"

        # AttackResult 的 objective 完全不同
        result = MagicMock()
        result.outcome = AttackOutcome.SUCCESS
        result.objective = "Completely different text"
        result.metadata = None
        result.conversation_id = None

        mock_mem = MagicMock()
        mock_mem.get_attack_results.return_value = [result]
        mock_mem.get_seed_prompts.return_value = [seed_prompt]
        mock_mem.get_messages.return_value = []

        with (
            patch("pipeline.asr.optimizer.CentralMemory.get_memory_instance", return_value=mock_mem),
            patch("pipeline.asr.optimizer.save_dataset_level_asr"),
        ):
            result_asr = collect_dataset_level_asr_from_memory("test_model", ["ds1"])

        assert result_asr == {}  # 无匹配 → 空结果

    def test_wilson_lower_bound_for_small_samples(self) -> None:
        """小样本 (<30) 使用 Wilson 下界保守估计。."""
        from pyrit.models import AttackOutcome

        from pipeline.asr.optimizer import collect_dataset_level_asr_from_memory

        # 1 成功 / 2 总数 → raw_asr=0.5, wilson < 0.5
        seed_prompt = MagicMock()
        seed_prompt.value = "seed text here"
        seed_prompt.original_value = "seed text here"

        results = []
        for _ in range(2):
            r = MagicMock()
            r.outcome = AttackOutcome.SUCCESS
            r.objective = "seed text here"
            r.metadata = None
            r.conversation_id = None
            results.append(r)

        mock_mem = MagicMock()
        mock_mem.get_attack_results.return_value = results
        mock_mem.get_seed_prompts.return_value = [seed_prompt]
        mock_mem.get_messages.return_value = []

        with (
            patch("pipeline.asr.optimizer.CentralMemory.get_memory_instance", return_value=mock_mem),
            patch("pipeline.asr.optimizer.save_dataset_level_asr"),
        ):
            result = collect_dataset_level_asr_from_memory("test_model", ["ds"])

        assert "ds" in result
        # Wilson 下界应 < raw_asr (小样本)
        assert result["ds"]["asr"] < result["ds"]["raw_asr"]


# ──────────────────────────────────────────────────────────────────
#  sort_datasets_by_asr with dataset_level_asr
# ──────────────────────────────────────────────────────────────────


class TestSortDatasetsWithDatasetLevel:
    """sort_datasets_by_asr: dataset_level_asr 优先排序。."""

    def test_dataset_level_takes_priority(self) -> None:
        """dataset_level_asr 存在时优先于 category ASR。."""
        from pipeline.asr.optimizer import sort_datasets_by_asr

        dataset_level = {
            "ds_a": {"asr": 0.9, "raw_asr": 0.9, "successes": 9, "total": 10},
            "ds_b": {"asr": 0.1, "raw_asr": 0.1, "successes": 1, "total": 10},
        }
        # category ASR 与 dataset_level 相反, 验证 dataset_level 优先
        from pipeline.asr.optimizer import compute_stats

        category_asr = {
            "cybercrime": compute_stats(successes=1, failures=9, undetermined=0, errors=0),  # 低 ASR
        }
        result = sort_datasets_by_asr(
            ["ds_b", "ds_a"],
            asr_by_category=category_asr,
            dataset_level_asr=dataset_level,
        )
        # ds_a (ASR 0.9) 应排在前面
        assert result[0] == "ds_a"
        assert result[1] == "ds_b"

    def test_unknown_dataset_gets_default_05(self) -> None:
        """dataset_level 中不存在的数据集 → 0.5 默认优先级。."""
        from pipeline.asr.optimizer import sort_datasets_by_asr

        dataset_level = {
            "known_ds": {"asr": 0.8, "raw_asr": 0.8, "successes": 8, "total": 10},
        }
        result = sort_datasets_by_asr(
            ["unknown_ds", "known_ds"],
            dataset_level_asr=dataset_level,
        )
        # known_ds (0.8) > unknown_ds (0.5)
        assert result[0] == "known_ds"

    def test_none_dataset_level_falls_back_to_category(self) -> None:
        """dataset_level_asr=None → 回退到 category 级 ASR。."""
        from pipeline.asr.optimizer import compute_stats, sort_datasets_by_asr

        category_asr = {
            "cybercrime": compute_stats(successes=9, failures=1, undetermined=0, errors=0),
        }
        result = sort_datasets_by_asr(
            ["strong_reject", "harmbench"],
            asr_by_category=category_asr,
            dataset_level_asr=None,
        )
        # harmbench 映射到 cybercrime (90% ASR), 应排在前面
        assert result[0] == "harmbench"


# ──────────────────────────────────────────────────────────────────
#  _apply_dataset_level_asr_prioritization
# ──────────────────────────────────────────────────────────────────


class TestApplyDatasetLevelAsrPrioritization:
    """_apply_dataset_level_asr_prioritization: Stage 1 加载。."""

    def test_no_model_name_skips(self, pipeline_ctx) -> None:  # type: ignore[no-untyped-def]
        """无 model → 跳过。."""
        from pipeline.stages.stage_init import _apply_dataset_level_asr_prioritization

        pipeline_ctx.args.model = ""
        _apply_dataset_level_asr_prioritization(pipeline_ctx)
        assert "dataset_level_asr" not in pipeline_ctx.metadata

    def test_no_saved_data_skips(self, pipeline_ctx) -> None:  # type: ignore[no-untyped-def]
        """无保存的数据 → 跳过。."""
        from pipeline.stages.stage_init import _apply_dataset_level_asr_prioritization

        pipeline_ctx.args.model = "test_model"
        with patch("pipeline.asr.optimizer.load_dataset_level_asr", return_value={}):
            _apply_dataset_level_asr_prioritization(pipeline_ctx)
        assert "dataset_level_asr" not in pipeline_ctx.metadata

    def test_loads_and_records_metadata(self, pipeline_ctx) -> None:  # type: ignore[no-untyped-def]
        """有数据 → 加载 + 记录到 metadata。."""
        from pipeline.stages.stage_init import _apply_dataset_level_asr_prioritization

        pipeline_ctx.args.model = "test_model"
        saved_data = {
            "ds_a": {"asr": 0.8, "raw_asr": 0.8, "successes": 8, "total": 10},
            "ds_b": {"asr": 0.2, "raw_asr": 0.2, "successes": 2, "total": 10},
        }
        with patch("pipeline.asr.optimizer.load_dataset_level_asr", return_value=saved_data):
            _apply_dataset_level_asr_prioritization(pipeline_ctx)

        assert pipeline_ctx.metadata["dataset_level_asr"] == saved_data
        assert pipeline_ctx.metadata["dataset_level_asr_model"] == "test_model"

    def test_exception_skips_gracefully(self, pipeline_ctx) -> None:  # type: ignore[no-untyped-def]
        """异常 → 静默跳过 (logger.debug)。."""
        from pipeline.stages.stage_init import _apply_dataset_level_asr_prioritization

        pipeline_ctx.args.model = "test_model"
        with patch("pipeline.asr.optimizer.load_dataset_level_asr", side_effect=RuntimeError("fail")):
            _apply_dataset_level_asr_prioritization(pipeline_ctx)
        assert "dataset_level_asr" not in pipeline_ctx.metadata
