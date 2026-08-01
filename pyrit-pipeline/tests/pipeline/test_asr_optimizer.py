# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_asr_optimizer — ASR 驱动优化器单元测试。.

覆盖:
  - compute_stats: 统计构建 (替代私有 _compute_stats)
  - query_historical_asr_by_category: 历史查询 + 异常保护
  - sort_datasets_by_asr: 数据集排序 (Laplace 平滑)
  - query_historical_asr_by_technique: 按技术查询
  - query_current_run_asr_by_technique: 同次运行反馈
  - get_asr_summary / get_technique_asr_summary / get_current_run_asr_summary: 展示

> **日期**: 2026-8-1
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.asr.optimizer import (
    compute_stats,
    get_asr_summary,
    get_current_run_asr_summary,
    get_technique_asr_summary,
    query_current_run_asr_by_technique,
    query_historical_asr_by_category,
    query_historical_asr_by_technique,
    sort_datasets_by_asr,
)

# ──────────────────────────────────────────────────────────────────
#  compute_stats
# ──────────────────────────────────────────────────────────────────


class TestComputeStats:
    """compute_stats 单元测试。."""

    def test_basic_stats(self) -> None:
        """正常输入: 10 成功, 5 失败。."""
        stats = compute_stats(successes=10, failures=5, undetermined=0, errors=0)
        assert stats.successes == 10
        assert stats.failures == 5
        assert stats.total_decided == 15
        assert stats.success_rate == pytest.approx(10 / 15)

    def test_zero_successes(self) -> None:
        """零成功。."""
        stats = compute_stats(successes=0, failures=5, undetermined=0, errors=0)
        assert stats.success_rate == 0.0
        assert stats.total_decided == 5

    def test_all_success(self) -> None:
        """全部成功。."""
        stats = compute_stats(successes=10, failures=0, undetermined=0, errors=0)
        assert stats.success_rate == 1.0

    def test_no_decided(self) -> None:
        """无确定结果 (全 undetermined)。."""
        stats = compute_stats(successes=0, failures=0, undetermined=5, errors=0)
        assert stats.success_rate is None
        assert stats.total_decided == 0

    def test_errors_included(self) -> None:
        """错误计入但不算在 total_decided 中。."""
        stats = compute_stats(successes=5, failures=3, undetermined=0, errors=2)
        assert stats.errors == 2
        assert stats.total_decided == 8  # successes + failures


# ──────────────────────────────────────────────────────────────────
#  query_historical_asr_by_category
# ──────────────────────────────────────────────────────────────────


class TestQueryHistoricalASRByCategory:
    """query_historical_asr_by_category 单元测试。."""

    def test_empty_memory(self, mock_memory: MagicMock) -> None:
        """空 memory 返回空字典。."""
        mock_memory.get_attack_results.return_value = []
        result = query_historical_asr_by_category(memory=mock_memory)
        assert result == {}

    def test_with_results(
        self,
        mock_memory: MagicMock,
        mock_attack_result_success: MagicMock,
        mock_attack_result_failure: MagicMock,
    ) -> None:
        """有结果时按 category 聚合。."""
        mock_memory.get_attack_results.return_value = [
            mock_attack_result_success,
            mock_attack_result_failure,
        ]
        result = query_historical_asr_by_category(memory=mock_memory)
        assert "cybercrime" in result
        assert "illegal" in result
        assert result["cybercrime"].successes == 1
        assert result["illegal"].failures == 1

    def test_database_exception_returns_empty(self, mock_memory: MagicMock) -> None:
        """数据库异常时优雅降级返回空字典。."""
        mock_memory.get_attack_results.side_effect = RuntimeError("DB error")
        result = query_historical_asr_by_category(memory=mock_memory)
        assert result == {}


# ──────────────────────────────────────────────────────────────────
#  sort_datasets_by_asr
# ──────────────────────────────────────────────────────────────────


class TestSortDatasetsByASR:
    """sort_datasets_by_asr 单元测试。."""

    def test_empty_input(self) -> None:
        """空输入返回空列表。."""
        result = sort_datasets_by_asr([], asr_by_category={})
        assert result == []

    def test_no_asr_data_preserves_order(self) -> None:
        """无 ASR 数据时保持原始顺序 (所有 0.5)。."""
        datasets = ["harmbench", "jbb_behaviors", "strong_reject"]
        result = sort_datasets_by_asr(datasets, asr_by_category={})
        # 所有数据集 ASR 相同 (0.5), Python sort 稳定排序保持原序
        assert result == datasets

    def test_unknown_dataset_gets_default_score(self) -> None:
        """未知数据集获得中等优先级。."""
        datasets = ["unknown_dataset", "harmbench"]
        result = sort_datasets_by_asr(datasets, asr_by_category={})
        # 两者都是 0.5, 稳定排序保持原序
        assert result == datasets

    def test_high_asr_dataset_first(self) -> None:
        """高 ASR 的数据集排在前面。."""
        from pipeline.asr.optimizer import compute_stats

        asr_data = {
            "cybercrime": compute_stats(successes=9, failures=1, undetermined=0, errors=0),
        }
        # harmbench 映射到 cybercrime (ASR 90%), 其他数据集无映射
        datasets = ["strong_reject", "harmbench"]
        result = sort_datasets_by_asr(datasets, asr_by_category=asr_data)
        assert result[0] == "harmbench"  # 高 ASR 在前


# ──────────────────────────────────────────────────────────────────
#  query_historical_asr_by_technique
# ──────────────────────────────────────────────────────────────────


class TestQueryHistoricalASRByTechnique:
    """query_historical_asr_by_technique 单元测试。."""

    def test_empty_memory(self, mock_memory: MagicMock) -> None:
        """空 memory 返回空字典。."""
        mock_memory.get_attack_results.return_value = []
        result = query_historical_asr_by_technique(memory=mock_memory)
        assert result == {}

    def test_with_results(
        self,
        mock_memory: MagicMock,
        mock_attack_result_success: MagicMock,
        mock_attack_result_failure: MagicMock,
    ) -> None:
        """有结果时按技术聚合。."""
        mock_memory.get_attack_results.return_value = [
            mock_attack_result_success,
            mock_attack_result_failure,
        ]
        result = query_historical_asr_by_technique(memory=mock_memory)
        assert "many_shot" in result
        assert "tap" in result
        assert result["many_shot"].successes == 1
        assert result["tap"].failures == 1

    def test_database_exception_returns_empty(self, mock_memory: MagicMock) -> None:
        """数据库异常时优雅降级。."""
        mock_memory.get_attack_results.side_effect = RuntimeError("DB error")
        result = query_historical_asr_by_technique(memory=mock_memory)
        assert result == {}


# ──────────────────────────────────────────────────────────────────
#  query_current_run_asr_by_technique
# ──────────────────────────────────────────────────────────────────


class TestQueryCurrentRunASRByTechnique:
    """query_current_run_asr_by_technique 单元测试。."""

    def test_empty_scenario_id(self, mock_memory: MagicMock) -> None:
        """空 scenario_result_id 返回空。."""
        result = query_current_run_asr_by_technique("", memory=mock_memory)
        assert result == {}

    def test_no_completed_results(self, mock_memory: MagicMock) -> None:
        """无已完成结果时返回空 (冷启动)。."""
        mock_memory.get_attack_results.return_value = []
        result = query_current_run_asr_by_technique("run-123", memory=mock_memory)
        assert result == {}

    def test_with_completed_results(
        self,
        mock_memory: MagicMock,
        mock_attack_result_success: MagicMock,
    ) -> None:
        """有已完成结果时返回统计。."""
        mock_memory.get_attack_results.return_value = [mock_attack_result_success]
        result = query_current_run_asr_by_technique("run-123", memory=mock_memory)
        assert "many_shot" in result
        assert result["many_shot"].successes == 1

    def test_database_exception_returns_empty(self, mock_memory: MagicMock) -> None:
        """数据库异常时优雅降级。."""
        mock_memory.get_attack_results.side_effect = RuntimeError("DB error")
        result = query_current_run_asr_by_technique("run-123", memory=mock_memory)
        assert result == {}


# ──────────────────────────────────────────────────────────────────
#  Summary functions
# ──────────────────────────────────────────────────────────────────


class TestSummaryFunctions:
    """摘要函数单元测试。."""

    def test_get_asr_summary_empty(self) -> None:
        """空 ASR 数据返回冷启动提示。."""
        result = get_asr_summary(asr_by_category={})
        assert "首次运行" in result

    def test_get_asr_summary_with_data(self) -> None:
        """有数据时返回格式化摘要。."""
        from pipeline.asr.optimizer import compute_stats

        asr = {"cybercrime": compute_stats(successes=8, failures=2, undetermined=0, errors=0)}
        result = get_asr_summary(asr_by_category=asr)
        assert "cybercrime" in result
        assert "80.0%" in result

    def test_get_technique_asr_summary_empty(self, mock_memory: MagicMock) -> None:
        """空技术 ASR 返回冷启动提示。."""
        mock_memory.get_attack_results.return_value = []
        result = get_technique_asr_summary(memory=mock_memory)
        assert "首次运行" in result

    def test_get_current_run_asr_summary_empty(self) -> None:
        """空当前运行 ASR 返回冷启动提示。."""
        result = get_current_run_asr_summary({})
        assert "冷启动" in result

    def test_get_current_run_asr_summary_with_data(self) -> None:
        """有数据时返回格式化摘要。."""
        from pipeline.asr.optimizer import compute_stats

        asr = {"many_shot": compute_stats(successes=5, failures=5, undetermined=0, errors=0)}
        result = get_current_run_asr_summary(asr)
        assert "many_shot" in result
        assert "50.0%" in result
