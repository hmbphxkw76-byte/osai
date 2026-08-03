# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""benchmark_curate.py 单元测试。.

测试覆盖:
  1. 合成种子生成
  2. MinHashLSH 去重基准
  3. TF-IDF 聚类基准
  4. ASR 排序基准

> **日期**: 2026-8-3
"""

from __future__ import annotations

import sys
from pathlib import Path

# 将 scripts/ 添加到 path
_SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent.parent / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)


class TestGenerateSyntheticSeeds:
    """合成种子生成测试。"""

    def test_generate_default_count(self) -> None:
        """默认生成 100 个种子 (测试用小规模)。"""
        from benchmark_curate import generate_synthetic_seeds

        seeds = generate_synthetic_seeds(count=100)
        assert len(seeds) == 100
        assert all("text" in s for s in seeds)
        assert all("category" in s for s in seeds)
        assert all("hash" in s for s in seeds)

    def test_generate_reproducible(self) -> None:
        """相同 seed 生成相同结果 (可复现)。"""
        from benchmark_curate import generate_synthetic_seeds

        seeds1 = generate_synthetic_seeds(count=50)
        seeds2 = generate_synthetic_seeds(count=50)
        assert [s["text"] for s in seeds1] == [s["text"] for s in seeds2]

    def test_generate_has_categories(self) -> None:
        """生成的种子包含多种类别。"""
        from benchmark_curate import generate_synthetic_seeds

        seeds = generate_synthetic_seeds(count=200)
        categories = {s["category"] for s in seeds}
        assert len(categories) > 1  # 至少 2 种类别


class TestBenchmarkDedup:
    """MinHashLSH 去重基准测试。"""

    def test_dedup_small_scale(self) -> None:
        """小规模去重测试 (100 种子)。"""
        from benchmark_curate import benchmark_dedup, generate_synthetic_seeds

        seeds = generate_synthetic_seeds(count=100)
        result = benchmark_dedup(seeds)

        assert result["method"] == "MinHashLSH"
        assert result["total_seeds"] == 100
        assert result["duration_seconds"] >= 0
        assert "unique_after_dedup" in result
        assert "duplicates_removed" in result


class TestBenchmarkTfidfClustering:
    """TF-IDF 聚类基准测试。"""

    def test_clustering_small_scale(self) -> None:
        """小规模聚类测试 (100 种子)。"""
        from benchmark_curate import benchmark_tfidf_clustering, generate_synthetic_seeds

        seeds = generate_synthetic_seeds(count=100)
        result = benchmark_tfidf_clustering(seeds, n_clusters=5)

        assert result["method"] == "TF-IDF+KMeans"
        assert result["total_seeds"] == 100
        assert result["n_clusters"] == 5
        assert result["duration_seconds"] >= 0


class TestBenchmarkAsrRanking:
    """ASR 排序基准测试。"""

    def test_ranking_small_scale(self) -> None:
        """小规模排序测试 (100 种子)。"""
        from benchmark_curate import benchmark_asr_ranking, generate_synthetic_seeds

        seeds = generate_synthetic_seeds(count=100)
        result = benchmark_asr_ranking(seeds)

        assert result["method"] == "ASR_Ranking"
        assert result["total_seeds"] == 100
        assert result["duration_seconds"] >= 0


class TestRunBenchmark:
    """完整基准测试。"""

    def test_run_benchmark_small(self) -> None:
        """运行小规模基准测试 (500 种子, 验证全流程)。"""
        from benchmark_curate import run_benchmark

        results = run_benchmark(count=500)

        assert results["seed_count"] == 500
        assert "steps" in results
        assert "dedup" in results["steps"]
        assert "asr_ranking" in results["steps"]
        assert "clustering" in results["steps"]
        assert "total_duration_seconds" in results
        assert "validation" in results

        # 验证 MinHashLSH < 30s (500 种子应该远低于此)
        assert results["validation"]["minhash_lsh_under_30s"] is True
