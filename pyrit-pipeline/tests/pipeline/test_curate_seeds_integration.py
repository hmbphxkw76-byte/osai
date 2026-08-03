# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""curate_seeds.py 端到端集成测试 — 验证完整 6 步管线输出。."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))
import curate_seeds  # noqa: E402


class TestCurationIntegration:
    """端到端集成测试: 验证完整精简管线."""

    @pytest.fixture
    def synthetic_seeds(self) -> list[dict[str, Any]]:
        """创建 60 个合成种子覆盖 5 个类别."""
        seeds: list[dict[str, Any]] = []
        categories = ["illegal", "Violence", "Privacy", "Malware/Hacking", "Disinformation"]
        for cat in categories:
            for i in range(12):
                seeds.append({
                    "value": f"{cat} attack prompt number {i} with unique content",
                    "dataset_name": "synthetic",
                    "category": cat,
                    "modality": "text",
                    "metadata": {"difficulty": "medium"},
                })
        return seeds

    def test_full_pipeline_produces_valid_output(
        self,
        synthetic_seeds: list[dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        """完整 6 步管线应产生有效的种子集."""
        # Step 1: 去重
        deduped = curate_seeds.dedup_seeds(synthetic_seeds)
        assert len(deduped) > 0

        # Step 2: 类别均衡
        balanced = curate_seeds.category_balanced_sample(deduped, per_category=5)
        assert len(balanced) > 0
        assert len(balanced) <= len(deduped)

        # Step 3: 聚类
        clustered = curate_seeds.diversity_cluster(balanced, n_clusters=10)
        assert len(clustered) > 0
        assert len(clustered) <= 10

        # Step 4: 模型感知排序
        ranked = curate_seeds.model_aware_asr_rank(clustered, model_name="gpt-4o")
        assert len(ranked) == len(clustered)
        assert all("_estimated_asr" in s for s in ranked)

        # Step 5: 模态过滤
        filtered = curate_seeds.modality_aware_filter(ranked, modality="text")
        assert len(filtered) > 0

        # Step 6: Tier 分层
        final = curate_seeds.tier_stratified_sample(filtered, target_count=10)
        assert len(final) <= 10

        # 验证输出
        output_path = tmp_path / "curated_test.prompt"
        curate_seeds.save_curated_seeds(final, output_path)
        assert output_path.exists()

        # 验证 YAML 格式
        with open(output_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert "seeds" in data
        assert len(data["seeds"]) == len(final)
        assert data["dataset_name"] == "curated_seeds"

    def test_pipeline_preserves_categories(self, synthetic_seeds: list[dict[str, Any]]) -> None:
        """精简后应保留至少 3 个类别."""
        deduped = curate_seeds.dedup_seeds(synthetic_seeds)
        balanced = curate_seeds.category_balanced_sample(deduped, per_category=5)
        categories = {s["category"] for s in balanced}
        assert len(categories) >= 3

    def test_model_aware_rank_changes_order(
        self,
        synthetic_seeds: list[dict[str, Any]],
    ) -> None:
        """不同模型的排序应不同."""
        import copy

        seeds_for_gpt4o = copy.deepcopy(synthetic_seeds[:20])
        seeds_for_llama = copy.deepcopy(synthetic_seeds[:20])
        ranked_gpt4o = curate_seeds.model_aware_asr_rank(seeds_for_gpt4o, model_name="gpt-4o")
        ranked_llama = curate_seeds.model_aware_asr_rank(seeds_for_llama, model_name="llama-3-8b")

        # 至少有一个种子的估计 ASR 不同
        diffs = [
            abs(s1.get("_estimated_asr", 0) - s2.get("_estimated_asr", 0))
            for s1, s2 in zip(ranked_gpt4o, ranked_llama, strict=False)
        ]
        assert max(diffs) > 0.01
