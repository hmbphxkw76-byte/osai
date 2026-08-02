# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_rank_builder — ASR 排行榜构建器单元测试.

覆盖:
  - GroupFallbackExecutor.build_fallback_plan: 降级链构建
  - GroupFallbackResult: 结果数据结构
  - GroupFallbackExecutor._compute_asr: ASR 计算

> **日期**: 2026-8-2
"""

from __future__ import annotations

from pipeline.asr.rank_builder import (
    FallbackRecord,
    GroupFallbackExecutor,
    GroupFallbackResult,
)

# ──────────────────────────────────────────────────────────────────
#  GroupFallbackResult
# ──────────────────────────────────────────────────────────────────


class TestGroupFallbackResult:
    """GroupFallbackResult 数据结构测试."""

    def test_default_values(self) -> None:
        """默认值正确."""
        result = GroupFallbackResult()
        assert result.execution_order == []
        assert result.fallback_records == []
        assert result.successful_groups == []
        assert result.failed_groups == []
        assert result.total_groups == 0

    def test_fallback_count_property(self) -> None:
        """fallback_count 属性正确."""
        result = GroupFallbackResult(
            fallback_records=[
                FallbackRecord("a", "b", "S", "A", "test", 0.8, 0.5),
            ],
        )
        assert result.fallback_count == 1

    def test_success_rate_empty(self) -> None:
        """空结果 success_rate 为 0."""
        result = GroupFallbackResult()
        assert result.success_rate == 0.0

    def test_success_rate_with_data(self) -> None:
        """有数据时 success_rate 正确."""
        result = GroupFallbackResult(
            successful_groups=["a", "b"],
            total_groups=4,
        )
        assert result.success_rate == 0.5


# ──────────────────────────────────────────────────────────────────
#  GroupFallbackExecutor.build_fallback_plan
# ──────────────────────────────────────────────────────────────────


class TestBuildFallbackPlan:
    """build_fallback_plan 单元测试."""

    def test_empty_techniques(self) -> None:
        """空技术列表返回空计划."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        plan = executor.build_fallback_plan([])
        assert plan.total_groups == 0
        assert plan.fallback_count == 0
        assert plan.execution_order == []

    def test_single_technique(self) -> None:
        """单个技术返回单个执行项."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        plan = executor.build_fallback_plan(["many_shot"])
        assert len(plan.execution_order) == 1
        assert plan.execution_order[0] == "many_shot"
        assert plan.fallback_count == 0

    def test_multiple_techniques(self) -> None:
        """多个技术返回全部执行项."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        plan = executor.build_fallback_plan(["many_shot", "tap", "prompt_sending"])
        assert len(plan.execution_order) == 3
        assert set(plan.execution_order) == {"many_shot", "tap", "prompt_sending"}

    def test_fallback_count_is_int(self) -> None:
        """fallback_count 返回整数."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        plan = executor.build_fallback_plan(["a", "b", "c"])
        assert isinstance(plan.fallback_count, int)
        assert plan.fallback_count >= 0

    def test_historical_asr_affects_order(self) -> None:
        """历史 ASR 影响执行顺序."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        historical_asr = {
            "many_shot": 0.8,
            "tap": 0.3,
            "prompt_sending": 0.1,
        }
        plan = executor.build_fallback_plan(
            ["tap", "prompt_sending", "many_shot"],
            historical_asr=historical_asr,
        )
        # many_shot (ASR=0.8, S Tier) 应该在前面
        assert plan.execution_order[0] == "many_shot"


# ──────────────────────────────────────────────────────────────────
#  GroupFallbackExecutor._compute_asr
# ──────────────────────────────────────────────────────────────────


class TestComputeASR:
    """_compute_asr 单元测试."""

    def test_historical_asr_takes_priority(self) -> None:
        """历史 ASR 优先."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        asr = executor._compute_asr("many_shot", historical_asr={"many_shot": 0.75})
        assert asr == 0.75

    def test_base_technique_fallback(self) -> None:
        """变体名的基础技术匹配."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        asr = executor._compute_asr(
            "many_shot+stealth_evasion",
            historical_asr={"many_shot": 0.6},
        )
        assert asr == 0.6

    def test_no_historical_returns_prior(self) -> None:
        """无历史数据时返回学术先验."""
        executor = GroupFallbackExecutor(model_name="gpt-4o", model_tier="strong")
        asr = executor._compute_asr("many_shot")
        # 学术先验应该 > 0
        assert asr > 0
        assert asr <= 1.0
