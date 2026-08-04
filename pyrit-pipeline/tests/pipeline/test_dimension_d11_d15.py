# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""D11-D15 多维路由增强测试.

测试覆盖:
  D11: ConverterChainAdvisor — 失败类型→Converter 链调整
  D12: SuccessPropagationTracker — 成功组合传播
  D13: score_chain_combo — 链组合协同评分
  D14: get_chain_cost_weight — 预算感知权重
  D15: _probe_safety_filter — 安全过滤探测 (mock)

> **日期**: 2026-8-4
"""

from __future__ import annotations

from unittest.mock import MagicMock

from pipeline.converters.chains import (
    COMBO_MULTIPLIERS,
    CONVERTER_VARIANT_CHAINS,
    get_chain_cost_weight,
    score_chain_combo,
)
from pipeline.converters.converter_feedback import (
    ConverterChainAdvisor,
    SuccessPropagationTracker,
    extract_converter_chain_names,
)

# ============================================================
# D11: ConverterChainAdvisor
# ============================================================


class TestConverterChainAdvisor:
    """测试 D11: 失败类型→Converter 链调整建议。."""

    def test_empty_advisor_unknown_failure_type(self) -> None:
        """空 Advisor 对未知失败类型返回当前链。."""
        advisor = ConverterChainAdvisor()
        assert not advisor.has_data
        result = advisor.get_recommended_shift("nonexistent_type", ["stealth_evasion"])
        assert result == ["stealth_evasion"]

    def test_record_failure_and_success(self) -> None:
        """记录失败和成功后 has_data=True。."""
        advisor = ConverterChainAdvisor()
        advisor.record(failure_type="model_refusal", converter_chains=["encoding_bypass"], success=False)
        advisor.record(failure_type="model_refusal", converter_chains=["encoding_bypass"], success=True)
        assert advisor.has_data

    def test_model_refusal_recommends_encoding(self) -> None:
        """model_refusal 建议编码链 (静态映射)。."""
        advisor = ConverterChainAdvisor()
        result = advisor.get_recommended_shift("model_refusal", ["stealth_evasion"])
        # 应该在前面加入 encoding_bypass 或 multi_encoding_v2
        assert "encoding_bypass" in result or "multi_encoding_v2" in result
        assert result[0] != "stealth_evasion"  # 推荐链排前

    def test_content_filter_recommends_obfuscation(self) -> None:
        """content_filter_block 建议混淆链。."""
        advisor = ConverterChainAdvisor()
        result = advisor.get_recommended_shift("content_filter_block", ["encoding_bypass"])
        # 应该推荐 stealth_evasion 或 unicode_attack
        assert "stealth_evasion" in result or "unicode_attack" in result

    def test_unknown_failure_type_returns_current(self) -> None:
        """未知失败类型返回当前链不变。."""
        advisor = ConverterChainAdvisor()
        result = advisor.get_recommended_shift("nonexistent_type", ["stealth_evasion"])
        assert result == ["stealth_evasion"]

    def test_runtime_data_overrides_static(self) -> None:
        """运行时数据优先于静态映射。."""
        advisor = ConverterChainAdvisor()
        # 记录 encoding_bypass 在 model_refusal 下 100% 成功
        advisor.record(failure_type="model_refusal", converter_chains=["encoding_bypass"], success=True)
        advisor.record(failure_type="model_refusal", converter_chains=["encoding_bypass"], success=True)
        # 记录 stealth_evasion 在 model_refusal 下 0% 成功
        advisor.record(failure_type="model_refusal", converter_chains=["stealth_evasion"], success=False)

        result = advisor.get_recommended_shift("model_refusal", ["stealth_evasion"])
        # encoding_bypass 应排前面 (运行时 ASR=100%)
        assert result[0] == "encoding_bypass"

    def test_get_stats_returns_dict(self) -> None:
        """get_stats 返回字典。."""
        advisor = ConverterChainAdvisor()
        advisor.record(failure_type="timeout", converter_chains=["stealth_evasion"], success=False)
        stats = advisor.get_stats()
        assert "timeout" in stats
        assert "stealth_evasion" in stats["timeout"]


# ============================================================
# D12: SuccessPropagationTracker
# ============================================================


class TestSuccessPropagationTracker:
    """测试 D12: 成功组合传播。."""

    def test_empty_tracker_no_data(self) -> None:
        """空 Tracker 无数据。."""
        tracker = SuccessPropagationTracker()
        assert not tracker.has_data
        assert tracker.total_successes == 0

    def test_record_success_increments_count(self) -> None:
        """记录成功后计数增加。."""
        tracker = SuccessPropagationTracker()
        tracker.record_success(
            payload_category="encoding",
            technique="prompt_sending",
            converter_chains=["encoding_bypass"],
        )
        assert tracker.has_data
        assert tracker.total_successes == 1

    def test_get_winning_chains(self) -> None:
        """获取成功次数最多的链。."""
        tracker = SuccessPropagationTracker()
        tracker.record_success(
            payload_category="encoding",
            technique="prompt_sending",
            converter_chains=["encoding_bypass"],
        )
        tracker.record_success(
            payload_category="encoding",
            technique="prompt_sending",
            converter_chains=["encoding_bypass"],
        )
        tracker.record_success(
            payload_category="encoding",
            technique="prompt_sending",
            converter_chains=["stealth_evasion"],
        )
        winners = tracker.get_winning_chains("encoding", "prompt_sending")
        assert winners[0] == "encoding_bypass"  # 2 次成功
        assert winners[1] == "stealth_evasion"  # 1 次成功

    def test_get_best_combo(self) -> None:
        """获取全局最优组合。."""
        tracker = SuccessPropagationTracker()
        tracker.record_success(
            payload_category="encoding",
            technique="crescendo",
            converter_chains=["encoding_bypass"],
        )
        tracker.record_success(
            payload_category="encoding",
            technique="crescendo",
            converter_chains=["encoding_bypass"],
        )
        best = tracker.get_best_combo()
        assert best is not None
        assert best["chain"] == "encoding_bypass"
        assert best["success_count"] == 2

    def test_get_best_combo_empty_returns_none(self) -> None:
        """无数据时 get_best_combo 返回 None。."""
        tracker = SuccessPropagationTracker()
        assert tracker.get_best_combo() is None

    def test_get_stats_returns_dict(self) -> None:
        """get_stats 返回字典。."""
        tracker = SuccessPropagationTracker()
        tracker.record_success(
            payload_category="encoding",
            technique="prompt_sending",
            converter_chains=["encoding_bypass"],
        )
        stats = tracker.get_stats()
        assert stats["total_successes"] == 1
        assert "encoding" in stats["success_map"]


# ============================================================
# D13: score_chain_combo
# ============================================================


class TestScoreChainCombo:
    """测试 D13: 链组合协同评分。."""

    def test_empty_chains_returns_1(self) -> None:
        """空链列表返回 1.0 (无协同)。."""
        assert score_chain_combo([]) == 1.0

    def test_no_combo_match_returns_1(self) -> None:
        """无已知组合匹配时返回 1.0。."""
        result = score_chain_combo(["random_case"])
        assert result == 1.0

    def test_known_combo_returns_multiplier(self) -> None:
        """已知组合返回乘数。."""
        result = score_chain_combo(["encoding_bypass", "stealth_evasion"])
        # encoding_bypass + stealth_evasion = 1.5x
        assert result >= 1.5

    def test_best_combo_selected(self) -> None:
        """多个组合匹配时取最高乘数。."""
        # encoding_bypass + unicode_attack = 1.6x (最高)
        result = score_chain_combo(["encoding_bypass", "unicode_attack", "stealth_evasion"])
        assert result >= 1.6

    def test_combo_multipliers_loaded(self) -> None:
        """combo_multipliers 从 YAML 加载。."""
        assert len(COMBO_MULTIPLIERS) > 0
        for combo in COMBO_MULTIPLIERS:
            assert "chains" in combo
            assert "multiplier" in combo


# ============================================================
# D14: get_chain_cost_weight
# ============================================================


class TestGetChainCostWeight:
    """测试 D14: 预算感知权重。."""

    def test_non_llm_chain_high_weight(self) -> None:
        """非 LLM 链权重高 (cheap)。."""
        weight = get_chain_cost_weight("encoding_bypass")
        assert weight == 1.0  # cheap

    def test_llm_chain_low_weight(self) -> None:
        """LLM 链权重低 (expensive)。."""
        weight = get_chain_cost_weight("persuasion_authority")
        assert weight == 0.4  # expensive

    def test_unknown_chain_default_cheap(self) -> None:
        """未知链默认 cheap。."""
        weight = get_chain_cost_weight("nonexistent_chain")
        assert weight == 1.0

    def test_cost_tier_in_chain_metadata(self) -> None:
        """链元数据包含 cost_tier 字段。."""
        for name, meta in CONVERTER_VARIANT_CHAINS.items():
            assert "cost_tier" in meta, f"Chain '{name}' missing cost_tier"


# ============================================================
# D15: extract_converter_chain_names
# ============================================================


class TestExtractConverterChainNames:
    """测试从 AttackResult 提取 Converter 链名。."""

    def test_empty_converters_returns_empty(self) -> None:
        """无 Converter 时返回空列表。."""
        ar = MagicMock()
        ar.request_converters = []
        result = extract_converter_chain_names(ar)
        assert result == []

    def test_no_request_converters_attr(self) -> None:
        """无 request_converters 属性时返回空列表。."""
        ar = MagicMock()
        del ar.request_converters
        result = extract_converter_chain_names(ar)
        assert result == []

    def test_known_converter_class_extracted(self) -> None:
        """已知 Converter 类名正确映射到链名。."""
        class Base64Converter:
            pass

        ar = MagicMock()
        ar.request_converters = [Base64Converter()]
        result = extract_converter_chain_names(ar)
        assert "encoding_bypass" in result

    def test_multiple_converters_deduped(self) -> None:
        """多个同类 Converter 去重。."""
        class Base64Converter:
            pass

        class ROT13Converter:
            pass

        ar = MagicMock()
        ar.request_converters = [Base64Converter(), ROT13Converter()]
        result = extract_converter_chain_names(ar)
        assert len(result) == 1  # both map to encoding_bypass
        assert result[0] == "encoding_bypass"
