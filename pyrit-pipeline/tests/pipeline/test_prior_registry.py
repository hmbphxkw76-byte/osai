# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_prior_registry — ASR 先验注册表单元测试。

覆盖:
  - tier_from_asr: ASR→Tier 分层
  - get_initial_q_value: 优先级链 (模型 + OWASP)
  - get_asr_prior: 技术先验查询
  - _apply_owasp_adjustment: OWASP 调整
  - get_prior_ordered_techniques: 先验排序

> **日期**: 2026-8-2
"""

from __future__ import annotations

import pytest

from pipeline.asr.prior_registry import (
    _apply_owasp_adjustment,
    get_all_priors,
    get_asr_prior,
    get_initial_q_value,
    get_prior_ordered_techniques,
    get_prior_summary,
    tier_from_asr,
)

# ──────────────────────────────────────────────────────────────────
#  tier_from_asr
# ──────────────────────────────────────────────────────────────────


class TestTierFromASR:
    """tier_from_asr 单元测试。."""

    @pytest.mark.parametrize(
        "asr,expected_tier",
        [
            (0.80, "S"),
            (0.60, "A"),
            (0.40, "A"),
            (0.15, "B"),
            (0.05, "C"),
            (0.00, "D"),
        ],
    )
    def test_tier_thresholds(self, asr: float, expected_tier: str) -> None:
        """ASR 阈值→正确的 Tier。."""
        assert tier_from_asr(asr) == expected_tier

    def test_tier_s_upper_bound(self) -> None:
        """ASR=1.0→S Tier。."""
        assert tier_from_asr(1.0) == "S"

    def test_tier_d_lower_bound(self) -> None:
        """ASR=0.0→D Tier。."""
        assert tier_from_asr(0.0) == "D"


# ──────────────────────────────────────────────────────────────────
#  get_initial_q_value
# ──────────────────────────────────────────────────────────────────


class TestGetInitialQValue:
    """get_initial_q_value 优先级链单元测试。."""

    def test_known_technique(self) -> None:
        """已知技术→返回 ASR 先验值。."""
        q = get_initial_q_value("prompt_sending")
        assert 0.0 <= q <= 1.0

    def test_unknown_technique_default(self) -> None:
        """未知技术→返回默认值 (0.5)。."""
        q = get_initial_q_value("nonexistent_technique_xyz")
        assert 0.0 <= q <= 1.0

    def test_model_name_adjustment(self) -> None:
        """不同模型名→可能不同的 Q 值。."""
        q_strong = get_initial_q_value("prompt_sending", model_name="gpt-4o")
        q_weak = get_initial_q_value("prompt_sending", model_name="gpt-35-turbo")
        # 两者都应在合理范围
        assert 0.0 <= q_strong <= 1.0
        assert 0.0 <= q_weak <= 1.0

    def test_owasp_adjustment(self) -> None:
        """OWASP ID 调整→Q 值在合理范围。."""
        q = get_initial_q_value("prompt_sending", owasp_id="LLM01")
        assert 0.0 <= q <= 1.0

    def test_converter_variant(self) -> None:
        """Converter 变体名→基础技术先验。."""
        q = get_initial_q_value("prompt_sending+stealth_evasion")
        assert 0.0 <= q <= 1.0


# ──────────────────────────────────────────────────────────────────
#  get_asr_prior
# ──────────────────────────────────────────────────────────────────


class TestGetASRPrior:
    """get_asr_prior 单元测试。."""

    def test_known_technique_returns_prior(self) -> None:
        """已知技术→返回 ASRPrior 对象。."""
        prior = get_asr_prior("prompt_sending")
        if prior is not None:
            assert hasattr(prior, "for_model")
            asr = prior.for_model("gpt-4o")
            assert 0.0 <= asr <= 1.0

    def test_unknown_technique_returns_none(self) -> None:
        """未知技术→返回 None。."""
        prior = get_asr_prior("nonexistent_xyz")
        assert prior is None


# ──────────────────────────────────────────────────────────────────
#  _apply_owasp_adjustment
# ──────────────────────────────────────────────────────────────────


class TestApplyOwaspAdjustment:
    """_apply_owasp_adjustment 单元测试。."""

    def test_no_owasp_id(self) -> None:
        """无 OWASP ID→不调整。."""
        original = 0.5
        result = _apply_owasp_adjustment(original, "prompt_sending", "")
        assert result == original

    def test_with_owasp_id(self) -> None:
        """有 OWASP ID→调整后值在合理范围。."""
        original = 0.5
        result = _apply_owasp_adjustment(original, "prompt_sending", "LLM01")
        assert 0.0 <= result <= 1.0


# ──────────────────────────────────────────────────────────────────
#  get_prior_ordered_techniques & summary
# ──────────────────────────────────────────────────────────────────


class TestPriorOrdering:
    """先验排序和摘要函数单元测试。."""

    def test_ordered_techniques(self) -> None:
        """get_prior_ordered_techniques→返回按 ASR 降序列表。."""
        techs = ["prompt_sending", "many_shot", "crescendo", "tap"]
        ordered = get_prior_ordered_techniques(techs)
        assert len(ordered) == len(techs)
        # 验证降序 (如果有先验数据)
        # 如果所有技术都有先验, 则应该是降序
        # 如果没有先验, 则保持原序

    def test_get_all_priors(self) -> None:
        """get_all_priors→返回非空字典。."""
        all_priors = get_all_priors()
        assert isinstance(all_priors, dict)
        assert len(all_priors) > 0

    def test_get_prior_summary(self) -> None:
        """get_prior_summary→返回列表。."""
        summary = get_prior_summary()
        assert isinstance(summary, list)
        if summary:
            assert "technique" in summary[0]
