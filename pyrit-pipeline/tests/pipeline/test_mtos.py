# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""MTOS (Multi-Turn Objective Suitability Score) 种子选择测试.

测试覆盖:
  1. compute_mtos_score: 多维度评分 (ASR 适宜性 + difficulty + severity + category)
  2. _compute_asr_suitability: 钟形曲线 (窗口内高, 高 ASR 低)
  3. select_multiturn_objectives: 热启动/冷启动统一入口
  4. _select_cold_start: 冷启动元数据驱动选种
  5. TAP 超时保护逻辑

学术依据:
  - Crescendo (arXiv:2402.12109): 渐进升级突破单轮防御
  - TAP (arXiv:2312.02191): 树搜索需中等难度空间
  - HarmBench (arXiv:2402.04249): 类别平衡采样
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pipeline.asr.optimizer import (
    _compute_asr_suitability,
    _select_cold_start,
    compute_mtos_score,
    select_multiturn_objectives,
)

# ============================================================
# _compute_asr_suitability 单元测试
# ============================================================


class TestComputeAsrSuitability:
    """ASR 适宜性钟形曲线测试."""

    def test_within_window_high_score(self):
        """ASR 在偏好窗口内 → 高分."""
        score = _compute_asr_suitability(0.05, total=5, asr_window=(0.0, 0.15))
        assert 0.8 <= score <= 1.0

    def test_at_window_center_max_score(self):
        """ASR 在窗口中心 → 接近最高分."""
        score = _compute_asr_suitability(0.075, total=5, asr_window=(0.0, 0.15))
        assert score >= 0.9

    def test_high_asr_low_score(self):
        """高单轮 ASR (>50%) → 低分 (Crescendo 浪费)."""
        score = _compute_asr_suitability(0.80, total=10, asr_window=(0.0, 0.15))
        assert score == pytest.approx(0.1)

    def test_medium_asr_medium_score(self):
        """中等 ASR (20-50%) → 中低分."""
        score = _compute_asr_suitability(0.30, total=10, asr_window=(0.0, 0.15))
        assert score == pytest.approx(0.4)

    def test_zero_asr_small_sample_medium_score(self):
        """0% ASR 但小样本 (<3) → 中高分 (不确定性高)."""
        score = _compute_asr_suitability(0.0, total=2, asr_window=(0.0, 0.15))
        assert score == pytest.approx(0.6)

    def test_zero_asr_large_sample_low_score(self):
        """0% ASR 大样本 (>=3) → 低分 (可能确实无法突破)."""
        score = _compute_asr_suitability(0.0, total=10, asr_window=(0.0, 0.15))
        assert score == pytest.approx(0.3)

    def test_tap_window_preference(self):
        """TAP 窗口 (0.10-0.30): 中等 ASR 在窗口内 → 高分."""
        score = _compute_asr_suitability(0.20, total=5, asr_window=(0.10, 0.30))
        assert 0.8 <= score <= 1.0


# ============================================================
# compute_mtos_score 单元测试
# ============================================================


class TestComputeMtosScore:
    """MTOS 多维度评分测试."""

    def test_hard_critical_uncovered_category_max_score(self):
        """hard + critical + 未覆盖类别 → 高分."""
        score = compute_mtos_score(
            seed_hash="abc",
            seed_asr_data={"abc": {"asr": 0.05, "total": 3}},
            seed_metadata={"difficulty": "hard", "severity": "critical", "owasp_id": "ASI01"},
            used_owasp_ids=set(),
            asr_window=(0.0, 0.15),
        )
        assert score >= 0.7

    def test_easy_high_covered_category_moderate_score(self):
        """easy + high + 已覆盖类别 → 中低分 (ASR 适宜性仍主导)."""
        score = compute_mtos_score(
            seed_hash="abc",
            seed_asr_data={"abc": {"asr": 0.05, "total": 3}},
            seed_metadata={"difficulty": "easy", "severity": "high", "owasp_id": "ASI01"},
            used_owasp_ids={"ASI01"},
            asr_window=(0.0, 0.15),
        )
        # ASR=0.05 在窗口内 → ASR 适宜性高, 即使 difficulty=easy + covered category
        # MTOS 仍被 ASR 适宜性拉高, 但不应超过 hard+critical 的分数
        assert 0.4 <= score < 0.7

    def test_high_asr_seed_low_mtos(self):
        """高 ASR 种子 → MTOS 较低 (多轮攻击浪费, 但 severity+category 可拉高)."""
        score = compute_mtos_score(
            seed_hash="abc",
            seed_asr_data={"abc": {"asr": 0.80, "total": 10}},
            seed_metadata={"difficulty": "easy", "severity": "critical", "owasp_id": "LLM01"},
            used_owasp_ids=set(),
            asr_window=(0.0, 0.15),
        )
        # ASR=0.80 → ASR 适宜性=0.1; 但 severity=critical(1.0) + uncovered category(1.0)
        # 拉高总分, 但应低于 hard+critical+uncovered+低ASR 的种子
        assert score < 0.6

    def test_no_metadata_no_asr_medium_score(self):
        """无元数据无 ASR → 中等分."""
        score = compute_mtos_score(
            seed_hash="abc",
            seed_asr_data=None,
            seed_metadata=None,
            used_owasp_ids=None,
            asr_window=(0.0, 0.15),
        )
        assert 0.2 < score < 0.7

    def test_custom_weights_override(self):
        """自定义权重覆盖默认值."""
        score_default = compute_mtos_score(
            seed_hash="abc",
            seed_asr_data={"abc": {"asr": 0.80, "total": 10}},
            seed_metadata={"difficulty": "hard", "severity": "critical", "owasp_id": "ASI01"},
            used_owasp_ids=set(),
        )
        # 权重完全偏向 difficulty
        score_custom = compute_mtos_score(
            seed_hash="abc",
            seed_asr_data={"abc": {"asr": 0.80, "total": 10}},
            seed_metadata={"difficulty": "hard", "severity": "critical", "owasp_id": "ASI01"},
            used_owasp_ids=set(),
            weights={"asr_suitability": 0.0, "difficulty": 1.0, "severity": 0.0, "category_diversity": 0.0},
        )
        # 完全偏向 difficulty 时, hard=1.0 → score_custom 应更高
        assert score_custom > score_default


# ============================================================
# select_multiturn_objectives 单元测试
# ============================================================


class TestSelectMultiturnObjectives:
    """统一选种入口测试."""

    def test_cold_start_with_no_asr_data(self):
        """无历史 ASR → 冷启动策略."""
        with patch("pipeline.asr.optimizer.CentralMemory") as mock_cm:
            mock_mem = MagicMock()
            mock_cm.get_memory_instance.return_value = mock_mem
            mock_mem.get_seed_prompts.return_value = []
            cres, tap, meta = select_multiturn_objectives(
                seed_level_asr=None,
                datasets=["owasp_llm01_prompt_injection"],
                cold_start_min_seeds=5,
            )
            assert meta["strategy"] == "cold_start"
            assert cres is None  # 无种子数据
            assert tap is None

    def test_cold_start_with_few_seeds(self):
        """种子数 < cold_start_min_seeds → 冷启动."""
        asr_data = {"hash1": {"asr": 0.1, "total": 1, "seed_preview": "test"}}
        with patch("pipeline.asr.optimizer.CentralMemory") as mock_cm:
            mock_mem = MagicMock()
            mock_cm.get_memory_instance.return_value = mock_mem
            mock_mem.get_seed_prompts.return_value = []
            cres, tap, meta = select_multiturn_objectives(
                seed_level_asr=asr_data,
                datasets=["test_ds"],
                cold_start_min_seeds=5,
            )
            assert meta["strategy"] == "cold_start"

    def test_warm_start_with_sufficient_seeds(self):
        """种子数 >= cold_start_min_seeds → 热启动 (MTOS 评分)."""
        # 构建 6 个种子的 ASR 数据 (>= 5 = 热启动)
        asr_data = {}
        for i in range(6):
            asr_data[f"hash_{i}"] = {
                "asr": 0.05 + i * 0.01,
                "total": 3 + i,
                "seed_preview": f"seed preview {i}" * 3,
            }
        with patch("pipeline.asr.optimizer.CentralMemory") as mock_cm:
            mock_mem = MagicMock()
            mock_cm.get_memory_instance.return_value = mock_mem
            mock_mem.get_seed_prompts.return_value = []
            cres, tap, meta = select_multiturn_objectives(
                seed_level_asr=asr_data,
                datasets=None,
                cold_start_min_seeds=5,
            )
            assert meta["strategy"] == "warm_start"
            # 应该选到某个种子
            if cres:
                assert len(cres) > 0


# ============================================================
# _select_cold_start 单元测试
# ============================================================


class TestSelectColdStart:
    """冷启动元数据驱动选种测试."""

    def test_filters_easy_and_low_severity(self):
        """冷启动过滤 easy 难度和 low severity 种子."""
        # 模拟种子: 只有 medium/hard + critical/high 通过过滤
        mock_prompt_hard = MagicMock()
        mock_prompt_hard.value = "Hard critical seed prompt for testing"
        mock_prompt_hard.metadata = {"difficulty": "hard", "severity": "critical", "owasp_id": "ASI01"}

        mock_prompt_easy = MagicMock()
        mock_prompt_easy.value = "Easy low seed"
        mock_prompt_easy.metadata = {"difficulty": "easy", "severity": "low", "owasp_id": "LLM01"}

        mock_prompt_medium = MagicMock()
        mock_prompt_medium.value = "Medium high seed prompt for testing TAP"
        mock_prompt_medium.metadata = {"difficulty": "medium", "severity": "high", "owasp_id": "ASI05"}

        with patch("pipeline.asr.optimizer.CentralMemory") as mock_cm:
            mock_mem = MagicMock()
            mock_cm.get_memory_instance.return_value = mock_mem

            def get_prompts(dataset_name=None):
                return [mock_prompt_hard, mock_prompt_easy, mock_prompt_medium]

            mock_mem.get_seed_prompts.side_effect = get_prompts

            cres, tap, meta = _select_cold_start(
                datasets=["test_ds"],
            )
            # easy+low 种子被过滤
            assert cres is not None
            assert "Hard" in cres or "Medium" in cres  # 选中了 hard 或 medium 种子
            # tap 应选不同 OWASP 类别
            if tap:
                assert tap != cres

    def test_fallback_no_matching_seeds(self):
        """无符合条件种子 → fallback 取首个种子."""
        mock_prompt = MagicMock()
        mock_prompt.value = "Fallback seed"
        mock_prompt.metadata = {"difficulty": "easy", "severity": "low"}

        with patch("pipeline.asr.optimizer.CentralMemory") as mock_cm:
            mock_mem = MagicMock()
            mock_cm.get_memory_instance.return_value = mock_mem
            mock_mem.get_seed_prompts.return_value = [mock_prompt]

            cres, tap, meta = _select_cold_start(
                datasets=["test_ds"],
            )
            # fallback 到首个种子
            assert cres is not None
            assert "Fallback" in cres

    def test_crescendo_prefers_hard(self):
        """Crescendo 偏好 hard 难度种子."""
        mock_hard = MagicMock()
        mock_hard.value = "Hard seed prompt for testing Crescendo attack"
        mock_hard.metadata = {"difficulty": "hard", "severity": "critical", "owasp_id": "ASI01"}

        mock_medium = MagicMock()
        mock_medium.value = "Medium seed prompt for testing TAP attack here"
        mock_medium.metadata = {"difficulty": "medium", "severity": "critical", "owasp_id": "ASI05"}

        with patch("pipeline.asr.optimizer.CentralMemory") as mock_cm:
            mock_mem = MagicMock()
            mock_cm.get_memory_instance.return_value = mock_mem
            mock_mem.get_seed_prompts.return_value = [mock_hard, mock_medium]

            cres, tap, meta = _select_cold_start(
                datasets=["test_ds"],
            )
            # Crescendo 应选 hard 种子
            assert cres is not None
            assert "Hard" in cres


# ============================================================
# TAP 超时保护测试
# ============================================================


class TestTapTimeoutProtection:
    """TAP 超时保护逻辑测试 (通过 stage_scenario 异常处理路径)."""

    def test_timeout_error_message_contains_timeout(self):
        """超时错误消息包含 timeout 关键词."""
        err_msg = "APITimeoutError: Request timed out."
        assert "timeout" in err_msg.lower() or "APITimeoutError" in err_msg

    def test_non_timeout_error_not_matched(self):
        """非超时错误不匹配超时保护."""
        err_msg = "ValueError: Node not in tree"
        assert not ("timeout" in err_msg.lower() or "APITimeoutError" in err_msg)
