"""L5 v30 Post-hoc Dual Judge 评分架构测试.

测试内容:
    1. precompute_outcomes_async score_all 参数
    2. 全局统计计数器 (_dual_judge_* 系列)
    3. get_dual_judge_stats / _reset_dual_judge_stats
    4. collect_dual_judge_stats 优先从全局计数器获取
    5. _classify_score_consistency 返回 "Post-hoc Dual Judge"
    6. config/defaults.yaml 中 post_hoc_dual_judge_enabled 参数

学术依据:
    - Zhang et al. (arXiv:2308.07920) — 双 Judge 交叉验证
    - Mazeika et al. (arXiv:2402.04249) — HarmBench 评分基准
    - Cohen (1960) — Cohen's Kappa 一致性度量
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


class TestL5V30GlobalCounters:
    """L5 v30 全局统计计数器测试。"""

    def test_reset_dual_judge_stats(self):
        """测试 _reset_dual_judge_stats 重置计数器。"""
        import pipeline.assess.asr_stats as stats
        from pipeline.assess.asr_tracker import _reset_dual_judge_stats

        stats._dual_judge_total_scored = 100
        stats._dual_judge_agreements = 80
        stats._dual_judge_disagreements = 20

        _reset_dual_judge_stats()

        assert stats._dual_judge_total_scored == 0
        assert stats._dual_judge_agreements == 0
        assert stats._dual_judge_disagreements == 0
        assert stats._dual_judge_judge1_successes == 0
        assert stats._dual_judge_judge2_successes == 0

    def test_get_dual_judge_stats_empty(self):
        """测试 get_dual_judge_stats 在无数据时返回零值。"""
        from pipeline.assess.asr_tracker import _reset_dual_judge_stats, get_dual_judge_stats

        _reset_dual_judge_stats()
        stats = get_dual_judge_stats()

        assert stats["total_scored"] == 0
        assert stats["agreements"] == 0
        assert stats["disagreements"] == 0
        assert stats["agreement_rate"] == 0.0
        assert stats["dual_judge_invoked"] == 0
        assert stats["dual_judge_rate"] == 0.0
        assert stats["high_confidence_threshold"] == 0.85

    def test_get_dual_judge_stats_with_data(self):
        """测试 get_dual_judge_stats 在有数据时返回正确统计。"""
        import pipeline.assess.asr_stats as stats
        from pipeline.assess.asr_tracker import get_dual_judge_stats

        stats._dual_judge_total_scored = 10
        stats._dual_judge_agreements = 8
        stats._dual_judge_disagreements = 2
        stats._dual_judge_judge1_successes = 7
        stats._dual_judge_judge2_successes = 6

        stats_result = get_dual_judge_stats()

        assert stats_result["total_scored"] == 10
        assert stats_result["agreements"] == 8
        assert stats_result["disagreements"] == 2
        assert stats_result["agreement_rate"] == 80.0
        assert stats_result["dual_judge_invoked"] == 10
        assert stats_result["dual_judge_rate"] == 100.0
        assert stats_result["judge1_successes"] == 7
        assert stats_result["judge2_successes"] == 6

        # 清理
        from pipeline.assess.asr_tracker import _reset_dual_judge_stats
        _reset_dual_judge_stats()


class TestL5V30CollectDualJudgeStats:
    """L5 v30 collect_dual_judge_stats 测试。"""

    def test_collect_from_global_counter(self):
        """测试当全局计数器有数据时, collect_dual_judge_stats 从计数器获取。"""
        import pipeline.assess.asr_stats as stats
        from pipeline.assess.asr_tracker import collect_dual_judge_stats

        stats._dual_judge_total_scored = 5
        stats._dual_judge_agreements = 4
        stats._dual_judge_disagreements = 1

        ctx = MagicMock()
        stats_result = collect_dual_judge_stats(ctx)

        assert stats_result["total_scored"] == 5
        assert stats_result["agreements"] == 4
        assert stats_result["disagreements"] == 1
        assert stats_result["agreement_rate"] == 80.0

        # 清理
        from pipeline.assess.asr_tracker import _reset_dual_judge_stats
        _reset_dual_judge_stats()

    def test_collect_fallback_to_scorer(self):
        """测试当全局计数器无数据时, fallback 到 ctx.scorer。"""
        from pipeline.assess.asr_tracker import _reset_dual_judge_stats, collect_dual_judge_stats

        _reset_dual_judge_stats()

        mock_scorer = MagicMock()
        mock_scorer.get_stats.return_value = {"total_scored": 3, "agreements": 2}
        ctx = MagicMock()
        ctx.scorer = mock_scorer

        stats = collect_dual_judge_stats(ctx)

        assert stats["total_scored"] == 3
        assert stats["agreements"] == 2


class TestL5V30PrecomputeOutcomesAsync:
    """L5 v30 precompute_outcomes_async 测试。"""

    @pytest.mark.asyncio
    async def test_precompute_score_all_param_exists(self):
        """测试 precompute_outcomes_async 接受 score_all 参数。"""
        from pipeline.assess.asr_tracker import precompute_outcomes_async

        # 空字典不应报错
        await precompute_outcomes_async({}, score_all=True)
        await precompute_outcomes_async({}, score_all=False)

    @pytest.mark.asyncio
    async def test_precompute_score_all_resets_counter(self):
        """测试 score_all=True 时重置全局计数器。"""
        import pipeline.assess.asr_stats as stats
        from pipeline.assess.asr_tracker import precompute_outcomes_async

        # 设置一些旧数据
        stats._dual_judge_total_scored = 999

        # 用空字典调用 score_all=True
        await precompute_outcomes_async({}, score_all=True)

        # 计数器应被重置
        assert stats._dual_judge_total_scored == 0


class TestL5V30ConfigYaml:
    """L5 v30 config/defaults.yaml 测试。"""

    def test_post_hoc_dual_judge_enabled_in_config(self):
        # V2 精简: post_hoc_dual_judge_enabled 已从 defaults.yaml 删除
        pytest.skip("V2: post_hoc_dual_judge_enabled removed from defaults.yaml")


class TestL5V30ReportConsistency:
    """L5 v30 报告一致性分析测试。"""

    def test_classify_single_scorer_returns_post_hoc(self):
        """测试单 scorer 时返回 'Post-hoc Dual Judge' 而非 'Single Judge'。"""
        from pipeline.report.generator import _classify_score_consistency

        # 单 scorer
        score_details = [{"scorer": "Score", "score_value": "True"}]
        result = _classify_score_consistency(score_details)
        assert result == "Post-hoc Dual Judge"

    def test_classify_no_details_returns_na(self):
        """测试空 score_details 返回 N/A。"""
        from pipeline.report.generator import _classify_score_consistency

        result = _classify_score_consistency([])
        assert result == "N/A"

    def test_classify_consistent(self):
        """测试多 scorer 一致时返回 Consistent。"""
        from pipeline.report.generator import _classify_score_consistency

        score_details = [
            {"scorer": "J1", "score_value": "True"},
            {"scorer": "J2", "score_value": "True"},
        ]
        result = _classify_score_consistency(score_details)
        assert result == "Consistent"

    def test_classify_minor_disagreement(self):
        """测试多 scorer 分歧时返回 Minor Disagreement。"""
        from pipeline.report.generator import _classify_score_consistency

        score_details = [
            {"scorer": "J1", "score_value": "True"},
            {"scorer": "J2", "score_value": "False"},
        ]
        result = _classify_score_consistency(score_details)
        assert result == "Minor Disagreement"


class TestL5V30MainIntegration:
    """L5 v30 main.py 集成测试。"""

    def test_main_imports_precompute_outcomes_async(self):
        """测试 main.py 导入了 precompute_outcomes_async。"""
        from pathlib import Path

        main_path = Path(__file__).resolve().parent.parent.parent / "main.py"
        source = main_path.read_text(encoding="utf-8")

        assert "precompute_outcomes_async" in source
        assert "score_all=" in source  # L5 v31+: uses score_all parameter
        assert "L5 v3" in source  # L5 version marker


class TestL5V30CohensKappaWithStats:
    """L5 v30 Cohen's Kappa 配合双 Judge 统计测试。"""

    def test_kappa_perfect_agreement(self):
        """测试完美一致时 Kappa = 1.0。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        kappa = compute_cohens_kappa(agreements=10, disagreements=0)
        # P_o = 1.0, P_e = 0.5, kappa = (1.0 - 0.5) / (1 - 0.5) = 1.0
        assert kappa == 1.0

    def test_kappa_no_agreement(self):
        """测试完全分歧时 Kappa = -1.0。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        kappa = compute_cohens_kappa(agreements=0, disagreements=10)
        # P_o = 0.0, P_e = 0.5, kappa = (0.0 - 0.5) / (1 - 0.5) = -1.0
        assert kappa == -1.0

    def test_kappa_moderate_agreement(self):
        """测试 70% 一致时 Kappa 值。"""
        from pipeline.assess.asr_tracker import compute_cohens_kappa

        kappa = compute_cohens_kappa(agreements=7, disagreements=3)
        # P_o = 0.7, P_e = 0.5, kappa = (0.7 - 0.5) / (1 - 0.5) = 0.4
        assert kappa == 0.4
