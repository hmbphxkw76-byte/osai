"""
评分器评估器测试
================

测试 PyRIT 1.0.0 Scoring 子系统的 evaluator.py 模块。

覆盖范围：
  1. ScorerAccuracyEvaluator 初始化
  2. 工厂函数
  3. 三层评估方法（run_full_evaluation / evaluate_with_dataset / evaluate_quick）
  4. 一致性评估
  5. 鲁棒性评估
  6. 批量评估
  7. A/B 比较
  8. 指标查询
  9. 指标报告格式化
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from uuid import uuid4

from src.scorers.evaluator import (
    ScorerAccuracyEvaluator,
    create_scorer_evaluator,
    evaluate_scorer_quick,
    format_metrics_report,
)


# ============================================================
# 1. ScorerAccuracyEvaluator 初始化
# ============================================================

class TestScorerAccuracyEvaluatorInit:
    """测试 ScorerAccuracyEvaluator 初始化"""

    def test_init_no_chat_target(self):
        """无 chat_target 初始化"""
        evaluator = ScorerAccuracyEvaluator()
        assert evaluator.chat_target is None

    def test_init_with_chat_target(self):
        """带 chat_target 初始化"""
        mock_target = MagicMock()
        evaluator = ScorerAccuracyEvaluator(chat_target=mock_target)
        assert evaluator.chat_target is mock_target


# ============================================================
# 2. 工厂函数
# ============================================================

class TestFactoryFunctions:
    """测试工厂函数"""

    def test_create_scorer_evaluator_no_target(self):
        """无 target 创建评估器"""
        evaluator = create_scorer_evaluator()
        assert isinstance(evaluator, ScorerAccuracyEvaluator)
        assert evaluator.chat_target is None

    def test_create_scorer_evaluator_with_target(self):
        """带 target 创建评估器"""
        mock_target = MagicMock()
        evaluator = create_scorer_evaluator(chat_target=mock_target)
        assert isinstance(evaluator, ScorerAccuracyEvaluator)
        assert evaluator.chat_target is mock_target


# ============================================================
# 3. 三层评估方法
# ============================================================

class TestEvaluationMethods:
    """测试三层评估方法"""

    def test_run_full_evaluation_exists(self):
        """run_full_evaluation 方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "run_full_evaluation")

    def test_evaluate_with_dataset_exists(self):
        """evaluate_with_dataset 方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "evaluate_with_dataset")

    def test_evaluate_quick_exists(self):
        """evaluate_quick 方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "evaluate_quick")

    def test_evaluate_quick_raises_for_harm_type(self):
        """evaluate_quick 对 HARM 类型引发 ValueError"""
        import asyncio
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async
        from pyrit.score import SubStringScorer
        from pyrit.score import MetricsType

        async def _run():
            await initialize_pyrit_async(memory_db_type=IN_MEMORY, silent=True)
            scorer = SubStringScorer(substring="test")
            evaluator = ScorerAccuracyEvaluator()
            # 强制 HARM 类型应引发 ValueError
            await evaluator.evaluate_quick(
                scorer=scorer,
                samples=[{"text": "test", "label": True, "objective": "test"}],
                metrics_type=MetricsType.HARM,
            )

        with pytest.raises(ValueError, match="HARM"):
            asyncio.new_event_loop().run_until_complete(_run())

    def test_run_full_evaluation_is_async(self):
        """run_full_evaluation 是异步方法"""
        import inspect
        evaluator = ScorerAccuracyEvaluator()
        assert inspect.iscoroutinefunction(evaluator.run_full_evaluation)

    def test_evaluate_with_dataset_is_async(self):
        """evaluate_with_dataset 是异步方法"""
        import inspect
        evaluator = ScorerAccuracyEvaluator()
        assert inspect.iscoroutinefunction(evaluator.evaluate_with_dataset)

    def test_evaluate_quick_is_async(self):
        """evaluate_quick 是异步方法"""
        import inspect
        evaluator = ScorerAccuracyEvaluator()
        assert inspect.iscoroutinefunction(evaluator.evaluate_quick)


# ============================================================
# 4. 一致性评估
# ============================================================

class TestConsistencyEvaluation:
    """测试一致性评估"""

    def test_evaluate_consistency_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "evaluate_consistency")

    def test_evaluate_consistency_is_async(self):
        """异步方法"""
        import inspect
        evaluator = ScorerAccuracyEvaluator()
        assert inspect.iscoroutinefunction(evaluator.evaluate_consistency)

    def test_evaluate_consistency_returns_dict(self):
        """返回字典"""
        import asyncio
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async
        from pyrit.score import SubStringScorer

        async def _run():
            await initialize_pyrit_async(memory_db_type=IN_MEMORY, silent=True)
            scorer = SubStringScorer(substring="test")
            evaluator = ScorerAccuracyEvaluator()
            result = await evaluator.evaluate_consistency(
                scorer=scorer,
                consistency_dataset=["test text", "another test"],
                num_repetitions=2,
            )
            return result

        result = asyncio.new_event_loop().run_until_complete(_run())
        assert isinstance(result, dict)
        # TrueFalseScorer 应返回 agreement_rate
        if result:
            assert "agreement_rate" in result


# ============================================================
# 5. 鲁棒性评估
# ============================================================

class TestRobustnessEvaluation:
    """测试鲁棒性评估"""

    def test_evaluate_robustness_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "evaluate_robustness")

    def test_evaluate_robustness_is_async(self):
        """异步方法"""
        import inspect
        evaluator = ScorerAccuracyEvaluator()
        assert inspect.iscoroutinefunction(evaluator.evaluate_robustness)

    def test_evaluate_robustness_empty_dataset(self):
        """空数据集返回默认值"""
        import asyncio
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async
        from pyrit.score import SubStringScorer

        async def _run():
            await initialize_pyrit_async(memory_db_type=IN_MEMORY, silent=True)
            scorer = SubStringScorer(substring="test")
            evaluator = ScorerAccuracyEvaluator()
            result = await evaluator.evaluate_robustness(
                scorer=scorer,
                adversarial_dataset=[],
            )
            return result

        result = asyncio.new_event_loop().run_until_complete(_run())
        assert result["robustness_score"] == 1.0

    def test_evaluate_robustness_with_data(self):
        """有数据时返回结果"""
        import asyncio
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async
        from pyrit.score import SubStringScorer

        async def _run():
            await initialize_pyrit_async(memory_db_type=IN_MEMORY, silent=True)
            scorer = SubStringScorer(substring="test")
            evaluator = ScorerAccuracyEvaluator()
            dataset = [
                {
                    "original": "test text",
                    "perturbations": ["Test text", "test  text"],
                }
            ]
            result = await evaluator.evaluate_robustness(
                scorer=scorer,
                adversarial_dataset=dataset,
            )
            return result

        result = asyncio.new_event_loop().run_until_complete(_run())
        assert isinstance(result, dict)
        assert "robustness_score" in result


# ============================================================
# 6. 批量评估
# ============================================================

class TestBatchEvaluation:
    """测试批量评估"""

    def test_evaluate_multiple_scorers_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "evaluate_multiple_scorers")

    def test_evaluate_multiple_scorers_is_async(self):
        """异步方法"""
        import inspect
        evaluator = ScorerAccuracyEvaluator()
        assert inspect.iscoroutinefunction(evaluator.evaluate_multiple_scorers)


# ============================================================
# 7. A/B 比较
# ============================================================

class TestCompareScorers:
    """测试 A/B 比较"""

    def test_compare_scorers_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "compare_scorers")

    def test_compare_scorers_returns_dict(self):
        """返回字典"""
        from pyrit.score import SubStringScorer

        scorer_a = SubStringScorer(substring="a")
        scorer_b = SubStringScorer(substring="b")
        evaluator = ScorerAccuracyEvaluator()

        result = evaluator.compare_scorers(scorer_a, scorer_b)
        assert isinstance(result, dict)
        assert "scorer_a" in result
        assert "scorer_b" in result
        assert "comparison" in result
        assert result["scorer_a"]["name"] == "SubStringScorer"
        assert result["scorer_b"]["name"] == "SubStringScorer"


# ============================================================
# 8. 指标查询
# ============================================================

class TestMetricsQueries:
    """测试指标查询方法"""

    def test_get_scorer_metrics_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "get_scorer_metrics")

    def test_get_scorer_eval_hash_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "get_scorer_eval_hash")

    def test_list_all_objective_metrics_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "list_all_objective_metrics")

    def test_list_all_harm_metrics_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "list_all_harm_metrics")

    def test_find_metrics_by_eval_hash_exists(self):
        """方法存在"""
        evaluator = ScorerAccuracyEvaluator()
        assert hasattr(evaluator, "find_metrics_by_eval_hash")

    def test_get_scorer_eval_hash_returns_none_or_str(self):
        """返回 None 或字符串"""
        from pyrit.score import SubStringScorer
        scorer = SubStringScorer(substring="test")
        evaluator = ScorerAccuracyEvaluator()
        result = evaluator.get_scorer_eval_hash(scorer)
        assert result is None or isinstance(result, str)


# ============================================================
# 9. 指标报告格式化
# ============================================================

class TestFormatMetricsReport:
    """测试指标报告格式化"""

    def test_format_metrics_report_with_objective(self):
        """格式化 Objective 指标"""
        from pyrit.score import ObjectiveScorerMetrics

        metrics = ObjectiveScorerMetrics(
            dataset_name="test_dataset",
            dataset_version="1.0",
            num_responses=100,
            num_human_raters=2,
            num_scorer_trials=3,
            average_score_time_seconds=0.5,
            accuracy=0.85,
            accuracy_standard_error=0.03,
            precision=0.82,
            recall=0.88,
            f1_score=0.85,
        )

        report = format_metrics_report(metrics)
        assert isinstance(report, str)
        assert "Objective Metrics" in report
        assert "0.8500" in report
        assert "accuracy" in report.lower()

    def test_format_metrics_report_with_harm(self):
        """格式化 Harm 指标"""
        from pyrit.score import HarmScorerMetrics

        metrics = HarmScorerMetrics(
            dataset_name="test_dataset",
            dataset_version="1.0",
            num_responses=100,
            num_human_raters=2,
            num_scorer_trials=3,
            average_score_time_seconds=0.5,
            mean_absolute_error=0.15,
            mae_standard_error=0.02,
            t_statistic=1.5,
            p_value=0.05,
            krippendorff_alpha_combined=0.8,
            krippendorff_alpha_humans=0.85,
            krippendorff_alpha_model=0.9,
        )

        report = format_metrics_report(metrics)
        assert isinstance(report, str)
        assert "Harm Metrics" in report
        assert "0.1500" in report

    def test_format_metrics_report_contains_basic_info(self):
        """报告包含基本信息"""
        from pyrit.score import ObjectiveScorerMetrics

        metrics = ObjectiveScorerMetrics(
            dataset_name="test_dataset",
            dataset_version="1.0",
            num_responses=100,
            num_human_raters=2,
            num_scorer_trials=3,
            average_score_time_seconds=0.5,
            accuracy=0.85,
            accuracy_standard_error=0.03,
            precision=0.82,
            recall=0.88,
            f1_score=0.85,
        )

        report = format_metrics_report(metrics)
        assert "test_dataset" in report
        assert "100" in report
        assert "0.500" in report


# ============================================================
# 10. evaluate_scorer_quick 工厂函数
# ============================================================

class TestEvaluateScorerQuick:
    """测试 evaluate_scorer_quick 工厂函数"""

    def test_is_async(self):
        """异步函数"""
        import inspect
        assert inspect.iscoroutinefunction(evaluate_scorer_quick)

    def test_returns_dict(self):
        """返回字典"""
        import asyncio
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async
        from pyrit.score import SubStringScorer

        async def _run():
            await initialize_pyrit_async(memory_db_type=IN_MEMORY, silent=True)
            scorer = SubStringScorer(substring="test")
            result = await evaluate_scorer_quick(
                scorer=scorer,
                positive_samples=["test text"],
                negative_samples=["no match"],
            )
            return result

        result = asyncio.new_event_loop().run_until_complete(_run())
        assert isinstance(result, dict)
