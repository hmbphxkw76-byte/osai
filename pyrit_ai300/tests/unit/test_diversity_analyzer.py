"""
多样性分析器测试
================

测试攻击多样性与覆盖度分析功能。

覆盖范围：
  1. Shannon 熵计算（基础、归一化、边界条件）
  2. 覆盖率与集中度计算
  3. 技术/失败分布拆分
  4. DiversityAnalyzer 完整分析流程
  5. 报告渲染
  6. 边界条件（空输入、单类别等）
"""

import pytest
from unittest.mock import MagicMock

from src.reporting.diversity_analyzer import (
    DiversityAnalyzer,
    DiversityAnalysisResult,
    calculate_shannon_entropy,
    calculate_normalized_entropy,
    calculate_coverage_ratio,
    calculate_concentration_ratio,
    split_technique_distribution_by_outcome,
    calculate_owasp_coverage_breadth,
    render_diversity_section,
)


# ============================================================
# 测试辅助
# ============================================================


def _make_attack_result(technique: str, outcome: str = "success") -> MagicMock:
    """创建模拟 AttackResult"""
    mock = MagicMock()
    mock.get_attack_strategy_identifier.return_value = None
    mock.atomic_attack_identifier = technique
    mock.labels = {"attack_technique": technique}
    mock.outcome = MagicMock()
    mock.outcome.value = outcome
    return mock


def _make_coverage_matrix(covered_ids: list) -> dict:
    """创建模拟覆盖矩阵"""
    matrix = {}
    for i in range(1, 11):
        owasp_id = f"LLM{i:02d}"
        matrix[owasp_id] = {
            "name": f"LLM {i}",
            "covered": owasp_id in covered_ids,
            "attack_count": 1 if owasp_id in covered_ids else 0,
            "success_count": 1 if owasp_id in covered_ids else 0,
            "success_rate": 100.0 if owasp_id in covered_ids else 0.0,
        }
    for i in range(1, 11):
        owasp_id = f"ASI{i:02d}"
        matrix[owasp_id] = {
            "name": f"ASI {i}",
            "covered": owasp_id in covered_ids,
            "attack_count": 1 if owasp_id in covered_ids else 0,
            "success_count": 1 if owasp_id in covered_ids else 0,
            "success_rate": 100.0 if owasp_id in covered_ids else 0.0,
        }
    return matrix


# ============================================================
# Shannon 熵测试
# ============================================================


class TestShannonEntropy:
    """测试 Shannon 熵计算"""

    def test_uniform_distribution(self):
        """均匀分布的熵应该最大"""
        dist = {"a": 4, "b": 4, "c": 4, "d": 4}
        entropy = calculate_shannon_entropy(dist)
        # log2(4) = 2.0
        assert entropy == pytest.approx(2.0, abs=0.001)

    def test_single_category(self):
        """单一类别的熵应该为 0"""
        dist = {"a": 10}
        entropy = calculate_shannon_entropy(dist)
        assert entropy == 0.0

    def test_empty_distribution(self):
        """空分布的熵应该为 0"""
        entropy = calculate_shannon_entropy({})
        assert entropy == 0.0

    def test_two_categories_equal(self):
        """两个等量类别的熵应该为 1.0"""
        dist = {"a": 5, "b": 5}
        entropy = calculate_shannon_entropy(dist)
        assert entropy == pytest.approx(1.0, abs=0.001)

    def test_two_categories_unequal(self):
        """不等量类别的熵应该在 0 和 1 之间"""
        dist = {"a": 9, "b": 1}
        entropy = calculate_shannon_entropy(dist)
        assert 0.0 < entropy < 1.0


class TestNormalizedEntropy:
    """测试归一化 Shannon 熵"""

    def test_uniform_distribution(self):
        """均匀分布的归一化熵应该为 1.0"""
        dist = {"a": 4, "b": 4, "c": 4, "d": 4}
        norm = calculate_normalized_entropy(dist)
        assert norm == pytest.approx(1.0, abs=0.001)

    def test_single_category(self):
        """单一类别的归一化熵应该为 0"""
        norm = calculate_normalized_entropy({"a": 10})
        assert norm == 0.0

    def test_empty_distribution(self):
        """空分布的归一化熵应该为 0"""
        norm = calculate_normalized_entropy({})
        assert norm == 0.0

    def test_range_0_to_1(self):
        """归一化熵应该在 0 到 1 之间"""
        dist = {"a": 7, "b": 2, "c": 1}
        norm = calculate_normalized_entropy(dist)
        assert 0.0 <= norm <= 1.0


# ============================================================
# 覆盖率与集中度测试
# ============================================================


class TestCoverageAndConcentration:
    """测试覆盖率和集中度计算"""

    def test_coverage_full(self):
        """全覆盖"""
        ratio = calculate_coverage_ratio(10, 10)
        assert ratio == 1.0

    def test_coverage_half(self):
        """半覆盖"""
        ratio = calculate_coverage_ratio(5, 10)
        assert ratio == 0.5

    def test_coverage_zero(self):
        """零覆盖"""
        ratio = calculate_coverage_ratio(0, 10)
        assert ratio == 0.0

    def test_coverage_over_100(self):
        """覆盖率不超过 1.0"""
        ratio = calculate_coverage_ratio(15, 10)
        assert ratio == 1.0

    def test_coverage_zero_total(self):
        """总可用为 0"""
        ratio = calculate_coverage_ratio(5, 0)
        assert ratio == 0.0

    def test_concentration_single(self):
        """单一类别集中度为 1.0"""
        dist = {"a": 10}
        ratio = calculate_concentration_ratio(dist)
        assert ratio == 1.0

    def test_concentration_uniform(self):
        """均匀分布集中度较低"""
        dist = {"a": 5, "b": 5}
        ratio = calculate_concentration_ratio(dist)
        assert ratio == 0.5

    def test_concentration_empty(self):
        """空分布集中度为 0"""
        ratio = calculate_concentration_ratio({})
        assert ratio == 0.0


# ============================================================
# 技术分布拆分测试
# ============================================================


class TestSplitDistribution:
    """测试成功/失败技术分布拆分"""

    def test_split_mixed_results(self):
        """测试混合成功/失败结果的拆分"""
        results = [
            _make_attack_result("prompt_sending", "success"),
            _make_attack_result("prompt_sending", "failure"),
            _make_attack_result("crescendo", "success"),
            _make_attack_result("red_teaming", "failure"),
        ]

        success_dist, failure_dist = split_technique_distribution_by_outcome(results)

        assert success_dist.get("prompt_sending") == 1
        assert success_dist.get("crescendo") == 1
        assert failure_dist.get("prompt_sending") == 1
        assert failure_dist.get("red_teaming") == 1

    def test_split_all_success(self):
        """测试全部成功"""
        results = [
            _make_attack_result("prompt_sending", "success"),
            _make_attack_result("crescendo", "success"),
        ]

        success_dist, failure_dist = split_technique_distribution_by_outcome(results)

        assert len(success_dist) == 2
        assert len(failure_dist) == 0

    def test_split_empty(self):
        """测试空列表"""
        success_dist, failure_dist = split_technique_distribution_by_outcome([])
        assert success_dist == {}
        assert failure_dist == {}


# ============================================================
# OWASP 覆盖广度测试
# ============================================================


class TestOwaspCoverage:
    """测试 OWASP 覆盖广度计算"""

    def test_full_coverage(self):
        """全覆盖"""
        all_ids = [f"LLM{i:02d}" for i in range(1, 11)] + [f"ASI{i:02d}" for i in range(1, 11)]
        matrix = _make_coverage_matrix(all_ids)
        covered, total, ratio = calculate_owasp_coverage_breadth(matrix)
        assert covered == 20
        assert ratio == 1.0

    def test_partial_coverage(self):
        """部分覆盖"""
        matrix = _make_coverage_matrix(["LLM01", "LLM02", "ASI01"])
        covered, total, ratio = calculate_owasp_coverage_breadth(matrix)
        assert covered == 3
        assert 0.0 < ratio < 1.0

    def test_no_coverage(self):
        """无覆盖"""
        matrix = _make_coverage_matrix([])
        covered, total, ratio = calculate_owasp_coverage_breadth(matrix)
        assert covered == 0
        assert ratio == 0.0

    def test_empty_matrix(self):
        """空矩阵"""
        covered, total, ratio = calculate_owasp_coverage_breadth({})
        assert covered == 0
        assert ratio == 0.0


# ============================================================
# DiversityAnalyzer 完整测试
# ============================================================


class TestDiversityAnalyzer:
    """测试 DiversityAnalyzer 完整分析流程"""

    @pytest.fixture
    def analyzer(self):
        return DiversityAnalyzer()

    def test_full_analysis(self, analyzer):
        """测试完整多样性分析"""
        attack_results = [
            _make_attack_result("prompt_sending", "success"),
            _make_attack_result("crescendo", "success"),
            _make_attack_result("red_teaming", "failure"),
            _make_attack_result("prompt_sending", "failure"),
        ]
        technique_dist = {"prompt_sending": 2, "crescendo": 1, "red_teaming": 1}
        converter_usage = {"stealth_evasion": 1, "encoding_bypass": 1}
        failure_reasons = {"model_refusal": 1, "timeout": 1}
        coverage_matrix = _make_coverage_matrix(["LLM01", "ASI01"])

        result = analyzer.analyze(
            attack_results=attack_results,
            technique_distribution=technique_dist,
            converter_usage=converter_usage,
            failure_reasons=failure_reasons,
            coverage_matrix=coverage_matrix,
            total_attacks=4,
        )

        assert isinstance(result, DiversityAnalysisResult)
        assert result.technique_entropy > 0
        assert 0.0 <= result.technique_normalized_entropy <= 1.0
        assert result.unique_techniques_used == 3
        assert result.unique_converters_used == 2
        assert result.owasp_covered_count == 2
        assert result.failure_concentration == 0.5  # 2 reasons, each 1 → max is 1/2 = 0.5
        assert "prompt_sending" in result.success_technique_distribution
        assert "prompt_sending" in result.failure_technique_distribution

    def test_analysis_empty_inputs(self, analyzer):
        """测试空输入"""
        result = analyzer.analyze(
            attack_results=[],
            technique_distribution={},
            converter_usage={},
            failure_reasons={},
            coverage_matrix=None,
            total_attacks=0,
        )

        assert result.technique_entropy == 0.0
        assert result.unique_techniques_used == 0
        assert result.owasp_covered_count == 0
        assert result.failure_concentration == 0.0
        assert result.top_failure_reason == ""

    def test_analysis_single_technique(self, analyzer):
        """测试单一技术（低多样性）"""
        result = analyzer.analyze(
            attack_results=[_make_attack_result("prompt_sending", "success")],
            technique_distribution={"prompt_sending": 1},
            converter_usage={},
            failure_reasons={},
            coverage_matrix=None,
            total_attacks=1,
        )

        assert result.technique_entropy == 0.0
        assert result.technique_normalized_entropy == 0.0
        assert result.unique_techniques_used == 1

    def test_to_dict(self, analyzer):
        """测试 to_dict 序列化"""
        result = analyzer.analyze(
            attack_results=[_make_attack_result("prompt_sending", "success")],
            technique_distribution={"prompt_sending": 1},
            converter_usage={},
            failure_reasons={},
            coverage_matrix=None,
            total_attacks=1,
        )

        d = result.to_dict()
        assert isinstance(d, dict)
        assert "technique_entropy" in d
        assert "technique_normalized_entropy" in d
        assert "unique_techniques_used" in d
        assert "owasp_coverage_ratio" in d
        assert "failure_concentration" in d

    def test_get_diversity_grade(self, analyzer):
        """测试多样性等级"""
        # Excellent (>= 0.8)
        result = analyzer.analyze(
            attack_results=[],
            technique_distribution={"a": 4, "b": 4, "c": 4, "d": 4, "e": 4},
            converter_usage={},
            failure_reasons={},
            total_attacks=0,
        )
        assert result.get_diversity_grade() == "Excellent"

        # Poor (< 0.2)
        result = analyzer.analyze(
            attack_results=[],
            technique_distribution={"a": 1},
            converter_usage={},
            failure_reasons={},
            total_attacks=0,
        )
        assert result.get_diversity_grade() == "Poor"


# ============================================================
# 报告渲染测试
# ============================================================


class TestRenderDiversitySection:
    """测试多样性分析章节渲染"""

    def test_render_full_result(self):
        """测试完整结果的渲染"""
        result = DiversityAnalysisResult(
            technique_entropy=1.5,
            technique_normalized_entropy=0.75,
            technique_coverage_ratio=0.5,
            unique_techniques_used=6,
            owasp_covered_count=5,
            owasp_total_count=20,
            owasp_coverage_ratio=0.25,
            converter_diversity_ratio=0.3,
            unique_converters_used=2,
            failure_concentration=0.6,
            top_failure_reason="model_refusal",
            success_technique_distribution={"prompt_sending": 2, "crescendo": 1},
            failure_technique_distribution={"red_teaming": 1},
        )

        markdown = render_diversity_section(result)

        assert "### Diversity & Coverage Analysis" in markdown
        assert "Technique Entropy" in markdown
        assert "1.50 bits" in markdown
        assert "Normalized Entropy" in markdown
        assert "Diversity Grade" in markdown
        assert "Good" in markdown  # 0.75 → Good
        assert "OWASP Coverage" in markdown
        assert "Successful Attack Techniques" in markdown
        assert "Failed Attack Techniques" in markdown
        assert "Failure Mode Analysis" in markdown
        assert "model_refusal" in markdown

    def test_render_empty_result(self):
        """测试空结果的渲染"""
        result = DiversityAnalysisResult()

        markdown = render_diversity_section(result)

        assert "### Diversity & Coverage Analysis" in markdown
        assert "Technique Entropy" in markdown
        # 空结果不应包含成功/失败技术分布
        assert "Successful Attack Techniques" not in markdown
        assert "Failed Attack Techniques" not in markdown

    def test_render_high_concentration_warning(self):
        """测试高集中度警告"""
        result = DiversityAnalysisResult(
            failure_concentration=0.8,
            top_failure_reason="timeout",
        )

        markdown = render_diversity_section(result)

        assert "Warning" in markdown
        assert "systematic issue" in markdown

    def test_render_no_concentration_warning(self):
        """测试低集中度无警告"""
        result = DiversityAnalysisResult(
            failure_concentration=0.3,
            top_failure_reason="timeout",
        )

        markdown = render_diversity_section(result)

        assert "Warning" not in markdown
