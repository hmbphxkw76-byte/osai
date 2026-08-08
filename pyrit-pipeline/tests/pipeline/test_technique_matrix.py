# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_technique_matrix — 技术有效性矩阵和辅助函数单元测试。

覆盖:
  - ReportGenerator._build_technique_effectiveness_matrix: 按技术名分组统计 ASR
  - is_known_technique: 技术名 vs 数据集名判别
  - ProgressPoller._get_latest_technique_name: 从最近 AttackResult 提取技术名

> **日期**: 2026-8-8
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

# ──────────────────────────────────────────────────────────────────
#  _build_technique_effectiveness_matrix
# ──────────────────────────────────────────────────────────────────


class TestBuildTechniqueEffectivenessMatrix:
    """ReportGenerator._build_technique_effectiveness_matrix: 技术有效性矩阵。."""

    def test_empty_results(self) -> None:
        """空结果 → 空矩阵。"""
        from pipeline.reporting.report_generator import ReportGenerator

        rg = ReportGenerator.__new__(ReportGenerator)
        result = rg._build_technique_effectiveness_matrix([])
        assert result == []

    def test_single_technique_all_success(self) -> None:
        """单技术全成功 → ASR=100%。"""
        from pyrit.models import AttackOutcome

        from pipeline.reporting.report_generator import ReportGenerator

        results = [MagicMock(outcome=AttackOutcome.SUCCESS) for _ in range(3)]
        rg = ReportGenerator.__new__(ReportGenerator)
        with (
            patch(
                "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
                return_value="many_shot",
            ),
        ):
            matrix = rg._build_technique_effectiveness_matrix(results)
        assert len(matrix) == 1
        assert matrix[0]["technique"] == "many_shot"
        assert matrix[0]["total"] == 3
        assert matrix[0]["success"] == 3
        assert matrix[0]["asr"] == 100.0

    def test_multiple_techniques_sorted_by_asr(self) -> None:
        """多技术 → 按 ASR 降序排列。"""
        from pyrit.models import AttackOutcome

        from pipeline.reporting.report_generator import ReportGenerator

        # many_shot: 3/4=75%, prompt_sending: 1/4=25%
        results = []
        tech_map = {
            "many_shot": [
                AttackOutcome.SUCCESS,
                AttackOutcome.SUCCESS,
                AttackOutcome.SUCCESS,
                AttackOutcome.FAILURE,
            ],
            "prompt_sending": [
                AttackOutcome.SUCCESS,
                AttackOutcome.FAILURE,
                AttackOutcome.FAILURE,
                AttackOutcome.FAILURE,
            ],
        }
        for tech, outcomes in tech_map.items():
            for outcome in outcomes:
                ar = MagicMock(outcome=outcome)
                results.append((tech, ar))

        rg = ReportGenerator.__new__(ReportGenerator)

        def mock_extract(ar: object) -> str:
            for tech, mock_ar in results:
                if mock_ar is ar:
                    return tech
            return "unknown"

        with patch(
            "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
            side_effect=mock_extract,
        ):
            ar_list = [ar for _, ar in results]
            matrix = rg._build_technique_effectiveness_matrix(ar_list)

        assert len(matrix) == 2
        assert matrix[0]["technique"] == "many_shot"
        assert matrix[0]["asr"] == 75.0
        assert matrix[1]["technique"] == "prompt_sending"
        assert matrix[1]["asr"] == 25.0

    def test_exception_returns_empty(self) -> None:
        """异常 → 返回空列表。"""
        from pipeline.reporting.report_generator import ReportGenerator

        rg = ReportGenerator.__new__(ReportGenerator)
        with patch(
            "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
            side_effect=RuntimeError("fail"),
        ):
            matrix = rg._build_technique_effectiveness_matrix([MagicMock()])
        assert matrix == []

    def test_unknown_technique_included(self) -> None:
        """unknown 技术也应包含在矩阵中。"""
        from pyrit.models import AttackOutcome

        from pipeline.reporting.report_generator import ReportGenerator

        results = [MagicMock(outcome=AttackOutcome.SUCCESS)]
        rg = ReportGenerator.__new__(ReportGenerator)
        with patch(
            "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
            return_value="unknown",
        ):
            matrix = rg._build_technique_effectiveness_matrix(results)
        assert len(matrix) == 1
        assert matrix[0]["technique"] == "unknown"


# ──────────────────────────────────────────────────────────────────
#  is_known_technique
# ──────────────────────────────────────────────────────────────────


class TestIsKnownTechnique:
    """is_known_technique: 技术名 vs 数据集名判别。."""

    def test_known_technique(self) -> None:
        """已知技术名 → True。"""
        from pipeline.analysis.technique_name_mapper import is_known_technique

        assert is_known_technique("many_shot") is True
        assert is_known_technique("prompt_sending") is True
        assert is_known_technique("crescendo") is True

    def test_dataset_name_rejected(self) -> None:
        """数据集名 → False。"""
        from pipeline.analysis.technique_name_mapper import is_known_technique

        assert is_known_technique("owasp_llm05") is False
        assert is_known_technique("harmbench") is False
        assert is_known_technique("darkbench") is False

    def test_empty_string(self) -> None:
        """空字符串 → False。"""
        from pipeline.analysis.technique_name_mapper import is_known_technique

        assert is_known_technique("") is False

    def test_unknown_string(self) -> None:
        """未知字符串 → False。"""
        from pipeline.analysis.technique_name_mapper import is_known_technique

        assert is_known_technique("random_nonexistent") is False


# ──────────────────────────────────────────────────────────────────
#  _get_latest_technique_name (ProgressPoller)
# ──────────────────────────────────────────────────────────────────


class TestGetLatestTechniqueName:
    """ProgressPoller._get_latest_technique_name: 从最近结果提取技术名。."""

    def test_with_results(self) -> None:
        """有 AttackResult → 返回技术名。"""
        from pipeline.reporting.output_manager import ProgressPoller

        poller = ProgressPoller.__new__(ProgressPoller)
        poller._dashboard = MagicMock()
        poller._dashboard.completed = 5
        poller._scenario_result_id = "test_srid"

        mock_mem = MagicMock()
        mock_results = [MagicMock()]
        mock_mem.get_scenario_results.return_value = mock_results

        with (
            patch("pyrit.memory.CentralMemory.get_memory_instance", return_value=mock_mem),
            patch(
                "pipeline.analysis.attack_result_analyzer.AttackResultAnalyzer.extract_technique_name",
                return_value="crescendo",
            ),
        ):
            result = poller._get_latest_technique_name()
        assert result == "crescendo"

    def test_no_results(self) -> None:
        """无 AttackResult → 返回 None。"""
        from pipeline.reporting.output_manager import ProgressPoller

        poller = ProgressPoller.__new__(ProgressPoller)
        poller._dashboard = MagicMock()
        poller._dashboard.completed = 0
        poller._scenario_result_id = "test_srid"

        result = poller._get_latest_technique_name()
        assert result == ""

    def test_exception_returns_none(self) -> None:
        """异常 → 返回 None。"""
        from pipeline.reporting.output_manager import ProgressPoller

        poller = ProgressPoller.__new__(ProgressPoller)
        poller._dashboard = MagicMock()
        poller._dashboard.completed = 5
        poller._scenario_result_id = None  # 无 srid → 早退

        result = poller._get_latest_technique_name()
        assert result == ""
