# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_stage_post_analysis_evolution — Stage 5 技术池演化追溯单元测试。

覆盖:
  - _print_tech_pool_evolution: Stage 2→4→5 技术池演化 (匹配/未执行/额外)
  - 修复: Stage 4 技术名从 AttackResult 提取 (非 display_group 数据集名)

> **日期**: 2026-8-8
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.context import PipelineContext
from pipeline.stages.stage_post_analysis import _print_tech_pool_evolution

# ──────────────────────────────────────────────────────────────────
#  辅助函数
# ──────────────────────────────────────────────────────────────────


def _make_attack_result(technique_name: str) -> MagicMock:
    """构建 mock AttackResult, extract_technique_name 返回指定技术名。.

    AttackResultAnalyzer.extract_technique_name() 调用路径:
        ar.get_attack_strategy_identifier() → ComponentIdentifier
        identifier.name → 技术名
    """
    identifier = MagicMock()
    identifier.name = technique_name
    identifier.class_name = None

    ar = MagicMock()
    ar.get_attack_strategy_identifier.return_value = identifier
    return ar


def _make_result(attack_results_by_group: dict[str, list]) -> MagicMock:
    """构建 mock ScenarioResult, get_display_groups 返回指定分组。."""
    result = MagicMock()
    result.get_display_groups.return_value = attack_results_by_group
    return result


# ──────────────────────────────────────────────────────────────────
#  _print_tech_pool_evolution
# ──────────────────────────────────────────────────────────────────


class TestPrintTechPoolEvolution:
    """_print_tech_pool_evolution: 技术池演化追溯。."""

    def test_matched_techniques(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Stage 2 技术与 Stage 4 技术有交集 → 显示匹配数。."""
        ctx = PipelineContext()
        ctx.warm_start_asr = {"many_shot": 0.5, "crescendo": 0.3}
        ctx.asr_per_technique = {"many_shot": 60.0}

        ar1 = _make_attack_result("many_shot")
        ar2 = _make_attack_result("crescendo")
        result = _make_result({"ds1": [ar1, ar2]})
        ctx.result = result

        _print_tech_pool_evolution(ctx)

        captured = capsys.readouterr()
        assert "技术池演化" in captured.out
        assert "2" in captured.out  # Stage 2: 2 techniques
        assert "技术匹配" in captured.out

    def test_unmatched_techniques(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Stage 2 技术与 Stage 4 技术无交集 → 全部 unmatched。."""
        ctx = PipelineContext()
        ctx.warm_start_asr = {"tap": 0.6}
        ctx.asr_per_technique = {}

        ar = _make_attack_result("prompt_sending")
        result = _make_result({"ds1": [ar]})
        ctx.result = result

        _print_tech_pool_evolution(ctx)

        captured = capsys.readouterr()
        assert "未执行" in captured.out
        assert "tap" in captured.out

    def test_extra_techniques(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Stage 4 有 Stage 2 没有的技术 → 显示额外。."""
        ctx = PipelineContext()
        ctx.warm_start_asr = {"many_shot": 0.5}
        ctx.asr_per_technique = {"many_shot": 60.0}

        ar = _make_attack_result("crescendo")
        result = _make_result({"ds1": [ar]})
        ctx.result = result

        _print_tech_pool_evolution(ctx)

        captured = capsys.readouterr()
        assert "额外" in captured.out
        assert "crescendo" in captured.out

    def test_no_warm_start(self, capsys: pytest.CaptureFixture[str]) -> None:
        """无 warm_start_asr → Stage 2 为 0。."""
        ctx = PipelineContext()
        ctx.asr_per_technique = {"prompt_sending": 40.0}

        ar = _make_attack_result("prompt_sending")
        result = _make_result({"ds1": [ar]})
        ctx.result = result

        _print_tech_pool_evolution(ctx)

        captured = capsys.readouterr()
        assert "0" in captured.out  # Stage 2: 0 techniques

    def test_no_result(self, capsys: pytest.CaptureFixture[str]) -> None:
        """无执行结果 → Stage 4 为 0。."""
        ctx = PipelineContext()
        ctx.warm_start_asr = {"many_shot": 0.5}
        ctx.result = None

        _print_tech_pool_evolution(ctx)

        captured = capsys.readouterr()
        assert "技术池演化" in captured.out
        assert "0" in captured.out  # Stage 4: 0

    def test_evolution_insight(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Stage 2 和 Stage 5 都有数据 → 显示演化洞察。."""
        ctx = PipelineContext()
        ctx.warm_start_asr = {"many_shot": 0.5, "crescendo": 0.3}
        ctx.asr_per_technique = {"many_shot": 60.0, "crescendo": 30.0}

        ar1 = _make_attack_result("many_shot")
        ar2 = _make_attack_result("crescendo")
        result = _make_result({"ds1": [ar1, ar2]})
        ctx.result = result

        _print_tech_pool_evolution(ctx)

        captured = capsys.readouterr()
        assert "匹配率" in captured.out

    def test_unknown_technique_filtered(self, capsys: pytest.CaptureFixture[str]) -> None:
        """AttackResult 返回 'unknown' 技术名 → 不计入 stage4_techs。."""
        ctx = PipelineContext()
        ctx.warm_start_asr = {"many_shot": 0.5}
        ctx.asr_per_technique = {}

        ar = _make_attack_result("unknown")
        result = _make_result({"ds1": [ar]})
        ctx.result = result

        _print_tech_pool_evolution(ctx)

        captured = capsys.readouterr()
        # stage4_techs should be 0 (unknown filtered out)
        # Since stage4_techs is empty, the match analysis is skipped
        # Verify Stage 4 shows 0
        assert "Stage 4" in captured.out
        assert "0" in captured.out
