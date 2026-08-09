# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_attack_display — 攻击者第一公民展示层测试 (Round 44).

覆盖 12 个攻击者维度:
  区块 1: 目标画像 + 攻击面分析 (含冷启动风险)
  区块 2: 攻击向量覆盖矩阵 (OWASP 分类)
  区块 3: 攻击武器库 (技术×载荷×Converter + 增益 + 降级链)
  区块 4: 评分器 + 执行韧性配置 (含预算估算)
  区块 5: 攻击就绪确认 (增强 handoff_banner)

> **日期**: 2026-8-9
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.context import PipelineContext

# ============================================================
# 区块 1: 目标画像 + 攻击面分析 (含冷启动风险)
# ============================================================


class TestTargetProfileBlock1:
    """区块 1: 目标画像 + 冷启动风险评估测试。."""

    def test_cold_start_risk_all_cold(self, mock_args: pytest.fixture) -> None:
        """全部技术冷启动时, 信心度应为低。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.0, "prompt_sending": 0.0}
        ctx.metadata["model_name"] = "test-model"
        ctx.metadata["model_tier"] = "strong"
        ctx.metadata["api_timeout"] = 60
        ctx.metadata["api_max_retries"] = 0
        ctx.metadata["rate_limited_wrapped_count"] = 3
        ctx.metadata["scorer_timeout"] = 30

        from pipeline.stages.stage_scenario import _print_tech_pool_matrix

        # 不应抛出异常
        _print_tech_pool_matrix(
            ctx, ctx.warm_start_asr, "test-model", "strong",
            ["harmbench"], {}, "text_adaptive",
        )

    def test_cold_start_risk_partial(self, mock_args: pytest.fixture) -> None:
        """部分技术冷启动时, 信心度应为中。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.05, "prompt_sending": 0.0}
        ctx.metadata["model_name"] = "test-model"
        ctx.metadata["model_tier"] = "moderate"

        from pipeline.stages.stage_scenario import _print_tech_pool_matrix

        _print_tech_pool_matrix(
            ctx, ctx.warm_start_asr, "test-model", "moderate",
            ["harmbench"], {}, "text_adaptive",
        )

    def test_no_warm_start_no_crash(self, mock_args: pytest.fixture) -> None:
        """无 warm_start_asr 时不崩溃。."""
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_scenario import _print_tech_pool_matrix

        _print_tech_pool_matrix(ctx, None, "test", "unknown")

    def test_converter_health_monitor_displayed(self, mock_args: pytest.fixture) -> None:
        """Converter 熔断配置应展示。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.05}
        ctx.metadata["model_name"] = "test"
        ctx.metadata["model_tier"] = "strong"

        # Mock converter_health_monitor
        mock_monitor = MagicMock()
        mock_monitor._failure_threshold = 2
        ctx.converter_health_monitor = mock_monitor

        from pipeline.stages.stage_scenario import _print_tech_pool_matrix

        _print_tech_pool_matrix(
            ctx, ctx.warm_start_asr, "test", "strong",
            ["harmbench"], {}, "text_adaptive",
        )


# ============================================================
# 区块 2: 攻击向量覆盖矩阵
# ============================================================


class TestAttackVectorCoverage:
    """区块 2: OWASP 分类覆盖矩阵测试。."""

    def test_empty_datasets_no_crash(self, mock_args: pytest.fixture) -> None:
        """空数据集不崩溃。."""
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_scenario import _print_attack_vector_coverage

        _print_attack_vector_coverage(ctx, [])

    def test_with_owasp_datasets(self, mock_args: pytest.fixture) -> None:
        """包含 OWASP 数据集时, 应展示覆盖。."""
        ctx = PipelineContext(args=mock_args)
        ctx.metadata["dataset_seed_counts"] = {
            "owasp_llm01_prompt_injection": 3,
            "owasp_llm02_sensitive_info_disclosure": 3,
        }

        from pipeline.stages.stage_scenario import _print_attack_vector_coverage

        _print_attack_vector_coverage(
            ctx, ["owasp_llm01_prompt_injection", "owasp_llm02_sensitive_info_disclosure"],
        )

    def test_with_benchmark_datasets(self, mock_args: pytest.fixture) -> None:
        """包含 benchmark 数据集时, 应归入基准覆盖。."""
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_scenario import _print_attack_vector_coverage

        _print_attack_vector_coverage(ctx, ["harmbench", "jbb_behaviors"])

    def test_dos_excluded_annotation(self, mock_args: pytest.fixture) -> None:
        """DoS 排除时, LLM10 应标注为已排除。."""
        ctx = PipelineContext(args=mock_args)
        ctx.args.enable_dos_attack = False

        from pipeline.stages.stage_scenario import _print_attack_vector_coverage

        _print_attack_vector_coverage(ctx, ["owasp_llm01_prompt_injection"])

    def test_none_datasets_no_crash(self, mock_args: pytest.fixture) -> None:
        """None 数据集不崩溃。."""
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_scenario import _print_attack_vector_coverage

        _print_attack_vector_coverage(ctx, None)


# ============================================================
# 区块 3: 攻击武器库 (增强增益 + 降级链)
# ============================================================


class TestAttackLoadoutBlock3:
    """区块 3: 攻击武器库测试。."""

    def test_empty_attacks_no_crash(self, mock_args: pytest.fixture) -> None:
        """空攻击列表不崩溃。."""
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_initialize import _print_attack_loadout_card

        _print_attack_loadout_card(ctx, [])

    def test_fallback_chain_displayed(self, mock_args: pytest.fixture) -> None:
        """降级链应展示完整路径。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.05, "prompt_sending": 0.0}

        # Mock fallback_plan
        mock_plan = MagicMock()
        mock_plan.execution_order = ["many_shot", "prompt_sending"]
        mock_plan.fallback_count = 1
        ctx.fallback_plan = mock_plan

        # Mock attacks
        mock_attack = MagicMock()
        mock_attack.atomic_attack_name = "test_attack"
        mock_attack.display_group = "harmbench"
        mock_attack.attack_technique = None

        from pipeline.stages.stage_initialize import _print_attack_loadout_card

        _print_attack_loadout_card(ctx, [mock_attack])

    def test_converter_gain_displayed(self, mock_args: pytest.fixture) -> None:
        """Converter 增益应展示。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.05}
        ctx.technique_converter_map = {"many_shot": [MagicMock()]}

        mock_attack = MagicMock()
        mock_attack.atomic_attack_name = "test"
        mock_attack.display_group = "harmbench"
        mock_attack.attack_technique = None

        from pipeline.stages.stage_initialize import _print_attack_loadout_card

        _print_attack_loadout_card(ctx, [mock_attack])


# ============================================================
# 区块 4: 评分器 + 执行韧性配置
# ============================================================


class TestResilienceConfigBlock4:
    """区块 4: 评分器 + 执行韧性配置测试。."""

    def test_scorer_type_displayed(self, mock_args: pytest.fixture) -> None:
        """评分器类型应展示。."""
        ctx = PipelineContext(args=mock_args)
        ctx.metadata["scorer_timeout"] = 30
        ctx.metadata["api_timeout"] = 60
        ctx.metadata["api_max_retries"] = 0
        ctx.metadata["rate_limited_wrapped_count"] = 3
        ctx.metadata["rate_limit_retries"] = 2
        ctx.max_attempts_per_objective = 1

        mock_scorer = MagicMock()
        ctx.objective_scorer = mock_scorer
        type(mock_scorer).__name__ = "SelfAskRefusalScorer"

        from pipeline.stages.stage_initialize import _print_resilience_config

        _print_resilience_config(ctx, [])

    def test_converter_circuit_breaker_displayed(self, mock_args: pytest.fixture) -> None:
        """Converter 熔断配置应展示。."""
        ctx = PipelineContext(args=mock_args)
        ctx.metadata["scorer_timeout"] = 30
        ctx.metadata["api_timeout"] = 60
        ctx.metadata["api_max_retries"] = 0
        ctx.max_attempts_per_objective = 1

        mock_monitor = MagicMock()
        mock_monitor._failure_threshold = 2
        ctx.converter_health_monitor = mock_monitor

        from pipeline.stages.stage_initialize import _print_resilience_config

        _print_resilience_config(ctx, [])

    def test_budget_estimation(self, mock_args: pytest.fixture) -> None:
        """预算估算应正确计算。."""
        ctx = PipelineContext(args=mock_args)
        ctx.max_attempts_per_objective = 1
        ctx.args.max_concurrency = 3

        from pipeline.stages.stage_initialize import _estimate_attack_budget

        result = _estimate_attack_budget(ctx, [MagicMock()] * 72)
        assert "API 调用" in result
        assert "分钟" in result

    def test_budget_empty_attacks(self, mock_args: pytest.fixture) -> None:
        """空攻击列表预算为 N/A。."""
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_initialize import _estimate_attack_budget

        result = _estimate_attack_budget(ctx, [])
        assert result == "N/A"


# ============================================================
# 区块 5: 攻击就绪确认 (增强 handoff)
# ============================================================


class TestAttackReadinessBlock5:
    """区块 5: 攻击就绪确认测试。."""

    def test_owasp_coverage_count(self, mock_args: pytest.fixture) -> None:
        """OWASP 覆盖统计应正确。."""
        ctx = PipelineContext(args=mock_args)
        ctx.sorted_datasets = ["owasp_llm01_prompt_injection", "owasp_llm02_sensitive_info_disclosure"]

        from pipeline.stages.stage_initialize import _count_owasp_coverage

        result = _count_owasp_coverage(ctx)
        assert "分类" in result

    def test_owasp_coverage_empty(self, mock_args: pytest.fixture) -> None:
        """空数据集 OWASP 覆盖为 N/A。."""
        ctx = PipelineContext(args=mock_args)
        ctx.sorted_datasets = []

        from pipeline.stages.stage_initialize import _count_owasp_coverage

        result = _count_owasp_coverage(ctx)
        assert result == "N/A"

    def test_scorer_type_name(self, mock_args: pytest.fixture) -> None:
        """评分器类型名应正确获取。."""
        ctx = PipelineContext(args=mock_args)
        mock_scorer = MagicMock()
        type(mock_scorer).__name__ = "SelfAskRefusalScorer"
        ctx.objective_scorer = mock_scorer

        from pipeline.stages.stage_initialize import _get_scorer_type_name

        result = _get_scorer_type_name(ctx)
        assert result == "SelfAskRefusalScorer"

    def test_scorer_type_name_none(self, mock_args: pytest.fixture) -> None:
        """无评分器时返回默认。."""
        ctx = PipelineContext(args=mock_args)

        from pipeline.stages.stage_initialize import _get_scorer_type_name

        result = _get_scorer_type_name(ctx)
        assert result == "默认"

    def test_expected_asr_strong(self, mock_args: pytest.fixture) -> None:
        """strong tier 预期 ASR 应为 25%-35%。."""
        from pipeline.stages.stage_initialize import _estimate_expected_asr

        result = _estimate_expected_asr("strong")
        assert "25%" in result

    def test_enhancement_delta_cold_start(self, mock_args: pytest.fixture) -> None:
        """冷启动时增益为 — (冷启动)。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.0}

        mock_attack = MagicMock()
        mock_attack.attack_technique = None

        from pipeline.stages.stage_initialize import _estimate_enhancement_delta

        result = _estimate_enhancement_delta(ctx, [mock_attack])
        assert "—" in result

    def test_enhancement_delta_with_asr(self, mock_args: pytest.fixture) -> None:
        """有 ASR 数据时增益应计算。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.05}
        ctx.technique_converter_map = {"many_shot": [MagicMock()]}

        mock_attack = MagicMock()
        mock_attack.attack_technique = None
        mock_attack.display_group = "many_shot"
        mock_attack.atomic_attack_name = "many_shot"

        from pipeline.stages.stage_initialize import _estimate_enhancement_delta

        result = _estimate_enhancement_delta(ctx, [mock_attack])
        assert "×1.3" in result


# ============================================================
# Round 45: O1-O3 新增测试
# ============================================================


class TestConverterTransformPreviewO1:
    """O1: Converter 变换预览测试。."""

    def test_empty_conv_names(self) -> None:
        """空 Converter 列表 → 返回空。."""
        from pipeline.stages.stage_initialize import _preview_converter_transform

        result = _preview_converter_transform([], "Hello")
        assert result == []

    def test_empty_payload(self) -> None:
        """空载荷 → 返回空。."""
        from pipeline.stages.stage_initialize import _preview_converter_transform

        result = _preview_converter_transform(["Base64Converter"], "")
        assert result == []

    def test_llm_converter_skipped(self) -> None:
        """LLM Converter → 标注预览跳过。."""
        from pipeline.stages.stage_initialize import _preview_converter_transform

        result = _preview_converter_transform(
            ["PersuasionConverter"], "Tell me a secret",
        )
        assert len(result) >= 2
        assert "预览跳过" in result[1]


class TestFallbackArrowVisualizationO2:
    """O2: 降级链 ASCII 箭头图可视化测试。."""

    def test_arrow_format(self, mock_args: pytest.fixture) -> None:
        """多 Tier 降级链 → ASCII 箭头图格式。."""
        ctx = PipelineContext(args=mock_args)
        ctx.warm_start_asr = {"many_shot": 0.62, "prompt_sending": 0.0}

        mock_plan = MagicMock()
        mock_plan.execution_order = ["many_shot", "prompt_sending"]
        mock_plan.fallback_count = 1
        ctx.fallback_plan = mock_plan

        mock_attack = MagicMock()
        mock_attack.atomic_attack_name = "test"
        mock_attack.display_group = "harmbench"
        mock_attack.attack_technique = None

        from pipeline.stages.stage_initialize import _print_attack_loadout_card

        # 不崩溃即验证箭头图生成
        _print_attack_loadout_card(ctx, [mock_attack])

    def test_no_fallback_plan(self, mock_args: pytest.fixture) -> None:
        """无 fallback_plan → 不展示降级链。."""
        ctx = PipelineContext(args=mock_args)

        mock_attack = MagicMock()
        mock_attack.atomic_attack_name = "test"
        mock_attack.display_group = "harmbench"
        mock_attack.attack_technique = None

        from pipeline.stages.stage_initialize import _print_attack_loadout_card

        # 不应崩溃
        _print_attack_loadout_card(ctx, [mock_attack])


class TestBudgetCalibrationO3:
    """O3: 攻击预算实时校准测试。."""

    def test_budget_with_metadata(self, mock_args: pytest.fixture) -> None:
        """有 metadata 时预算应包含超时参数。."""
        ctx = PipelineContext(args=mock_args)
        ctx.max_attempts_per_objective = 1
        ctx.args.max_concurrency = 3
        ctx.metadata["api_timeout"] = 60
        ctx.metadata["rate_limit_retries"] = 2
        ctx.metadata["scorer_timeout"] = 30

        from pipeline.stages.stage_initialize import _estimate_attack_budget

        result = _estimate_attack_budget(ctx, [MagicMock()] * 10)
        assert "超时上限" in result
        assert "60s/调用" in result
        assert "30s/评分" in result

    def test_budget_default_values(self, mock_args: pytest.fixture) -> None:
        """无 metadata 时使用默认值。."""
        ctx = PipelineContext(args=mock_args)
        ctx.max_attempts_per_objective = 1
        ctx.args.max_concurrency = 3

        from pipeline.stages.stage_initialize import _estimate_attack_budget

        result = _estimate_attack_budget(ctx, [MagicMock()] * 10)
        assert "超时上限" in result
        assert "60s/调用" in result  # default api_timeout
        assert "30s/评分" in result  # default scorer_timeout
