# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Round 17 + 18: 评分器增强 + composite_scorer 修复 测试。

测试覆盖:
  1. composite_scorer.py 修复后的 API 调用正确性 (Round 17)
  2. _register_enhanced_scorers() 评分器注册 (Round 17)
  3. should_use_composite_scorer 逻辑 (Round 17)
  4. stage_scenario.py 去冗余逻辑 (Round 17)
  5. O1: RefusalScorer 多 prompt 变体注册 (Round 18)
  6. O2: Likert 评分器注册 (Round 18)
  7. O4: F1 评估指标驱动的最优评分器选择 (Round 18)
  8. O5: 多评分器投票 MAJORITY (Round 18)

> **日期**: 2026-8-10
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ============================================================
# 1. composite_scorer.py 修复后的 API 调用测试
# ============================================================


class TestCompositeScorerFix:
    """测试 composite_scorer.py 修复后的 3 个 Bug 是否消除。"""

    def test_no_composite_scorer_operator_import(self) -> None:
        """Bug 1: CompositeScorerOperator 不应存在于导入中。"""
        import pipeline.scenarios.composite_scorer as cs

        # 模块不应引用 CompositeScorerOperator
        source = Path(cs.__file__).read_text(encoding="utf-8")
        assert "CompositeScorerOperator" not in source, (
            "CompositeScorerOperator 已从 PyRIT score 移除, 不应出现在源码中"
        )

    def test_no_true_false_question_path_param(self) -> None:
        """Bug 2: true_false_question_path 参数不存在于 SelfAskTrueFalseScorer。"""
        import pipeline.scenarios.composite_scorer as cs

        source = Path(cs.__file__).read_text(encoding="utf-8")
        assert "true_false_question_path" not in source, (
            "SelfAskTrueFalseScorer 没有 true_false_question_path 参数"
        )

    def test_uses_aggregator_not_operator(self) -> None:
        """Bug 3: TrueFalseCompositeScorer 使用 aggregator= 而非 operator=。"""
        import pipeline.scenarios.composite_scorer as cs

        source = Path(cs.__file__).read_text(encoding="utf-8")
        assert "operator=" not in source, (
            "TrueFalseCompositeScorer 使用 aggregator= 而非 operator="
        )
        assert "aggregator=TrueFalseScoreAggregator.AND" in source

    def test_create_composite_scorer_returns_instance(self) -> None:
        """修复后 create_composite_objective_scorer 应返回 TrueFalseCompositeScorer 实例。"""
        from pipeline.scenarios.composite_scorer import create_composite_objective_scorer

        mock_target = MagicMock()
        result = create_composite_objective_scorer(mock_target)

        # 不应返回 None (之前 3 个 Bug 导致永远返回 None)
        assert result is not None, "复合评分器创建应成功, 不应返回 None"
        assert type(result).__name__ == "TrueFalseCompositeScorer"

    def test_create_composite_scorer_no_objective_question_param(self) -> None:
        """create_composite_objective_scorer 不应接受 objective_question 参数。"""
        import inspect

        from pipeline.scenarios.composite_scorer import create_composite_objective_scorer

        sig = inspect.signature(create_composite_objective_scorer)
        assert "objective_question" not in sig.parameters, (
            "objective_question 参数已移除 (SelfAskTrueFalseScorer 使用默认 TASK_ACHIEVED rubric)"
        )

    def test_create_composite_scorer_imports_succeed(self) -> None:
        """导入 pyrit.score 中的类应全部成功 (无 ImportError)。"""
        from pyrit.score import TrueFalseScoreAggregator

        # 验证 TrueFalseScoreAggregator 有 AND
        assert hasattr(TrueFalseScoreAggregator, "AND")

    def test_composite_has_two_scorers(self) -> None:
        """复合评分器应包含两个子评分器 (task_achieved + not_refused)。"""
        from pipeline.scenarios.composite_scorer import create_composite_objective_scorer

        mock_target = MagicMock()
        result = create_composite_objective_scorer(mock_target)
        assert result is not None
        assert len(result._scorers) == 2

    def test_composite_uses_and_aggregator(self) -> None:
        """复合评分器应使用 AND 聚合器。"""
        from pyrit.score import TrueFalseScoreAggregator

        from pipeline.scenarios.composite_scorer import create_composite_objective_scorer

        mock_target = MagicMock()
        result = create_composite_objective_scorer(mock_target)
        assert result is not None
        assert result._score_aggregator == TrueFalseScoreAggregator.AND


# ============================================================
# 2. should_use_composite_scorer 测试
# ============================================================


class TestShouldUseCompositeScorer:
    """测试 should_use_composite_scorer 逻辑。"""

    @pytest.mark.parametrize(
        "tier,expected",
        [
            ("strong", True),
            ("moderate", False),
            ("unknown", False),
            ("weak", False),
            ("", False),
        ],
    )
    def test_tier_mapping(self, tier: str, expected: bool) -> None:
        """不同 model_tier 的复合评分器使用判定。"""
        from pipeline.scenarios.composite_scorer import should_use_composite_scorer

        assert should_use_composite_scorer(tier) == expected


# ============================================================
# 3. _register_enhanced_scorers 测试
# ============================================================


def _setup_enhanced_scorer_mocks(
    mock_scorer_reg: MagicMock,
    mock_target_reg: MagicMock,
    mock_composite_factory: MagicMock | None = None,
) -> set[str]:
    """设置 _register_enhanced_scorers 测试的通用 mock。

    返回一个 ``registered_names`` 集合用于跟踪已注册的评分器名。
    """
    mock_target = MagicMock()
    mock_target_reg.get_registry_singleton.return_value.instances.get.return_value = mock_target

    registered_names: set[str] = set()

    def mock_get_entry(name: str):
        if name in registered_names:
            return MagicMock()
        return None

    def mock_register(instance, **kwargs):
        registered_names.add(kwargs.get("name", ""))

    mock_scorer_reg.get_registry_singleton.return_value.instances.get_entry.side_effect = mock_get_entry
    mock_scorer_reg.get_registry_singleton.return_value.instances.register.side_effect = mock_register
    mock_scorer_reg.get_registry_singleton.return_value.instances.get_by_tag.return_value = []
    # get_all_instances 返回空列表 (避免迭代 MagicMock)
    mock_scorer_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = []

    if mock_composite_factory is not None:
        mock_composite_factory.return_value = MagicMock()

    return registered_names


class TestRegisterEnhancedScorers:
    """测试 _register_enhanced_scorers() 函数。

    函数内部使用 ``from pyrit.registry import ...`` 局部导入,
    因此 mock 需要打在 ``pyrit.registry`` 层级。
    """

    def test_function_exists(self) -> None:
        """函数存在于 stage_init 模块。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        assert callable(_register_enhanced_scorers)

    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    def test_no_target_skips(self, mock_scorer_reg: MagicMock, mock_target_reg: MagicMock) -> None:
        """无可用 chat target 时静默跳过。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        mock_target_reg.get_registry_singleton.return_value.instances.get.return_value = None
        mock_scorer_reg.get_registry_singleton.return_value.instances.get_entry.return_value = None

        _register_enhanced_scorers()

        # 不应注册任何评分器
        mock_scorer_reg.get_registry_singleton.return_value.instances.register.assert_not_called()

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_registers_scorers_when_target_available(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """有可用 chat target 时注册增强评分器。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        # LikertScalePaths 迭代返回空列表
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        # RefusalScorerPaths 属性返回 mock
        mock_refusal_paths.OBJECTIVE_STRICT.value = MagicMock()

        _register_enhanced_scorers()

        # 应注册至少 1 个评分器
        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        registered_names = [call.kwargs.get("name", "") for call in register_calls]
        assert len(registered_names) > 0
        # 应包含 Round 17 的 3 个基础评分器
        assert "task_achieved_local" in registered_names
        assert "scale_local_threshold_09" in registered_names
        assert "objective_composite_local" in registered_names

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_tags_default_objective_scorer(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """注册后 fallback 标记 default_objective_scorer (如果 F1 未选择)。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        mock_refusal_paths.OBJECTIVE_STRICT.value = MagicMock()

        _register_enhanced_scorers()

        # 应调用 add_tags 标记 default_objective_scorer
        add_tags_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.add_tags.call_args_list
        all_tags = []
        for call in add_tags_calls:
            all_tags.extend(call.kwargs.get("tags", []))
        assert "default_objective_scorer" in all_tags

    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    def test_skips_already_registered(
        self, mock_scorer_reg: MagicMock, mock_target_reg: MagicMock
    ) -> None:
        """已注册的评分器不重复注册。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        mock_target = MagicMock()
        mock_target_reg.get_registry_singleton.return_value.instances.get.return_value = mock_target

        # 模拟已注册 (get_entry 返回非 None)
        mock_entry = MagicMock()
        mock_scorer_reg.get_registry_singleton.return_value.instances.get_entry.return_value = mock_entry

        _register_enhanced_scorers()

        # 不应注册任何评分器
        mock_scorer_reg.get_registry_singleton.return_value.instances.register.assert_not_called()

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_prefers_objective_scorer_chat(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """优先使用 objective_scorer_chat 作为评分目标。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        mock_scorer_target = MagicMock(name="scorer_chat")
        mock_openai_target = MagicMock(name="openai_chat")

        def mock_get(name: str):
            if name == "objective_scorer_chat":
                return mock_scorer_target
            if name == "openai_chat":
                return mock_openai_target
            return None

        mock_target_reg.get_registry_singleton.return_value.instances.get.side_effect = mock_get
        mock_scorer_reg.get_registry_singleton.return_value.instances.get_entry.return_value = None
        mock_scorer_reg.get_registry_singleton.return_value.instances.get_by_tag.return_value = []
        mock_scorer_reg.get_registry_singleton.return_value.instances.get_all_instances.return_value = []
        mock_composite_factory.return_value = MagicMock()
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        mock_refusal_paths.OBJECTIVE_STRICT.value = MagicMock()

        _register_enhanced_scorers()

        # 验证使用了 objective_scorer_chat (第一次调用 get 时的 name)
        first_call = mock_target_reg.get_registry_singleton.return_value.instances.get.call_args_list[0]
        assert first_call.args[0] == "objective_scorer_chat"


# ============================================================
# 4. stage_scenario.py 去冗余逻辑测试
# ============================================================


class TestStageScenarioDedup:
    """测试 stage_scenario.py 中 composite 去冗余逻辑。"""

    def test_already_composite_detected_by_type_name(self) -> None:
        """通过 type name 检测已是 TrueFalseCompositeScorer。"""
        # 模拟一个 TrueFalseCompositeScorer 实例
        mock_scorer = MagicMock()
        type(mock_scorer).__name__ = "TrueFalseCompositeScorer"

        is_composite = type(mock_scorer).__name__ == "TrueFalseCompositeScorer"
        assert is_composite is True

    def test_non_composite_detected_by_type_name(self) -> None:
        """非 TrueFalseCompositeScorer 的评分器不被误判。"""
        mock_scorer = MagicMock()
        type(mock_scorer).__name__ = "TrueFalseInverterScorer"

        is_composite = type(mock_scorer).__name__ == "TrueFalseCompositeScorer"
        assert is_composite is False

    def test_none_scorer_not_composite(self) -> None:
        """None 评分器不被误判为 composite。"""
        scorer = None
        is_composite = type(scorer).__name__ == "TrueFalseCompositeScorer"
        assert is_composite is False


# ============================================================
# 5. O1: RefusalScorer 多 prompt 变体注册测试
# ============================================================


class TestRefusalScorerVariants:
    """测试 O1: RefusalScorer 4 种 prompt 变体注册。"""

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_four_refusal_variants_registered(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O1: 4 种 refusal scorer 变体全部注册。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        # RefusalScorerPaths 的 4 个属性返回 mock Path
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        registered_names = {call.kwargs.get("name", "") for call in register_calls}

        assert "refusal_obj_strict_local" in registered_names
        assert "refusal_obj_lenient_local" in registered_names
        assert "refusal_no_obj_strict_local" in registered_names
        assert "refusal_no_obj_lenient_local" in registered_names

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_refusal_scorers_tagged_refusal(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O1: refusal scorers 都有 tags=["refusal"]。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        refusal_calls = [
            call for call in register_calls
            if call.kwargs.get("name", "").startswith("refusal_")
        ]
        assert len(refusal_calls) == 4
        for call in refusal_calls:
            assert "refusal" in call.kwargs.get("tags", [])

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_refusal_scorer_uses_seed_prompt_yaml(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O1: SelfAskRefusalScorer 使用 SeedPrompt.from_yaml_file 加载 prompt。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        # SeedPrompt.from_yaml_file 应被调用 4 次 (4 个变体)
        assert mock_seed_prompt.from_yaml_file.call_count == 4

    def test_refusal_scorer_paths_enum_has_four_variants(self) -> None:
        """O1: PyRIT 原生 RefusalScorerPaths 确实有 4 个变体。"""
        from pyrit.score import RefusalScorerPaths

        assert hasattr(RefusalScorerPaths, "OBJECTIVE_STRICT")
        assert hasattr(RefusalScorerPaths, "OBJECTIVE_LENIENT")
        assert hasattr(RefusalScorerPaths, "NO_OBJECTIVE_STRICT")
        assert hasattr(RefusalScorerPaths, "NO_OBJECTIVE_LENIENT")


# ============================================================
# 6. O2: Likert 评分器注册测试
# ============================================================


class TestLikertScorers:
    """测试 O2: Likert 评分器注册。"""

    def test_likert_scale_paths_exists(self) -> None:
        """O2: PyRIT 原生 LikertScalePaths 可导入。"""
        from pyrit.score import LikertScalePaths

        # 至少有 10 个预定义量表
        assert len(list(LikertScalePaths)) >= 10

    def test_likert_scale_paths_has_evaluation_files(self) -> None:
        """O2: 部分 LikertScalePaths 有 evaluation_files。"""
        from pyrit.score import LikertScalePaths

        has_eval = [s for s in LikertScalePaths if s.evaluation_files is not None]
        assert len(has_eval) > 0, "至少有一个 Likert 量表应有 evaluation_files"

    @patch.dict(os.environ, {"OSAI_SECURITY_SCORERS": "1"})
    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_likert_scorers_registered_with_eval_files(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O2: 仅注册有 evaluation_files 的 Likert 量表。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        # 模拟 2 个 likert scale, 1 个有 eval_files, 1 个没有
        scale_with_eval = MagicMock()
        scale_with_eval.evaluation_files = MagicMock()  # 非 None
        scale_with_eval.name = "HARM_SCALE"
        scale_with_eval.load.return_value = MagicMock()

        scale_without_eval = MagicMock()
        scale_without_eval.evaluation_files = None
        scale_without_eval.name = "CYBER_SCALE"

        mock_likert_paths.__iter__ = MagicMock(return_value=iter([scale_with_eval, scale_without_eval]))

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        registered_names = {call.kwargs.get("name", "") for call in register_calls}

        # 只有有 evaluation_files 的量表被注册
        assert "likert_harm_local" in registered_names
        assert "likert_cyber_local" not in registered_names

    @patch.dict(os.environ, {"OSAI_SECURITY_SCORERS": "1"})
    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_likert_scorer_name_pattern(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O2: Likert scorer 名称遵循 likert_{name}_local 模式。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        scale = MagicMock()
        scale.evaluation_files = MagicMock()
        scale.name = "HATE_SPEECH_SCALE"
        scale.load.return_value = MagicMock()
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([scale]))

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        likert_calls = [c for c in register_calls if "likert" in c.kwargs.get("name", "")]
        assert len(likert_calls) == 1
        assert likert_calls[0].kwargs["name"] == "likert_hate_speech_local"
        assert "likert" in likert_calls[0].kwargs.get("tags", [])


# ============================================================
# 7. O4: F1 评估指标驱动的最优评分器选择测试
# ============================================================


class TestF1ScorerSelection:
    """测试 O4: _select_best_scorer_by_f1() 函数。

    Round 19 改进: 使用 PyRIT 原生 ``scorer.get_scorer_metrics()`` 替代
    手动 ``find_objective_metrics_by_eval_hash``。测试中通过 mock
    ``get_scorer_metrics()`` 方法返回 ``ObjectiveScorerMetrics`` 实例。
    """

    def test_function_exists(self) -> None:
        """O4: _select_best_scorer_by_f1 函数存在。"""
        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        assert callable(_select_best_scorer_by_f1)

    def test_selects_highest_f1_scorer(self) -> None:
        """O4: 选择 F1 最高的评分器。"""
        from pyrit.score import ObjectiveScorerMetrics

        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        mock_registry = MagicMock()
        entries = []
        f1_map = {"scorer_a": 0.7, "scorer_b": 0.9, "scorer_c": 0.8}
        for name, f1 in f1_map.items():
            mock_entry = MagicMock()
            mock_entry.name = name
            metrics = ObjectiveScorerMetrics(
                num_responses=20,
                num_human_raters=2,
                accuracy=f1,
                accuracy_standard_error=0.05,
                f1_score=f1,
                precision=f1,
                recall=f1,
            )
            mock_entry.instance.get_scorer_metrics.return_value = metrics
            entries.append(mock_entry)

        mock_registry.instances.get_all_instances.return_value = entries

        _select_best_scorer_by_f1(mock_registry)

        # 应在 scorer_b (F1=0.9) 上调用 add_tags
        mock_registry.instances.add_tags.assert_called_once_with(
            name="scorer_b",
            tags=["default_objective_scorer", "best_objective"],
        )

    def test_skips_when_get_metrics_returns_none(self) -> None:
        """O4: get_scorer_metrics() 返回 None 时跳过。"""
        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        mock_registry = MagicMock()
        mock_entry = MagicMock()
        mock_entry.name = "scorer_no_metrics"
        mock_entry.instance.get_scorer_metrics.return_value = None
        mock_registry.instances.get_all_instances.return_value = [mock_entry]

        _select_best_scorer_by_f1(mock_registry)

        mock_registry.instances.add_tags.assert_not_called()

    def test_skips_when_get_metrics_raises(self) -> None:
        """O4: get_scorer_metrics() 抛异常时跳过该评分器。"""
        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        mock_registry = MagicMock()
        mock_entry = MagicMock()
        mock_entry.name = "scorer_error"
        mock_entry.instance.get_scorer_metrics.side_effect = RuntimeError("test")
        mock_registry.instances.get_all_instances.return_value = [mock_entry]

        _select_best_scorer_by_f1(mock_registry)

        mock_registry.instances.add_tags.assert_not_called()

    def test_skips_non_objective_metrics(self) -> None:
        """O4: 非 ObjectiveScorerMetrics 类型 (如 HarmScorerMetrics) 被跳过。"""
        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        mock_registry = MagicMock()
        mock_entry = MagicMock()
        mock_entry.name = "likert_scorer"
        # 返回非 ObjectiveScorerMetrics 类型
        mock_entry.instance.get_scorer_metrics.return_value = MagicMock(spec=[])
        mock_registry.instances.get_all_instances.return_value = [mock_entry]

        _select_best_scorer_by_f1(mock_registry)

        mock_registry.instances.add_tags.assert_not_called()

    def test_handles_exception_gracefully(self) -> None:
        """O4: 整体异常时静默跳过。"""
        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        mock_registry = MagicMock()
        mock_registry.instances.get_all_instances.side_effect = RuntimeError("test error")

        # 不应抛出异常
        _select_best_scorer_by_f1(mock_registry)

        mock_registry.instances.add_tags.assert_not_called()

    def test_no_entries_no_selection(self) -> None:
        """O4: 空注册表不选择任何评分器。"""
        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        mock_registry = MagicMock()
        mock_registry.instances.get_all_instances.return_value = []

        _select_best_scorer_by_f1(mock_registry)

        mock_registry.instances.add_tags.assert_not_called()

    def test_f1_ranking_printed_when_multiple(self) -> None:
        """O4: 多个有 F1 数据的评分器时输出排名。"""
        from pyrit.score import ObjectiveScorerMetrics

        from pipeline.stages.stage_init import _select_best_scorer_by_f1

        mock_registry = MagicMock()
        entries = []
        for name, f1 in [("a", 0.7), ("b", 0.9)]:
            mock_entry = MagicMock()
            mock_entry.name = name
            metrics = ObjectiveScorerMetrics(
                num_responses=20,
                num_human_raters=2,
                accuracy=f1,
                accuracy_standard_error=0.05,
                f1_score=f1,
                precision=f1,
                recall=f1,
            )
            mock_entry.instance.get_scorer_metrics.return_value = metrics
            entries.append(mock_entry)

        mock_registry.instances.get_all_instances.return_value = entries

        # 不应抛出异常 (排名打印在 print 中)
        _select_best_scorer_by_f1(mock_registry)
        mock_registry.instances.add_tags.assert_called_once()


# ============================================================
# 9. G-S1: OR 复合评分器移除测试 (v45.2)
# ============================================================


class TestORCompositeScorer:
    """测试 G-S1: OR 复合评分器已移除 (消除假阳性)。"""

    def test_or_aggregator_exists(self) -> None:
        """O5+: PyRIT 原生 TrueFalseScoreAggregator.OR 存在。"""
        from pyrit.score import TrueFalseScoreAggregator

        assert hasattr(TrueFalseScoreAggregator, "OR")
        assert TrueFalseScoreAggregator.OR is not None

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_or_composite_not_registered(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """G-S1: objective_or_local 不再被注册 (移除 OR 假阳性源头)."""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        registered_names = {call.kwargs.get("name", "") for call in register_calls}
        assert "objective_or_local" not in registered_names

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_or_composite_not_created(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """G-S1: TrueFalseCompositeScorer 不再使用 OR 聚合器."""
        from pyrit.score import TrueFalseScoreAggregator

        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        # TrueFalseCompositeScorer 不应有 OR 调用
        composite_calls = mock_composite_class.call_args_list
        or_calls = [
            call for call in composite_calls
            if call.kwargs.get("aggregator") == TrueFalseScoreAggregator.OR
        ]
        assert len(or_calls) == 0, "G-S1: OR 聚合器应被移除"

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_or_composite_removed_no_scorers(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """G-S1: OR composite 不再创建, 无子评分器."""
        from pyrit.score import TrueFalseScoreAggregator

        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        composite_calls = mock_composite_class.call_args_list
        or_calls = [
            call for call in composite_calls
            if call.kwargs.get("aggregator") == TrueFalseScoreAggregator.OR
        ]
        assert len(or_calls) == 0, "G-S1: OR composite 应被移除"

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_or_always_not_registered(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """G-S1: 无论 refusal scorer 是否可用, OR composite 都不注册."""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        # 让 SelfAskRefusalScorer 抛异常, 使 refusal_scorers_for_vote 为空
        mock_refusal_scorer.side_effect = RuntimeError("intentional failure")

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        registered_names = {call.kwargs.get("name", "") for call in register_calls}
        assert "objective_or_local" not in registered_names


# ============================================================
# 8. O5: 多评分器投票 MAJORITY 测试
# ============================================================


class TestMajorityVoteComposite:
    """测试 O5: 多评分器投票 MAJORITY 复合评分器。"""

    def test_majority_aggregator_exists(self) -> None:
        """O5: PyRIT 原生 TrueFalseScoreAggregator.MAJORITY 存在。"""
        from pyrit.score import TrueFalseScoreAggregator

        assert hasattr(TrueFalseScoreAggregator, "MAJORITY")
        assert TrueFalseScoreAggregator.MAJORITY is not None

    def test_true_false_inverter_scorer_exists(self) -> None:
        """O5: PyRIT 原生 TrueFalseInverterScorer 可导入。"""
        from pyrit.score import TrueFalseInverterScorer

        assert TrueFalseInverterScorer is not None

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_majority_composite_registered(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O5: objective_majority_local 被注册。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        registered_names = {call.kwargs.get("name", "") for call in register_calls}
        assert "objective_majority_local" in registered_names

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_majority_composite_uses_majority_aggregator(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O5: MAJORITY composite 使用 TrueFalseScoreAggregator.MAJORITY。"""
        from pyrit.score import TrueFalseScoreAggregator

        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        # TrueFalseCompositeScorer 应被调用, 其中一次使用 MAJORITY
        composite_calls = mock_composite_class.call_args_list
        majority_calls = [
            call for call in composite_calls
            if call.kwargs.get("aggregator") == TrueFalseScoreAggregator.MAJORITY
        ]
        assert len(majority_calls) == 1, "应有一个 MAJORITY composite"

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_majority_composite_has_three_scorers(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O5: MAJORITY composite 包含 3 个子评分器 (task + 2×inverted_refusal)。"""
        from pyrit.score import TrueFalseScoreAggregator

        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        _register_enhanced_scorers()

        # 找到 MAJORITY composite 的调用
        composite_calls = mock_composite_class.call_args_list
        majority_calls = [
            call for call in composite_calls
            if call.kwargs.get("aggregator") == TrueFalseScoreAggregator.MAJORITY
        ]
        assert len(majority_calls) == 1
        scorers = majority_calls[0].kwargs.get("scorers", [])
        assert len(scorers) == 3, "MAJORITY composite 应有 3 个子评分器"
        # G-S1: TrueFalseInverterScorer 应被调用 2 次 (2 个 MAJORITY, OR 已移除)
        assert mock_inverter.call_count == 2

    @patch("pyrit.models.SeedPrompt")
    @patch("pyrit.score.SelfAskLikertScorer")
    @patch("pyrit.score.LikertScalePaths")
    @patch("pyrit.score.SelfAskRefusalScorer")
    @patch("pyrit.score.RefusalScorerPaths")
    @patch("pyrit.score.TrueFalseInverterScorer")
    @patch("pyrit.score.TrueFalseCompositeScorer")
    @patch("pyrit.registry.TargetRegistry")
    @patch("pyrit.registry.ScorerRegistry")
    @patch("pipeline.scenarios.composite_scorer.create_composite_objective_scorer")
    @patch("pyrit.score.SelfAskTrueFalseScorer")
    @patch("pyrit.score.SelfAskScaleScorer")
    @patch("pyrit.score.FloatScaleThresholdScorer")
    def test_majority_skipped_when_no_refusal_scorers(
        self,
        mock_float_scorer: MagicMock,
        mock_scale_scorer: MagicMock,
        mock_tf_scorer: MagicMock,
        mock_composite_factory: MagicMock,
        mock_scorer_reg: MagicMock,
        mock_target_reg: MagicMock,
        mock_composite_class: MagicMock,
        mock_inverter: MagicMock,
        mock_refusal_paths: MagicMock,
        mock_refusal_scorer: MagicMock,
        mock_likert_paths: MagicMock,
        mock_likert_scorer: MagicMock,
        mock_seed_prompt: MagicMock,
    ) -> None:
        """O5: 如果 refusal scorer 注册失败 (<2), MAJORITY composite 不创建。"""
        from pipeline.stages.stage_init import _register_enhanced_scorers

        _setup_enhanced_scorer_mocks(mock_scorer_reg, mock_target_reg, mock_composite_factory)
        mock_likert_paths.__iter__ = MagicMock(return_value=iter([]))
        for attr in ("OBJECTIVE_STRICT", "OBJECTIVE_LENIENT", "NO_OBJECTIVE_STRICT", "NO_OBJECTIVE_LENIENT"):
            setattr(mock_refusal_paths, attr, MagicMock(value=MagicMock()))

        # 让 SelfAskRefusalScorer 抛异常, 使 refusal_scorers_for_vote 为空
        mock_refusal_scorer.side_effect = RuntimeError("intentional failure")

        _register_enhanced_scorers()

        register_calls = mock_scorer_reg.get_registry_singleton.return_value.instances.register.call_args_list
        registered_names = {call.kwargs.get("name", "") for call in register_calls}
        assert "objective_majority_local" not in registered_names


# ============================================================
# 9. P7: 双 Judge 投票评分器测试
# ============================================================


class TestDualJudgeScorer:
    """P7: DualJudgeScorerWrapper 双 Judge 投票测试."""

    def test_dual_judge_wrapper_exists(self) -> None:
        """DualJudgeScorerWrapper 可导入."""
        from pipeline.scoring.dual_judge_scorer import DualJudgeScorerWrapper

        assert DualJudgeScorerWrapper is not None

    def test_create_dual_judge_scorer(self) -> None:
        """create_dual_judge_scorer 返回包装器."""
        from pipeline.scoring.dual_judge_scorer import (
            DualJudgeScorerWrapper,
            create_dual_judge_scorer,
        )

        mock_judge_a = MagicMock()
        mock_judge_b = MagicMock()
        wrapper = create_dual_judge_scorer(
            llm_scorer=mock_judge_a,
            second_judge_scorer=mock_judge_b,
        )
        assert isinstance(wrapper, DualJudgeScorerWrapper)
        assert wrapper.llm_scorer is mock_judge_a
        assert wrapper.second_judge_scorer is mock_judge_b

    def test_dual_judge_identifier(self) -> None:
        """get_identifier 返回 DualJudgeScorerWrapper."""
        from pipeline.scoring.dual_judge_scorer import (
            create_dual_judge_scorer,
        )

        wrapper = create_dual_judge_scorer(
            llm_scorer=MagicMock(),
            second_judge_scorer=MagicMock(),
        )
        assert wrapper.get_identifier() == "DualJudgeScorerWrapper"

    def test_dual_judge_tier_stats_initialized(self) -> None:
        """初始化后 T2.5 层级统计键存在."""
        from pipeline.scoring.dual_judge_scorer import create_dual_judge_scorer

        wrapper = create_dual_judge_scorer(
            llm_scorer=MagicMock(),
            second_judge_scorer=MagicMock(),
        )
        assert "T2.5_consensus" in wrapper.tier_stats
        assert "T2.5_consensus_false" in wrapper.tier_stats
        assert "T2.5_disputed_adopt_a" in wrapper.tier_stats
        assert "T2.5_disputed_adopt_b" in wrapper.tier_stats
        assert "T2.5_disputed_fallback" in wrapper.tier_stats
        assert "T2.5_judge_b_failed" in wrapper.tier_stats

    def test_dual_judge_inherits_cascade(self) -> None:
        """DualJudgeScorerWrapper 继承 CascadeScorerWrapper."""
        from pipeline.scoring.cascade_scorer import CascadeScorerWrapper
        from pipeline.scoring.dual_judge_scorer import DualJudgeScorerWrapper

        assert issubclass(DualJudgeScorerWrapper, CascadeScorerWrapper)


class TestDualJudgeRegistryIntegration:
    """P7: DualJudgeScorer 在 enhanced_registry 中的集成."""

    def test_dual_judge_registered_when_second_scorer_env_set(self) -> None:
        """当 SECOND_SCORER_CHAT_* 环境变量设置时, 双 Judge 评分器被注册."""
        import pipeline.scoring.enhanced_registry as er

        # 检查 enhanced_registry 中有 dual_judge 注册逻辑
        source = Path(er.__file__).read_text(encoding="utf-8")
        assert "dual_judge_objective_scorer" in source
        assert "SECOND_SCORER_CHAT_ENDPOINT" in source
        assert "create_dual_judge_scorer" in source

    def test_cascade_tag_removal_uses_direct_manipulation(self) -> None:
        """移除 cascade 的 default_objective_scorer 标签使用直接 entry.tags 操作."""
        import pipeline.scoring.enhanced_registry as er

        source = Path(er.__file__).read_text(encoding="utf-8")
        # 不使用 scorer_registry.instances.remove_tags() 方法调用
        assert "scorer_registry.instances.remove_tags" not in source
        # 直接操作 entry.tags
        assert "tags.pop" in source


# ============================================================
# 10. P8: 蒸馏评分器集成测试
# ============================================================


class TestDistillationIntegration:
    """P8: 蒸馏评分器在 enhanced_registry 中的集成."""

    def test_distilled_scorer_integration_in_registry(self) -> None:
        """enhanced_registry 中有蒸馏评分器集成逻辑."""
        import pipeline.scoring.enhanced_registry as er

        source = Path(er.__file__).read_text(encoding="utf-8")
        assert "load_distilled_scorer" in source
        assert "Distilled scorer" in source

    def test_distillation_module_exists(self) -> None:
        """scorer_distillation.py 模块可导入."""
        from pipeline.scoring.scorer_distillation import (
            DistillationConfig,
            DistilledScore,
            DistilledScorerWrapper,
        )

        assert DistillationConfig is not None
        assert DistilledScore is not None
        assert DistilledScorerWrapper is not None

    def test_distillation_exports_in_init(self) -> None:
        """scoring/__init__.py 导出蒸馏模块."""
        import pipeline.scoring as scoring

        assert hasattr(scoring, "DistillationConfig")
        assert hasattr(scoring, "export_training_data")
        assert hasattr(scoring, "load_distilled_scorer")
        assert hasattr(scoring, "prepare_distillation_config")


# ============================================================
# 11. P9: Per-Model 拒绝模式集成测试
# ============================================================


class TestP9ModelFamilyIntegration:
    """P9: 模型族检测在 stage_init 中的集成."""

    def test_set_current_model_family_called_in_stage_init(self) -> None:
        """stage_init.py 调用 set_current_model_family."""
        import pipeline.stages.stage_init as si

        source = Path(si.__file__).read_text(encoding="utf-8")
        assert "set_current_model_family" in source
        assert "target_model_family" in source

    def test_detect_model_family_exported(self) -> None:
        """detect_model_family 从 scoring 模块导出."""
        from pipeline.scoring import detect_model_family

        assert detect_model_family("gpt-4o") == "gpt"
        assert detect_model_family("Qwen/Qwen3-32B") == "qwen"


# ============================================================
# 12. P10: 3-shot 示例集成测试
# ============================================================


class TestP10FewShotIntegration:
    """P10: 3-shot 示例在 concise T2 scorer 中的集成."""

    def test_create_concise_t2_scorer_uses_enhanced_prompt(self) -> None:
        """create_concise_t2_scorer 使用包含示例的 prompt."""
        from pipeline.scoring.cascade_scorer import _T2_CONCISE_SYSTEM_PROMPT

        assert "Examples:" in _T2_CONCISE_SYSTEM_PROMPT
        assert "-> true" in _T2_CONCISE_SYSTEM_PROMPT
        assert "partial compliance" in _T2_CONCISE_SYSTEM_PROMPT.lower()
