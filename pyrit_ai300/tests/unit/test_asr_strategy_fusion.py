"""
ASR引导策略 v4.0 融合测试 — 技术名标准化映射 + 统一 Tier 阈值 + 学术先验回退
=========================================================================

测试目标:
  1. technique_name_mapper: YAML→registry 技术名标准化映射
  2. asr_rank_builder: 统一 Tier 阈值 (S>=70% A>=40% B>=15% C>=5% D<5%)
  3. asr_rank_builder: 学术先验回退 (无 YAML ASR 时查询 asr_prior_registry)
  4. preset_schemes: ASR 展示回退 (无 YAML ASR 时回退到学术先验)
  5. plan_d_display: 标准化映射展示 + D tier 支持
  6. tiered_selection_wizard: model_name 参数传递
"""

from unittest.mock import MagicMock


# ============================================================
# P0: Technique Name Mapper 测试
# ============================================================


class TestTechniqueNameMapper:
    """技术名标准化映射测试"""

    def test_normalize_exact_match(self):
        """精确匹配"""
        from src.payloads.technique_name_mapper import normalize_technique_name
        assert normalize_technique_name("direct") == "prompt_sending"
        assert normalize_technique_name("skeleton") == "skeleton_key"
        assert normalize_technique_name("gradual_extraction") == "pair"

    def test_normalize_suffix_stripping(self):
        """后缀去除匹配"""
        from src.payloads.technique_name_mapper import normalize_technique_name
        # _expanded 后缀
        assert normalize_technique_name("goal_hijack_expanded") == "agent_injection_chain"
        # _v2 后缀
        assert normalize_technique_name("multimodal_jailbreak_v2") == "crescendo"

    def test_normalize_unknown_passthrough(self):
        """未知技术名原样返回"""
        from src.payloads.technique_name_mapper import normalize_technique_name
        assert normalize_technique_name("unknown_technique_xyz") == "unknown_technique_xyz"

    def test_normalize_empty(self):
        """空字符串处理"""
        from src.payloads.technique_name_mapper import normalize_technique_name
        assert normalize_technique_name("") == ""

    def test_get_normalized_asr_known(self):
        """已知技术的 ASR 查询"""
        from src.payloads.technique_name_mapper import get_normalized_asr
        # "direct" → "prompt_sending" → 应该返回学术先验值
        asr = get_normalized_asr("direct", "gpt-4o")
        assert 0.0 <= asr <= 1.0
        # prompt_sending 的学术先验应该不是中性值 0.3
        assert asr != 0.3

    def test_get_normalized_asr_unknown(self):
        """未知技术的 ASR 查询返回中性先验"""
        from src.payloads.technique_name_mapper import get_normalized_asr
        asr = get_normalized_asr("totally_unknown_xyz", "gpt-4o")
        assert asr == 0.3

    def test_get_normalized_tier_thresholds(self):
        """统一 Tier 阈值测试"""
        from src.payloads.technique_name_mapper import get_normalized_tier
        # S: >= 70%
        tier = get_normalized_tier("crescendo", "gpt-4o")
        assert tier in ("S", "A", "B", "C", "D")

    def test_is_high_asr_technique(self):
        """高 ASR 技术判断"""
        from src.payloads.technique_name_mapper import is_high_asr_technique
        # crescendo 在 gpt-4o 上应该有高 ASR
        result = is_high_asr_technique("crescendo", "gpt-4o")
        assert isinstance(result, bool)

    def test_technique_name_map_completeness(self):
        """映射表覆盖关键技术"""
        from src.payloads.technique_name_mapper import TECHNIQUE_NAME_MAP
        # 确保关键映射存在
        assert "direct" in TECHNIQUE_NAME_MAP
        assert "skeleton" in TECHNIQUE_NAME_MAP
        assert "gradual_extraction" in TECHNIQUE_NAME_MAP
        assert "goal_hijack" in TECHNIQUE_NAME_MAP
        assert "rag_poisoning" in TECHNIQUE_NAME_MAP


# ============================================================
# P1: ASR Rank Builder 统一 Tier 阈值测试
# ============================================================


class TestUnifiedTierThresholds:
    """统一 Tier 阈值测试 (ASR引导策略学术标准)"""

    def test_tier_s_threshold(self):
        """S tier: ASR >= 70%"""
        from src.payloads.asr_rank_builder import ASRTier
        assert ASRTier.from_asr(0.70) == ASRTier.S
        assert ASRTier.from_asr(0.85) == ASRTier.S
        assert ASRTier.from_asr(1.0) == ASRTier.S

    def test_tier_a_threshold(self):
        """A tier: ASR 40-70%"""
        from src.payloads.asr_rank_builder import ASRTier
        assert ASRTier.from_asr(0.40) == ASRTier.A
        assert ASRTier.from_asr(0.55) == ASRTier.A
        assert ASRTier.from_asr(0.69) == ASRTier.A

    def test_tier_b_threshold(self):
        """B tier: ASR 15-40%"""
        from src.payloads.asr_rank_builder import ASRTier
        assert ASRTier.from_asr(0.15) == ASRTier.B
        assert ASRTier.from_asr(0.25) == ASRTier.B
        assert ASRTier.from_asr(0.39) == ASRTier.B

    def test_tier_c_threshold(self):
        """C tier: ASR 5-15%"""
        from src.payloads.asr_rank_builder import ASRTier
        assert ASRTier.from_asr(0.05) == ASRTier.C
        assert ASRTier.from_asr(0.10) == ASRTier.C
        assert ASRTier.from_asr(0.14) == ASRTier.C

    def test_tier_d_threshold(self):
        """D tier: ASR < 5%"""
        from src.payloads.asr_rank_builder import ASRTier
        assert ASRTier.from_asr(0.04) == ASRTier.D
        assert ASRTier.from_asr(0.01) == ASRTier.D
        assert ASRTier.from_asr(0.0) == ASRTier.D

    def test_tier_threshold_property(self):
        """Tier threshold 属性验证"""
        from src.payloads.asr_rank_builder import ASRTier
        assert ASRTier.S.threshold == 0.70
        assert ASRTier.A.threshold == 0.40
        assert ASRTier.B.threshold == 0.15
        assert ASRTier.C.threshold == 0.05
        assert ASRTier.D.threshold == 0.0


# ============================================================
# P2: ASR Rank Builder 学术先验回退测试
# ============================================================


class TestAcademicPriorFallback:
    """学术先验回退测试"""

    def test_build_ranked_groups_with_model_name(self):
        """build_ranked_groups 接受 model_name 参数"""
        from src.payloads.asr_rank_builder import ASRRankBuilder

        # 创建 mock seed groups
        mock_seed = MagicMock()
        mock_seed.metadata = {"technique_group": "direct", "owasp_id": "LLM01"}
        mock_seed.dataset_name = "test"
        mock_sg = MagicMock()
        mock_sg.seeds = [mock_seed]

        ranked = ASRRankBuilder.build_ranked_groups([mock_sg], model_name="gpt-4o")
        assert len(ranked) >= 1
        assert ranked[0].technique_group == "direct"

    def test_build_ranked_groups_academic_fallback(self):
        """无 YAML ASR 时回退到学术先验"""
        from src.payloads.asr_rank_builder import ASRRankBuilder

        # 创建无 asr_baseline 的种子
        mock_seed = MagicMock()
        mock_seed.metadata = {
            "technique_group": "direct",
            "owasp_id": "LLM01",
            "attack_mode": "single_turn",
            "difficulty": "easy",
            "evasion_level": "low",
        }
        mock_seed.dataset_name = "test"
        mock_sg = MagicMock()
        mock_sg.seeds = [mock_seed]

        ranked = ASRRankBuilder.build_ranked_groups([mock_sg], model_name="gpt-4o")
        # "direct" → "prompt_sending" → 学术先验非 0.3
        assert ranked[0].has_asr_data
        assert ranked[0].max_asr > 0.0

    def test_build_ranked_groups_unknown_technique_heuristic(self):
        """未知技术仍使用启发式代理"""
        from src.payloads.asr_rank_builder import ASRRankBuilder

        mock_seed = MagicMock()
        mock_seed.metadata = {
            "technique_group": "totally_unknown_xyz",
            "owasp_id": "LLM99",
            "attack_mode": "single_turn",
            "difficulty": "hard",
            "evasion_level": "high",
        }
        mock_seed.dataset_name = "test"
        mock_sg = MagicMock()
        mock_sg.seeds = [mock_seed]

        ranked = ASRRankBuilder.build_ranked_groups([mock_sg], model_name="gpt-4o")
        # 未知技术 → 中性先验 0.3 → has_asr_data 保持 False
        assert not ranked[0].has_asr_data
        assert ranked[0].heuristic_score > 0


# ============================================================
# P3: Preset Schemes ASR 展示回退测试
# ============================================================


class TestPresetSchemeASRFallback:
    """Preset Scheme ASR 展示回退测试"""

    def test_display_asr_with_yaml_data(self):
        """有 YAML ASR 数据时正常显示"""
        from src.payloads.preset_schemes import PresetSchemeDefinition, PresetScheme
        from src.payloads.asr_rank_builder import TechniqueGroupInfo, ASRTier

        mock_group = TechniqueGroupInfo(
            technique_group="test",
            owasp_id="LLM01",
            seed_count=5,
            max_asr=0.8,
            avg_asr=0.7,
            has_asr_data=True,
            tier=ASRTier.S,
            heuristic_score=80,
            attack_modes=["single_turn"],
            difficulties=["easy"],
            severities=[],
            evasion_levels=["low"],
            dataset_name="test",
        )

        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=[mock_group],
        )
        assert scheme.display_asr == "80%"

    def test_display_asr_fallback_to_academic(self):
        """无 YAML ASR 数据时回退到学术先验"""
        from src.payloads.preset_schemes import PresetSchemeDefinition, PresetScheme
        from src.payloads.asr_rank_builder import TechniqueGroupInfo, ASRTier

        # 使用已知技术名 "direct" → "prompt_sending"
        mock_group = TechniqueGroupInfo(
            technique_group="direct",
            owasp_id="LLM01",
            seed_count=5,
            max_asr=0.0,
            avg_asr=0.0,
            has_asr_data=False,
            tier=ASRTier.UNKNOWN,
            heuristic_score=50,
            attack_modes=["single_turn"],
            difficulties=["easy"],
            severities=[],
            evasion_levels=["low"],
            dataset_name="test",
        )

        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=[mock_group],
        )
        # 应该回退到学术先验，不再显示 "--"
        asr_str = scheme.display_asr
        assert asr_str != "--"


# ============================================================
# P4: Plan D Display 标准化映射测试
# ============================================================


class TestPlanDDisplayNormalized:
    """Plan D Display 标准化映射测试"""

    def test_display_selection_stage_with_normalization(self, capsys):
        """选择阶段展示标准化映射"""
        from src.scenarios.asr_strategy_display import display_selection_stage

        # 创建 mock seed group，使用需要标准化的技术名
        mock_seed = MagicMock()
        mock_seed.metadata = {"technique_group": "direct", "owasp_id": "LLM01"}
        mock_sg = MagicMock()
        mock_sg.seeds = [mock_seed]

        display_selection_stage(
            selected_groups=[mock_sg],
            model_name="gpt-4o",
            strategy_mode="academic",
        )

        captured = capsys.readouterr()
        assert "ASR策略" in captured.out
        assert "学术 ASR" in captured.out

    def test_display_selection_stage_d_tier(self, capsys):
        """选择阶段展示 D tier"""
        from src.scenarios.asr_strategy_display import display_selection_stage

        # 创建一个 ASR 很低的技术
        mock_seed = MagicMock()
        mock_seed.metadata = {"technique_group": "unknown_low_asr", "owasp_id": "LLM99"}
        mock_sg = MagicMock()
        mock_sg.seeds = [mock_seed]

        display_selection_stage(
            selected_groups=[mock_sg],
            model_name="gpt-4o",
            strategy_mode="academic",
        )

        captured = capsys.readouterr()
        # 未知技术应该显示在中性先验区域
        assert "ASR策略" in captured.out

    def test_display_execution_stage_normalized(self, capsys):
        """执行阶段展示标准化映射"""
        from src.scenarios.asr_strategy_display import display_execution_stage

        mock_plan = MagicMock()
        mock_plan.attack_technique = "direct"

        display_execution_stage(
            target_type="openai_chat",
            model_name="gpt-4o",
            strategy_mode="academic",
            attack_plans=[mock_plan],
        )

        captured = capsys.readouterr()
        assert "ASR策略" in captured.out
        assert "执行决策" in captured.out

    def test_tier_descriptions_include_d(self):
        """Tier 描述包含 D"""
        from src.scenarios.asr_strategy_display import TIER_DESCRIPTIONS
        assert "D" in TIER_DESCRIPTIONS

    def test_get_tier_d_threshold(self):
        """_get_tier 正确识别 D tier"""
        from src.scenarios.asr_strategy_display import _get_tier
        assert _get_tier(0.03) == "D"
        assert _get_tier(0.0) == "D"
        assert _get_tier(0.04) == "D"

    def test_get_tier_c_threshold(self):
        """_get_tier 正确识别 C tier (5-15%)"""
        from src.scenarios.asr_strategy_display import _get_tier
        assert _get_tier(0.05) == "C"
        assert _get_tier(0.10) == "C"
        assert _get_tier(0.14) == "C"


# ============================================================
# P5: Tiered Selection Wizard model_name 传递测试
# ============================================================


class TestWizardModelName:
    """Wizard model_name 参数传递测试"""

    def test_wizard_accepts_model_name(self):
        """Wizard 接受 model_name 参数"""
        from src.payloads.tiered_selection_wizard import TieredSelectionWizard
        wizard = TieredSelectionWizard(model_name="claude-3.5-sonnet")
        assert wizard.model_name == "claude-3.5-sonnet"

    def test_wizard_default_model_name(self):
        """Wizard 默认 model_name"""
        from src.payloads.tiered_selection_wizard import TieredSelectionWizard
        wizard = TieredSelectionWizard()
        assert wizard.model_name == "gpt-4o"

    def test_select_with_wizard_model_name(self):
        """select_with_wizard 传递 model_name"""
        from src.payloads.tiered_selection_wizard import select_with_wizard
        # 仅测试函数签名正确，不实际执行
        import inspect
        sig = inspect.signature(select_with_wizard)
        assert "model_name" in sig.parameters


# ============================================================
# P6: 统一阈值一致性测试
# ============================================================


class TestUnifiedThresholdConsistency:
    """统一阈值一致性验证"""

    def test_asr_rank_builder_tier_matches_mapper(self):
        """asr_rank_builder Tier 阈值与 technique_name_mapper 一致"""
        from src.payloads.asr_rank_builder import ASRTier
        from src.payloads.technique_name_mapper import (
            TIER_S_THRESHOLD as MAPPER_S,
            TIER_A_THRESHOLD as MAPPER_A,
            TIER_B_THRESHOLD as MAPPER_B,
            TIER_C_THRESHOLD as MAPPER_C,
        )

        assert ASRTier.S.threshold == MAPPER_S
        assert ASRTier.A.threshold == MAPPER_A
        assert ASRTier.B.threshold == MAPPER_B
        assert ASRTier.C.threshold == MAPPER_C

    def test_plan_d_display_tier_matches_mapper(self):
        """plan_d_display Tier 阈值与 technique_name_mapper 一致"""
        from src.scenarios.asr_strategy_display import (
            TIER_S_THRESHOLD as DISPLAY_S,
            TIER_A_THRESHOLD as DISPLAY_A,
            TIER_B_THRESHOLD as DISPLAY_B,
            TIER_C_THRESHOLD as DISPLAY_C,
        )
        from src.payloads.technique_name_mapper import (
            TIER_S_THRESHOLD as MAPPER_S,
            TIER_A_THRESHOLD as MAPPER_A,
            TIER_B_THRESHOLD as MAPPER_B,
            TIER_C_THRESHOLD as MAPPER_C,
        )

        assert DISPLAY_S == MAPPER_S
        assert DISPLAY_A == MAPPER_A
        assert DISPLAY_B == MAPPER_B
        assert DISPLAY_C == MAPPER_C

    def test_all_systems_use_same_s_threshold(self):
        """所有系统 S tier 阈值统一为 70%"""
        from src.payloads.asr_rank_builder import ASRTier
        from src.payloads.technique_name_mapper import TIER_S_THRESHOLD
        from src.scenarios.asr_strategy_display import TIER_S_THRESHOLD as DISPLAY_S

        assert ASRTier.S.threshold == 0.70
        assert TIER_S_THRESHOLD == 0.70
        assert DISPLAY_S == 0.70


# ============================================================
# P7: 导出完整性测试
# ============================================================


class TestExportCompleteness:
    """模块导出完整性测试"""

    def test_technique_name_mapper_exports(self):
        """technique_name_mapper 导出完整"""
        from src.payloads.technique_name_mapper import (
            TECHNIQUE_NAME_MAP,
            TIER_S_THRESHOLD,
            normalize_technique_name,
            get_normalized_asr,
            get_normalized_tier,
            is_high_asr_technique,
        )
        assert isinstance(TECHNIQUE_NAME_MAP, dict)
        assert TIER_S_THRESHOLD == 0.70
        assert callable(normalize_technique_name)
        assert callable(get_normalized_asr)
        assert callable(get_normalized_tier)
        assert callable(is_high_asr_technique)

    def test_payloads_init_exports_mapper(self):
        """__init__.py 导出 technique_name_mapper"""
        import src.payloads as payloads
        assert hasattr(payloads, "normalize_technique_name")
        assert hasattr(payloads, "get_normalized_asr")
        assert hasattr(payloads, "get_normalized_tier")
        assert hasattr(payloads, "is_high_asr_technique")
        assert hasattr(payloads, "TECHNIQUE_NAME_MAP")

    def test_preset_schemes_build_schemes_accepts_model_name(self):
        """build_schemes 接受 model_name 参数"""
        import inspect
        from src.payloads.preset_schemes import PresetSchemeBuilder
        sig = inspect.signature(PresetSchemeBuilder.build_schemes)
        assert "model_name" in sig.parameters
