# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""v38.1: 技术名映射到 TextAdaptiveTechnique 枚举值测试.

验证 _map_to_text_adaptive_techniques 函数正确将规范技术名
映射到 PyRIT TextAdaptiveTechnique 枚举值, 修复载荷匹配率 12% → 100%.
"""

from __future__ import annotations

from pipeline.stages.stage_scenario import (
    _TECHNIQUE_TO_TEXTADAPTIVE,
    _map_to_text_adaptive_techniques,
)


class TestTechniqueMapping:
    """技术名映射测试."""

    def test_crescendo_maps_to_simulated(self):
        """crescendo → crescendo_simulated."""
        result = _map_to_text_adaptive_techniques(["crescendo"])
        assert result == ["crescendo_simulated"]

    def test_best_of_n_maps_to_flip(self):
        """best_of_n_jailbreak → flip (PyRIT 工厂名)."""
        result = _map_to_text_adaptive_techniques(["best_of_n_jailbreak"])
        assert result == ["flip"]

    def test_tree_of_attacks_pruned_maps_to_tap(self):
        """tree_of_attacks_pruned → tap."""
        result = _map_to_text_adaptive_techniques(["tree_of_attacks_pruned"])
        assert result == ["tap"]

    def test_tap_passes_through(self):
        """tap 直接映射 (已是枚举值)."""
        result = _map_to_text_adaptive_techniques(["tap"])
        assert result == ["tap"]

    def test_pair_passes_through(self):
        """pair 直接映射."""
        result = _map_to_text_adaptive_techniques(["pair"])
        assert result == ["pair"]

    def test_red_teaming_passes_through(self):
        """red_teaming 直接映射."""
        result = _map_to_text_adaptive_techniques(["red_teaming"])
        assert result == ["red_teaming"]

    def test_context_compliance_passes_through(self):
        """context_compliance 直接映射."""
        result = _map_to_text_adaptive_techniques(["context_compliance"])
        assert result == ["context_compliance"]

    def test_skeleton_key_passes_through(self):
        """skeleton_key 直接映射."""
        result = _map_to_text_adaptive_techniques(["skeleton_key"])
        assert result == ["skeleton_key"]

    def test_violent_durian_passes_through(self):
        """violent_durian 直接映射."""
        result = _map_to_text_adaptive_techniques(["violent_durian"])
        assert result == ["violent_durian"]

    def test_role_play_variants_pass_through(self):
        """角色扮演变体直接映射."""
        techs = [
            "role_play_movie_script",
            "role_play_persuasion",
            "role_play_persuasion_written",
            "role_play_trivia_game",
            "role_play_video_game",
        ]
        result = _map_to_text_adaptive_techniques(techs)
        assert result == techs

    def test_crescendo_variants_pass_through(self):
        """Crescendo 变体直接映射."""
        techs = [
            "crescendo_movie_director",
            "crescendo_history_lecture",
            "crescendo_journalist_interview",
        ]
        result = _map_to_text_adaptive_techniques(techs)
        assert result == techs


class TestTechniqueFiltering:
    """无效技术过滤测试."""

    def test_converter_chain_names_filtered(self):
        """Converter 链名 (非技术) 应被过滤."""
        techs = ["encoding_bypass", "stealth_evasion", "persuasion_authority", "tap"]
        result = _map_to_text_adaptive_techniques(techs)
        assert "encoding_bypass" not in result
        assert "stealth_evasion" not in result
        assert "persuasion_authority" not in result
        assert result == ["tap"]

    def test_prompt_sending_filtered(self):
        """prompt_sending 不在 TextAdaptiveTechnique 枚举中."""
        result = _map_to_text_adaptive_techniques(["prompt_sending"])
        assert result == []

    def test_bad_likert_judge_filtered(self):
        """bad_likert_judge 不在 TextAdaptive 枚举中."""
        result = _map_to_text_adaptive_techniques(["bad_likert_judge"])
        assert result == []

    def test_wrapping_attack_filtered(self):
        """wrapping_attack 不在 TextAdaptive 枚举中."""
        result = _map_to_text_adaptive_techniques(["wrapping_attack"])
        assert result == []

    def test_empty_input(self):
        """空列表返回空列表."""
        assert _map_to_text_adaptive_techniques([]) == []

    def test_all_invalid_returns_empty(self):
        """全部无效技术返回空列表."""
        result = _map_to_text_adaptive_techniques(["foo", "bar", "baz"])
        assert result == []


class TestTechniqueDedup:
    """去重测试."""

    def test_duplicate_crescendo_dedup(self):
        """crescendo + crescendo_simulated 应去重为 1 个."""
        result = _map_to_text_adaptive_techniques(["crescendo", "crescendo_simulated"])
        assert result == ["crescendo_simulated"]

    def test_tap_variants_dedup(self):
        """tap + tree_of_attacks_pruned 应去重为 1 个."""
        result = _map_to_text_adaptive_techniques(["tap", "tree_of_attacks_pruned"])
        assert result == ["tap"]

    def test_best_of_n_and_flip_dedup(self):
        """best_of_n_jailbreak + flip 应去重为 1 个."""
        result = _map_to_text_adaptive_techniques(["best_of_n_jailbreak", "flip"])
        assert result == ["flip"]


class TestMixedInput:
    """混合输入测试 (模拟实际场景)."""

    def test_realistic_tech_list(self):
        """模拟实际 scenario_techniques 输入 (含有效+无效技术名)."""
        techs = [
            "crescendo",  # → crescendo_simulated
            "tap",  # → tap
            "pair",  # → pair
            "red_teaming",  # → red_teaming
            "context_compliance",  # → context_compliance
            "skeleton_key",  # → skeleton_key
            "best_of_n_jailbreak",  # → flip
            "violent_durian",  # → violent_durian
            "encoding_bypass",  # 跳过 (Converter)
            "stealth_evasion",  # 跳过 (Converter)
            "prompt_sending",  # 跳过 (基线)
            "bad_likert_judge",  # 跳过 (不在枚举)
            "wrapping_attack",  # 跳过 (不在枚举)
            "persuasion_authority",  # 跳过 (Converter)
            "decomposition_chain",  # 跳过 (Converter)
        ]
        result = _map_to_text_adaptive_techniques(techs)
        # 8 个有效技术
        assert len(result) == 8
        assert "crescendo_simulated" in result
        assert "tap" in result
        assert "pair" in result
        assert "red_teaming" in result
        assert "context_compliance" in result
        assert "skeleton_key" in result
        assert "flip" in result
        assert "violent_durian" in result

    def test_full_valid_tech_list(self):
        """全部有效技术 (排除 many_shot 和 prompt_sending)."""
        techs = [
            "crescendo_simulated",
            "crescendo_movie_director",
            "crescendo_history_lecture",
            "crescendo_journalist_interview",
            "tap",
            "pair",
            "red_teaming",
            "context_compliance",
            "skeleton_key",
            "violent_durian",
            "best_of_n_jailbreak",  # → flip
            "role_play_movie_script",
            "role_play_persuasion",
            "role_play_persuasion_written",
            "role_play_trivia_game",
            "role_play_video_game",
        ]
        result = _map_to_text_adaptive_techniques(techs)
        # 16 个输入 → 16 个有效 (best_of_n_jailbreak → flip 不重复)
        assert len(result) == 16
        assert "flip" in result
        assert "crescendo_simulated" in result


class TestMappingTable:
    """映射表完整性测试."""

    def test_all_mapped_values_are_valid_enum(self):
        """映射表中的所有目标值必须是有效的 TextAdaptiveTechnique 枚举值."""
        from pyrit.scenario.scenarios.adaptive import TextAdaptive

        tech_enum = TextAdaptive.get_technique_class()
        valid_enum_names = {t.value for t in tech_enum}
        for source, target in _TECHNIQUE_TO_TEXTADAPTIVE.items():
            assert target in valid_enum_names, (
                f"Mapping {source} → {target}: target not in TextAdaptiveTechnique enum"
            )

    def test_mapping_covers_all_text_adaptive_techniques(self):
        """映射表覆盖所有 TextAdaptiveTechnique 枚举成员 (排除聚合标签)."""
        from pyrit.scenario.scenarios.adaptive import TextAdaptive

        tech_enum = TextAdaptive.get_technique_class()
        # 聚合标签不在映射表中 (由 PyRIT 内部处理)
        aggregate_tags = {"all", "default", "core", "extra", "light", "multi_turn", "single_turn"}
        individual_techniques = {
            t.value for t in tech_enum
        } - aggregate_tags

        # 每个个别技术应该至少有一个映射到它
        mapped_targets = set(_TECHNIQUE_TO_TEXTADAPTIVE.values())
        for tech in individual_techniques:
            assert tech in mapped_targets, (
                f"TextAdaptiveTechnique.{tech} has no mapping in _TECHNIQUE_TO_TEXTADAPTIVE"
            )
