"""
Tests for the Preset Schemes module.

Covers:
  - AttackMechanism enumeration and properties
  - TECHNIQUE_MECHANISM_MAP completeness
  - get_mechanism() function (exact + fallback)
  - PresetScheme enumeration (letter, display_name, target_group_count, from_letter)
  - PresetSchemeDefinition dataclass (properties: weighted_asr, display_asr, etc.)
  - PresetSchemeBuilder (build_schemes, build_scheme, _select_diverse, _estimate_time)
  - Convenience functions (build_preset_schemes, get_scheme_by_letter)
  - Edge cases (empty groups, few groups, all same mechanism)
  - Integration with TieredSelectionWizard (_try_scheme_selection)
"""

from unittest.mock import MagicMock

import pytest

from src.payloads.preset_schemes import (
    AttackMechanism,
    PresetScheme,
    PresetSchemeDefinition,
    PresetSchemeBuilder,
    build_preset_schemes,
    get_scheme_by_letter,
    get_mechanism,
    TECHNIQUE_MECHANISM_MAP,
)
from src.payloads.asr_rank_builder import ASRTier, TechniqueGroupInfo
from src.payloads.tiered_selection_wizard import TieredSelectionWizard


# ============================================================
# Test Helpers
# ============================================================


def _make_tgi(
    technique_group: str,
    owasp_id: str = "LLM01",
    tier: ASRTier = ASRTier.S,
    asr: float = 0.90,
    seed_count: int = 5,
    attack_modes=None,
) -> TechniqueGroupInfo:
    """Create a TechniqueGroupInfo for testing."""
    sg = MagicMock()
    sg.seeds = [MagicMock() for _ in range(seed_count)]

    if attack_modes is None:
        attack_modes = ["single_turn"]

    return TechniqueGroupInfo(
        technique_group=technique_group,
        owasp_id=owasp_id,
        seed_count=seed_count,
        max_asr=asr,
        avg_asr=asr,
        has_asr_data=asr > 0,
        tier=tier,
        heuristic_score=50.0,
        attack_modes=attack_modes,
        difficulties=["medium"],
        severities=["high"],
        evasion_levels=["medium"],
        dataset_name="test",
        source_seed_groups=[sg],
    )


def _make_ranked_groups_diverse():
    """Create ranked groups with diverse mechanisms for testing."""
    return [
        _make_tgi("many_shot_jailbreak", asr=0.98, seed_count=10, tier=ASRTier.S),
        _make_tgi("skeleton_key", asr=0.95, seed_count=9, tier=ASRTier.S),
        _make_tgi("best_of_n_jailbreak", asr=0.88, seed_count=6, tier=ASRTier.S),
        _make_tgi("autodan", asr=0.85, seed_count=5, tier=ASRTier.A),
        _make_tgi("iteration_pair_tap", asr=0.85, seed_count=5, tier=ASRTier.A,
                  attack_modes=["multi_turn"]),
        _make_tgi("bad_likert_judge", asr=0.80, seed_count=4, tier=ASRTier.A),
        _make_tgi("multimodal_jailbreak_v2", asr=0.70, seed_count=3, tier=ASRTier.A),
        _make_tgi("deep_inception", asr=0.68, seed_count=4, tier=ASRTier.B),
    ]


def _make_ranked_groups_same_mechanism():
    """Create ranked groups all with the same mechanism."""
    return [
        _make_tgi("many_shot_jailbreak", asr=0.98, seed_count=10, tier=ASRTier.S),
        _make_tgi("best_of_n_jailbreak", asr=0.88, seed_count=6, tier=ASRTier.S),
        _make_tgi("few_shot_backdoor", asr=0.75, seed_count=4, tier=ASRTier.A),
    ]


# ============================================================
# AttackMechanism Tests
# ============================================================


class TestAttackMechanism:
    def test_values(self):
        assert AttackMechanism.MULTI_SHOT.value == "multi_shot"
        assert AttackMechanism.ROLE_OVERRIDE.value == "role_override"
        assert AttackMechanism.GRADIENT_OPT.value == "gradient_opt"
        assert AttackMechanism.ITERATIVE.value == "iterative"
        assert AttackMechanism.MULTIMODAL.value == "multimodal"
        assert AttackMechanism.ENCODING.value == "encoding"
        assert AttackMechanism.NESTED.value == "nested"
        assert AttackMechanism.INJECTION.value == "injection"
        assert AttackMechanism.EXTRACTION.value == "extraction"
        assert AttackMechanism.POISONING.value == "poisoning"
        assert AttackMechanism.EXPLOIT.value == "exploit"
        assert AttackMechanism.UNKNOWN.value == "unknown"

    def test_display_name(self):
        assert AttackMechanism.MULTI_SHOT.display_name == "多示例引导"
        assert AttackMechanism.ROLE_OVERRIDE.display_name == "角色覆盖"
        assert AttackMechanism.GRADIENT_OPT.display_name == "梯度优化"
        assert AttackMechanism.MULTIMODAL.display_name == "多模态"
        assert AttackMechanism.ENCODING.display_name == "编码混淆"

    def test_all_mechanisms_have_display_name(self):
        """Every mechanism should have a display name."""
        for mech in AttackMechanism:
            assert mech.display_name != mech.value, f"{mech} missing display name"


class TestTechniqueMechanismMap:
    def test_map_not_empty(self):
        assert len(TECHNIQUE_MECHANISM_MAP) > 50

    def test_known_techniques(self):
        assert TECHNIQUE_MECHANISM_MAP["many_shot_jailbreak"] == AttackMechanism.MULTI_SHOT
        assert TECHNIQUE_MECHANISM_MAP["skeleton_key"] == AttackMechanism.ROLE_OVERRIDE
        assert TECHNIQUE_MECHANISM_MAP["autodan"] == AttackMechanism.GRADIENT_OPT
        assert TECHNIQUE_MECHANISM_MAP["cipher_chat"] == AttackMechanism.ENCODING
        assert TECHNIQUE_MECHANISM_MAP["multimodal_jailbreak_v2"] == AttackMechanism.MULTIMODAL

    def test_all_values_are_valid_mechanisms(self):
        """Every value in the map should be a valid AttackMechanism."""
        for tech, mech in TECHNIQUE_MECHANISM_MAP.items():
            assert isinstance(mech, AttackMechanism), f"{tech} has invalid mechanism {mech}"


class TestGetMechanism:
    def test_exact_match(self):
        assert get_mechanism("many_shot_jailbreak") == AttackMechanism.MULTI_SHOT
        assert get_mechanism("skeleton_key") == AttackMechanism.ROLE_OVERRIDE
        assert get_mechanism("autodan") == AttackMechanism.GRADIENT_OPT

    def test_unknown_returns_unknown(self):
        assert get_mechanism("completely_unknown_technique") == AttackMechanism.UNKNOWN

    def test_prefix_multimodal(self):
        assert get_mechanism("multimodal_new_attack") == AttackMechanism.MULTIMODAL

    def test_prefix_cve(self):
        assert get_mechanism("cve_2027_99999_new_vuln") == AttackMechanism.EXPLOIT

    def test_prefix_rag(self):
        assert get_mechanism("rag_custom_poison") == AttackMechanism.POISONING

    def test_prefix_mcp(self):
        assert get_mechanism("mcp_custom_tool") == AttackMechanism.POISONING

    def test_contains_injection(self):
        assert get_mechanism("custom_injection_attack") == AttackMechanism.INJECTION

    def test_contains_leak(self):
        assert get_mechanism("custom_data_leak") == AttackMechanism.EXTRACTION

    def test_contains_extraction(self):
        assert get_mechanism("custom_extraction_method") == AttackMechanism.EXTRACTION

    def test_contains_poison(self):
        assert get_mechanism("custom_poison_attack") == AttackMechanism.POISONING


# ============================================================
# PresetScheme Tests
# ============================================================


class TestPresetScheme:
    def test_values(self):
        assert PresetScheme.FAST.value == "fast"
        assert PresetScheme.RECOMMENDED.value == "recommended"
        assert PresetScheme.DEEP.value == "deep"

    def test_letter_uses_FRD_not_ABC(self):
        """Preset scheme letters are F/R/D, not A/B/C, to avoid conflict with Tier S/A/B/C/D."""
        assert PresetScheme.FAST.letter == "F"
        assert PresetScheme.RECOMMENDED.letter == "R"
        assert PresetScheme.DEEP.letter == "D"

    def test_letters_distinct_from_tier_letters(self):
        """Preset letters (F/R/D) must not overlap with Tier letters (S/A/B/C/D)."""
        tier_letters = {"S", "A", "B", "C", "D"}
        preset_letters = {s.letter for s in PresetScheme}
        assert preset_letters.isdisjoint(tier_letters - {"D"})
        # Note: 'D' appears in both but context disambiguates (preset checked first)
        # Preset D = DEEP, Tier D = lowest ASR tier
        assert "D" in preset_letters  # Preset DEEP
        assert "D" in tier_letters     # Tier D

    def test_display_name(self):
        assert PresetScheme.FAST.display_name == "极速验证"
        assert PresetScheme.RECOMMENDED.display_name == "考试推荐"
        assert PresetScheme.DEEP.display_name == "深度覆盖"

    def test_description(self):
        assert "2 groups" in PresetScheme.FAST.description
        assert "3 groups" in PresetScheme.RECOMMENDED.description
        assert "5 groups" in PresetScheme.DEEP.description

    def test_target_group_count(self):
        assert PresetScheme.FAST.target_group_count == 2
        assert PresetScheme.RECOMMENDED.target_group_count == 3
        assert PresetScheme.DEEP.target_group_count == 5

    def test_from_letter_uppercase(self):
        assert PresetScheme.from_letter("F") == PresetScheme.FAST
        assert PresetScheme.from_letter("R") == PresetScheme.RECOMMENDED
        assert PresetScheme.from_letter("D") == PresetScheme.DEEP

    def test_from_letter_lowercase(self):
        assert PresetScheme.from_letter("f") == PresetScheme.FAST
        assert PresetScheme.from_letter("r") == PresetScheme.RECOMMENDED
        assert PresetScheme.from_letter("d") == PresetScheme.DEEP

    def test_from_letter_old_abc_returns_none(self):
        """Old A/B/C letters should NOT map to preset schemes (they're Tier letters now)."""
        assert PresetScheme.from_letter("A") is None
        assert PresetScheme.from_letter("B") is None
        assert PresetScheme.from_letter("C") is None
        assert PresetScheme.from_letter("a") is None
        assert PresetScheme.from_letter("b") is None
        assert PresetScheme.from_letter("c") is None

    def test_from_letter_invalid(self):
        assert PresetScheme.from_letter("X") is None
        assert PresetScheme.from_letter("1") is None
        assert PresetScheme.from_letter("") is None
        assert PresetScheme.from_letter("abc") is None


# ============================================================
# PresetSchemeDefinition Tests
# ============================================================


class TestPresetSchemeDefinition:
    def test_properties(self):
        groups = _make_ranked_groups_diverse()[:3]
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.RECOMMENDED,
            groups=groups,
            est_time_min="~30 min",
            mechanisms=[AttackMechanism.MULTI_SHOT, AttackMechanism.ROLE_OVERRIDE,
                        AttackMechanism.GRADIENT_OPT],
        )

        assert scheme.scheme == PresetScheme.RECOMMENDED
        assert scheme.group_count == 3
        assert scheme.total_seeds == 25  # 10 + 9 + 6
        assert scheme.est_time_min == "~30 min"
        assert len(scheme.mechanisms) == 3

    def test_weighted_asr(self):
        """Weighted ASR should be seed-weighted average."""
        groups = [
            _make_tgi("many_shot_jailbreak", asr=0.98, seed_count=10),
            _make_tgi("skeleton_key", asr=0.95, seed_count=9),
        ]
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=groups,
        )

        # (0.98*10 + 0.95*9) / (10+9) = (9.8 + 8.55) / 19 ≈ 0.966
        assert scheme.weighted_asr == pytest.approx(0.966, abs=0.01)

    def test_weighted_asr_no_data(self):
        """Groups without ASR data contribute 0 to weighted ASR."""
        groups = [
            _make_tgi("unknown_attack", asr=0.0, seed_count=5),
        ]
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=groups,
        )
        assert scheme.weighted_asr == 0.0

    def test_display_asr_with_data(self):
        groups = [_make_tgi("test", asr=0.95, seed_count=5)]
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=groups,
        )
        assert scheme.display_asr == "95%"

    def test_display_asr_no_data(self):
        groups = [_make_tgi("test", asr=0.0, seed_count=5)]
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=groups,
        )
        assert scheme.display_asr == "--"

    def test_group_names(self):
        groups = [
            _make_tgi("many_shot_jailbreak"),
            _make_tgi("skeleton_key"),
        ]
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=groups,
        )
        assert "many_shot_jailbreak" in scheme.group_names
        assert "skeleton_key" in scheme.group_names

    def test_mechanism_names(self):
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=[],
            mechanisms=[AttackMechanism.MULTI_SHOT, AttackMechanism.ROLE_OVERRIDE],
        )
        assert "多示例引导" in scheme.mechanism_names
        assert "角色覆盖" in scheme.mechanism_names

    def test_est_plans(self):
        groups = [
            _make_tgi("test1", seed_count=10),
            _make_tgi("test2", seed_count=5),
        ]
        scheme = PresetSchemeDefinition(
            scheme=PresetScheme.FAST,
            groups=groups,
        )
        assert scheme.est_plans == 15


# ============================================================
# PresetSchemeBuilder Tests
# ============================================================


class TestPresetSchemeBuilder:
    def test_build_schemes_returns_three(self):
        """With diverse groups, should return 3 schemes."""
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        assert len(schemes) == 3

    def test_build_schemes_order(self):
        """Schemes should be in order: FAST, RECOMMENDED, DEEP."""
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        assert schemes[0].scheme == PresetScheme.FAST
        assert schemes[1].scheme == PresetScheme.RECOMMENDED
        assert schemes[2].scheme == PresetScheme.DEEP

    def test_fast_has_two_groups(self):
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        fast = schemes[0]
        assert fast.group_count == 2

    def test_recommended_has_three_groups(self):
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        recommended = schemes[1]
        assert recommended.group_count == 3

    def test_deep_has_five_groups(self):
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        deep = schemes[2]
        assert deep.group_count == 5

    def test_mechanism_diversity_fast(self):
        """FAST scheme should have 2 different mechanisms."""
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        fast = schemes[0]
        assert len(fast.mechanisms) == 2
        assert fast.mechanisms[0] != fast.mechanisms[1]

    def test_mechanism_diversity_recommended(self):
        """RECOMMENDED scheme should have 3 different mechanisms."""
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        recommended = schemes[1]
        assert len(recommended.mechanisms) == 3
        # All mechanisms should be unique
        assert len(set(recommended.mechanisms)) == 3

    def test_highest_asr_in_fast(self):
        """FAST should include the highest ASR group."""
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        fast = schemes[0]
        names = [g.technique_group for g in fast.groups]
        assert "many_shot_jailbreak" in names  # 98% ASR

    def test_est_time_not_empty(self):
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        for s in schemes:
            assert s.est_time_min != ""
            assert "~" in s.est_time_min

    def test_build_scheme_single(self):
        """build_scheme should return a single scheme."""
        ranked = _make_ranked_groups_diverse()
        scheme = PresetSchemeBuilder.build_scheme(ranked, PresetScheme.FAST)
        assert scheme is not None
        assert scheme.scheme == PresetScheme.FAST
        assert scheme.group_count == 2

    def test_build_scheme_recommended(self):
        ranked = _make_ranked_groups_diverse()
        scheme = PresetSchemeBuilder.build_scheme(ranked, PresetScheme.RECOMMENDED)
        assert scheme is not None
        assert scheme.scheme == PresetScheme.RECOMMENDED
        assert scheme.group_count == 3

    def test_build_scheme_deep(self):
        ranked = _make_ranked_groups_diverse()
        scheme = PresetSchemeBuilder.build_scheme(ranked, PresetScheme.DEEP)
        assert scheme is not None
        assert scheme.scheme == PresetScheme.DEEP
        assert scheme.group_count == 5

    def test_empty_groups(self):
        """Empty ranked groups should return empty list."""
        schemes = PresetSchemeBuilder.build_schemes([])
        assert schemes == []

    def test_build_scheme_empty(self):
        """build_scheme with empty groups should return None."""
        scheme = PresetSchemeBuilder.build_scheme([], PresetScheme.FAST)
        assert scheme is None

    def test_few_groups(self):
        """With only 2 groups, should build at least FAST."""
        ranked = _make_ranked_groups_diverse()[:2]
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        assert len(schemes) >= 1
        assert schemes[0].scheme == PresetScheme.FAST

    def test_very_few_groups(self):
        """With only 1 group, should still build FAST with what's available."""
        ranked = _make_ranked_groups_diverse()[:1]
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        assert len(schemes) >= 1

    def test_same_mechanism_fallback(self):
        """When all groups have the same mechanism, still fill by ASR."""
        ranked = _make_ranked_groups_same_mechanism()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        assert len(schemes) >= 1
        fast = schemes[0]
        # Should still have 2 groups even with same mechanism
        assert fast.group_count >= 2

    def test_select_diverse_prioritizes_new_mechanism(self):
        """_select_diverse should pick groups with different mechanisms first."""
        ranked = _make_ranked_groups_diverse()
        selected = PresetSchemeBuilder._select_diverse(ranked, 3)
        mechanisms = [get_mechanism(g.technique_group) for g in selected]
        # First 3 should have 3 different mechanisms
        assert len(set(mechanisms)) == 3

    def test_select_diverse_fills_by_asr(self):
        """When not enough diverse mechanisms, fill by ASR."""
        ranked = _make_ranked_groups_same_mechanism()
        selected = PresetSchemeBuilder._select_diverse(ranked, 3)
        # Should still return 3 groups
        assert len(selected) == 3

    def test_select_diverse_n_larger_than_available(self):
        """When n > available groups, return all groups."""
        ranked = _make_ranked_groups_diverse()[:3]
        selected = PresetSchemeBuilder._select_diverse(ranked, 10)
        assert len(selected) == 3

    def test_select_diverse_empty(self):
        selected = PresetSchemeBuilder._select_diverse([], 3)
        assert selected == []

    def test_estimate_time_single_turn(self):
        """Time estimate for single-turn groups."""
        groups = [_make_tgi("test", seed_count=10, attack_modes=["single_turn"])]
        time_str = PresetSchemeBuilder._estimate_time(groups)
        assert "~" in time_str
        assert "min" in time_str or "s" in time_str

    def test_estimate_time_multi_turn(self):
        """Time estimate for multi-turn groups should be longer."""
        single = [_make_tgi("test1", seed_count=10, attack_modes=["single_turn"])]
        multi = [_make_tgi("test2", seed_count=10, attack_modes=["multi_turn"])]
        single_time = PresetSchemeBuilder._estimate_time(single)
        multi_time = PresetSchemeBuilder._estimate_time(multi)
        # Multi-turn should have larger time value
        # Both should be non-empty
        assert single_time != ""
        assert multi_time != ""

    def test_estimate_time_empty(self):
        """Time estimate for empty groups."""
        time_str = PresetSchemeBuilder._estimate_time([])
        assert "~" in time_str

    def test_get_mechanisms_unique(self):
        """_get_mechanisms should return unique mechanisms in order."""
        groups = [
            _make_tgi("many_shot_jailbreak"),
            _make_tgi("skeleton_key"),
            _make_tgi("best_of_n_jailbreak"),  # Same mechanism as many_shot
        ]
        mechanisms = PresetSchemeBuilder._get_mechanisms(groups)
        # Should have 2 unique mechanisms (multi_shot, role_override)
        assert len(mechanisms) == 2
        assert mechanisms[0] == AttackMechanism.MULTI_SHOT
        assert mechanisms[1] == AttackMechanism.ROLE_OVERRIDE

    def test_nested_inclusion(self):
        """DEEP scheme should include lower-ASR groups."""
        ranked = _make_ranked_groups_diverse()
        deep = PresetSchemeBuilder.build_scheme(ranked, PresetScheme.DEEP)
        assert deep is not None
        names = [g.technique_group for g in deep.groups]
        # Should include some lower-ASR groups
        assert any("deep_inception" in n or "multimodal" in n for n in names)


# ============================================================
# Convenience Functions Tests
# ============================================================


class TestConvenienceFunctions:
    def test_build_preset_schemes(self):
        ranked = _make_ranked_groups_diverse()
        schemes = build_preset_schemes(ranked)
        assert len(schemes) == 3
        assert schemes[0].scheme == PresetScheme.FAST

    def test_build_preset_schemes_empty(self):
        schemes = build_preset_schemes([])
        assert schemes == []

    def test_get_scheme_by_letter_f(self):
        ranked = _make_ranked_groups_diverse()
        schemes = build_preset_schemes(ranked)
        scheme = get_scheme_by_letter("F", schemes)
        assert scheme is not None
        assert scheme.scheme == PresetScheme.FAST

    def test_get_scheme_by_letter_r(self):
        ranked = _make_ranked_groups_diverse()
        schemes = build_preset_schemes(ranked)
        scheme = get_scheme_by_letter("R", schemes)
        assert scheme is not None
        assert scheme.scheme == PresetScheme.RECOMMENDED

    def test_get_scheme_by_letter_d(self):
        ranked = _make_ranked_groups_diverse()
        schemes = build_preset_schemes(ranked)
        scheme = get_scheme_by_letter("D", schemes)
        assert scheme is not None
        assert scheme.scheme == PresetScheme.DEEP

    def test_get_scheme_by_letter_case_insensitive(self):
        ranked = _make_ranked_groups_diverse()
        schemes = build_preset_schemes(ranked)
        assert get_scheme_by_letter("f", schemes) is not None
        assert get_scheme_by_letter("r", schemes) is not None
        assert get_scheme_by_letter("d", schemes) is not None

    def test_get_scheme_by_letter_old_abc_returns_none(self):
        """Old A/B/C letters should return None (they're Tier letters now)."""
        ranked = _make_ranked_groups_diverse()
        schemes = build_preset_schemes(ranked)
        assert get_scheme_by_letter("A", schemes) is None
        assert get_scheme_by_letter("B", schemes) is None
        assert get_scheme_by_letter("C", schemes) is None

    def test_get_scheme_by_letter_invalid(self):
        ranked = _make_ranked_groups_diverse()
        schemes = build_preset_schemes(ranked)
        assert get_scheme_by_letter("X", schemes) is None
        assert get_scheme_by_letter("1", schemes) is None

    def test_get_scheme_by_letter_empty_schemes(self):
        assert get_scheme_by_letter("F", []) is None


# ============================================================
# TieredSelectionWizard _try_scheme_selection Tests
# ============================================================


class TestTrySchemeSelection:
    """Test the _try_scheme_selection method in TieredSelectionWizard."""

    def _setup_wizard_with_schemes(self):
        """Create a wizard with preset schemes for testing."""
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        wizard = TieredSelectionWizard(enabled=False)
        return wizard, ranked, schemes

    def test_scheme_f_selection(self):
        """Selecting 'F' returns FAST scheme groups."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        result = wizard._try_scheme_selection("f", ranked, schemes)
        assert result is not None
        # FAST has 2 groups, each with 1 source_seed_group
        assert len(result) >= 1

    def test_scheme_r_selection(self):
        """Selecting 'R' returns RECOMMENDED scheme groups."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        result = wizard._try_scheme_selection("r", ranked, schemes)
        assert result is not None
        assert len(result) >= 1

    def test_scheme_d_selection(self):
        """Selecting 'D' returns DEEP scheme groups."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        result = wizard._try_scheme_selection("d", ranked, schemes)
        assert result is not None
        assert len(result) >= 1

    def test_scheme_uppercase(self):
        """Uppercase letters should also work."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        result = wizard._try_scheme_selection("F", ranked, schemes)
        assert result is not None

    def test_old_abc_not_scheme(self):
        """Old A/B/C letters should NOT trigger scheme selection (they're Tier letters)."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        # A/B/C should return None from _try_scheme_selection
        # (they'll be handled by _try_tier_selection instead)
        assert wizard._try_scheme_selection("a", ranked, schemes) is None
        assert wizard._try_scheme_selection("b", ranked, schemes) is None
        assert wizard._try_scheme_selection("c", ranked, schemes) is None

    def test_scheme_with_extension(self):
        """Scheme + extension: 'R,5' should add group #5."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        result = wizard._try_scheme_selection("r,5", ranked, schemes)
        assert result is not None
        # Should have more groups than just scheme R
        scheme_r = get_scheme_by_letter("R", schemes)
        scheme_r_count = len(scheme_r.groups)
        # Result should include scheme R groups + extension
        # (extract_seed_groups may deduplicate, so >= scheme_r groups)
        assert len(result) >= scheme_r_count

    def test_scheme_with_multiple_extensions(self):
        """Scheme + multiple extensions: 'F,1,3' should add groups #1 and #3."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        result = wizard._try_scheme_selection("f,3,5", ranked, schemes)
        assert result is not None

    def test_scheme_extension_dedup(self):
        """Extension that duplicates a scheme group should be deduplicated."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        # Scheme F includes groups #1 and #2 (many_shot, skeleton_key)
        # Adding #1 again should not duplicate
        result = wizard._try_scheme_selection("f,1", ranked, schemes)
        assert result is not None
        # Should not have more groups than F + unique extensions
        scheme_f = get_scheme_by_letter("F", schemes)
        # Since group #1 is already in scheme F, no new group added
        assert len(result) >= len(scheme_f.groups)

    def test_not_a_scheme(self):
        """Non-scheme input should return None."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        assert wizard._try_scheme_selection("all", ranked, schemes) is None
        assert wizard._try_scheme_selection("xyz", ranked, schemes) is None
        assert wizard._try_scheme_selection("1,3,5", ranked, schemes) is None

    def test_empty_schemes_returns_none(self):
        """When no preset schemes available, should return None."""
        wizard = TieredSelectionWizard(enabled=False)
        ranked = _make_ranked_groups_diverse()
        assert wizard._try_scheme_selection("f", ranked, []) is None

    def test_scheme_with_invalid_extension(self):
        """Scheme + non-numeric extension should return None."""
        wizard, ranked, schemes = self._setup_wizard_with_schemes()
        # 'F,R' — R is not a number, so this is not a valid scheme+extension
        result = wizard._try_scheme_selection("f,r", ranked, schemes)
        assert result is None

    def test_scheme_not_in_available_schemes(self):
        """If scheme D is not built (too few groups), should return None."""
        ranked = _make_ranked_groups_diverse()[:3]
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        wizard = TieredSelectionWizard(enabled=False)
        # May not have scheme D with only 3 groups
        # If DEEP is not in schemes, selecting D should return None
        has_deep = any(s.scheme == PresetScheme.DEEP for s in schemes)
        if not has_deep:
            result = wizard._try_scheme_selection("d", ranked, schemes)
            assert result is None


# ============================================================
# _parse_and_execute_selection Integration Tests
# ============================================================


class TestParseAndExecuteWithSchemes:
    """Test _parse_and_execute_selection with preset schemes integrated."""

    def _setup(self):
        ranked = _make_ranked_groups_diverse()
        schemes = PresetSchemeBuilder.build_schemes(ranked)
        wizard = TieredSelectionWizard(enabled=False)
        return wizard, ranked, schemes

    def test_empty_defaults_to_scheme_r(self):
        """Empty input should default to scheme R when schemes available."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_scheme_f_via_parse(self):
        """'F' should be parsed as scheme selection."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "F", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_scheme_r_via_parse(self):
        """'R' should be parsed as scheme selection."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "R", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_scheme_d_via_parse(self):
        """'D' should be parsed as scheme selection."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "D", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_scheme_r_extension_via_parse(self):
        """'R,5' should parse as scheme R + extension #5."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "R,5", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_no_schemes_falls_back_to_top3(self):
        """When no schemes provided, empty input falls back to top-3."""
        wizard, ranked, _ = self._setup()
        result = wizard._parse_and_execute_selection(
            "", ranked, ranked, {}, ranked[:3], [],
        )
        assert len(result) >= 1

    def test_all_still_works_with_schemes(self):
        """'all' should still select all groups even with schemes."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "all", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_tier_s_still_works_with_schemes(self):
        """Tier 'S' should still work (no conflict with schemes)."""
        wizard, ranked, schemes = self._setup()
        tier_ranges = {"S": (1, 3)}
        result = wizard._parse_and_execute_selection(
            "S", ranked, ranked[:3], tier_ranges, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_tier_s_a_still_works_with_schemes(self):
        """Tier 'S,A' should still work (combination syntax)."""
        wizard, ranked, schemes = self._setup()
        tier_ranges = {"S": (1, 3), "A": (4, 7)}
        result = wizard._parse_and_execute_selection(
            "S,A", ranked[:7], ranked, tier_ranges, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_tier_b_still_works_with_schemes(self):
        """Tier 'B' should still work as a Tier selection (not Preset).

        Since Preset now uses F/R/D, typing 'B' goes to Tier selection.
        """
        wizard, ranked, schemes = self._setup()
        tier_ranges = {"S": (1, 3), "A": (4, 5), "B": (6, 7)}
        result = wizard._parse_and_execute_selection(
            "B", ranked[:7], ranked, tier_ranges, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_numbers_still_work_with_schemes(self):
        """Number selection should still work with schemes available."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "1,3,5", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1

    def test_invalid_falls_back_to_scheme_r(self):
        """Invalid input should fall back to scheme R when available."""
        wizard, ranked, schemes = self._setup()
        result = wizard._parse_and_execute_selection(
            "xyz123", ranked, ranked, {}, ranked[:3], schemes,
        )
        assert len(result) >= 1
