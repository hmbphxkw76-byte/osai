"""Tests for arm.technique_picker module.

Covers: select_techniques, _validate_techniques, is_multi_turn_technique,
        augment_techniques_by_capability.
"""

from __future__ import annotations

from arm.technique_picker import (
    _AVAILABLE_TECHNIQUES,
    MULTI_TURN_TECHNIQUES,
    SINGLE_TURN_TECHNIQUES,
    augment_techniques_by_capability,
    is_multi_turn_technique,
    select_techniques,
)


class TestSelectTechniques:
    """Tests for select_techniques() function."""

    def test_auto_mode_returns_all_techniques_when_adversarial(self) -> None:
        """Auto mode with adversarial should return single + multi-turn."""
        result = select_techniques(mode="auto", has_adversarial=True)
        # Should contain all single-turn techniques
        for tech in SINGLE_TURN_TECHNIQUES:
            assert tech in result
        # Should contain all multi-turn techniques
        for tech in MULTI_TURN_TECHNIQUES:
            assert tech in result

    def test_auto_mode_excludes_multi_turn_without_adversarial(self) -> None:
        """Auto mode without adversarial should exclude multi-turn."""
        result = select_techniques(mode="auto", has_adversarial=False)
        for tech in SINGLE_TURN_TECHNIQUES:
            assert tech in result
        for tech in MULTI_TURN_TECHNIQUES:
            assert tech not in result

    def test_single_mode_returns_only_single_turn(self) -> None:
        """Single mode should return only single-turn techniques."""
        result = select_techniques(mode="single")
        assert result == list(SINGLE_TURN_TECHNIQUES)

    def test_multi_mode_returns_only_multi_turn(self) -> None:
        """Multi mode should return only multi-turn techniques."""
        result = select_techniques(mode="multi")
        assert result == list(MULTI_TURN_TECHNIQUES)

    def test_adaptive_mode_returns_adaptive_text(self) -> None:
        """Adaptive mode should return ['adaptive_text']."""
        result = select_techniques(mode="adaptive")
        assert result == ["adaptive_text"]

    def test_comma_separated_custom_mode(self) -> None:
        """Custom comma-separated mode should return specified techniques."""
        result = select_techniques(mode="prompt_sending,tap")
        assert "prompt_sending" in result
        assert "tap" in result
        assert len(result) == 2


class TestIsMultiTurnTechnique:
    """Tests for is_multi_turn_technique() function."""

    def test_multi_turn_techniques_return_true(self) -> None:
        """All MULTI_TURN_TECHNIQUES should return True."""
        for tech in MULTI_TURN_TECHNIQUES:
            assert is_multi_turn_technique(tech) is True, f"{tech} should be multi-turn"

    def test_single_turn_techniques_return_false(self) -> None:
        """All SINGLE_TURN_TECHNIQUES should return False."""
        for tech in SINGLE_TURN_TECHNIQUES:
            assert is_multi_turn_technique(tech) is False, f"{tech} should be single-turn"

    def test_adaptive_text_is_not_multi_turn(self) -> None:
        """adaptive_text should return False (special case)."""
        assert is_multi_turn_technique("adaptive_text") is False


class TestAugmentTechniquesByCapability:
    """Tests for augment_techniques_by_capability() function."""

    def test_none_capabilities_returns_unchanged(self) -> None:
        """None capabilities should return techniques unchanged."""
        base = ["prompt_sending"]
        result = augment_techniques_by_capability(base, None)
        assert result == base

    def test_empty_capabilities_returns_unchanged(self) -> None:
        """Empty string capabilities should return techniques unchanged."""
        base = ["prompt_sending"]
        result = augment_techniques_by_capability(base, "")
        assert result == base

    def test_mcp_capability_adds_techniques(self) -> None:
        """MCP capability should add context_compliance + skeleton_key."""
        base = ["prompt_sending"]
        result = augment_techniques_by_capability(base, "mcp")
        assert "context_compliance" in result
        assert "skeleton_key" in result

    def test_rag_capability_adds_context_compliance(self) -> None:
        """RAG capability should add context_compliance."""
        base = ["prompt_sending"]
        result = augment_techniques_by_capability(base, "rag")
        assert "context_compliance" in result

    def test_capability_deduplication(self) -> None:
        """Duplicate techniques should not be added."""
        base = ["context_compliance", "skeleton_key"]
        result = augment_techniques_by_capability(base, "mcp")
        # context_compliance and skeleton_key already present, no duplicates
        assert result.count("context_compliance") == 1
        assert result.count("skeleton_key") == 1

    def test_a2a_capability_backward_compat(self) -> None:
        """a2a alias should work like a2a_protocol."""
        base = ["prompt_sending"]
        result_a2a = augment_techniques_by_capability(base, "a2a")
        result_a2a_protocol = augment_techniques_by_capability(base, "a2a_protocol")
        assert result_a2a == result_a2a_protocol


class TestAvailableTechniques:
    """Tests for _AVAILABLE_TECHNIQUES catalog."""

    def test_single_turn_all_available(self) -> None:
        """All single-turn techniques should be in available set."""
        for tech in SINGLE_TURN_TECHNIQUES:
            assert tech in _AVAILABLE_TECHNIQUES, f"{tech} missing from available"

    def test_multi_turn_all_available(self) -> None:
        """All multi-turn techniques should be in available set."""
        for tech in MULTI_TURN_TECHNIQUES:
            assert tech in _AVAILABLE_TECHNIQUES, f"{tech} missing from available"
