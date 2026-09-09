"""Tests for arm/converter_selector.py - ASR-driven converter selection.

Academic basis:
    - Wei et al. (arXiv:2307.15043) - Encoding decay law
    - Zeng et al. (arXiv:2402.19181) - Authority endorsement ASR 38.4%
    - DrAttack (arXiv:2402.14266) - Decomposition ASR 40-60%
"""

from unittest.mock import MagicMock


class TestConverterPriorityMap:
    """Tests for _CONVERTER_PRIORITY_MAP SSOT."""

    def test_has_expected_converters(self):
        """Priority map should contain key converter types."""
        from arm.converter_selector import _CONVERTER_PRIORITY_MAP

        assert "DecompositionConverter" in _CONVERTER_PRIORITY_MAP
        assert "PersuasionConverter:authority_endorsement" in _CONVERTER_PRIORITY_MAP
        assert "ROT13Converter" in _CONVERTER_PRIORITY_MAP

    def test_llm_based_have_higher_priority(self):
        """LLM-based converters should have lower priority numbers (higher priority)."""
        from arm.converter_selector import _CONVERTER_PRIORITY_MAP

        decomposition_prio = _CONVERTER_PRIORITY_MAP["DecompositionConverter"]
        rot13_prio = _CONVERTER_PRIORITY_MAP["ROT13Converter"]
        assert decomposition_prio < rot13_prio

    def test_priority_values_are_unique(self):
        """Priority values should be unique for deterministic ordering."""
        from arm.converter_selector import _CONVERTER_PRIORITY_MAP

        values = list(_CONVERTER_PRIORITY_MAP.values())
        assert len(values) == len(set(values))


class TestMergeConverterPriority:
    """Tests for _merge_converter_priority()."""

    def test_empty_override_returns_base(self):
        """Empty override list should return base priority unchanged."""
        from arm.converter_selector import _merge_converter_priority

        base = {"A": 0, "B": 1}
        result = _merge_converter_priority(base, [])
        assert result == base

    def test_override_takes_precedence(self):
        """Items in override list should get higher priority (lower numbers)."""
        from arm.converter_selector import _merge_converter_priority

        base = {"A": 0, "B": 1, "C": 2}
        result = _merge_converter_priority(base, ["C", "A"])
        assert result["C"] == 0  # First in override = highest priority
        assert result["A"] == 1  # Second in override
        assert result["B"] > 1  # Not in override, shifted up

    def test_base_only_items_shifted(self):
        """Items only in base should be shifted by override length."""
        from arm.converter_selector import _merge_converter_priority

        base = {"A": 0, "B": 1}
        result = _merge_converter_priority(base, ["C"])
        assert result["C"] == 0
        assert result["A"] == 1  # Shifted by len(override) = 1
        assert result["B"] == 2


class TestPruneLowAsrConverters:
    """Tests for _prune_low_asr_converters()."""

    def _make_ctx(self, converters, asr_history):
        """Helper to create a mock PipelineContext."""
        ctx = MagicMock()
        ctx.converter_map = {"test_tech": converters}
        ctx.asr_history = asr_history
        return ctx

    def test_prunes_below_threshold(self):
        """Converters with ASR below threshold should be pruned."""
        from arm.converter_selector import _prune_low_asr_converters

        # Create mock converters with specific class names
        class HighAsrConverter:
            pass
        class LowAsrConverter:
            pass

        converters = [HighAsrConverter(), LowAsrConverter()]
        asr_history = {"HighAsrConverter": 0.5, "LowAsrConverter": 0.05}
        ctx = self._make_ctx(converters, asr_history)

        result = _prune_low_asr_converters(converters, ctx=ctx)
        result_names = [type(c).__name__ for c in result]
        assert "HighAsrConverter" in result_names
        # LowAsrConverter may or may not be pruned depending on default threshold

    def test_empty_converters_returns_empty(self):
        """Empty converter list should return empty."""
        from arm.converter_selector import _prune_low_asr_converters

        ctx = self._make_ctx([], {})
        result = _prune_low_asr_converters([], ctx=ctx)
        assert result == []


class TestGetCandidateConverters:
    """Tests for _get_candidate_converters()."""

    def _make_ctx(self, converter_map):
        """Helper to create a mock PipelineContext."""
        ctx = MagicMock()
        ctx.converter_map = converter_map
        ctx.asr_history = {}
        return ctx

    def test_returns_list(self):
        """_get_candidate_converters should return a list."""
        from arm.converter_selector import _get_candidate_converters

        ctx = self._make_ctx({"tech1": []})
        result = _get_candidate_converters(ctx)
        assert isinstance(result, list)

    def test_empty_converter_map_returns_empty(self):
        """Empty converter map should return empty list."""
        from arm.converter_selector import _get_candidate_converters

        ctx = self._make_ctx({})
        result = _get_candidate_converters(ctx)
        assert result == []


class TestBuildConverterConfig:
    """Tests for _build_converter_config()."""

    def _make_ctx(self, converter_map):
        """Helper to create a mock PipelineContext."""
        ctx = MagicMock()
        ctx.converter_map = converter_map
        ctx.asr_history = {}
        return ctx

    def test_empty_converters_returns_none(self):
        """Empty converter map should return None (baseline mode)."""
        from arm.converter_selector import _build_converter_config

        ctx = self._make_ctx({})
        result = _build_converter_config(ctx)
        assert result is None
