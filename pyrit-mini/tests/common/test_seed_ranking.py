"""Tests for arm/seed_ranking.py - ASR-based seed ranking with UCB1.

Academic basis:
    - Yosinski et al. (arXiv:1411.1792) - Transfer learning for cold start
    - Auer et al. (2002) - UCB1 algorithm for multi-armed bandit
"""

import hashlib
from unittest.mock import MagicMock, patch

from pyrit.models import AttackSeedGroup, SeedObjective


def _make_seed_group(value: str = "test jailbreak seed prompt"):
    """Helper to create a valid AttackSeedGroup for testing."""
    objective = SeedObjective(value=value)
    return AttackSeedGroup(seeds=[objective])


class TestModelFamilyMapping:
    """Tests for _get_model_family()."""

    def test_gpt_models(self):
        """GPT model names should map to gpt family."""
        from arm.seed_ranking import _get_model_family

        assert _get_model_family("gpt-4o") == "gpt"
        assert _get_model_family("gpt-4o-mini") == "gpt"

    def test_claude_models(self):
        """Claude model names should map to claude family."""
        from arm.seed_ranking import _get_model_family

        assert _get_model_family("claude-3.5-sonnet") == "claude"
        assert _get_model_family("claude-4-opus") == "claude"

    def test_gemini_models(self):
        """Gemini model names should map to gemini family."""
        from arm.seed_ranking import _get_model_family

        assert _get_model_family("gemini-2.5-pro") == "gemini"

    def test_unknown_model_returns_none(self):
        """Unknown model names should return None."""
        from arm.seed_ranking import _get_model_family

        assert _get_model_family("completely-unknown-model-xyz") is None

    def test_o_series(self):
        """OpenAI o-series should map to o family."""
        from arm.seed_ranking import _get_model_family

        assert _get_model_family("o1") == "o"
        assert _get_model_family("o3") == "o"

    def test_qwen_models(self):
        """Qwen model names should map to qwen family."""
        from arm.seed_ranking import _get_model_family

        assert _get_model_family("qwen3-235b") == "qwen"


class TestSeedKeyGeneration:
    """Tests for _make_seed_key()."""

    def test_deterministic(self):
        """_make_seed_key should produce deterministic output."""
        from arm.seed_ranking import _make_seed_key

        key1 = _make_seed_key("test objective")
        key2 = _make_seed_key("test objective")
        assert key1 == key2

    def test_16_hex_chars(self):
        """Key should be 16 hex characters (SHA256 truncated)."""
        from arm.seed_ranking import _make_seed_key

        key = _make_seed_key("any objective")
        assert len(key) == 16
        assert all(c in "0123456789abcdef" for c in key)

    def test_different_inputs_different_keys(self):
        """Different objectives should produce different keys."""
        from arm.seed_ranking import _make_seed_key

        key1 = _make_seed_key("objective A")
        key2 = _make_seed_key("objective B")
        assert key1 != key2

    def test_empty_input_returns_empty(self):
        """Empty objective should return empty string."""
        from arm.seed_ranking import _make_seed_key

        assert _make_seed_key("") == ""

    def test_sha256_truncation(self):
        """Verify key matches SHA256 hex digest truncated to 16 chars."""
        from arm.seed_ranking import _make_seed_key

        objective = "verify hash function"
        expected = hashlib.sha256(objective.encode("utf-8")).hexdigest()[:16]
        assert _make_seed_key(objective) == expected


class TestRankByAsr:
    """Tests for _rank_by_asr()."""

    def test_returns_list(self):
        """_rank_by_asr should return a list."""
        from arm.seed_ranking import _rank_by_asr

        seeds = [_make_seed_group()]
        result = _rank_by_asr(seeds, {})
        assert isinstance(result, list)

    def test_empty_seeds_returns_empty(self):
        """Empty seeds list should return empty."""
        from arm.seed_ranking import _rank_by_asr

        result = _rank_by_asr([], {})
        assert result == []


class TestCategoryDiversity:
    """Tests for _apply_category_diversity()."""

    def test_returns_list(self):
        """_apply_category_diversity should return a list."""
        from arm.seed_ranking import _apply_category_diversity

        seeds = [_make_seed_group()]
        result = _apply_category_diversity(seeds, max_seeds=10)
        assert isinstance(result, list)


class TestRankSeedsForMultiTurn:
    """Tests for rank_seeds_for_multi_turn()."""

    def test_returns_list(self):
        """rank_seeds_for_multi_turn should return a list."""
        from arm.seed_ranking import rank_seeds_for_multi_turn

        seeds = [_make_seed_group()]
        result = rank_seeds_for_multi_turn(seeds, {})
        assert isinstance(result, list)

    def test_empty_seeds_returns_empty(self):
        """Empty seeds list should return empty."""
        from arm.seed_ranking import rank_seeds_for_multi_turn

        result = rank_seeds_for_multi_turn([], {})
        assert result == []


class TestAsrPriors:
    """Tests for load_asr_priors and update_asr_priors."""

    def test_load_asr_priors_returns_dict(self):
        """load_asr_priors should return a dict."""
        from arm.seed_ranking import load_asr_priors

        result = load_asr_priors("gpt-4o")
        assert isinstance(result, dict)


class TestUpdateAsrHistory:
    """Tests for update_asr_history()."""

    def test_accepts_dict_input(self):
        """update_asr_history should accept dict input without error."""
        from arm.seed_ranking import update_asr_history

        # Mock file operations to avoid filesystem side effects
        with patch("arm.seed_ranking.Path.mkdir"):
            with patch("builtins.open", MagicMock()):
                with patch("json.dump"):
                    update_asr_history({"test/seed": 0.5})


class TestGetTechniqueAsrPrior:
    """Tests for get_technique_asr_prior()."""

    def test_returns_float(self):
        """get_technique_asr_prior should return a float."""
        from arm.seed_ranking import get_technique_asr_prior

        priors = {"technique_asr": {"prompt_sending": {"default": 0.3}}}
        result = get_technique_asr_prior("prompt_sending", "gpt-4o", priors=priors)
        assert isinstance(result, float)

    def test_unknown_technique_returns_zero(self):
        """Unknown technique should return 0.0."""
        from arm.seed_ranking import get_technique_asr_prior

        result = get_technique_asr_prior("nonexistent_technique", "gpt-4o", priors={})
        assert result == 0.0
