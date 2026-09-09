"""Tests for arm/seed_auto_expander.py - Async seed expansion with VariationConverter.

Academic basis:
    - AutoDAN (arXiv:2310.04451) - Automated prompt generation
    - Best-of-N (arXiv:2402.01135) - 3x seed expansion yields ASR 1.5-2x
"""

import asyncio
from unittest.mock import MagicMock, patch

from pyrit.models import AttackSeedGroup, SeedObjective


def _make_seed_group(value: str = "test jailbreak prompt for expansion"):
    """Helper to create a valid AttackSeedGroup for testing."""
    objective = SeedObjective(value=value)
    return AttackSeedGroup(seeds=[objective])


class TestUCBCComputation:
    """Tests for _compute_adaptive_ucb_c()."""

    def test_zero_pulls_returns_infinity(self):
        """Arms with zero pulls should get infinite UCB (force exploration)."""
        from arm.seed_auto_expander import _compute_adaptive_ucb_c

        result = _compute_adaptive_ucb_c(mean_reward=0.0, pull_count=0, total_pulls=10)
        assert result == float('inf')

    def test_higher_mean_reward_higher_ucb(self):
        """Arms with higher mean reward should have higher UCB."""
        from arm.seed_auto_expander import _compute_adaptive_ucb_c

        high_reward = _compute_adaptive_ucb_c(mean_reward=0.8, pull_count=5, total_pulls=20)
        low_reward = _compute_adaptive_ucb_c(mean_reward=0.2, pull_count=5, total_pulls=20)
        assert high_reward > low_reward

    def test_more_pulls_lower_exploration(self):
        """Arms with more pulls should have lower exploration bonus."""
        from arm.seed_auto_expander import _compute_adaptive_ucb_c

        few_pulls = _compute_adaptive_ucb_c(mean_reward=0.5, pull_count=1, total_pulls=20)
        many_pulls = _compute_adaptive_ucb_c(mean_reward=0.5, pull_count=10, total_pulls=20)
        assert few_pulls > many_pulls

    def test_custom_exploration_factor(self):
        """Higher exploration factor should increase UCB."""
        from arm.seed_auto_expander import _compute_adaptive_ucb_c

        default_factor = _compute_adaptive_ucb_c(mean_reward=0.5, pull_count=5, total_pulls=20, exploration_factor=1.414)
        high_factor = _compute_adaptive_ucb_c(mean_reward=0.5, pull_count=5, total_pulls=20, exploration_factor=3.0)
        assert high_factor > default_factor


class TestAutoGenerateSeedsAsync:
    """Tests for auto_generate_seeds_async()."""

    def test_no_target_returns_base_seeds(self):
        """Without converter_target, should return base seeds unchanged."""
        from arm.seed_auto_expander import auto_generate_seeds_async

        base_seeds = [_make_seed_group()]
        result = asyncio.run(auto_generate_seeds_async(base_seeds, None))
        assert result == base_seeds

    def test_empty_seeds_returns_empty(self):
        """Empty seed list should return empty."""
        from arm.seed_auto_expander import auto_generate_seeds_async

        result = asyncio.run(auto_generate_seeds_async([], MagicMock()))
        assert result == []

    async def test_import_error_returns_base_seeds(self):
        """When VariationConverter import fails, should return base seeds."""
        # Mock sys.modules to simulate import failure
        import sys

        from arm.seed_auto_expander import auto_generate_seeds_async
        real_module = sys.modules.get("pyrit.executor.converter")
        try:
            # Remove module to force ImportError
            if "pyrit.executor.converter" in sys.modules:
                del sys.modules["pyrit.executor.converter"]

            # Patch importlib to raise ImportError for this specific module
            original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

            def mock_import(name, *args, **kwargs):
                if name == "pyrit.executor.converter":
                    raise ImportError("Simulated import failure")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                base_seeds = [_make_seed_group("original prompt")]
                mock_target = MagicMock()

                result = await auto_generate_seeds_async(base_seeds, mock_target, expansion_factor=2)
                # Should return base seeds when import fails
                assert result == base_seeds
        finally:
            # Restore module
            if real_module:
                sys.modules["pyrit.executor.converter"] = real_module


class TestAutoGenerateSeeds:
    """Tests for auto_generate_seeds() sync wrapper."""

    def test_returns_list(self):
        """auto_generate_seeds should return a list."""
        from arm.seed_auto_expander import auto_generate_seeds

        base_seeds = [_make_seed_group()]
        result = auto_generate_seeds(base_seeds, None)
        assert isinstance(result, list)

    def test_no_target_passes_through(self):
        """Without target, seeds should pass through unchanged."""
        from arm.seed_auto_expander import auto_generate_seeds

        base_seeds = [_make_seed_group()]
        result = auto_generate_seeds(base_seeds, None)
        assert result == base_seeds
