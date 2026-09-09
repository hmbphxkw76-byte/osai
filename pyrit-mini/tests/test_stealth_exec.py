# -*- coding: utf-8 -*-
"""Tests for stealth_exec module.

Covers StealthConfig presets, Pareto delay distribution,
StealthExecutor state management, and session rotation logic.
"""
from __future__ import annotations

import pytest

from strike.stealth_exec import (
    StealthConfig,
    StealthExecutor,
    _pareto_delay,
)


class TestStealthConfig:
    """StealthConfig factory and validation."""

    def test_default_disabled(self) -> None:
        config = StealthConfig()
        assert config.enabled is False
        assert config.level == "c"

    def test_from_level_a(self) -> None:
        config = StealthConfig.from_level("a")
        assert config.enabled is True
        assert config.level == "a"
        assert config.base_delay == 5.0
        assert config.burst_size == 10
        assert config.enable_long_pause is False

    def test_from_level_c(self) -> None:
        config = StealthConfig.from_level("c")
        assert config.enabled is True
        assert config.level == "c"
        assert config.base_delay == 15.0
        assert config.burst_size == 5
        assert config.enable_long_pause is True

    def test_from_level_b(self) -> None:
        config = StealthConfig.from_level("b")
        assert config.enabled is True
        assert config.level == "b"
        assert config.base_delay == 45.0
        assert config.burst_size == 1

    def test_from_level_unknown_defaults_to_c(self) -> None:
        config = StealthConfig.from_level("unknown")
        assert config.level == "c"


class TestParetoDelay:
    """_pareto_delay utility function."""

    @pytest.mark.parametrize("base", [1.0, 5.0, 30.0])
    def test_delay_is_positive(self, base: float) -> None:
        for _ in range(20):
            delay = _pareto_delay(base, jitter=False)
            assert delay > 0

    def test_delay_scales_with_base(self) -> None:
        """Higher base should produce higher average delays."""
        small = [_pareto_delay(1.0, jitter=False) for _ in range(200)]
        large = [_pareto_delay(30.0, jitter=False) for _ in range(200)]
        assert sum(large) / len(large) > sum(small) / len(small)

    def test_jitter_increases_variance(self) -> None:
        """Jitter should add variability."""
        no_jitter = [_pareto_delay(10.0, jitter=False) for _ in range(100)]
        with_jitter = [_pareto_delay(10.0, jitter=True) for _ in range(100)]
        # Just verify they produce different values
        assert no_jitter != with_jitter


class TestStealthExecutor:
    """StealthExecutor class."""

    def test_init_default_disabled(self) -> None:
        executor = StealthExecutor()
        assert executor.config.enabled is False

    def test_init_with_config(self) -> None:
        config = StealthConfig.from_level("c")
        executor = StealthExecutor(config)
        assert executor.config.level == "c"

    @pytest.mark.asyncio
    async def test_pre_request_delay_disabled_returns_zero(self) -> None:
        executor = StealthExecutor()
        delay = await executor.pre_request_delay()
        assert delay == 0.0

    @pytest.mark.asyncio
    async def test_pre_request_delay_enabled_returns_positive(self) -> None:
        config = StealthConfig.from_level("a")
        executor = StealthExecutor(config)
        delay = await executor.pre_request_delay()
        assert delay >= 0.1

    @pytest.mark.asyncio
    async def test_pre_request_delay_increments_count(self) -> None:
        config = StealthConfig(enabled=True, level="a", base_delay=0.1)
        executor = StealthExecutor(config)
        await executor.pre_request_delay()
        assert executor._state.request_count == 1
        await executor.pre_request_delay()
        assert executor._state.request_count == 2

    @pytest.mark.asyncio
    async def test_refusal_hesitation_disabled(self) -> None:
        executor = StealthExecutor()
        delay = await executor.refusal_hesitation()
        assert delay == 0.0

    @pytest.mark.asyncio
    async def test_refusal_hesitation_enabled(self) -> None:
        config = StealthConfig(enabled=True, level="a", refusal_delay=0.1)
        executor = StealthExecutor(config)
        delay = await executor.refusal_hesitation()
        assert delay >= 0.05  # ~70% of 0.1 min

    def test_should_rotate_session_disabled(self) -> None:
        executor = StealthExecutor()
        assert executor.should_rotate_session() is False

    def test_should_rotate_session_after_burst(self) -> None:
        config = StealthConfig(enabled=True, level="c", burst_size=3)
        executor = StealthExecutor(config)
        for _ in range(3):
            executor._state.session_seed_count += 1
        assert executor.should_rotate_session() is True

    def test_should_rotate_session_below_threshold(self) -> None:
        config = StealthConfig(enabled=True, level="c", burst_size=5)
        executor = StealthExecutor(config)
        for _ in range(3):
            executor._state.session_seed_count += 1
        assert executor.should_rotate_session() is False

    def test_on_session_rotation_resets_counter(self) -> None:
        config = StealthConfig(enabled=True, level="c", burst_size=3)
        executor = StealthExecutor(config)
        for _ in range(5):
            executor._state.session_seed_count += 1
        executor.on_session_rotation()
        assert executor._state.session_seed_count == 0

    def test_stats_reporting(self) -> None:
        config = StealthConfig.from_level("c")
        executor = StealthExecutor(config)
        executor._state.request_count = 10
        executor._state.total_delay_seconds = 45.5
        stats = executor.stats
        assert stats["total_requests"] == 10
        assert stats["stealth_level"] == "c"
        assert stats["total_delay_seconds"] == 45.5


class TestImport:
    """Test that stealth modules are importable via strike package."""

    def test_import_from_strike_package(self) -> None:
        from strike import StealthConfig, StealthExecutor
        assert StealthConfig is not None
        assert StealthExecutor is not None

    def test_import_pareto_delay(self) -> None:
        from strike import _pareto_delay
        assert callable(_pareto_delay)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
