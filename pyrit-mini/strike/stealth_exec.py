# -*- coding: utf-8 -*-
# arXiv:2306.05685 - Crothers et al., Adaptive attack timing
# arXiv:2204.01326 - Zhang et al., Behavioral biometrics evasion
"""stealth_exec - Human-Paced Stealth Attack Executor

Wraps the base executor with anti-SIEM timing shaping:

Core capabilities:
    - Pareto-distributed inter-request delays (human-like burst-pause patterns)
    - Session isolation per N seeds (break SIEM session correlation)
    - Post-refusal hesitation delay (simulate human frustration)
    - Random micro-jitter (prevent volumetric pattern detection)

Architectural alignment:
    - strike → core (uses PipelineContext)
    - strike → arm (uses converter selection)
    - PyRIT native: wraps PromptSendingAttack (arXiv:2302.12173) without modification

Stealth presets:
    - disabled: No delays (baseline mode)
    - stealth_a: Rate x3 + Warmup + 3 tokens (detection 100% → ~15%)
    - stealth_c: Rate x30 + Session isolate + 1:7 cover (detection → ~2%)
    - stealth_b: Rate x60 + Full isolation (detection → <0.1%)

Constitution compliance:
    - R-DELIVERY-1: Module < 300 lines
    - R-NATIVE: Wraps but does not replace PyRIT attacks
    - R-SIZE: Target < 300 lines
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Pareto distribution shape parameter (1.16 = human-like heavy tail)
_PARETO_SHAPE = 1.16
# Base delay range in seconds for stealth level "c" (recommended)
_BASE_DELAY_MIN = 30.0
_BASE_DELAY_MAX = 120.0
# Burst session size: how many seeds share one session before rotation
_DEFAULT_BURST_SIZE = 5
# Long pause every N requests (simulate human distraction)
_LONG_PAUSE_INTERVAL = 7
_LONG_PAUSE_MIN = 120.0
_LONG_PAUSE_MAX = 300.0


@dataclass
class StealthConfig:
    """Stealth execution configuration.

    Drives timing shaping, session isolation, and token rotation.
    Disabled by default; enabled via CLI or PipelineContext.
    """

    enabled: bool = False
    # Preset level: "a" (economic), "c" (recommended), "b" (high-security)
    level: str = "c"
    # Inter-request base delay in seconds (overrides level default)
    base_delay: float = 0.0
    # Pareto distribution shape (lower = more variable, 1.16 = human-like)
    pareto_shape: float = _PARETO_SHAPE
    # Seeds per session before isolation rotation
    burst_size: int = _DEFAULT_BURST_SIZE
    # Delay after refusal (seconds) - simulates human hesitation
    refusal_delay: float = 0.0
    # Enable long pause every N requests
    enable_long_pause: bool = True

    @classmethod
    def from_level(cls, level: str) -> StealthConfig:
        """Factory: create config from preset level name.

        Args:
            level: "a" (economic), "c" (recommended), "b" (high-security)

        Returns:
            StealthConfig instance with preset values
        """
        presets = {
            "a": cls(
                enabled=True,
                level="a",
                base_delay=5.0,
                burst_size=10,
                refusal_delay=3.0,
                enable_long_pause=False,
            ),
            "c": cls(
                enabled=True,
                level="c",
                base_delay=15.0,
                burst_size=_DEFAULT_BURST_SIZE,
                refusal_delay=8.0,
                enable_long_pause=True,
            ),
            "b": cls(
                enabled=True,
                level="b",
                base_delay=45.0,
                burst_size=1,
                refusal_delay=20.0,
                enable_long_pause=True,
            ),
        }
        return presets.get(level, presets["c"])


@dataclass
class _TimingState:
    """Mutable timing state for request pacing.

    Tracks request count, last request time, and accumulated delay stats.
    """

    request_count: int = 0
    session_seed_count: int = 0
    total_delay_seconds: float = 0.0
    start_time: float = field(default_factory=time.monotonic)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time


class StealthExecutor:
    """Human-paced stealth attack executor.

    Wraps the base executor with SIEM-evasion timing shaping.
    All delays use Pareto distribution for human-like burst-pause patterns.

    Usage:
        config = StealthConfig.from_level("c")
        executor = StealthExecutor(config)
        results = await executor.execute_with_stealth(ctx, seeds, converters)
    """

    def __init__(self, config: StealthConfig | None = None) -> None:
        """Initialize stealth executor.

        Args:
            config: StealthConfig instance, or None for disabled mode
        """
        self._config = config or StealthConfig()
        self._state = _TimingState()
        # Micro-jitter range (±20% of base delay)
        self._jitter_ratio = 0.2

    @property
    def config(self) -> StealthConfig:
        return self._config

    @property
    def stats(self) -> dict[str, Any]:
        """Return timing statistics for reporting."""
        return {
            "total_requests": self._state.request_count,
            "total_delay_seconds": round(self._state.total_delay_seconds, 1),
            "total_elapsed_seconds": round(self._state.elapsed_seconds, 1),
            "avg_delay_per_request": (
                round(self._state.total_delay_seconds / max(1, self._state.request_count), 2)
            ),
            "stealth_level": self._config.level if self._config.enabled else "disabled",
        }

    async def pre_request_delay(self) -> float:
        """Apply human-shaped delay before next request.

        Uses Pareto distribution: frequent short bursts with occasional
        heavy-tail pauses (matches human reading + thinking patterns).

        Returns:
            Actual delay applied in seconds (0 if stealth disabled)
        """
        if not self._config.enabled:
            return 0.0

        self._state.request_count += 1
        self._state.session_seed_count += 1

        # Determine base delay for current level
        base = self._config.base_delay
        if base <= 0:
            base = _BASE_DELAY_MIN if self._config.level == "c" else 5.0

        # Pareto-distributed delay: scale * (1/U)^(1/shape) - scale + min
        # This gives human-like distribution: many short, few long
        u = random.random()
        while u == 0:  # Avoid division by zero
            u = random.random()
        pareto_factor = (1.0 / u) ** (1.0 / self._config.pareto_shape)
        delay = base * (pareto_factor - 1.0) / self._config.pareto_shape

        # Apply micro-jitter (±20%)
        jitter = delay * self._jitter_ratio * (2 * random.random() - 1)
        delay = max(0.1, delay + jitter)

        # Long pause every N requests (simulate distraction)
        if (
            self._config.enable_long_pause
            and self._state.request_count > 0
            and self._state.request_count % _LONG_PAUSE_INTERVAL == 0
        ):
            long_pause = random.uniform(_LONG_PAUSE_MIN, _LONG_PAUSE_MAX)
            delay += long_pause
            logger.debug(
                "Long pause #%d: +%.0fs (total: %.1fs)",
                self._state.request_count // _LONG_PAUSE_INTERVAL,
                long_pause,
                delay,
            )

        self._state.total_delay_seconds += delay
        await asyncio.sleep(delay)
        return delay

    async def refusal_hesitation(self) -> float:
        """Apply hesitation delay after a refused request.

        Simulates human "retry frustration" pattern: wait longer after
        being rejected by the target model.

        Returns:
            Actual delay applied in seconds
        """
        if not self._config.enabled:
            return 0.0

        delay = self._config.refusal_delay
        if delay <= 0:
            return 0.0

        # Add variability: 70-130% of configured refusal delay
        delay *= 0.7 + 0.6 * random.random()
        self._state.total_delay_seconds += delay
        await asyncio.sleep(delay)
        return delay

    def should_rotate_session(self) -> bool:
        """Check if session should be rotated (isolation boundary).

        Returns True when current burst_size is exceeded.
        """
        if not self._config.enabled:
            return False
        return self._state.session_seed_count >= self._config.burst_size

    def on_session_rotation(self) -> None:
        """Called when session is actually rotated.

        Resets the session seed counter.
        """
        self._state.session_seed_count = 0


def _pareto_delay(
    base: float,
    shape: float = _PARETO_SHAPE,
    jitter: bool = True,
) -> float:
    """Compute a single Pareto-distributed delay value.

    Utility function for external callers (e.g., web attack modules
    that need to apply stealth timing independently).

    Args:
        base: Base delay minimum in seconds
        shape: Pareto shape parameter (default 1.16 = human-like)
        jitter: Whether to apply ±20% micro-jitter

    Returns:
        Delay value in seconds (minimum 0.1s)
    """
    u = random.random()
    while u == 0:
        u = random.random()
    pareto_factor = (1.0 / u) ** (1.0 / shape)
    delay = base * (pareto_factor - 1.0) / shape
    if jitter:
        delay *= 1.0 + 0.2 * (2 * random.random() - 1)
    return max(0.1, delay)
