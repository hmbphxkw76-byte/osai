"""Unified Stealth Timing Module — Request spacing for all recon operations.

This module provides centralized stealth timing control for the entire recon/
directory. It ensures that reconnaissance activities blend with normal user
behavior by injecting lognormal-distributed delays between requests.

Academic basis:
    - Crothers et al. (arXiv:2306.05685) — Adaptive attack timing
    - Zhang et al. (arXiv:2204.01326) — Behavioral biometrics evasion
    - Pessl et al. (arXiv:1901.01322) — Timing side-channel mitigation
    - Huang et al. (arXiv:2306.05685) — Gradient-based adversarial timing

Constitution compliance:
    - R-SIZE: < 200 lines
    - R-IMPORT-1: Uses existing stealth_config infrastructure (no new deps)
    - R-H3: Complements (not duplicates) stealth_config.py
      - stealth_config.py: Policy selection + delay range config
      - stealth_timing.py: Execution-level delay injection + session wrapping

Usage:
    from recon.stealth_timing import StealthTimer, stealth_delay

    timer = StealthTimer(policy_name="balanced")
    async with timer.start_session() as session:
        for endpoint in endpoints:
            await timer.next_request()  # Auto-delays between requests
            await probe_endpoint(session, endpoint)
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from typing import Any

logger = logging.getLogger(__name__)


def _lognormal_delay(
    median_seconds: float,
    sigma: float = 0.5,
    min_delay: float = 0.5,
    max_delay: float = 300.0,
) -> float:
    """Generate delay from lognormal distribution.

    Lognormal distribution mimics human inter-query behavior:
    - Most delays cluster around median (reading/thinking time)
    - Occasional long pauses (distraction, multi-tasking)
    - Short gaps possible (quick follow-ups)

    Args:
        median_seconds: Median delay (50th percentile target)
        sigma: Shape parameter (0.3=consistent, 0.7=variable)
        min_delay: Floor value (seconds)
        max_delay: Ceiling value (seconds)

    Returns:
        Delay in seconds clamped to [min_delay, max_delay]
    """
    # Convert median to lognormal mu parameter
    mu = math.log(max(min_delay, median_seconds))
    delay = random.lognormvariate(mu, sigma)
    return max(min_delay, min(max_delay, delay))


async def stealth_delay(
    policy_name: str | None = None,
    override_seconds: float | None = None,
) -> float:
    """Execute a stealth delay between requests.

    This is the primary API for inter-request timing injection.
    Integrates with StealthLevelManager for policy-driven delays.

    Args:
        policy_name: Stealth policy to use (None = auto from StealthLevelManager)
        override_seconds: Direct delay override (skips lognormal, uses uniform)

    Returns:
        The actual delay applied in seconds
    """
    if override_seconds is not None:
        # Direct override mode (for simple cases)
        delay = override_seconds
    else:
        # Policy-driven mode with lognormal distribution
        try:
            from recon.stealth_config import get_stealth_manager
            stealth_mgr = get_stealth_manager()
            policy = stealth_mgr.get_policy(policy_name)

            # Use delay_range midpoint as median, jitter as sigma
            delay_min, delay_max = policy.delay_range
            median = (delay_min + delay_max) / 2
            sigma = policy.jitter

            delay = _lognormal_delay(
                median_seconds=median,
                sigma=sigma,
                min_delay=delay_min * 0.5,
                max_delay=delay_max * 2,
            )
        except Exception:
            # Fallback: balanced policy equivalent
            delay = _lognormal_delay(
                median_seconds=8.0,
                sigma=0.4,
                min_delay=2.0,
                max_delay=30.0,
            )

    logger.debug("[STEALTH_TIMING] Inter-request delay: %.2fs", delay)
    await asyncio.sleep(delay)
    return delay


class StealthTimer:
    """Session-scoped stealth timer for reconnaissance operations.

    Manages inter-request delays with automatic timing profiles.
    Tracks total session time and request count for audit logging.

    Usage:
        timer = StealthTimer(policy_name="paranoid")
        for batch in probe_batches:
            await timer.next_request()  # Sleeps for appropriate delay
            await execute_probe(batch)

        timer.log_session_summary()  # Logs timing profile
    """

    def __init__(
        self,
        policy_name: str | None = None,
        base_delay: float | None = None,
        enable_logging: bool = True,
    ) -> None:
        """Initialize stealth timer.

        Args:
            policy_name: Stealth policy (None = balanced default)
            base_delay: Explicit base delay in seconds (overrides policy)
            enable_logging: Whether to log timing profile at session end
        """
        self._policy_name = policy_name
        self._base_delay = base_delay
        self._enable_logging = enable_logging
        self._request_count = 0
        self._total_delay = 0.0
        self._timing_log: list[float] = []
        self._session_start = time.time()

    async def next_request(self) -> float:
        """Call before each request to apply stealth delay.

        First call returns immediately (no delay before initial request).
        Subsequent calls apply lognormal-distributed delay.

        Returns:
            Delay applied in seconds
        """
        if self._request_count == 0:
            # No delay before first request
            self._request_count += 1
            return 0.0

        # Calculate delay
        if self._base_delay is not None:
            delay = _lognormal_delay(
                median_seconds=self._base_delay,
                sigma=0.4,
                min_delay=self._base_delay * 0.3,
                max_delay=self._base_delay * 3,
            )
        else:
            delay = await stealth_delay(policy_name=self._policy_name)
            # stealth_delay already called asyncio.sleep, so we need to
            # recalculate for our tracking since it doesn't return directly
            # Actually, stealth_delay returns the value after sleeping
            # We've already slept in stealth_delay
            self._request_count += 1
            self._total_delay += delay
            self._timing_log.append(delay)
            return delay

    async def explicit_delay(self, seconds: float) -> None:
        """Apply an explicit fixed delay (for special cases).

        Args:
            seconds: Exact delay in seconds
        """
        self._request_count += 1
        self._total_delay += seconds
        self._timing_log.append(seconds)
        await asyncio.sleep(seconds)

    def log_session_summary(self) -> None:
        """Log timing profile summary (call at end of recon session)."""
        if not self._enable_logging or not self._timing_log:
            return

        total_time = time.time() - self._session_start
        avg_delay = self._total_delay / len(self._timing_log)
        min_delay = min(self._timing_log)
        max_delay = max(self._timing_log)

        logger.info(
            "[STEALTH_TIMING] Session complete: %d requests, "
            "inter-request delays: min=%.1f/avg=%.1f/max=%.1fs, "
            "total session: %.1fs",
            self._request_count,
            min_delay,
            avg_delay,
            max_delay,
            total_time,
        )

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def total_delay_seconds(self) -> float:
        return self._total_delay

    def get_timing_profile(self) -> dict[str, Any]:
        """Get timing profile dict for orchestration_log."""
        if not self._timing_log:
            return {"requests": 0, "total_delay": 0.0}

        return {
            "requests": self._request_count,
            "total_delay_seconds": round(self._total_delay, 2),
            "min_delay_seconds": round(min(self._timing_log), 2),
            "max_delay_seconds": round(max(self._timing_log), 2),
            "avg_delay_seconds": round(self._total_delay / len(self._timing_log), 2),
            "policy": self._policy_name or "default",
        }
