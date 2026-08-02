# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Runtime Stop Strategy Event Handler — L5 execution resilience Layer 3+5.

Replaces pre-filtering stop strategies with runtime dynamic decisions.

Three-layer optimal stopping strategy:
  L1: FIRST_SUCCESS (PyRIT native, same objective multi-technique
      chain stops on first success). NOT handled here.
  L2: OWASP category success rate threshold (runtime, this module)
  L3: Global first-success stop (runtime, this module)

Design:
  Implements PyRIT native StrategyEventHandler interface.
  Tracks success/failure on ON_POST_EXECUTE events.
  Dynamically decides whether to stop remaining attacks based on threshold.

Difference from pre-filtering:
  - Pre-filtering: reduces seed_groups count before execution (may skip too early)
  - Runtime: makes dynamic decisions based on actual success counts (more precise)

Academic basis:
  - Optimal stopping theory (arXiv:2402.04249 HarmBench)
  - Multi-armed bandit early stopping (arXiv:2307.15043 Wei et al.)

> **Date**: 2026-8-2
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Cap required successes per OWASP category to prevent excessive attempts
_MAX_SUCCESS_PER_OWASP = 5


@dataclass
class StopStrategyContext:
    """Runtime stop strategy state.

    Tracks OWASP category success/failure counts.
    Emits stop signal when threshold is reached.
    """

    owasp_success: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    owasp_total: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    global_success: int = 0
    should_stop: bool = False
    stop_reason: str = ""

    def record_success(self, owasp_id: str) -> None:
        """Record a success for an OWASP category."""
        self.global_success += 1
        self.owasp_success[owasp_id] += 1

    def record_attempt(self, owasp_id: str) -> None:
        """Record an attempt for an OWASP category."""
        self.owasp_total[owasp_id] += 1

    def check_threshold(self, owasp_id: str, threshold: float) -> bool:
        """Check if an OWASP category has reached its success threshold.

        Args:
            owasp_id: OWASP category ID
            threshold: Success rate threshold (0.0-1.0)

        Returns:
            True if threshold reached
        """
        if threshold <= 0:
            return False
        total = self.owasp_total[owasp_id]
        if total == 0:
            return False
        required = min(
            math.ceil(total * threshold),
            _MAX_SUCCESS_PER_OWASP,
        )
        return self.owasp_success[owasp_id] >= required

    def get_stats(self) -> dict[str, Any]:
        """Get statistics summary."""
        return {
            "owasp_success": dict(self.owasp_success),
            "owasp_total": dict(self.owasp_total),
            "global_success": self.global_success,
            "should_stop": self.should_stop,
            "stop_reason": self.stop_reason,
        }


class RuntimeStopEventHandler:
    """Runtime stop strategy event handler.

    L2: OWASP category success rate threshold (runtime)
    L3: Global first-success stop (runtime)

    Usage:
        handler = RuntimeStopEventHandler(
            owasp_threshold=0.3,
            stop_on_first_success=False,
        )
        # Register with attack executor (if PyRIT supports event handlers)
        # Or use post-execution scan in stage_execute.py

    Note: This is a non-intrusive observer. It does not modify the
    Strategy execution behavior. The should_stop flag can be polled
    by the execution loop to break early.
    """

    def __init__(
        self,
        *,
        owasp_threshold: float = 0.0,
        stop_on_first_success: bool = False,
    ) -> None:
        """Initialize RuntimeStopEventHandler.

        Args:
            owasp_threshold: L2 OWASP category success rate threshold (0.0=disabled)
            stop_on_first_success: L3 global first-success stop
        """
        self._owasp_threshold = owasp_threshold
        self._stop_on_first = stop_on_first_success
        self.stop_context = StopStrategyContext()

    def on_attack_result(self, attack_result: Any) -> None:
        """Process an AttackResult after execution.

        Non-async version for post-execution scan integration
        (compatible with stage_execute.py's _scan_results_post_execution pattern).

        Args:
            attack_result: AttackResult instance with outcome and memory_labels
        """
        if attack_result is None:
            return

        # Extract OWASP ID from memory_labels
        labels = getattr(attack_result, "memory_labels", {}) or {}
        owasp_id = labels.get("owasp_id", "UNKNOWN")

        self.stop_context.record_attempt(owasp_id)

        outcome = getattr(attack_result, "outcome", None)
        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()

        if outcome_str == "SUCCESS":
            self.stop_context.record_success(owasp_id)

            # L3: Global first-success stop
            if self._stop_on_first:
                self.stop_context.should_stop = True
                self.stop_context.stop_reason = "L3: global first success"
                logger.info("L3 Stop: global first success triggered (owasp=%s)", owasp_id)
                return

            # L2: OWASP category threshold
            if (
                self._owasp_threshold > 0
                and self.stop_context.check_threshold(owasp_id, self._owasp_threshold)
            ):
                    self.stop_context.should_stop = True
                    total = self.stop_context.owasp_total[owasp_id]
                    succ = self.stop_context.owasp_success[owasp_id]
                    self.stop_context.stop_reason = (
                        f"L2: OWASP {owasp_id} threshold reached "
                        f"({succ}/{total} >= {self._owasp_threshold:.0%})"
                    )
                    logger.info(
                        "L2 Stop: OWASP %s threshold reached (%d/%d >= %.0f%%)",
                        owasp_id, succ, total, self._owasp_threshold * 100,
                    )

    def get_stats(self) -> dict[str, Any]:
        """Get stop strategy statistics."""
        return self.stop_context.get_stats()

    @property
    def should_stop(self) -> bool:
        """Whether the stop signal has been triggered."""
        return self.stop_context.should_stop

    @property
    def stop_reason(self) -> str:
        """Human-readable reason for the stop signal."""
        return self.stop_context.stop_reason
