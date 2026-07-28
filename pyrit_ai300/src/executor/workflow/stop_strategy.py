"""
Stop Strategy Context
=====================

Encapsulates the three-layer optimal stopping strategy for batch attack execution.

Design (PyRIT-native-first + self-built enhancement):
  L1: completion_policy=FIRST_SUCCESS — PyRIT native, same objective multi-technique
      chain stops on first success. NOT handled here (native PyRIT behavior).
  L2: owasp_success_threshold — Self-built. Within the same OWASP category, skip
      remaining plans when success ratio >= threshold. Different OWASP categories
      are tracked independently. The required success count is capped at
      MAX_REQUIRED_SUCCESSES to prevent excessive attempts for large plan counts.
  L3: stop_on_first_success — Self-built. Global first-success stop (most aggressive,
      ignores OWASP boundaries).

Key fix (v2): Upgrade successes in `_try_upgrade_plans` are now counted toward L2
threshold statistics. Previously, only direct plan successes triggered L2 checks,
making the threshold almost unreachable when most successes came from upgrades.

This module is designed as a pure state container with no I/O side effects.
Logging/printing is left to the caller via the returned result objects.
"""

import logging
import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Cap required successes to prevent excessive attempts for large plan counts.
# e.g., 37 plans * 0.5 = 19 (too many) -> capped to 5
MAX_REQUIRED_SUCCESSES = 5


@dataclass
class ThresholdReachedInfo:
    """Information returned when an OWASP category just reached its success threshold."""

    owasp_id: str
    success_count: int
    total_count: int
    ratio: float
    threshold: float
    remaining: int

    def format_message(self) -> str:
        """Format a human-readable threshold-reached message."""
        return (
            f"OWASP {self.owasp_id} 达到成功率阈值 "
            f"({self.success_count}/{self.total_count}={self.ratio:.0%} >= {self.threshold:.0%}) "
            f"-> 跳过该分类剩余 {self.remaining} 个计划"
        )


@dataclass
class SuccessRecordResult:
    """Result of recording a success, indicating what stop conditions were triggered."""

    threshold_reached: Optional[ThresholdReachedInfo] = None
    global_stop_triggered: bool = False


class StopStrategyContext:
    """
    Mutable state container for L2/L3 stop strategy.

    Thread-safety: This class is NOT thread-safe. It is designed for use within
    a single ``execute_batch`` call, where concurrency is managed by
    ``asyncio.Semaphore`` and state mutations happen in the event loop thread.

    Usage::

        stop_ctx = StopStrategyContext(
            owasp_success_threshold=0.5,
            stop_on_first_success=False,
        )
        stop_ctx.register_plans(attack_plans)

        # In _run_one:
        if stop_ctx.should_skip(plan.owasp_id):
            stop_ctx.record_skip()
            return
        # ... execute attack ...
        if success:
            result = stop_ctx.record_success(plan.owasp_id)
            if result.threshold_reached:
                print(result.threshold_reached.format_message())
            if result.global_stop_triggered:
                print("  [STOP]  Global first-success stop")

        # In _try_upgrade_plans:
        if upgrade_success:
            result = stop_ctx.record_success(upgraded_plan.owasp_id)
            # ... handle threshold/global_stop ...
    """

    def __init__(
        self,
        owasp_success_threshold: float = 0.0,
        stop_on_first_success: bool = False,
    ):
        """
        Args:
            owasp_success_threshold: L2 threshold (0.0 = disabled, 0.5 = exam recommended).
                Within the same OWASP category, skip remaining plans when
                success_count / total_count >= threshold.
            stop_on_first_success: L3 global first-success stop.
                When True, any success (direct or upgrade) stops all remaining plans.
        """
        self.owasp_success_threshold = owasp_success_threshold
        self.stop_on_first_success = stop_on_first_success

        # L2 state: per-OWASP counters
        self._owasp_total: Dict[str, int] = defaultdict(int)
        self._owasp_success: Dict[str, int] = defaultdict(int)
        self._owasp_skip: Dict[str, bool] = defaultdict(bool)

        # L3 state: global stop flag
        self._global_stop: bool = False

        # Shared counter: plans skipped due to stop strategy
        self._skipped_by_stop: int = 0

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_plans(self, plans: List) -> None:
        """Pre-register all attack plans to populate per-OWASP total counts.

        Must be called once before any ``should_skip`` / ``record_success`` calls.

        Args:
            plans: List of AttackPlan objects (must have ``owasp_id`` attribute).
        """
        for p in plans:
            oid = getattr(p, "owasp_id", None) or "UNKNOWN"
            self._owasp_total[oid] += 1

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def is_enabled(self) -> bool:
        """Whether any stop strategy is active (L2 or L3)."""
        return self.owasp_success_threshold > 0.0 or self.stop_on_first_success

    def is_l2_enabled(self) -> bool:
        """Whether L2 (OWASP threshold) is active."""
        return self.owasp_success_threshold > 0.0

    def is_l3_enabled(self) -> bool:
        """Whether L3 (global first-success) is active."""
        return self.stop_on_first_success

    def should_skip(self, owasp_id: Optional[str]) -> bool:
        """Check if a plan with the given OWASP ID should be skipped.

        Combines L3 (global stop) and L2 (per-OWASP skip) checks.

        Args:
            owasp_id: The OWASP ID of the plan to check.

        Returns:
            True if the plan should be skipped.
        """
        oid = owasp_id or "UNKNOWN"
        # L3: global stop
        if self.stop_on_first_success and self._global_stop:
            return True
        # L2: per-OWASP skip
        if self.owasp_success_threshold > 0.0 and self._owasp_skip.get(oid, False):
            return True
        return False

    @property
    def global_stop(self) -> bool:
        """Whether L3 global stop has been triggered."""
        return self._global_stop

    @property
    def skipped_by_stop(self) -> int:
        """Total number of plans skipped due to stop strategy."""
        return self._skipped_by_stop

    @property
    def skipped_owasps(self) -> List[str]:
        """List of OWASP IDs that have reached their threshold (L2 skip set)."""
        return [oid for oid, skip in self._owasp_skip.items() if skip]

    @property
    def owasp_success_map(self) -> Dict[str, int]:
        """Per-OWASP success counts (for BatchAttackResult metadata)."""
        return dict(self._owasp_success)

    @property
    def owasp_total_map(self) -> Dict[str, int]:
        """Per-OWASP total plan counts (for BatchAttackResult metadata)."""
        return dict(self._owasp_total)

    # ------------------------------------------------------------------
    # Mutation methods
    # ------------------------------------------------------------------

    def record_skip(self) -> None:
        """Increment the skipped-by-stop counter."""
        self._skipped_by_stop += 1

    def record_success(self, owasp_id: Optional[str]) -> SuccessRecordResult:
        """Record a success (from direct plan execution OR upgrade retry).

        This is the core method that fixes the bug where upgrade successes
        were not counted toward L2 threshold statistics.

        Args:
            owasp_id: The OWASP ID of the successful plan/upgrade.

        Returns:
            SuccessRecordResult indicating what stop conditions were triggered.
        """
        oid = owasp_id or "UNKNOWN"
        result = SuccessRecordResult()

        # L3: global first-success stop
        if self.stop_on_first_success and not self._global_stop:
            self._global_stop = True
            result.global_stop_triggered = True
            logger.info("Global first-success stop (stop_on_first_success=True)")

        # Always record success count (for metadata/reporting even when L2 disabled)
        self._owasp_success[oid] += 1

        # L2: OWASP threshold check (only when enabled)
        if self.owasp_success_threshold > 0.0:
            total_for_owasp = self._owasp_total[oid]
            success_for_owasp = self._owasp_success[oid]
            ratio = success_for_owasp / total_for_owasp if total_for_owasp > 0 else 0.0

            # Cap required successes to prevent excessive attempts for large plan counts
            _raw_required = math.ceil(total_for_owasp * self.owasp_success_threshold)
            required = min(_raw_required, MAX_REQUIRED_SUCCESSES)

            if success_for_owasp >= required and not self._owasp_skip.get(oid, False):
                self._owasp_skip[oid] = True
                remaining = total_for_owasp - success_for_owasp
                result.threshold_reached = ThresholdReachedInfo(
                    owasp_id=oid,
                    success_count=success_for_owasp,
                    total_count=total_for_owasp,
                    ratio=ratio,
                    threshold=self.owasp_success_threshold,
                    remaining=remaining,
                )
                logger.info(
                    "OWASP %s reached success threshold (%d/%d=%.0f%% >= %.0f%%) -> "
                    "skipping remaining %d plans",
                    oid,
                    success_for_owasp,
                    total_for_owasp,
                    ratio * 100,
                    self.owasp_success_threshold * 100,
                    remaining,
                )

        return result

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_skip_reasons(self) -> List[str]:
        """Get human-readable skip reason strings for summary output."""
        reasons = []
        if self.owasp_success_threshold > 0.0 and self.skipped_owasps:
            reasons.append(f"OWASP 阈值跳过: {self.skipped_owasps}")
        if self.stop_on_first_success and self._global_stop:
            reasons.append("全局首成功即停")
        return reasons
