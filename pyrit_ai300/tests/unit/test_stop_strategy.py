"""
Tests for StopStrategyContext — the three-layer stopping strategy state container.

Key bug fix tested here:
  Before: Upgrade successes in _try_upgrade_plans were NOT counted toward L2
  OWASP threshold statistics, making the threshold almost unreachable.
  After:  stop_ctx.record_success() is called for both direct plan successes
  AND upgrade successes, ensuring L2 threshold is properly triggered.

Test coverage:
  1. StopStrategyContext basic state management
  2. L2 OWASP threshold logic (register_plans / should_skip / record_success)
  3. L3 global first-success stop
  4. MAX_REQUIRED_SUCCESSES cap for large plan counts
  5. Upgrade success counting toward L2 threshold (THE KEY BUG FIX)
  6. Upgrade success triggering L3 global stop
  7. ThresholdReachedInfo formatting
  8. Summary and metadata properties
  9. Disabled state (threshold=0.0, stop_on_first_success=False)
"""

import math
from unittest.mock import MagicMock

import pytest

from src.executor.workflow.stop_strategy import (
    MAX_REQUIRED_SUCCESSES,
    StopStrategyContext,
    SuccessRecordResult,
    ThresholdReachedInfo,
)


# ============================================================
# Helpers
# ============================================================


def _make_plan(plan_id="p1", owasp_id="LLM01"):
    """Create a mock plan with owasp_id attribute."""
    plan = MagicMock()
    plan.plan_id = plan_id
    plan.owasp_id = owasp_id
    return plan


def _make_plans(owasp_id="LLM01", count=6):
    """Create a list of mock plans for a single OWASP category."""
    return [_make_plan(f"p{i}", owasp_id) for i in range(count)]


# ============================================================
# 1. StopStrategyContext Basic State Management
# ============================================================


class TestStopStrategyContextBasic:
    """Test basic construction and state management."""

    def test_default_construction(self):
        """Default construction disables both L2 and L3."""
        ctx = StopStrategyContext()
        assert ctx.owasp_success_threshold == 0.0
        assert ctx.stop_on_first_success is False
        assert ctx.is_enabled() is False
        assert ctx.is_l2_enabled() is False
        assert ctx.is_l3_enabled() is False

    def test_l2_enabled(self):
        """L2 enabled with threshold > 0."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        assert ctx.is_l2_enabled() is True
        assert ctx.is_l3_enabled() is False
        assert ctx.is_enabled() is True

    def test_l3_enabled(self):
        """L3 enabled with stop_on_first_success=True."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        assert ctx.is_l2_enabled() is False
        assert ctx.is_l3_enabled() is True
        assert ctx.is_enabled() is True

    def test_both_enabled(self):
        """Both L2 and L3 enabled."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5, stop_on_first_success=True)
        assert ctx.is_l2_enabled() is True
        assert ctx.is_l3_enabled() is True
        assert ctx.is_enabled() is True

    def test_initial_state_empty(self):
        """Initial state has no plans registered."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        assert ctx.skipped_by_stop == 0
        assert ctx.skipped_owasps == []
        assert ctx.owasp_success_map == {}
        assert ctx.owasp_total_map == {}
        assert ctx.global_stop is False


# ============================================================
# 2. L2 OWASP Threshold Logic
# ============================================================


class TestL2ThresholdLogic:
    """Test L2 OWASP-aware success ratio threshold."""

    def test_register_plans_populates_totals(self):
        """register_plans correctly counts per-OWASP totals."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        plans = _make_plans("LLM01", 6) + _make_plans("LLM02", 4)
        ctx.register_plans(plans)
        assert ctx.owasp_total_map == {"LLM01": 6, "LLM02": 4}

    def test_should_skip_false_before_threshold(self):
        """should_skip returns False before threshold is reached."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        assert ctx.should_skip("LLM01") is False

    def test_record_success_no_threshold_before_reaching(self):
        """record_success returns no threshold_reached before threshold."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        # 50% of 6 = 3, need 3 successes
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is None
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is None

    def test_record_success_threshold_reached(self):
        """record_success returns threshold_reached when threshold met."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        # Need ceil(6 * 0.5) = 3 successes
        ctx.record_success("LLM01")
        ctx.record_success("LLM01")
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is not None
        assert result.threshold_reached.owasp_id == "LLM01"
        assert result.threshold_reached.success_count == 3
        assert result.threshold_reached.total_count == 6
        assert result.threshold_reached.remaining == 3

    def test_should_skip_true_after_threshold(self):
        """should_skip returns True after threshold is reached."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        # Reach threshold (3 successes)
        for _ in range(3):
            ctx.record_success("LLM01")
        assert ctx.should_skip("LLM01") is True

    def test_should_skip_other_owasp_after_threshold(self):
        """should_skip for other OWASP is not affected by one OWASP's threshold."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6) + _make_plans("LLM02", 4))
        # Reach threshold for LLM01
        for _ in range(3):
            ctx.record_success("LLM01")
        assert ctx.should_skip("LLM01") is True
        assert ctx.should_skip("LLM02") is False

    def test_threshold_not_re_triggered(self):
        """record_success only triggers threshold_reached once per OWASP."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        for _ in range(3):
            ctx.record_success("LLM01")
        # 4th success should not re-trigger
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is None

    def test_record_skip_increments_counter(self):
        """record_skip increments skipped_by_stop."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        ctx.record_skip()
        ctx.record_skip()
        assert ctx.skipped_by_stop == 2

    def test_unknown_owasp_id_handled(self):
        """None owasp_id is treated as 'UNKNOWN'."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans([_make_plan("p1", None)])
        assert ctx.owasp_total_map == {"UNKNOWN": 1}
        result = ctx.record_success(None)
        # 1 plan, 50% threshold = ceil(0.5) = 1 success needed
        assert result.threshold_reached is not None
        assert result.threshold_reached.owasp_id == "UNKNOWN"


# ============================================================
# 3. L3 Global First-Success Stop
# ============================================================


class TestL3GlobalStop:
    """Test L3 global first-success stop."""

    def test_global_stop_not_triggered_initially(self):
        """global_stop is False initially."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        assert ctx.global_stop is False

    def test_global_stop_triggered_on_success(self):
        """record_success triggers global_stop when L3 enabled."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        ctx.register_plans(_make_plans("LLM01", 3))
        result = ctx.record_success("LLM01")
        assert result.global_stop_triggered is True
        assert ctx.global_stop is True

    def test_should_skip_after_global_stop(self):
        """should_skip returns True for any OWASP after global stop."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        ctx.register_plans(_make_plans("LLM01", 3) + _make_plans("LLM02", 3))
        ctx.record_success("LLM01")
        # LLM02 should also be skipped
        assert ctx.should_skip("LLM02") is True
        assert ctx.should_skip("LLM01") is True
        assert ctx.should_skip("ANYTHING") is True

    def test_global_stop_only_triggered_once(self):
        """global_stop_triggered is only True on the first success."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        ctx.register_plans(_make_plans("LLM01", 3))
        result1 = ctx.record_success("LLM01")
        result2 = ctx.record_success("LLM01")
        assert result1.global_stop_triggered is True
        assert result2.global_stop_triggered is False

    def test_l3_without_l2(self):
        """L3 works independently without L2."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        ctx.register_plans(_make_plans("LLM01", 3))
        result = ctx.record_success("LLM01")
        assert result.global_stop_triggered is True
        assert result.threshold_reached is None  # L2 disabled


# ============================================================
# 4. MAX_REQUIRED_SUCCESSES Cap
# ============================================================


class TestMaxRequiredCap:
    """Test the MAX_REQUIRED_SUCCESSES cap for large plan counts."""

    def test_cap_applied_for_large_count(self):
        """37 plans * 0.5 = 19, but capped to MAX_REQUIRED_SUCCESSES."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 37))
        # Need min(ceil(37 * 0.5), 5) = min(19, 5) = 5 successes
        for _ in range(4):
            result = ctx.record_success("LLM01")
            assert result.threshold_reached is None
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is not None
        assert result.threshold_reached.success_count == 5

    def test_no_cap_for_small_count(self):
        """6 plans * 0.5 = 3, not capped."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        for _ in range(2):
            result = ctx.record_success("LLM01")
            assert result.threshold_reached is None
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is not None

    def test_cap_value(self):
        """MAX_REQUIRED_SUCCESSES is 5."""
        assert MAX_REQUIRED_SUCCESSES == 5

    def test_single_plan_threshold(self):
        """1 plan * 0.5 = 0.5, ceil = 1, cap = 1."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 1))
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is not None

    def test_high_threshold_large_count(self):
        """37 plans * 0.8 = 30, capped to 5."""
        ctx = StopStrategyContext(owasp_success_threshold=0.8)
        ctx.register_plans(_make_plans("LLM01", 37))
        for _ in range(4):
            ctx.record_success("LLM01")
        result = ctx.record_success("LLM01")
        assert result.threshold_reached is not None


# ============================================================
# 5. Upgrade Success Counting Toward L2 Threshold (KEY BUG FIX)
# ============================================================


class TestUpgradeSuccessCountsTowardL2:
    """
    THE KEY BUG FIX: Upgrade successes must count toward L2 threshold.

    Before fix: _try_upgrade_plans did not call owasp_success[oid] += 1,
    so L2 threshold was almost unreachable when most successes came from upgrades.

    After fix: stop_ctx.record_success() is called for both direct and upgrade
    successes, ensuring L2 threshold is properly triggered.
    """

    def test_upgrade_success_increments_owasp_success(self):
        """A single record_success call (simulating upgrade success) increments the counter."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        # Simulate: direct plan fails, upgrade succeeds
        ctx.record_success("LLM01")  # upgrade success
        assert ctx.owasp_success_map["LLM01"] == 1

    def test_upgrade_success_triggers_threshold(self):
        """Multiple upgrade successes can trigger L2 threshold."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        # Need 3 successes (ceil(6*0.5)=3)
        # Simulate: all 3 come from upgrades
        results = [ctx.record_success("LLM01") for _ in range(3)]
        assert results[-1].threshold_reached is not None
        assert ctx.should_skip("LLM01") is True

    def test_mixed_direct_and_upgrade_successes(self):
        """Mix of direct and upgrade successes correctly accumulates."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))
        # 1 direct success + 2 upgrade successes = 3 total
        ctx.record_success("LLM01")  # direct
        ctx.record_success("LLM01")  # upgrade
        result = ctx.record_success("LLM01")  # upgrade - should trigger
        assert result.threshold_reached is not None
        assert result.threshold_reached.success_count == 3

    def test_upgrade_success_skips_remaining_plans(self):
        """After upgrade success triggers threshold, remaining plans are skipped."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 4))
        # Need ceil(4*0.5) = 2 successes
        ctx.record_success("LLM01")  # direct success
        ctx.record_success("LLM01")  # upgrade success -> threshold reached
        assert ctx.should_skip("LLM01") is True

    def test_upgrade_success_different_owasp(self):
        """Upgrade success for one OWASP doesn't affect another."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 4) + _make_plans("LLM02", 4))
        # LLM01 reaches threshold via upgrades
        ctx.record_success("LLM01")
        ctx.record_success("LLM01")
        assert ctx.should_skip("LLM01") is True
        assert ctx.should_skip("LLM02") is False

    def test_upgrade_success_triggers_l3(self):
        """Upgrade success triggers L3 global stop when enabled."""
        ctx = StopStrategyContext(
            owasp_success_threshold=0.5,
            stop_on_first_success=True,
        )
        ctx.register_plans(_make_plans("LLM01", 6))
        # Simulate upgrade success
        result = ctx.record_success("LLM01")
        assert result.global_stop_triggered is True
        assert ctx.global_stop is True
        # All OWASPs should be skipped
        assert ctx.should_skip("LLM02") is True


# ============================================================
# 6. ThresholdReachedInfo Formatting
# ============================================================


class TestThresholdReachedInfo:
    """Test ThresholdReachedInfo formatting."""

    def test_format_message(self):
        """format_message produces human-readable message."""
        info = ThresholdReachedInfo(
            owasp_id="LLM01",
            success_count=3,
            total_count=6,
            ratio=0.5,
            threshold=0.5,
            remaining=3,
        )
        msg = info.format_message()
        assert "LLM01" in msg
        assert "3/6" in msg
        assert "50%" in msg
        assert "3" in msg

    def test_success_record_result_defaults(self):
        """SuccessRecordResult defaults are None/False."""
        result = SuccessRecordResult()
        assert result.threshold_reached is None
        assert result.global_stop_triggered is False


# ============================================================
# 7. Summary and Metadata Properties
# ============================================================


class TestSummaryAndMetadata:
    """Test summary output and metadata properties."""

    def test_get_skip_reasons_empty(self):
        """get_skip_reasons returns empty list when nothing skipped."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        assert ctx.get_skip_reasons() == []

    def test_get_skip_reasons_l2_only(self):
        """get_skip_reasons shows OWASP threshold when L2 triggered."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 2))
        ctx.record_success("LLM01")
        ctx.record_success("LLM01")
        reasons = ctx.get_skip_reasons()
        assert len(reasons) == 1
        assert "LLM01" in reasons[0]

    def test_get_skip_reasons_l3_only(self):
        """get_skip_reasons shows global stop when L3 triggered."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        ctx.register_plans(_make_plans("LLM01", 2))
        ctx.record_success("LLM01")  # Trigger global stop
        reasons = ctx.get_skip_reasons()
        assert len(reasons) == 1
        assert "全局首成功即停" in reasons[0]

    def test_get_skip_reasons_both(self):
        """get_skip_reasons shows both L2 and L3 when both triggered."""
        ctx = StopStrategyContext(
            owasp_success_threshold=0.5,
            stop_on_first_success=True,
        )
        ctx.register_plans(_make_plans("LLM01", 2))
        # 1 success triggers both L2 (ceil(2*0.5)=1) and L3
        ctx.record_success("LLM01")
        reasons = ctx.get_skip_reasons()
        assert len(reasons) == 2

    def test_owasp_success_map_after_successes(self):
        """owasp_success_map reflects recorded successes."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6) + _make_plans("LLM02", 4))
        ctx.record_success("LLM01")
        ctx.record_success("LLM01")
        ctx.record_success("LLM02")
        assert ctx.owasp_success_map == {"LLM01": 2, "LLM02": 1}

    def test_owasp_total_map_after_registration(self):
        """owasp_total_map reflects registered plans."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6) + _make_plans("LLM02", 4))
        assert ctx.owasp_total_map == {"LLM01": 6, "LLM02": 4}

    def test_skipped_owasps_after_threshold(self):
        """skipped_owasps lists OWASP IDs that reached threshold."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 2) + _make_plans("LLM02", 2))
        ctx.record_success("LLM01")
        ctx.record_success("LLM01")
        assert "LLM01" in ctx.skipped_owasps
        assert "LLM02" not in ctx.skipped_owasps


# ============================================================
# 8. Disabled State (Backward Compatibility)
# ============================================================


class TestDisabledState:
    """Test behavior when stop strategy is disabled (backward compatibility)."""

    def test_disabled_should_skip_always_false(self):
        """should_skip returns False when both L2 and L3 disabled."""
        ctx = StopStrategyContext()  # All disabled
        ctx.register_plans(_make_plans("LLM01", 6))
        assert ctx.should_skip("LLM01") is False

    def test_disabled_record_success_no_threshold(self):
        """record_success returns no threshold_reached when L2 disabled."""
        ctx = StopStrategyContext()
        ctx.register_plans(_make_plans("LLM01", 6))
        for _ in range(6):
            result = ctx.record_success("LLM01")
            assert result.threshold_reached is None

    def test_disabled_record_success_no_global_stop(self):
        """record_success returns no global_stop_triggered when L3 disabled."""
        ctx = StopStrategyContext()
        ctx.register_plans(_make_plans("LLM01", 6))
        result = ctx.record_success("LLM01")
        assert result.global_stop_triggered is False

    def test_disabled_success_still_recorded(self):
        """Successes are still recorded in owasp_success_map even when disabled."""
        ctx = StopStrategyContext()
        ctx.register_plans(_make_plans("LLM01", 6))
        ctx.record_success("LLM01")
        ctx.record_success("LLM01")
        # Map should still be populated (for metadata/reporting)
        assert ctx.owasp_success_map["LLM01"] == 2

    def test_disabled_get_skip_reasons_empty(self):
        """get_skip_reasons returns empty list when disabled."""
        ctx = StopStrategyContext()
        assert ctx.get_skip_reasons() == []

    def test_disabled_skipped_by_stop_still_works(self):
        """record_skip still increments counter even when disabled."""
        ctx = StopStrategyContext()
        ctx.record_skip()
        ctx.record_skip()
        assert ctx.skipped_by_stop == 2


# ============================================================
# 9. Integration Scenario: Simulating Real Batch Execution
# ============================================================


class TestIntegrationScenario:
    """
    Simulate a realistic batch execution flow to verify the bug fix.

    Scenario: 6 plans for LLM01, threshold=0.5 (need 3 successes).
    - Plan 1: direct success
    - Plan 2: fails, upgrade succeeds
    - Plan 3: direct success (triggers threshold)
    - Plans 4-6: should be skipped
    """

    def test_realistic_flow_with_upgrade_success(self):
        """Upgrade success in plan 2 counts toward threshold."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        plans = _make_plans("LLM01", 6)
        ctx.register_plans(plans)

        # Plan 1: direct success
        r1 = ctx.record_success("LLM01")
        assert r1.threshold_reached is None
        assert ctx.should_skip("LLM01") is False

        # Plan 2: fails, upgrade succeeds
        r2 = ctx.record_success("LLM01")  # upgrade success
        assert r2.threshold_reached is None
        assert ctx.should_skip("LLM01") is False

        # Plan 3: direct success -> triggers threshold (3/6 = 50%)
        r3 = ctx.record_success("LLM01")
        assert r3.threshold_reached is not None
        assert r3.threshold_reached.success_count == 3

        # Plans 4-6: should be skipped
        assert ctx.should_skip("LLM01") is True

        # Record skips for remaining plans
        for _ in range(3):
            ctx.record_skip()
        assert ctx.skipped_by_stop == 3

    def test_realistic_flow_all_upgrades(self):
        """All successes come from upgrades — threshold still triggers."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6))

        # All 3 successes come from upgrades (the bug scenario)
        for i in range(3):
            r = ctx.record_success("LLM01")
            if i < 2:
                assert r.threshold_reached is None
            else:
                assert r.threshold_reached is not None

        # Remaining 3 plans should be skipped
        assert ctx.should_skip("LLM01") is True

    def test_realistic_flow_l3_with_upgrade(self):
        """L3 global stop triggered by upgrade success."""
        ctx = StopStrategyContext(stop_on_first_success=True)
        ctx.register_plans(_make_plans("LLM01", 6) + _make_plans("LLM02", 6))

        # Plan 1 fails, upgrade succeeds -> L3 triggered
        r = ctx.record_success("LLM01")  # upgrade success
        assert r.global_stop_triggered is True

        # All remaining plans (both OWASPs) should be skipped
        assert ctx.should_skip("LLM01") is True
        assert ctx.should_skip("LLM02") is True

    def test_metadata_populated_correctly(self):
        """Result metadata is correctly populated after execution."""
        ctx = StopStrategyContext(owasp_success_threshold=0.5)
        ctx.register_plans(_make_plans("LLM01", 6) + _make_plans("LLM02", 4))

        # LLM01: 3 successes (triggers threshold)
        for _ in range(3):
            ctx.record_success("LLM01")
        # LLM02: 1 success
        ctx.record_success("LLM02")

        # 3 plans skipped (LLM01 remaining)
        for _ in range(3):
            ctx.record_skip()

        # Verify metadata
        assert ctx.owasp_success_map == {"LLM01": 3, "LLM02": 1}
        assert ctx.owasp_total_map == {"LLM01": 6, "LLM02": 4}
        assert ctx.skipped_by_stop == 3
        assert "LLM01" in ctx.skipped_owasps
        assert "LLM02" not in ctx.skipped_owasps
