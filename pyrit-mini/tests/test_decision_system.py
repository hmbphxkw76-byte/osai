# -*- coding: utf-8 -*-
"""tests/test_decision_system.py — Test suite for decision system modules.

Covers:
    - decision_safety: Safety boundary checks
    - asr_trend_tracker: ASR trend analysis
    - pair_tap_strategies: PAIR/TAP strategy determination
    - attack_knowledge_base: Cross-target knowledge transfer
    - attack_utils: SSOT is_attack_successful function
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest


# Test fixtures
@dataclass
class MockContext:
    """Mock PipelineContext for testing."""
    authorized_targets: list[str] | None = None
    forbidden_attack_types: list[str] | None = None
    max_concurrent_attacks: int | None = None
    current_concurrent_attacks: int = 0
    safety_budget_limit: int | None = None
    budget_consumed: dict[str, int] = field(default_factory=dict)
    forbidden_operations: list[str] | None = None
    max_objective_length: int = 10000
    enable_pair: bool = True
    enable_tap: bool = True
    decision_log: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class MockResult:
    """Mock attack result for testing."""
    outcome: str | None = None
    score_value: Any = None


# Test attack_utils SSOT
class TestAttackUtilsSSOT:
    """Test is_attack_successful as single source of truth."""

    def test_import_from_utils(self):
        """Verify import path works correctly."""
        from utils.attack_utils import is_attack_successful
        assert callable(is_attack_successful)

    def test_backward_compat_aliases(self):
        """Verify backward compatibility aliases exist."""
        from utils.attack_utils import _is_result_success, _is_success
        assert _is_success is not None
        assert _is_result_success is not None

    def test_success_outcome(self):
        """Test SUCCESS outcome detection."""
        from utils.attack_utils import is_attack_successful
        result = MockResult(outcome="SUCCESS")
        assert is_attack_successful(result) is True

    def test_failure_outcome(self):
        """Test FAILURE outcome detection."""
        from utils.attack_utils import is_attack_successful
        result = MockResult(outcome="FAILURE")
        assert is_attack_successful(result) is False

    def test_score_value_string(self):
        """Test string score_value detection."""
        from utils.attack_utils import is_attack_successful
        result = MockResult(score_value="true")
        assert is_attack_successful(result) is True

    def test_score_value_numeric(self):
        """Test numeric score_value detection."""
        from utils.attack_utils import is_attack_successful
        result = MockResult(score_value=1)
        assert is_attack_successful(result) is True

    def test_zero_score(self):
        """Test zero score returns False."""
        from utils.attack_utils import is_attack_successful
        result = MockResult(score_value=0)
        assert is_attack_successful(result) is False


# Test decision Safety
class TestDecisionSafety:
    """Test check_decision_safety_boundary."""

    def test_safe_decision(self):
        """Test decision passes safety check."""
        from strike.decision_safety import check_decision_safety_boundary
        ctx = MockContext(authorized_targets=["target1", "target2"])
        decision = {"target": "target1", "strategy": "pair"}
        is_safe, reason = check_decision_safety_boundary(ctx, decision)
        assert is_safe is True

    def test_unauthorized_target(self):
        """Test unauthorized target is blocked."""
        from strike.decision_safety import check_decision_safety_boundary
        ctx = MockContext(authorized_targets=["target1"])
        decision = {"target": "evil.com", "strategy": "pair"}
        is_safe, reason = check_decision_safety_boundary(ctx, decision)
        assert is_safe is False
        assert "not in authorized" in reason

    def test_forbidden_attack_type(self):
        """Test forbidden attack type is blocked."""
        from strike.decision_safety import check_decision_safety_boundary
        ctx = MockContext(forbidden_attack_types=["brute_force"])
        decision = {"target": "target1", "strategy": "brute_force"}
        is_safe, reason = check_decision_safety_boundary(ctx, decision)
        assert is_safe is False
        assert "forbidden" in reason

    def test_max_concurrent_exceeded(self):
        """Test max concurrent attacks limit."""
        from strike.decision_safety import check_decision_safety_boundary
        ctx = MockContext(max_concurrent_attacks=5, current_concurrent_attacks=5)
        decision = {"target": "target1", "strategy": "pair"}
        is_safe, reason = check_decision_safety_boundary(ctx, decision)
        assert is_safe is False
        assert "Max concurrent" in reason

    def test_budget_limit_exceeded(self):
        """Test budget limit enforcement."""
        from strike.decision_safety import check_decision_safety_boundary
        ctx = MockContext(safety_budget_limit=100, budget_consumed={"attacks": 100})
        decision = {"target": "target1", "strategy": "pair"}
        is_safe, reason = check_decision_safety_boundary(ctx, decision)
        assert is_safe is False
        assert "budget" in reason.lower()

    def test_validate_payload_success(self):
        """Test payload validation passes."""
        from strike.decision_safety import validate_decision_payload
        ctx = MockContext()
        is_valid, reason = validate_decision_payload(ctx, "pair", "test objective")
        assert is_valid is True

    def test_validate_payload_forbidden_op(self):
        """Test forbidden operation detection."""
        from strike.decision_safety import validate_decision_payload
        ctx = MockContext(forbidden_operations=["rm -rf", "delete"])
        is_valid, reason = validate_decision_payload(ctx, "pair", "delete all files")
        assert is_valid is False
        assert "forbidden" in reason.lower()

    def test_safety_report(self):
        """Test safety report generation."""
        from strike.decision_safety import get_decision_safety_report
        ctx = MockContext(
            authorized_targets=["target1"],
            decision_log=[
                {"target": "target1", "safety_check_passed": True},
                {"target": "evil.com", "safety_check_passed": False},
            ],
        )
        report = get_decision_safety_report(ctx)
        assert report["total_decisions"] == 2
        assert report["violations"] == 1


# Test ASR Trend Tracker
class TestASRTrendTracker:
    """Test ASRTrendTracker."""

    def test_basic_recording(self):
        """Test recording ASR measurements."""
        from strike.asr_trend_tracker import ASRRecord, ASRTrendTracker
        tracker = ASRTrendTracker()
        record = ASRRecord(phase="strike", technique="pair", asr=0.5)
        tracker.record(record)
        assert len(tracker.records) == 1

    def test_trend_analysis_improving(self):
        """Test improving trend detection."""
        from strike.asr_trend_tracker import ASRRecord, ASRTrendTracker
        tracker = ASRTrendTracker()
        for i, asr in enumerate([0.1, 0.2, 0.3, 0.4, 0.5]):
            tracker.record(ASRRecord(phase="strike", technique="pair", asr=asr))
        analysis = tracker.analyze_trend()
        assert analysis.trend_direction == "improving"

    def test_trend_analysis_degrading(self):
        """Test degrading trend detection."""
        from strike.asr_trend_tracker import ASRRecord, ASRTrendTracker
        tracker = ASRTrendTracker()
        for i, asr in enumerate([0.5, 0.4, 0.3, 0.2, 0.1]):
            tracker.record(ASRRecord(phase="strike", technique="pair", asr=asr))
        analysis = tracker.analyze_trend()
        assert analysis.trend_direction == "degrading"

    def test_cross_target_insights(self):
        """Test cross-target knowledge retrieval."""
        from strike.asr_trend_tracker import ASRRecord, ASRTrendTracker
        tracker = ASRTrendTracker()
        # Record data for previous targets
        tracker.record(ASRRecord(
            phase="strike", technique="pair", asr=0.8,
            target_id="previous_target_1",
        ))
        tracker.record(ASRRecord(
            phase="strike", technique="tap", asr=0.6,
            target_id="previous_target_1",
        ))
        # Query for new target
        insights = tracker.get_cross_target_insights("new_target")
        assert insights["has_previous_data"] is True
        assert insights["previous_targets"] == 1


# Test PAIR/TAP Strategies
class TestPairTapStrategies:
    """Test PAIR/TAP strategy determination."""

    def test_pair_recommended_for_low_asr(self):
        """Test PAIR is recommended for low ASR."""
        from strike.pair_tap_strategies import determine_pair_tap_strategy
        ctx = MockContext(enable_pair=True, enable_tap=True)
        strategy = determine_pair_tap_strategy(ctx, 0.05)
        assert strategy == "pair"

    def test_tap_recommended_for_moderate_asr(self):
        """Test TAP is recommended for moderate ASR."""
        from strike.pair_tap_strategies import determine_pair_tap_strategy
        ctx = MockContext(enable_pair=True, enable_tap=True)
        strategy = determine_pair_tap_strategy(ctx, 0.15)
        assert strategy == "tap"

    def test_none_for_high_asr(self):
        """Test no recommendation for high ASR."""
        from strike.pair_tap_strategies import determine_pair_tap_strategy
        ctx = MockContext()
        strategy = determine_pair_tap_strategy(ctx, 0.5)
        assert strategy is None

    def test_pair_disabled(self):
        """Test PAIR disabled falls back to None for very low ASR."""
        from strike.pair_tap_strategies import determine_pair_tap_strategy
        ctx = MockContext(enable_pair=False, enable_tap=True)
        strategy = determine_pair_tap_strategy(ctx, 0.05)
        assert strategy != "pair"

    def test_get_recommendation(self):
        """Test detailed recommendation with rationale."""
        from strike.pair_tap_strategies import get_pair_tap_recommendation
        ctx = MockContext()
        rec = get_pair_tap_recommendation(ctx, 0.05)
        assert rec["recommended"] is True
        assert rec["strategy"] == "pair"


# Test Attack Knowledge Base
class TestAttackKnowledgeBase:
    """Test AttackKnowledgeBase."""

    def test_record_and_query(self):
        """Test recording and querying entries."""
        from strike.attack_knowledge_base import (
            AttackKnowledgeBase,
            AttackKnowledgeEntry,
            KnowledgeQuery,
        )
        kb = AttackKnowledgeBase()  # In-memory only
        entry = AttackKnowledgeEntry(
            target_id="target1",
            target_type="openai",
            technique="pair",
            objective="test",
            asr=0.8,
        )
        kb.record(entry)
        results = kb.query(KnowledgeQuery(target_type="openai"))
        assert len(results) == 1
        assert results[0].technique == "pair"

    def test_best_techniques(self):
        """Test getting best techniques for target type."""
        from strike.attack_knowledge_base import (
            AttackKnowledgeBase,
            AttackKnowledgeEntry,
        )
        kb = AttackKnowledgeBase()
        kb.record(AttackKnowledgeEntry(
            target_id="t1", target_type="openai",
            technique="pair", objective="t", asr=0.9,
        ))
        kb.record(AttackKnowledgeEntry(
            target_id="t2", target_type="openai",
            technique="pair", objective="t", asr=0.7,
        ))
        kb.record(AttackKnowledgeEntry(
            target_id="t1", target_type="openai",
            technique="tap", objective="t", asr=0.5,
        ))
        best = kb.get_best_techniques("openai")
        assert best[0][0] == "pair"
        assert best[0][1] == 0.8  # Average of 0.9 and 0.7

    def test_transferable_strategies(self):
        """Test cross-target knowledge transfer."""
        from strike.attack_knowledge_base import (
            AttackKnowledgeBase,
            AttackKnowledgeEntry,
        )
        kb = AttackKnowledgeBase()
        kb.record(AttackKnowledgeEntry(
            target_id="previous", target_type="openai",
            technique="pair", objective="t", asr=0.85,
        ))
        result = kb.get_transferable_strategies("openai", "current_target")
        assert result["has_transferable_knowledge"] is True
        assert result["previous_targets"] == 1

    def test_empty_knowledge_base(self):
        """Test query on empty knowledge base."""
        from strike.attack_knowledge_base import (
            AttackKnowledgeBase,
            KnowledgeQuery,
        )
        kb = AttackKnowledgeBase()
        results = kb.query(KnowledgeQuery(target_type="openai"))
        assert len(results) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
