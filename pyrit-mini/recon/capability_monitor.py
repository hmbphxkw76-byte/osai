"""Capability Drift Monitor — 

Academic basis:
    - Chao et al. (arXiv:2310.08419) — ": ,
"
    - Anderson et al. (arXiv:2308.02678) — EvoCheck: 
    - Perez et al. (arXiv:2202.03286) — LLMs 

:
    1.  (Temporal Drift):  probe 
    2.  (Guardrail Update): 
    3.  (Model Version Change): model_family 
    4.  (Rate Limit): 

 (Rule 2: Stealth First):
     payload  ( probe),
     health check ()
    ""
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# 
# ====================================================================


@dataclass
class CapabilitySnapshot:
    """

    all,
    
    """
    timestamp: float
    seed_name: str
    converter_name: str
    attack_success: bool  # 
    refusal_detected: bool  # 
    response_time_ms: float  # 
    model_family: str | None = None
    status_code: int = 200
    error_type: str | None = None  # timeout / connection_error / parse_error


@dataclass
class DriftReport:
    """

    :
        has_drift: 
        drift_type:  (guardrail_update / model_change / rate_limit / consistent)
        confidence:  (0.0-1.0)
        evidence: 
        recommendations: 
    """
    has_drift: bool = False
    drift_type: str = "none"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    recommendations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_drift": self.has_drift,
            "drift_type": self.drift_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
        }


# ====================================================================
# 
# ====================================================================


class CapabilityDriftMonitor:
    """

    converter(s) probe ,
    

    Usage:
        >>> monitor = CapabilityDriftMonitor()
        >>> monitor.record_attack(attack_snapshot)
        >>> report = monitor.analyze_drift()
        >>> if report.has_drift:
        ...     handle_drift(report)
    """

    def __init__(self, window_size: int = 10, drift_threshold: float = 0.3) -> None:
        """

        Args:
            window_size:  ( 10 converter(s))
            drift_threshold:  ()
        """
        self._snapshots: list[CapabilitySnapshot] = []
        self._window_size = window_size
        self._drift_threshold = drift_threshold
        self._initial_model_family: str | None = None
        self._initial_refusal_rate: float = 0.0

    def record_attack(self, snapshot: CapabilitySnapshot) -> None:
        """

        
        , 

        Args:
            snapshot: 
        """
        # 
        if len(self._snapshots) == 0:
            self._initial_model_family = snapshot.model_family

        self._snapshots.append(snapshot)

        # 
        if len(self._snapshots) > self._window_size * 2:
            self._snapshots = self._snapshots[-self._window_size:]

        #  ()
        self._update_baseline()

    def _update_baseline(self) -> None:
        """ ( N converter(s))"""
        if len(self._snapshots) < 3:
            return

        initial_window = self._snapshots[: min(5, len(self._snapshots) // 2)]
        if not initial_window:
            return

        refused = sum(1 for s in initial_window if s.refusal_detected)
        self._initial_refusal_rate = refused / len(initial_window)

    def analyze_drift(self) -> DriftReport:
        """, 

        :
            1. :  >  + threshold
            2. : model_family 
            3. : 
            4. : 

        Returns:
            DriftReport 
        """
        report = DriftReport()

        if len(self._snapshots) < 5:
            report.drift_type = "insufficient_data"
            report.evidence.append(f"Only {len(self._snapshots)} snapshots, need >= 5")
            return report

        #  ( vs )
        mid = len(self._snapshots) // 2
        first_half = self._snapshots[:mid]
        second_half = self._snapshots[mid:]

        # 1. 
        first_refusal_rate = sum(1 for s in first_half if s.refusal_detected) / len(first_half)
        second_refusal_rate = sum(1 for s in second_half if s.refusal_detected) / len(second_half)

        if second_refusal_rate - first_refusal_rate > self._drift_threshold:
            report.has_drift = True
            report.drift_type = "guardrail_update"
            report.confidence = min(1.0, (second_refusal_rate - first_refusal_rate) * 2)
            report.evidence.append(
                f"Refusal rate increased: {first_refusal_rate:.0%} → {second_refusal_rate:.0%} "
                f"(threshold: {self._drift_threshold:.0%})"
            )
            report.recommendations = {
                "action": "slow_down_and_switch_strategy",
                "switch_to_templates": ["researcher_scenario_key_given", "chinese_academic_scenario"],
                "avoid_templates": ["system_override_skeleton_key", "direct_instruction"],
                "delay_range": [30.0, 60.0],
                "max_attempts_reduction": 0.5,
            }
            return report

        # 2. 
        model_families = {s.model_family for s in second_half if s.model_family}
        if model_families and self._initial_model_family:
            if any(mf != self._initial_model_family for mf in model_families):
                report.has_drift = True
                report.drift_type = "model_change"
                report.confidence = 0.85
                report.evidence.append(
                    f"Model family changed: '{self._initial_model_family}' → '{model_families}'"
                )
                report.recommendations = {
                    "action": "reidentify_and_remap_seeds",
                    "redetect_model_family": True,
                    "rebuild_seed_mapping": True,
                }
                return report

        # 3. 
        first_rt = sum(s.response_time_ms for s in first_half) / max(1, len(first_half))
        second_rt = sum(s.response_time_ms for s in second_half) / max(1, len(second_half))

        if second_rt > 0 and first_rt > 0:
            rt_ratio = second_rt / first_rt
            if rt_ratio > 3.0 and second_rt > 5000:  #  > 5s
                report.has_drift = True
                report.drift_type = "rate_limit"
                report.confidence = min(1.0, (rt_ratio - 2.0) / 5.0)
                report.evidence.append(
                    f"Response time increased: {first_rt:.0f}ms → {second_rt:.0f}ms "
                    f"(ratio: {rt_ratio:.1f}x)"
                )
                report.recommendations = {
                    "action": "exponential_backoff",
                    "delay_range": [60.0, 120.0],
                    "pause_attacks": True,
                    "resume_after_seconds": 300,
                }
                return report

        # 4. 
        report.drift_type = "consistent"
        report.evidence.append("No significant drift detected in recent snapshots")

        # Even if, 
        if second_refusal_rate > first_refusal_rate:
            report.recommendations = {
                "action": "monitor_closely",
                "trend": "refusal_rate_increasing_slightly",
                "suggestion": "Prepare alternative strategies",
            }
        else:
            report.recommendations = {"action": "continue_current_strategy"}

        return report

    def get_current_stats(self) -> dict[str, Any]:
        """"""
        if not self._snapshots:
            return {"total_snapshots": 0}

        total = len(self._snapshots)
        refused = sum(1 for s in self._snapshots if s.refusal_detected)
        success = sum(1 for s in self._snapshots if s.attack_success)
        avg_rt = sum(s.response_time_ms for s in self._snapshots) / max(1, total)

        return {
            "total_snapshots": total,
            "refusal_rate": round(refused / total, 3),
            "success_rate": round(success / total, 3),
            "avg_response_time_ms": round(avg_rt, 1),
            "model_family_history": list(
                {s.model_family for s in self._snapshots if s.model_family}
            ),
            "time_range_seconds": round(
                self._snapshots[-1].timestamp - self._snapshots[0].timestamp, 1
            ) if len(self._snapshots) >= 2 else 0,
        }

    def reset(self) -> None:
        """"""
        self._snapshots.clear()
        self._initial_model_family = None
        self._initial_refusal_rate = 0.0


# ====================================================================
# 
# ====================================================================

_default_monitor: CapabilityDriftMonitor | None = None


def get_drift_monitor() -> CapabilityDriftMonitor:
    """ CapabilityDriftMonitor """
    global _default_monitor
    if _default_monitor is None:
        _default_monitor = CapabilityDriftMonitor()
    return _default_monitor
