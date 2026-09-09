# -*- coding: utf-8 -*-
"""asr_trend_tracker.py — ASR Trend Tracking for Adaptive Decision Making.

Tracks ASR evolution across attack phases to inform strategy decisions.
Provides historical analysis for cross-target knowledge transfer.

Academic basis:
    - Thompson (arXiv:2403.04132): LLM Agent 攻击的统计显著性分析
    - Wei et al. (arXiv:2307.15043): 攻击乘数效应的量化评估
    - PyRIT (arXiv:2407.01232): 攻击结果追踪与统计分析

Constitution compliance:
    - R-DECIDE-2: Audit trail for decision rationale
    - R-H3: Single source for ASR trend data

Data Flow:
    攻击执行 → 记录 ASR → 趋势分析 → 策略调优
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ASRRecord:
    """Single ASR measurement at a point in time."""
    phase: str              # recon, arm, strike, escalate, advanced
    technique: str          # Attack technique name
    asr: float              # Attack Success Rate (0.0 - 1.0)
    timestamp: float = 0.0  # Unix timestamp
    target_id: str = ""     # Target identifier for cross-target transfer
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ASRTrendAnalysis:
    """ASR trend analysis result."""
    trend_direction: str    # improving, degrading, stable
    trend_slope: float      # Rate of change per phase
    peak_asr: float         # Maximum ASR achieved
    peak_technique: str     # Technique that achieved peak ASR
    recommendations: list[str] = field(default_factory=list)


class ASRTrendTracker:
    """Track and analyze ASR trends across attack phases.

    Enables data-driven strategy decisions based on historical performance.
    Supports cross-target knowledge transfer by storing target-specific data.
    """

    def __init__(self, max_history: int = 100) -> None:
        self.max_history = max_history
        self.records: list[ASRRecord] = []
        self._target_index: dict[str, list[int]] = {}  # target_id -> record indices

    def record(self, record: ASRRecord) -> None:
        """Add an ASR measurement to the tracker."""
        if len(self.records) >= self.max_history:
            self.records.pop(0)

        idx = len(self.records)
        self.records.append(record)

        # Update target index
        if record.target_id:
            if record.target_id not in self._target_index:
                self._target_index[record.target_id] = []
            self._target_index[record.target_id].append(idx)

    def analyze_trend(
        self,
        window: int = 5,
        target_id: str | None = None,
    ) -> ASRTrendAnalysis:
        """Analyze ASR trend over recent measurements.

        Args:
            window: Number of recent measurements to consider.
            target_id: If provided, filter records for specific target.

        Returns:
            ASRTrendAnalysis with trend direction, slope, and recommendations.
        """
        records = self._get_records(target_id)
        if len(records) < 2:
            return ASRTrendAnalysis(
                trend_direction="insufficient_data",
                trend_slope=0.0,
                peak_asr=records[-1].asr if records else 0.0,
                peak_technique=records[-1].technique if records else "",
                recommendations=["Need more data points for trend analysis"],
            )

        # Use sliding window
        window_records = records[-window:]
        asr_values = [r.asr for r in window_records]

        # Simple linear regression for trend slope
        n = len(asr_values)
        x_values = list(range(n))
        x_mean = sum(x_values) / n
        y_mean = sum(asr_values) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, asr_values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        slope = numerator / denominator if denominator > 0 else 0.0

        # Determine trend direction
        if slope > 0.05:
            direction = "improving"
        elif slope < -0.05:
            direction = "degrading"
        else:
            direction = "stable"

        # Find peak performance
        peak_asr = max(asr_values)
        peak_idx = asr_values.index(peak_asr)
        peak_technique = window_records[peak_idx].technique

        # Generate recommendations
        recommendations = self._generate_recommendations(
            direction, slope, peak_asr, peak_technique, window_records,
        )

        return ASRTrendAnalysis(
            trend_direction=direction,
            trend_slope=slope,
            peak_asr=peak_asr,
            peak_technique=peak_technique,
            recommendations=recommendations,
        )

    def get_cross_target_insights(
        self,
        current_target_id: str,
    ) -> dict[str, Any]:
        """Get insights from previous targets to inform current strategy.

        Cross-target knowledge transfer: uses data from similar targets
        to bootstrap strategy selection.

        Args:
            current_target_id: The current target to exclude from "previous" data.

        Returns:
            Dict with best_performing_techniques, common_patterns, and suggested_strategies.
        """
        previous_records = [
            r for r in self.records
            if r.target_id and r.target_id != current_target_id
        ]

        if not previous_records:
            return {
                "has_previous_data": False,
                "recommendation": "No previous target data available",
            }

        # Aggregate by technique
        technique_asrs: dict[str, list[float]] = {}
        for r in previous_records:
            if r.technique not in technique_asrs:
                technique_asrs[r.technique] = []
            technique_asrs[r.technique].append(r.asr)

        # Calculate average ASR per technique
        avg_by_technique = {
            tech: sum(asrs) / len(asrs)
            for tech, asrs in technique_asrs.items()
        }

        # Sort by performance
        sorted_techniques = sorted(
            avg_by_technique.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return {
            "has_previous_data": True,
            "previous_targets": len(set(r.target_id for r in previous_records)),
            "best_performing_techniques": sorted_techniques[:5],
            "common_patterns": self._extract_common_patterns(previous_records),
        }

    def _get_records(self, target_id: str | None = None) -> list[ASRRecord]:
        """Get records, optionally filtered by target."""
        if target_id is None:
            return self.records
        indices = self._target_index.get(target_id, [])
        return [self.records[i] for i in indices if i < len(self.records)]

    def _generate_recommendations(
        self,
        direction: str,
        slope: float,
        peak_asr: float,
        peak_technique: str,
        window_records: list[ASRRecord],
    ) -> list[str]:
        """Generate strategy recommendations based on trend analysis."""
        recommendations = []

        if direction == "improving":
            recommendations.append(
                f"ASR trending up ({slope:+.3f}/phase) — continue current approach",
            )
            recommendations.append(
                f"Peak technique: {peak_technique} ({peak_asr:.1%})",
            )
        elif direction == "degrading":
            recommendations.append(
                f"ASR declining ({slope:.3f}/phase) — consider strategy pivot",
            )
            recommendations.append(
                f"Last peak: {peak_technique} ({peak_asr:.1%})",
            )
            recommendations.append("Try alternative techniques or escalation")
        else:
            recommendations.append(
                "ASR stable — explore new techniques to break plateau",
            )

        return recommendations

    def _extract_common_patterns(
        self,
        records: list[ASRRecord],
    ) -> list[str]:
        """Extract common success patterns from historical records."""
        if not records:
            return []

        # Count high-ASR technique occurrences
        high_asr_records = [r for r in records if r.asr >= 0.5]
        if not high_asr_records:
            return ["No high-ASR patterns found in previous targets"]

        technique_counts: dict[str, int] = {}
        for r in high_asr_records:
            technique_counts[r.technique] = technique_counts.get(r.technique, 0) + 1

        # Return top patterns
        sorted_patterns = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
        return [f"{tech} (count: {count})" for tech, count in sorted_patterns[:3]]
