# -*- coding: utf-8 -*-
"""
AI-300 Framework - Remediation ROI Calculator (REV-10 / GAP-10)
修复建议 ROI 排序器：按修复投资回报率排序修复建议

核心功能：
1. 计算每个修复建议的 ROI（风险降低/修复成本）
2. 基于修复难度、实施时间、业务影响计算修复成本
3. 按降序排列修复建议（高 ROI 优先）
4. 支持自定义权重调整

ROI 计算公式：
- Risk Reduction = (Current Risk × Remediation Effectiveness) - Residual Risk
- Remediation Cost = Difficulty × Time × Business Disruption
- ROI = Risk Reduction / Remediation Cost

对齐文档：docs/architecture_review.md §5.2 GAP-10
预期收益：修复建议可执行性提升，优先处理高价值修复项
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 修复难度/时间/影响评估
# ──────────────────────────────────────────────────────────────────────────────

# 修复难度等级
REMEDIATION_DIFFICULTY = {
    "trivial": {"value": 1, "label": "Trivial", "hours": 2, "cost_factor": 0.5},
    "easy": {"value": 2, "label": "Easy", "hours": 8, "cost_factor": 1.0},
    "medium": {"value": 3, "label": "Medium", "hours": 40, "cost_factor": 2.0},
    "hard": {"value": 4, "label": "Hard", "hours": 160, "cost_factor": 5.0},
    "complex": {"value": 5, "label": "Complex", "hours": 640, "cost_factor": 10.0},
}

# 修复有效性（风险降低程度）
REMEDIATION_EFFECTIVENESS = {
    "high": 0.9,   # 减少 90% 风险
    "medium": 0.7, # 减少 70% 风险
    "low": 0.4,    # 减少 40% 风险
    "partial": 0.2, # 减少 20% 风险
}

# 业务影响（修复期间业务中断）
BUSINESS_IMPACT = {
    "none": {"value": 0, "label": "No Impact"},
    "low": {"value": 1, "label": "Low"},
    "medium": {"value": 2, "label": "Medium"},
    "high": {"value": 3, "label": "High"},
}


@dataclass
class RemediationSuggestion:
    """修复建议"""
    finding_id: str
    finding_name: str
    owasp_id: str
    cvss_score: float
    severity: str
    description: str
    remediation_text: str
    difficulty: str = "medium"
    effectiveness: str = "high"
    business_impact: str = "low"
    estimated_hours: int = 0
    estimated_cost: float = 0.0
    risk_reduction: float = 0.0
    roi: float = 0.0
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_name": self.finding_name,
            "owasp_id": self.owasp_id,
            "cvss_score": round(self.cvss_score, 1),
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation_text,
            "difficulty": self.difficulty,
            "effectiveness": self.effectiveness,
            "business_impact": self.business_impact,
            "estimated_hours": self.estimated_hours,
            "estimated_cost": round(self.estimated_cost, 0),
            "risk_reduction": round(self.risk_reduction, 2),
            "roi": round(self.roi, 2),
            "priority": self.priority,
        }


class ROICalculator:
    """
    修复建议 ROI 计算器 (REV-10)

    计算修复建议的投资回报率，并按降序排序。

    使用方式：
        calculator = ROICalculator()
        suggestions = [
            RemediationSuggestion(
                finding_id="F1",
                finding_name="Prompt Injection",
                owasp_id="LLM01",
                cvss_score=9.1,
                severity="Critical",
                description="...",
                remediation_text="Deploy prompt injection detection...",
                difficulty="medium",
                effectiveness="high",
            ),
        ]
        ranked = calculator.calculate_and_rank(suggestions)
        # ranked[0] 是 ROI 最高的修复建议
    """

    def __init__(
        self,
        hourly_rate: float = 100.0,
        weights: Optional[Dict[str, float]] = None,
    ):
        """
        Args:
            hourly_rate: 小时工时成本（美元）
            weights: 权重调整 {difficulty, effectiveness, business_impact}
        """
        self.hourly_rate = hourly_rate
        self.weights = weights or {"difficulty": 1.0, "effectiveness": 1.0, "business_impact": 1.0}

    def calculate_and_rank(
        self,
        suggestions: List[RemediationSuggestion],
    ) -> List[RemediationSuggestion]:
        """
        计算并排序修复建议

        Args:
            suggestions: 修复建议列表

        Returns:
            按 ROI 降序排序的修复建议列表
        """
        for suggestion in suggestions:
            self._calculate_roi(suggestion)

        # 按 ROI 降序排序
        ranked = sorted(suggestions, key=lambda s: (-s.roi, -s.cvss_score))

        # 分配优先级
        for i, suggestion in enumerate(ranked):
            suggestion.priority = i + 1

        return ranked

    def _calculate_roi(self, suggestion: RemediationSuggestion) -> None:
        """计算单个修复建议的 ROI"""
        # 1. 计算修复成本
        diff_info = REMEDIATION_DIFFICULTY.get(suggestion.difficulty, REMEDIATION_DIFFICULTY["medium"])
        hours = diff_info["hours"]
        if suggestion.estimated_hours > 0:
            hours = suggestion.estimated_hours

        # 修复成本 = 工时成本 × 难度因子 × 业务影响因子
        impact_info = BUSINESS_IMPACT.get(suggestion.business_impact, BUSINESS_IMPACT["low"])
        cost_factor = diff_info["cost_factor"] * (1 + impact_info["value"] * 0.5)
        cost = hours * self.hourly_rate * cost_factor * self.weights.get("difficulty", 1.0)

        suggestion.estimated_hours = hours
        suggestion.estimated_cost = cost

        # 2. 计算风险降低
        effectiveness = REMEDIATION_EFFECTIVENESS.get(
            suggestion.effectiveness, REMEDIATION_EFFECTIVENESS["high"]
        )

        # 风险降低 = CVSS 分数 × 有效性 × 权重
        risk_reduction = suggestion.cvss_score * effectiveness * self.weights.get("effectiveness", 1.0)

        # 残留风险（修复后仍存在的风险）
        residual_risk = suggestion.cvss_score * (1 - effectiveness)
        net_risk_reduction = risk_reduction - residual_risk

        suggestion.risk_reduction = net_risk_reduction

        # 3. 计算 ROI
        if cost > 0:
            suggestion.roi = net_risk_reduction / cost
        else:
            suggestion.roi = 0.0

    def get_remediation_priority_report(
        self,
        suggestions: List[RemediationSuggestion],
    ) -> str:
        """
        生成修复优先级报告

        Args:
            suggestions: 已排序的修复建议列表

        Returns:
            Markdown 格式的报告
        """
        lines = ["## 8. Remediation Recommendations (ROI-Based Priority)\n"]

        if not suggestions:
            lines.append("No remediation suggestions available.\n")
            return "\n".join(lines)

        # 总成本和风险降低汇总
        total_cost = sum(s.estimated_cost for s in suggestions)
        total_risk_reduction = sum(s.risk_reduction for s in suggestions)

        lines.append(
            f"**Total Estimated Cost:** ${total_cost:,.0f}\n"
            f"**Total Risk Reduction:** {total_risk_reduction:.1f} CVSS points\n"
        )

        # 按优先级分组
        high_roi = [s for s in suggestions if s.roi > 0.05]
        medium_roi = [s for s in suggestions if 0.02 <= s.roi <= 0.05]
        low_roi = [s for s in suggestions if s.roi < 0.02]

        # 高 ROI 修复项
        if high_roi:
            lines.append("\n### High Priority (ROI > 0.05)\n")
            lines.append("| Priority | Finding | Severity | CVSS | Cost | Hours | Risk Reduction | ROI |")
            lines.append("|----------|---------|----------|------|------|-------|----------------|-----|")
            for s in high_roi:
                lines.append(
                    f"| {s.priority} | {s.finding_name} | {s.severity} | {s.cvss_score:.1f} | "
                    f"${s.estimated_cost:,.0f} | {s.estimated_hours}h | {s.risk_reduction:.2f} | {s.roi:.3f} |"
                )

        # 中 ROI 修复项
        if medium_roi:
            lines.append("\n### Medium Priority (ROI 0.02-0.05)\n")
            lines.append("| Priority | Finding | Severity | CVSS | Cost | Hours | Risk Reduction | ROI |")
            lines.append("|----------|---------|----------|------|------|-------|----------------|-----|")
            for s in medium_roi:
                lines.append(
                    f"| {s.priority} | {s.finding_name} | {s.severity} | {s.cvss_score:.1f} | "
                    f"${s.estimated_cost:,.0f} | {s.estimated_hours}h | {s.risk_reduction:.2f} | {s.roi:.3f} |"
                )

        # 低 ROI 修复项
        if low_roi:
            lines.append("\n### Low Priority (ROI < 0.02)\n")
            lines.append("| Priority | Finding | Severity | CVSS | Cost | Hours | Risk Reduction | ROI |")
            lines.append("|----------|---------|----------|------|------|-------|----------------|-----|")
            for s in low_roi:
                lines.append(
                    f"| {s.priority} | {s.finding_name} | {s.severity} | {s.cvss_score:.1f} | "
                    f"${s.estimated_cost:,.0f} | {s.estimated_hours}h | {s.risk_reduction:.2f} | {s.roi:.3f} |"
                )

        # 详细建议（仅显示前 5 个）
        lines.append("\n### Top 5 Detailed Remediation\n")
        for s in suggestions[:5]:
            lines.append(
                f"#### #{s.priority} - {s.finding_name}\n"
                f"**OWASP:** {s.owasp_id} | **Severity:** {s.severity} | **CVSS:** {s.cvss_score:.1f}\n\n"
                f"**Recommended Action:**\n{s.remediation_text}\n\n"
                f"**Estimates:** {s.estimated_hours}h, ${s.estimated_cost:,.0f}, "
                f"Risk Reduction: {s.risk_reduction:.2f}, ROI: {s.roi:.3f}\n"
            )

        return "\n".join(lines)


def calculate_roi_and_rank(
    suggestions: List[RemediationSuggestion],
    hourly_rate: float = 100.0,
) -> List[RemediationSuggestion]:
    """便捷函数：计算并排序修复建议"""
    calculator = ROICalculator(hourly_rate=hourly_rate)
    return calculator.calculate_and_rank(suggestions)