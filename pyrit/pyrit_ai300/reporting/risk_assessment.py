# -*- coding: utf-8 -*-
"""
AI-300 Framework - 结构化风险评估模型

灵感来源：DeepTeam red_teamer/risk_assessment.py

提供结构化的风险评估数据模型，用于：
1. 将攻击结果转换为结构化风险评估
2. 生成统计摘要（按严重等级/风险类别/OWASP ID 分组）
3. 导出为 JSON/YAML 供下游系统消费
4. 支持报告生成器动态渲染
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from collections import Counter
import json


@dataclass
class RiskFinding:
    """单个风险发现"""
    finding_id: str               # 唯一标识
    owasp_id: str                 # OWASP ID（如 "LLM01"）
    owasp_title: str              # OWASP 标题
    category: str                 # 原始漏洞类别
    severity: str                 # 严重等级 critical/high/medium/low
    confidence: float = 0.5       # 置信度 0.0-1.0
    risk_category: str = ""      # 风险类别（如 "Security"）
    description: str = ""        # 描述
    evidence: str = ""           # 证据
    remediation: str = ""        # 修复建议
    tool: str = ""               # 发现工具
    source: str = ""             # 来源（recon/attack）

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "owasp_id": self.owasp_id,
            "owasp_title": self.owasp_title,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "risk_category": self.risk_category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "tool": self.tool,
            "source": self.source,
        }


@dataclass
class RiskAssessment:
    """
    结构化风险评估

    包含所有发现、统计摘要和风险评估结论。
    """
    findings: List[RiskFinding] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_risk_level: str = "unknown"
    owasp_coverage: List[str] = field(default_factory=list)  # 覆盖的 OWASP ID 列表
    risk_categories: List[str] = field(default_factory=list)
    framework_id: str = ""
    framework_name: str = ""

    def add_finding(self, finding: RiskFinding) -> None:
        """添加一个发现"""
        self.findings.append(finding)
        self._update_stats()

    def _update_stats(self) -> None:
        """更新统计"""
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == "critical")
        self.high_count = sum(1 for f in self.findings if f.severity == "high")
        self.medium_count = sum(1 for f in self.findings if f.severity == "medium")
        self.low_count = sum(1 for f in self.findings if f.severity == "low")

        # 更新总体风险等级
        if self.critical_count > 0:
            self.overall_risk_level = "critical"
        elif self.high_count > 0:
            self.overall_risk_level = "high"
        elif self.medium_count > 0:
            self.overall_risk_level = "medium"
        elif self.low_count > 0:
            self.overall_risk_level = "low"
        else:
            self.overall_risk_level = "none"

        # 更新 OWASP 覆盖
        self.owasp_coverage = sorted(set(f.owasp_id for f in self.findings if f.owasp_id))

        # 更新风险类别
        self.risk_categories = sorted(set(f.risk_category for f in self.findings if f.risk_category))

    def get_findings_by_severity(self, severity: str) -> List[RiskFinding]:
        """按严重等级筛选发现"""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_owasp(self, owasp_id: str) -> List[RiskFinding]:
        """按 OWASP ID 筛选发现"""
        return [f for f in self.findings if f.owasp_id == owasp_id]

    def get_findings_by_risk_category(self, category: str) -> List[RiskFinding]:
        """按风险类别筛选发现"""
        return [f for f in self.findings if f.risk_category == category]

    def get_severity_breakdown(self) -> Dict[str, int]:
        """获取严重等级分布"""
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "total": self.total_findings,
        }

    def get_owasp_breakdown(self) -> Dict[str, int]:
        """获取 OWASP ID 分布"""
        counter = Counter(f.owasp_id for f in self.findings if f.owasp_id)
        return dict(counter.most_common())

    def get_risk_category_breakdown(self) -> Dict[str, int]:
        """获取风险类别分布"""
        counter = Counter(f.risk_category for f in self.findings if f.risk_category)
        return dict(counter.most_common())

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        self._update_stats()
        return {
            "total_findings": self.total_findings,
            "severity_breakdown": self.get_severity_breakdown(),
            "owasp_breakdown": self.get_owasp_breakdown(),
            "risk_category_breakdown": self.get_risk_category_breakdown(),
            "overall_risk_level": self.overall_risk_level,
            "owasp_coverage": self.owasp_coverage,
            "risk_categories": self.risk_categories,
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """序列化为 JSON"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


@dataclass
class RedTeamingOverview:
    """
    红队评估概览

    提供高层视角的评估摘要，用于报告的 Executive Summary 部分。
    """
    assessment_id: str = ""
    target: str = ""
    framework_id: str = ""
    framework_name: str = ""
    overall_risk_level: str = "unknown"
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    owasp_coverage: List[str] = field(default_factory=list)
    risk_categories: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    assessment_duration: float = 0.0
    summary: str = ""

    @classmethod
    def from_risk_assessment(
        cls,
        assessment: RiskAssessment,
        target: str = "",
        tools_used: Optional[List[str]] = None,
        assessment_duration: float = 0.0,
    ) -> "RedTeamingOverview":
        """从 RiskAssessment 构建概览"""
        return cls(
            assessment_id="",
            target=target,
            framework_id=assessment.framework_id,
            framework_name=assessment.framework_name,
            overall_risk_level=assessment.overall_risk_level,
            total_findings=assessment.total_findings,
            critical_count=assessment.critical_count,
            high_count=assessment.high_count,
            medium_count=assessment.medium_count,
            low_count=assessment.low_count,
            owasp_coverage=assessment.owasp_coverage,
            risk_categories=assessment.risk_categories,
            tools_used=tools_used or [],
            assessment_duration=assessment_duration,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "overall_risk_level": self.overall_risk_level,
            "total_findings": self.total_findings,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "owasp_coverage": self.owasp_coverage,
            "risk_categories": self.risk_categories,
            "tools_used": self.tools_used,
            "assessment_duration": round(self.assessment_duration, 2),
            "summary": self.summary,
        }


def build_risk_assessment(
    results: List[dict],
    framework_id: str = "",
) -> RiskAssessment:
    """
    从攻击结果列表构建结构化风险评估

    Args:
        results: 攻击结果列表（pipeline 的 results 格式）
        framework_id: 框架 ID（如 "owasp_llm_2025"）

    Returns:
        RiskAssessment 实例
    """
    from ..standards.owasp_2025 import (
        get_owasp_entry,
        get_owasp_title,
        normalize_category,
    )
    from ..standards.risk_category import get_risk_category

    # 获取框架信息
    framework_name = ""
    if framework_id:
        from ..standards.framework_registry import get_framework
        fw = get_framework(framework_id)
        if fw:
            framework_name = fw.framework_name

    assessment = RiskAssessment(
        framework_id=framework_id,
        framework_name=framework_name,
    )

    finding_counter = 0

    for result in results:
        module = result.get("module", "unknown")
        findings_list = result.get("findings", [])
        owasp_mapping = result.get("owasp_mapping", "")
        summary = result.get("summary", {})

        # 如果没有 findings 列表，从 summary 创建简化发现
        if not findings_list and summary:
            owasp_ids = result.get("owasp_ids", [])
            if not owasp_ids and owasp_mapping:
                import re
                owasp_ids = re.findall(r'(?:LLM|ASI)\d{2}', owasp_mapping)

            for owasp_id in owasp_ids or ["unknown"]:
                entry = get_owasp_entry(owasp_id)
                finding_counter += 1
                risk_cat = get_risk_category(owasp_id)
                assessment.add_finding(RiskFinding(
                    finding_id=f"F{finding_counter:04d}",
                    owasp_id=owasp_id,
                    owasp_title=entry.title if entry else "Unknown",
                    category=module,
                    severity=entry.severity if entry else "medium",
                    confidence=0.6,
                    risk_category=risk_cat.display_name if risk_cat else "",
                    description=f"Finding from {module} module",
                    remediation=entry.description if entry else "",
                    tool=module,
                    source="attack",
                ))
            continue

        # 处理 findings 列表
        for f in findings_list:
            category = f.get("category", "unknown")
            owasp_id = f.get("owasp_mapping", "") or normalize_category(category, "deepteam")

            # 如果 owasp_mapping 是空字符串，尝试从 owasp_mapping 字段提取
            if not owasp_id and f.get("owasp_mapping"):
                import re
                matches = re.findall(r'(?:LLM|ASI)\d{2}', f["owasp_mapping"])
                if matches:
                    owasp_id = matches[0]

            entry = get_owasp_entry(owasp_id) if owasp_id else None
            risk_cat = get_risk_category(owasp_id) if owasp_id else None

            finding_counter += 1
            assessment.add_finding(RiskFinding(
                finding_id=f"F{finding_counter:04d}",
                owasp_id=owasp_id or "unknown",
                owasp_title=entry.title if entry else category,
                category=category,
                severity=f.get("severity", entry.severity if entry else "medium"),
                confidence=float(f.get("confidence", 0.5)),
                risk_category=risk_cat.display_name if risk_cat else "",
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                remediation=entry.description if entry else "",
                tool=f.get("tool", module),
                source="attack",
            ))

    # 确保统计是最新的（处理空结果的情况）
    assessment._update_stats()

    return assessment
