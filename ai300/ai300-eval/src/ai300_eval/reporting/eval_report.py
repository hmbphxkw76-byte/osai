# -*- coding: utf-8 -*-
"""
评估报告模型
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

from ai300_schemas import UnifiedFinding, dedup_findings

from ..adapters.base import EvalResult


@dataclass
class EvalReport:
    """评估执行报告"""

    # 目标域名或 URL
    target: str = ""
    # 使用的适配器列表
    adapters: List[str] = field(default_factory=list)
    # 执行的策略名称列表
    strategies: List[str] = field(default_factory=list)
    # 各适配器各策略的执行结果
    results: List[EvalResult] = field(default_factory=list)
    # 报告生成时间（UTC ISO 8601）
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    def findings(self) -> List[UnifiedFinding]:
        """汇总所有发现并去重"""
        all_findings: List[UnifiedFinding] = []
        for result in self.results:
            all_findings.extend(result.findings)
        return dedup_findings(all_findings)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "target": self.target,
            "adapters": self.adapters,
            "strategies": self.strategies,
            "created_at": self.created_at,
            "results": [
                {
                    "adapter": r.adapter,
                    "strategy": r.strategy,
                    "success": r.success,
                    "findings": [f.to_dict() for f in r.findings],
                    "error": r.error,
                }
                for r in self.results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """序列化为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def summary(self) -> str:
        """生成文本摘要"""
        findings = self.findings()
        lines = [
            f"Target: {self.target}",
            f"Adapters: {', '.join(self.adapters)}",
            f"Strategies: {', '.join(self.strategies)}",
            f"Total Findings: {len(findings)}",
        ]
        severity_count: Dict[str, int] = {}
        for f in findings:
            severity_count[f.severity] = severity_count.get(f.severity, 0) + 1
        if severity_count:
            lines.append("Severity Distribution:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in severity_count:
                    lines.append(f"  {sev}: {severity_count[sev]}")
        return "\n".join(lines)
