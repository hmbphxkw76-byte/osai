# -*- coding: utf-8 -*-
"""
攻击报告模型
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

from ai300_schemas import UnifiedFinding, dedup_findings

from ..adapters.base import AttackResult


@dataclass
class AttackReport:
    """攻击执行报告"""

    target: str = ""
    adapters: List[str] = field(default_factory=list)
    strategies: List[str] = field(default_factory=list)
    results: List[AttackResult] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def findings(self) -> List[UnifiedFinding]:
        """汇总所有发现"""
        all_findings: List[UnifiedFinding] = []
        for result in self.results:
            all_findings.extend(result.findings)
        return dedup_findings(all_findings)

    def to_dict(self) -> Dict[str, Any]:
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
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def summary(self) -> str:
        """文本摘要"""
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
