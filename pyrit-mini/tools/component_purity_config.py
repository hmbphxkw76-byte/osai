# -*- coding: utf-8 -*-
"""tools/component_purity_config.py - Component Purity 验证结果类型

基线数据已抽出到 `tools._purity_baselines`（R-DELIVERY-1），此处重新导出以保持
`tools.component_purity_config._STRIKE_COMPONENT_BASELINES` 等引用零回归。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 基线数据（纯数据，抽出到 _purity_baselines）— 重新导出，保证下游导入零回归。
from ._purity_baselines import (
    _RECON_COMPONENT_BASELINES,
    _STRIKE_COMPONENT_BASELINES,
)

__all__ = [
    "PurityFinding",
    "ComponentPurityReport",
    "_STRIKE_COMPONENT_BASELINES",
    "_RECON_COMPONENT_BASELINES",
]


# ====================================================================
# Validation Result Types
# ====================================================================


@dataclass
class PurityFinding:
    """A single purity validation finding."""

    severity: str  # "error", "warning", "info"
    component: str
    module: str
    finding_type: str  # "forbidden_technique", "missing_technique", "cross_contamination"
    message: str
    line_number: int | None = None
    suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "component": self.component,
            "module": self.module,
            "type": self.finding_type,
            "message": self.message,
            "line": self.line_number,
            "suggestion": self.suggestion,
        }


@dataclass
class ComponentPurityReport:
    """Complete purity report for a component."""

    component: str
    component_path: str
    findings: list[PurityFinding] = field(default_factory=list)
    coverage_score: float = 0.0  # 0.0-1.0
    technique_count: int = 0
    high_asr_technique_count: int = 0
    missing_techniques: list[str] = field(default_factory=list)
    redundant_techniques: list[str] = field(default_factory=list)
    purity_score: float = 1.0  # 1.0 = pure, 0.0 = contaminated

    @property
    def is_pure(self) -> bool:
        """Check if component has no purity violations."""
        return not any(f.severity == "error" for f in self.findings)

    @property
    def is_complete(self) -> bool:
        """Check if component has all required techniques."""
        return len(self.missing_techniques) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "path": self.component_path,
            "purity_score": self.purity_score,
            "coverage_score": self.coverage_score,
            "technique_count": self.technique_count,
            "high_asr_technique_count": self.high_asr_technique_count,
            "is_pure": self.is_pure,
            "is_complete": self.is_complete,
            "missing_techniques": self.missing_techniques,
            "redundant_techniques": self.redundant_techniques,
            "findings": [f.to_dict() for f in self.findings],
        }
