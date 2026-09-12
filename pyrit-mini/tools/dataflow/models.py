"""
数据流完整性验证器 — 数据模型

定义 Phase 枚举、DataSnapshot / ValidationResult / DataFlowReport 数据类。
被 DataFlowValidator 和测试套件共享。

Academic basis:
    - NIST SP 800-115: Technical Guide to Information Security Testing
    - OWASP Testing Guide v4.2: Data Integrity Verification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Phase(str, Enum):
    """流水线阶段标识"""

    RECON = "recon"
    ARM = "arm"
    STRIKE = "strike"
    ASSESS = "assess"
    REPORT = "report"


@dataclass
class DataSnapshot:
    """单个阶段的数据快照"""

    phase: str
    timestamp: float
    context_hash: int  # 上下文对象 ID
    fields: dict[str, Any]  # 关键字段状态
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """单条验证结果"""

    rule_id: str
    rule_name: str
    passed: bool
    phase_from: str
    phase_to: str
    message: str
    severity: str  # "error", "warning", "info"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlowReport:
    """完整数据流验证报告"""

    timestamp: str
    total_rules: int
    passed: int
    failed: int
    warnings: int
    results: list[ValidationResult]
    snapshots: list[DataSnapshot]
    duration_seconds: float

    @property
    def is_valid(self) -> bool:
        """是否无错误"""
        return self.failed == 0
