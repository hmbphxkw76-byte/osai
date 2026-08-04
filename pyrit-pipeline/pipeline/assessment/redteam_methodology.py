# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""RedTeamMethodology — 5 阶段红队评估方法论。.

结构化红队评估流程, 与 mcp-attack-labs 的 5-Phase Assessment 对齐:

Phase 1: Scoping & Threat Modeling — 范围定义和威胁建模 (CSA 类别映射)
Phase 2: Attack Surface Enumeration — 攻击面枚举 (输入向量映射)
Phase 3: Automated Scanning — 自动化扫描 (Promptfoo/Garak 集成)
Phase 4: Deep Exploitation — 深度利用 (PyRIT Crescendo/TAP)
Phase 5: Manual Expert Testing — 专家手动测试 (Kill Chain)

4-Layer Testing Strategy:
  Layer 1: Broad Scan (30-60 min) — Garak/Promptfoo 全探针扫描
  Layer 2: Compliance Scan (15-30 min) — OWASP Agentic 预设
  Layer 3: Deep Exploitation (2-4 hours) — PyRIT 多轮攻击
  Layer 4: Expert Manual (1-2 days) — 人工业务逻辑攻击

> **日期**: 2026-8-4
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pipeline.assessment.framework_mapper import (
    AssessmentPhase,
    CoverageMatrix,
    FrameworkMapper,
    OWASPAgenticCode,
)


@dataclass
class PhaseResult:
    """单阶段评估结果。.

    Attributes:
        phase: 阶段枚举。
        name: 阶段名称。
        status: 状态 (pending/in_progress/completed/skipped)。
        findings: 发现列表。
        duration_minutes: 持续时间 (分钟)。
        notes: 备注。
    """

    phase: AssessmentPhase = AssessmentPhase.SCOPING
    name: str = ""
    status: str = "pending"
    findings: list[str] = field(default_factory=list)
    duration_minutes: int = 0
    notes: str = ""


@dataclass
class AssessmentResult:
    """完整评估结果。.

    Attributes:
        target_name: 目标名称。
        phases: 各阶段结果列表。
        coverage: 框架覆盖矩阵。
        total_findings: 总发现数。
        critical_findings: 关键发现数。
        overall_risk: 总体风险等级。
        kill_chains: 发现的 Kill Chain 列表。
    """

    target_name: str = ""
    phases: list[PhaseResult] = field(default_factory=list)
    coverage: CoverageMatrix = field(default_factory=CoverageMatrix)
    total_findings: int = 0
    critical_findings: int = 0
    overall_risk: str = "low"
    kill_chains: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "target_name": self.target_name,
            "phases": [
                {
                    "phase": p.phase.value,
                    "name": p.name,
                    "status": p.status,
                    "findings": p.findings,
                    "duration_minutes": p.duration_minutes,
                    "notes": p.notes,
                }
                for p in self.phases
            ],
            "coverage": self.coverage.to_dict(),
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "overall_risk": self.overall_risk,
            "kill_chains": self.kill_chains,
        }


# ── 阶段默认名称 ──
_PHASE_NAMES: dict[AssessmentPhase, str] = {
    AssessmentPhase.SCOPING: "Scoping & Threat Modeling",
    AssessmentPhase.ENUMERATION: "Attack Surface Enumeration",
    AssessmentPhase.AUTOMATED_SCAN: "Automated Scanning",
    AssessmentPhase.DEEP_EXPLOITATION: "Deep Exploitation",
    AssessmentPhase.MANUAL_TESTING: "Manual Expert Testing",
}

# ── 阶段默认时间 (分钟) ──
_PHASE_DEFAULT_DURATION: dict[AssessmentPhase, int] = {
    AssessmentPhase.SCOPING: 90,
    AssessmentPhase.ENUMERATION: 150,
    AssessmentPhase.AUTOMATED_SCAN: 45,
    AssessmentPhase.DEEP_EXPLOITATION: 180,
    AssessmentPhase.MANUAL_TESTING: 480,
}


class RedTeamMethodology:
    """5 阶段红队评估方法论。.

    提供结构化的红队评估流程管理, 包括:
    - 阶段定义和默认配置
    - CSA 威胁类别 → 测试矩阵生成
    - 覆盖率跟踪
    - Kill Chain 记录

    用法:
        methodology = RedTeamMethodology(target_name="DocuAssist")
        methodology.start_phase(AssessmentPhase.SCOPING)
        methodology.add_finding(AssessmentPhase.SCOPING, "ASI01 applicable")
        methodology.complete_phase(AssessmentPhase.SCOPING, duration_minutes=60)
        result = methodology.get_result()
    """

    def __init__(self, target_name: str = "") -> None:
        """初始化评估方法论。.

        Args:
            target_name: 目标系统名称。
        """
        self.target_name = target_name
        self._mapper = FrameworkMapper()
        self._phases: dict[AssessmentPhase, PhaseResult] = {
            phase: PhaseResult(
                phase=phase,
                name=_PHASE_NAMES.get(phase, phase.value),
            )
            for phase in AssessmentPhase
        }
        self._tested_owasp: set[OWASPAgenticCode] = set()
        self._tested_csa: set[str] = set()
        self._kill_chains: list[dict[str, Any]] = []

    def start_phase(self, phase: AssessmentPhase) -> None:
        """开始指定阶段。.

        Args:
            phase: 要开始的阶段。
        """
        if phase in self._phases:
            self._phases[phase].status = "in_progress"

    def add_finding(
        self,
        phase: AssessmentPhase,
        finding: str,
        *,
        owasp_code: OWASPAgenticCode | None = None,
        csa_category: str | None = None,
    ) -> None:
        """添加阶段发现。.

        Args:
            phase: 阶段。
            finding: 发现描述。
            owasp_code: 关联的 OWASP 代码 (可选)。
            csa_category: 关联的 CSA 类别 (可选)。
        """
        if phase not in self._phases:
            return
        self._phases[phase].findings.append(finding)
        if owasp_code:
            self._tested_owasp.add(owasp_code)
        if csa_category:
            self._tested_csa.add(csa_category)

    def complete_phase(
        self,
        phase: AssessmentPhase,
        *,
        duration_minutes: int | None = None,
        notes: str = "",
    ) -> None:
        """完成指定阶段。.

        Args:
            phase: 阶段。
            duration_minutes: 实际持续时间。
            notes: 阶段备注。
        """
        if phase not in self._phases:
            return
        self._phases[phase].status = "completed"
        if duration_minutes is not None:
            self._phases[phase].duration_minutes = duration_minutes
        elif phase in _PHASE_DEFAULT_DURATION:
            self._phases[phase].duration_minutes = _PHASE_DEFAULT_DURATION[phase]
        if notes:
            self._phases[phase].notes = notes

    def skip_phase(self, phase: AssessmentPhase, reason: str = "") -> None:
        """跳过指定阶段。.

        Args:
            phase: 阶段。
            reason: 跳过原因。
        """
        if phase not in self._phases:
            return
        self._phases[phase].status = "skipped"
        self._phases[phase].notes = reason

    def add_kill_chain(
        self,
        *,
        name: str,
        chain: list[str],
        owasp_codes: list[OWASPAgenticCode],
    ) -> None:
        """添加发现的 Kill Chain。.

        Args:
            name: Kill Chain 名称。
            chain: 攻击链步骤列表。
            owasp_codes: 关联的 OWASP 代码列表。
        """
        atlas_techniques: list[str] = []
        for code in owasp_codes:
            atlas_techniques.extend(self._mapper.owasp_to_atlas(code))

        self._kill_chains.append({
            "name": name,
            "chain": chain,
            "owasp_codes": [c.value for c in owasp_codes],
            "atlas_techniques": atlas_techniques,
        })
        self._tested_owasp.update(owasp_codes)

    def get_result(self) -> AssessmentResult:
        """获取完整评估结果。.

        Returns:
            AssessmentResult 评估结果。
        """
        all_findings = sum(
            len(p.findings) for p in self._phases.values()
        )
        critical_count = sum(
            1
            for p in self._phases.values()
            for f in p.findings
            if "critical" in f.lower()
        )

        risk = "low"
        if critical_count >= 3:
            risk = "critical"
        elif critical_count >= 1:
            risk = "high"
        elif all_findings >= 5:
            risk = "medium"

        coverage = self._mapper.build_coverage_matrix(
            tested_owasp=self._tested_owasp,
            tested_csa=self._tested_csa,
        )

        return AssessmentResult(
            target_name=self.target_name,
            phases=list(self._phases.values()),
            coverage=coverage,
            total_findings=all_findings,
            critical_findings=critical_count,
            overall_risk=risk,
            kill_chains=self._kill_chains,
        )

    def generate_scoping_matrix(self) -> list[dict[str, str]]:
        """生成 Phase 1 范围定义矩阵。.

        Returns:
            CSA 类别 → OWASP 映射列表, 每项含类别、代码、优先级。
        """
        matrix: list[dict[str, str]] = []
        for csa_cat, owasp_codes in (
            self._mapper.get_all_csa_categories_as_dict().items()
            if hasattr(self._mapper, "get_all_csa_categories_as_dict")
            else []
        ):
            for code in owasp_codes:
                matrix.append({
                    "csa_category": csa_cat,
                    "owasp_code": code.value,
                    "description": self._mapper.owasp_description(code),
                    "priority": "critical" if code in (
                        OWASPAgenticCode.ASI01,
                        OWASPAgenticCode.ASI02,
                    ) else "high",
                })
        return matrix
