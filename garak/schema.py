"""
===============================================================================
Garak 数据模型 — AI 安全侦查 (L1) 结构化 Schema
===============================================================================

定义 Garak 扫描器使用的核心数据类:
  - GarakProbeResult:     单个探针执行结果
  - VulnerabilityFingerprint: 漏洞指纹（可复现的漏洞特征）
  - SecurityProfile:      结构化安全画像（L1 产出物）

这些模型被 scanner.py 和外部消费者使用。
===============================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GarakProbeResult:
    """单个 Garak Probe 的执行结果。"""
    probe_name: str
    probe_class: str
    status: str  # "pass" | "fail" | "error" | "skipped"
    score: float = 0.0
    total_attempts: int = 0
    successful_attempts: int = 0
    detection_rate: float = 0.0
    details: dict = field(default_factory=dict)


@dataclass
class VulnerabilityFingerprint:
    """漏洞指纹 — 可复现的漏洞特征描述。"""
    category: str
    severity: str  # "low" | "medium" | "high" | "critical"
    confidence: float  # 0.0~1.0
    probe_results: list[str] = field(default_factory=list)
    description: str = ""
    recommendation: str = ""


@dataclass
class SecurityProfile:
    """结构化安全画像 — L1 产出物。"""
    target_id: str
    scan_timestamp: str = ""
    scan_type: str = "baseline"  # "baseline" | "deep" | "targeted"
    total_probes: int = 0
    passed_probes: int = 0
    failed_probes: int = 0
    error_probes: int = 0
    vulnerability_fingerprints: list[VulnerabilityFingerprint] = field(default_factory=list)
    probe_results: list[GarakProbeResult] = field(default_factory=list)
    recommended_attack_paths: list[str] = field(default_factory=list)
    raw_garak_output: dict = field(default_factory=dict)

    @property
    def overall_risk(self) -> str:
        """基于漏洞指纹计算总体风险等级。"""
        if not self.vulnerability_fingerprints:
            return "low"
        severities = [v.severity for v in self.vulnerability_fingerprints]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    @property
    def pass_rate(self) -> float:
        """探针通过率。"""
        if self.total_probes == 0:
            return 0.0
        return self.passed_probes / self.total_probes


__all__ = [
    "GarakProbeResult",
    "VulnerabilityFingerprint",
    "SecurityProfile",
]
