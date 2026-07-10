"""
===============================================================================
Garak 模块 — Layer 1: AI 安全侦查
===============================================================================
本包提供:
  - GarakScanner: 两阶段 AI 安全扫描器（基线 + 深度验证）
  - SecurityProfile: 结构化安全画像
  - VulnerabilityFingerprint: 漏洞指纹（可复现攻击特征）
  - GarakProbeResult: 单个探针执行结果

架构位置: L1 — AI 安全侦查层
依赖方向: → 独立模块，仅依赖 garak CLI（可选）
=======================================================================
"""
from garak.schema import (
    GarakProbeResult,
    VulnerabilityFingerprint,
    SecurityProfile,
)
from garak.scanner import GarakScanner

__all__ = [
    "GarakScanner",
    "GarakProbeResult",
    "VulnerabilityFingerprint",
    "SecurityProfile",
]
