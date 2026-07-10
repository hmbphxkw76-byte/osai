"""
===============================================================================
向后兼容桥接 — Garak 扫描器
===============================================================================
⚠️ 此模块已迁移到 garak/ 独立目录 (Layer 1: AI 安全侦查)。

原代码位于: pyrit/executor/garak_scanner.py
新代码位于: garak/scanner.py

本文件保留向后兼容，所有导入重定向到新位置。
===============================================================================
"""
# 向后兼容: 从新位置重新导出
from garak.scanner import GarakScanner
from garak.schema import GarakProbeResult, VulnerabilityFingerprint, SecurityProfile

__all__ = [
    "GarakScanner",
    "GarakProbeResult",
    "VulnerabilityFingerprint",
    "SecurityProfile",
]
