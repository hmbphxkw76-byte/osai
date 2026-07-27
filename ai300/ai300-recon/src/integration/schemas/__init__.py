# -*- coding: utf-8 -*-
"""
Integration Schemas
===================

定义跨工具统一数据模型，用于 recon、scan、attack 结果的标准化交换。
"""

from .unified_finding import Evidence, UnifiedFinding, dedup_findings

__all__ = [
    "Evidence",
    "UnifiedFinding",
    "dedup_findings",
]
