# -*- coding: utf-8 -*-
"""
UnifiedFinding Schema
=====================

ai300-recon 对 ai300-schemas 的重新导出，
保持原有导入路径不变，便于现有代码迁移。

实际数据契约定义位于：ai300-schemas/src/ai300_schemas/unified_finding.py
"""

from __future__ import annotations

from ai300_schemas import (
    Evidence,
    UnifiedFinding,
    dedup_findings,
)

__all__ = ["Evidence", "UnifiedFinding", "dedup_findings"]
