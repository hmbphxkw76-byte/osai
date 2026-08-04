# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""评分模块 — AI-VSS 漏洞评分系统。.

本包提供 AI 漏洞评分标准 (AI-VSS) 实现, 扩展标准 CVSS
以覆盖 AI 特有风险维度。

> **日期**: 2026-8-4
"""

from __future__ import annotations

from pipeline.scoring.ai_vss_scorer import (
    AIVSSModifier,
    AIVSSScore,
    AIVSSScorer,
    AIVSSSeverity,
)

__all__ = [
    "AIVSSModifier",
    "AIVSSScore",
    "AIVSSScorer",
    "AIVSSSeverity",
]
