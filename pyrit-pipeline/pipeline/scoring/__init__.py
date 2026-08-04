# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""评分模块 — AI-VSS 漏洞评分系统 + PyRIT 原生 Scorer 桥接。.

本包提供 AI 漏洞评分标准 (AI-VSS) 实现, 扩展标准 CVSS
以覆盖 AI 特有风险维度。同时提供桥接器将 PyRIT 原生
Scorer 结果增强为 AI-VSS 漏洞评分。

**R-022 PyRIT 原生优先**: AI-VSS 为纯数据层增强, 不修改
原生 Scorer 的 score_async 生命周期, 仅消费 Score 公开字段。

> **日期**: 2026-8-4
"""

from __future__ import annotations

from pipeline.scoring.ai_vss_bridge import AIVSSAugmentedScore, AIVSSBridge
from pipeline.scoring.ai_vss_scorer import (
    AIVSSModifier,
    AIVSSScore,
    AIVSSScorer,
    AIVSSSeverity,
)

__all__ = [
    "AIVSSAugmentedScore",
    "AIVSSBridge",
    "AIVSSModifier",
    "AIVSSScore",
    "AIVSSScorer",
    "AIVSSSeverity",
]
