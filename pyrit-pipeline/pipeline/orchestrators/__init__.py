# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""高级攻击编排器 — PyRIT 原生框架增强。.

本包提供两类高级攻击编排器, 作为 PyRIT 原生 PromptSendingAttack 的增强:

1. AdvancedCrescendoOrchestrator — 多轮渐进式攻击
   - 攻击者 LLM 生成逐步升级的消息
   - 评分 LLM 评估每轮是否达到目标
   - 支持回退和角度切换

2. TAPOrchestrator — 树状攻击路径
   - 并行探索多条攻击路径
   - 预评分裁剪 + 递归精炼
   - 基于成功阈值提前终止

设计原则 (R-010/R-022: PyRIT 原生优先):
  - 使用 PyRIT 原生 PromptSendingAttack 作为底层执行引擎
  - 编排器为选择层增强, 不修改 PyRIT Scenario 生命周期
  - 所有 LLM 交互通过原生 ChatTarget 接口

学术依据:
  - Crescendo: Tahvidou-Zadeh et al. (arXiv:2402.12109)
  - TAP: Mehrotra et al. (arXiv:2310.04451)

> **日期**: 2026-8-4
"""

from __future__ import annotations

from pipeline.orchestrators.advanced_crescendo import (
    AdvancedCrescendoOrchestrator,
    CrescendoResult,
)
from pipeline.orchestrators.tap_orchestrator import (
    TAPOrchestrator,
    TAPResult,
)

__all__ = [
    "AdvancedCrescendoOrchestrator",
    "CrescendoResult",
    "TAPOrchestrator",
    "TAPResult",
]
