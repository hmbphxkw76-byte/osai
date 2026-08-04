# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""高级攻击编排器 — PyRIT 原生框架配置适配层。.

本包提供两类高级攻击编排器, 作为 PyRIT 原生攻击执行器的配置增强层 (R-022):

1. AdvancedCrescendoOrchestrator — PyRIT 原生 CrescendoAttack 配置适配器
   - 底层 100% 使用原生 CrescendoAttack
   - 原生 AttackAdversarialConfig + AttackScoringConfig
   - 原生 max_backtracks 回溯机制
   - 原生 Memory 对话历史持久化

2. TAPOrchestrator — PyRIT 原生 TAPAttack 配置适配器
   - 底层 100% 使用原生 TAPAttack
   - 原生 AttackAdversarialConfig + AttackScoringConfig
   - 原生 tree_width/depth/branching_factor/batch_size
   - 原生 tree_visualization 树可视化

设计原则 (R-022: PyRIT 原生优先):
  - 自研代码仅负责配置适配, 不重新实现攻击算法
  - 底层执行 100% 使用 PyRIT 原生 CrescendoAttack / TAPAttack
  - 原生 AttackScoringConfig 提供三层评分 (objective/refusal/auxiliary)
  - 原生 AttackAdversarialConfig 提供对抗 LLM 配置
  - 编排器为配置层, 不修改 PyRIT Scenario 生命周期

学术依据:
  - Crescendo: Tahvidou-Zadeh et al. (arXiv:2402.12109)
  - TAP: Mehrotra et al. (arXiv:2310.04451)

> **日期**: 2026-8-4 | **更新**: 2026-8-5 (R-022 原生化)
"""

from __future__ import annotations

from pipeline.orchestrators.advanced_crescendo import (
    AdvancedCrescendoOrchestrator,
    CrescendoResult,
    CrescendoTurn,
)
from pipeline.orchestrators.tap_orchestrator import (
    TAPNode,
    TAPOrchestrator,
    TAPResult,
)

__all__ = [
    "AdvancedCrescendoOrchestrator",
    "CrescendoResult",
    "CrescendoTurn",
    "TAPOrchestrator",
    "TAPNode",
    "TAPResult",
]
