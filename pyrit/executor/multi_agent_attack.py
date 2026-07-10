"""
===============================================================================
向后兼容桥接 — 多 Agent 系统攻击
===============================================================================
⚠️ 此模块已迁移到 pyrit/multi_agent/ 目录 (Layer 4: 多 Agent 系统攻击)。

原代码位于: pyrit/executor/multi_agent_attack.py
新代码位于: pyrit/multi_agent/__init__.py

本文件保留向后兼容，所有导入重定向到新位置。
===============================================================================
"""
# 向后兼容: 从新位置重新导出
from pyrit.multi_agent import (
    MultiAgentAttackExecutor,
    MultiAgentAttackResult,
    MultiAgentAttackReport,
    AgentState,
    InterAgentMessage,
    AttackVector,
    AgentRole,
)

__all__ = [
    "MultiAgentAttackExecutor",
    "MultiAgentAttackResult",
    "MultiAgentAttackReport",
    "AgentState",
    "InterAgentMessage",
    "AttackVector",
    "AgentRole",
]
