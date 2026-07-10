"""PyRIT Scenario Layer — 攻击场景与目标抽象.

场景层定义红队攻击的目标上下文，与 attacks/（攻击执行机制）分离：

- multi_agent/        : 多 Agent 系统攻击场景
  - Agent 间通信劫持
  - 级联故障触发
  - 记忆/上下文持久化投毒
  - 人机信任利用攻击

未来扩展：
- single_agent/       : 单一 LLM 对话场景
- rag_system/         : RAG 系统攻防场景
- tool_chain/         : Agent 工具链场景
"""

from __future__ import annotations

from scenario.multi_agent import MultiAgentAttackCoordinator

__all__ = [
    "MultiAgentAttackCoordinator",
]
