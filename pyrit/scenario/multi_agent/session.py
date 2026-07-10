"""
===============================================================================
Multi-Agent Session Orchestrator — PyRIT 会话级多 Agent 编排
===============================================================================
职责:
  - 创建 PyRIT Memory 隔离的会话上下文
  - 编排多 Agent 系统攻击的完整生命周期
  - 决策 Agent 间消息路由与加密策略
===============================================================================
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from pyrit.multi_agent import MultiAgentAttackExecutor, MultiAgentAttackReport


class PyRITMultiAgentOrchestrator:
    """PyRIT 多 Agent 会话编排器。

    基于 PyRIT 的 SQLiteMemory + CentralMemory 实现:
      - 每个会话创建独立 Memory 实例
      - 支持多 Agent 攻击链的持久化追踪
      - 提供攻击回放和取证功能
    """

    def __init__(self, session_name: str = ""):
        self.session_name = session_name or datetime.now(timezone.utc).strftime("multi_agent_%Y%m%d_%H%M%S")

    async def run_multi_agent_campaign(
        self,
        target_url: str,
        agent_count: int = 3,
        attack_vectors: Optional[list] = None,
    ) -> MultiAgentAttackReport:
        """执行多 Agent 攻击战役。

        Args:
            target_url: 目标多 Agent 系统 URL
            agent_count: 模拟 Agent 数量
            attack_vectors: 启用的攻击向量列表

        Returns:
            MultiAgentAttackReport: 多 Agent 攻击报告
        """
        executor = MultiAgentAttackExecutor(
            target_url=target_url,
            agent_count=agent_count,
            attack_vectors=attack_vectors,
        )
        report = await executor.run_all()
        return report


__all__ = ["PyRITMultiAgentOrchestrator"]
