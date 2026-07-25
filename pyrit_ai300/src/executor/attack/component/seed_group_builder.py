"""
Seed Group Builder
==================

AttackSeedGroup 构建器 — 从 AttackPlan 构建 AttackSeedGroup。

对齐 pyrit.executor.attack.component (ConversationManager / PrependedConversationConfig)
功能：从 AttackPlan 构建 AttackSeedGroup，编码多轮对话为 SeedPrompt 序列。

设计原则：
- 角色交替规则：even → user, odd → assistant, 最后一轮强制 user
- 原生 from_seed_group_async 自动提取三要素：
  objective / next_message / prepended_conversation
- 不修改 AttackPlan 原始对象
"""

from typing import List

from pyrit.models import (
    AttackSeedGroup,
    Seed,
    SeedObjective,
    SeedPrompt,
)

from src.payloads.models import AttackPlan


class SeedGroupBuilder:
    """
    AttackSeedGroup 构建器

    从 AttackPlan 构建 AttackSeedGroup，让原生 from_seed_group_async
    自动提取三要素（objective / next_message / prepended_conversation）。

    用法：
        builder = SeedGroupBuilder()
        seed_group = builder.build(plan, objective, include_conversation=True)
    """

    @staticmethod
    def build(
        plan: AttackPlan,
        objective: str,
        *,
        include_conversation: bool = True,
    ) -> AttackSeedGroup:
        """
        从 AttackPlan 构建 AttackSeedGroup

        PyRIT 原生 AttackSeedGroup 强制恰好一个 objective。
        如果有 multi_turn_steps 且 include_conversation=True，将其编码为 SeedPrompt 序列，
        让原生 from_seed_group_async 自动提取三要素：
          - objective:       SeedObjective.value
          - next_message:    最后一个 user 序列的 SeedPrompt
          - prepended_conversation: 除最后 user 序列外的所有 SeedPrompt

        角色交替规则（模拟真实对话）：
          even index → "user",  odd index → "assistant"
          最后一轮强制为 "user"，确保原生提取为 next_message

        Args:
            plan: 攻击计划
            objective: 攻击目标
            include_conversation: 是否编码 multi_turn_steps 为 SeedPrompt 序列
                （MULTI_TURN 逐轮发送时设为 False，每轮只需 objective）

        Returns:
            AttackSeedGroup 实例
        """
        seeds: List[Seed] = [SeedObjective(value=objective)]

        if include_conversation and plan.prompt_item.multi_turn_steps:
            turns = plan.prompt_item.multi_turn_steps
            last_idx = len(turns) - 1
            for i, turn_value in enumerate(turns):
                # 交替角色：even → user, odd → assistant
                role = "user" if i % 2 == 0 else "assistant"
                # 最后一轮强制为 user，使原生提取为 next_message
                if i == last_idx:
                    role = "user"
                seeds.append(SeedPrompt(
                    value=turn_value,
                    sequence=i,
                    role=role,
                ))

        return AttackSeedGroup(seeds=seeds)
