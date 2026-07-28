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
- 多模态支持：保留 image_path / audio_path 数据类型
- system 角色支持：保留 role="system" 种子
"""

import logging
from typing import List, Optional

from pyrit.models import (
    AttackSeedGroup,
    Seed,
    SeedObjective,
    SeedPrompt,
)

from src.payloads.models import AttackPlan

logger = logging.getLogger(__name__)


class SeedGroupBuilder:
    """
    AttackSeedGroup 构建器

    从 AttackPlan 构建 AttackSeedGroup，让原生 from_seed_group_async
    自动提取三要素（objective / next_message / prepended_conversation）。

    多模态支持（PyRIT 1.0.0 对齐）：
    - 当 metadata 中包含 multimodal 信息时，构建 image_path/audio_path 类型 SeedPrompt
    - system 角色种子保留原样，不参与角色交替规则

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

        多模态处理：
          当 metadata["multimodal"] 存在时，构建对应 data_type 的 SeedPrompt。
          多模态片段不影响角色交替规则。

        system 角色处理：
          当 metadata 中包含 role="system" 的提示词时，保留 system 角色。
          system 角色不参与 user/assistant 交替。

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

            # 提取多模态信息（如果有）
            multimodal_pieces = (plan.prompt_item.metadata or {}).get("multimodal", [])

            # 提取 system 角色信息（如果有）
            system_message = (plan.prompt_item.metadata or {}).get("system_message")

            # 提取结构化输出约束（如果有）
            response_json_schema = plan.prompt_item.response_json_schema

            # 如果有 system 消息，添加到种子列表最前面（在 objective 之后）
            # system 消息使用负序列号避免与 user/assistant 消息冲突
            if system_message:
                seeds.append(SeedPrompt(
                    value=system_message,
                    sequence=-1,
                    role="system",
                    data_type="text",
                ))

            for i, turn_value in enumerate(turns):
                # 交替角色：even → user, odd → assistant
                role = "user" if i % 2 == 0 else "assistant"
                # 最后一轮强制为 user，使原生提取为 next_message
                if i == last_idx:
                    role = "user"

                # 检查是否有对应的多模态片段
                data_type = "text"
                multimodal_match = None
                for piece in multimodal_pieces:
                    if piece.get("sequence") == i:
                        data_type = piece.get("data_type", "text")
                        multimodal_match = piece
                        break

                # 如果有多模态片段，使用多模态值
                actual_value = turn_value
                if multimodal_match and data_type != "text":
                    actual_value = multimodal_match.get("value", turn_value)

                # 构建带 response_json_schema 的 SeedPrompt（仅在最后一轮 user 消息上设置）
                prompt_kwargs: dict = {
                    "value": actual_value,
                    "sequence": i,
                    "role": role,
                    "data_type": data_type,
                }
                # response_json_schema 仅设置在最后一轮 user 消息上（即 next_message）
                if response_json_schema and i == last_idx:
                    prompt_kwargs["response_json_schema"] = response_json_schema

                seeds.append(SeedPrompt(**prompt_kwargs))

        elif not include_conversation:
            # 即使不包含对话，也传递 response_json_schema 到第一个 SeedPrompt
            response_json_schema = plan.prompt_item.response_json_schema
            if response_json_schema:
                seeds.append(SeedPrompt(
                    value=plan.prompt_item.objective,
                    sequence=0,
                    role="user",
                    data_type="text",
                    response_json_schema=response_json_schema,
                ))

        return AttackSeedGroup(seeds=seeds)

    @staticmethod
    def build_with_multimodal(
        plan: AttackPlan,
        objective: str,
        *,
        multimodal_pieces: List[dict],
        include_conversation: bool = True,
    ) -> AttackSeedGroup:
        """
        构建带多模态内容的 AttackSeedGroup

        便捷方法：直接传入多模态片段列表，构建包含 image_path / audio_path
        类型 SeedPrompt 的 AttackSeedGroup。

        Args:
            plan: 攻击计划
            objective: 攻击目标
            multimodal_pieces: 多模态片段列表，每个片段包含：
                - data_type: "image_path" / "audio_path" / "text"
                - value: 文件路径或 URL
                - sequence: 序列号
                - role: 角色（默认 "user"）
            include_conversation: 是否编码 multi_turn_steps

        Returns:
            AttackSeedGroup 实例（含多模态种子）
        """
        seeds: List[Seed] = [SeedObjective(value=objective)]

        for piece in multimodal_pieces:
            data_type = piece.get("data_type", "text")
            value = piece.get("value", "")
            sequence = piece.get("sequence", 0)
            role = piece.get("role", "user")

            seeds.append(SeedPrompt(
                value=value,
                sequence=sequence,
                role=role,
                data_type=data_type,
            ))

        # 如果还需要编码 multi_turn_steps
        if include_conversation and plan.prompt_item.multi_turn_steps:
            turns = plan.prompt_item.multi_turn_steps
            # 使用已有序列号的最大值 + 1 作为起始
            existing_max_seq = max((p.get("sequence", 0) for p in multimodal_pieces), default=-1)
            for i, turn_value in enumerate(turns):
                seq = existing_max_seq + 1 + i
                role = "user" if i % 2 == 0 else "assistant"
                seeds.append(SeedPrompt(
                    value=turn_value,
                    sequence=seq,
                    role=role,
                ))

        return AttackSeedGroup(seeds=seeds)

    @staticmethod
    def build_from_seed_group(
        seed_group: AttackSeedGroup,
        objective_override: Optional[str] = None,
    ) -> AttackSeedGroup:
        """
        从现有 AttackSeedGroup 重新构建（支持 objective 覆盖）

        用于多轮攻击逐轮发送场景：保留原有 SeedPrompt 序列和角色，
        仅替换 objective。

        Args:
            seed_group: 原始 AttackSeedGroup
            objective_override: 新的 objective（如果为 None，使用原 objective）

        Returns:
            新的 AttackSeedGroup 实例
        """
        seeds: List[Seed] = []
        for s in seed_group.seeds:
            if isinstance(s, SeedObjective):
                new_obj = SeedObjective(
                    value=objective_override or s.value,
                    dataset_name=getattr(s, "dataset_name", "synthetic"),
                    harm_categories=getattr(s, "harm_categories", []) or [],
                    metadata=getattr(s, "metadata", {}),
                )
                seeds.append(new_obj)
            else:
                seeds.append(s)

        return AttackSeedGroup(seeds=seeds)
