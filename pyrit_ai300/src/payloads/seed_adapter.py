"""
Seed Prompt Adapter
===================

数据模型桥接层 - 在 PyRIT 原生 SeedDataset/SeedObjective/SeedPrompt/SeedSimulatedConversation
与项目自定义 PromptItem/PromptBatch 之间双向转换。

核心功能：
1. 将 PyRIT SeedDataset → PromptBatch（保持兼容当前管道）
2. 利用 PyRIT 原生 SeedDataset.seed_groups 进行种子分组
3. 利用 SeedGroup.objective / .prompts / .simulated_conversation_config 提取结构化信息
4. 将 PromptItem → SeedObjective（反向转换）
5. 处理 metadata.attack_mode → AttackMode 映射

架构原则：桥接而非替换 - 保留当前管道业务逻辑，在底层与 PyRIT 原生 API 对齐。
"""

import logging
from typing import Any, List, Optional, Sequence

# 全部从 pyrit.models 公共 API 导入（SeedGroup/AttackSeedGroup 已在 pyrit.models.__init__ 中导出）
from pyrit.models import (
    AttackSeedGroup,
    SeedDataset,
    SeedGroup,
    SeedObjective,
    SeedPrompt,
    SeedSimulatedConversation,
)

from src.payloads.models import (
    AttackMode,
    PromptBatch,
    PromptItem,
    SequentialStep,
)

logger = logging.getLogger(__name__)


# ============================================================
# Attack Mode 映射
# ============================================================

_ATTACK_MODE_MAP: dict[str, AttackMode] = {
    "single_turn": AttackMode.SINGLE_TURN,
    "multi_turn": AttackMode.MULTI_TURN,
    "converter_enhanced": AttackMode.CONVERTER_ENHANCED,
    "sequential": AttackMode.SEQUENTIAL,
}


def _get_attack_mode(metadata: Optional[dict[str, Any]], default: AttackMode = AttackMode.SINGLE_TURN) -> AttackMode:
    """从 metadata 中提取 attack_mode"""
    if not metadata:
        return default
    mode_str = metadata.get("attack_mode", default.value)
    return _ATTACK_MODE_MAP.get(mode_str, default)


# ============================================================
# SeedDataset → PromptBatch 适配器
# ============================================================


class SeedPromptAdapter:
    """
    PyRIT SeedDataset ↔ 项目 PromptBatch/PromptItem 双向适配器

    用法：
        # 从 PyRIT SeedDataset 转换
        batches = SeedPromptAdapter.dataset_to_batches(seed_dataset)

        # 从 PromptItem 反向转换
        objective = SeedPromptAdapter.item_to_objective(prompt_item)
    """

    @staticmethod
    def dataset_to_batches(
        dataset: SeedDataset,
        owasp_id: Optional[str] = None,
    ) -> List[PromptBatch]:
        """
        将 PyRIT SeedDataset 转换为项目 PromptBatch 列表

        使用 PyRIT 原生 SeedDataset.seed_groups 进行种子分组，
        利用 SeedGroup.objective / .prompts / .simulated_conversation_config
        提取结构化信息。

        策略：
        1. 调用 dataset.seed_groups 获取原生分组（按 prompt_group_id）
        2. 每个分组生成 PromptItem
           - AttackSeedGroup（含 objective）→ multi_turn / sequential
           - SeedGroup（无 objective）→ single_turn / converter_enhanced
        3. 按 OWASP ID 聚合为 PromptBatch

        Args:
            dataset: PyRIT SeedDataset
            owasp_id: 可选的 OWASP ID 覆盖

        Returns:
            PromptBatch 列表
        """
        # 按 OWASP ID 分组 items
        items_by_owasp: dict[str, List[PromptItem]] = {}
        dataset_name = dataset.dataset_name or dataset.name or "unknown"
        description = dataset.description or ""

        for seed_group in dataset.seed_groups:
            item = SeedPromptAdapter._seed_group_to_item(
                seed_group, owasp_id=owasp_id, dataset_name=dataset_name
            )
            if item is None:
                continue

            oid = item.owasp_id or owasp_id or "unknown"
            items_by_owasp.setdefault(oid, []).append(item)

        batches: List[PromptBatch] = []
        for group_owasp_id, items in items_by_owasp.items():
            if not items:
                continue
            batches.append(PromptBatch(
                source_id=dataset_name,
                owasp_id=group_owasp_id,
                category=description,
                description=description,
                prompts=items,
            ))

        return batches

    @staticmethod
    def _seed_group_to_item(
        seed_group: SeedGroup,
        owasp_id: Optional[str],
        dataset_name: str,
    ) -> Optional[PromptItem]:
        """
        将单个 SeedGroup（或 AttackSeedGroup）转换为 PromptItem

        利用 PyRIT 原生 SeedGroup API：
        - seed_group.objective: SeedObjective | None
        - seed_group.prompts: Sequence[SeedPrompt]
        - seed_group.simulated_conversation_config: SeedSimulatedConversation | None
        - seed_group.is_single_turn(): bool
        - seed_group.is_single_request(): bool
        """
        objective = seed_group.objective
        prompts = list(seed_group.prompts)
        simulated_config = seed_group.simulated_conversation_config

        # 从第一个有 metadata 的 seed 获取 attack_mode
        first_meta: dict[str, Any] = {}
        for seed in seed_group.seeds:
            if seed.metadata:
                first_meta = seed.metadata
                break

        owasp_id_resolved = owasp_id or first_meta.get("owasp_id")
        attack_mode = _get_attack_mode(first_meta)

        # 提取 objective 描述
        objective_value = objective.value if objective else None

        # 提取 simulated_conversation 配置
        sim_config = SeedPromptAdapter._extract_simulated_config(simulated_config) if simulated_config else None

        # 构建 metadata
        meta = {**first_meta}
        if objective_value is not None:
            meta["has_objective"] = True
            meta["objective_value"] = objective_value
            meta["seed_type"] = "objective"
        else:
            meta["has_objective"] = False
            meta["seed_type"] = "prompt"

        if sim_config:
            meta["simulated_conversation"] = sim_config

        # 根据 attack_mode 构建不同结构
        if attack_mode == AttackMode.MULTI_TURN and prompts:
            return PromptItem(
                id=str(getattr(prompts[0], "prompt_group_alias", "")) or str(getattr(prompts[0], "id", "")) or prompts[0].value[:50],
                objective=objective_value or prompts[0].value,
                attack_mode=AttackMode.MULTI_TURN,
                owasp_id=owasp_id_resolved,
                source_id=dataset_name,
                category=first_meta.get("category"),
                multi_turn_steps=[p.value for p in prompts],
                metadata=meta,
            )

        elif attack_mode == AttackMode.SEQUENTIAL and prompts:
            steps = []
            for p in prompts:
                p_meta = p.metadata or {}
                steps.append(SequentialStep(
                    attack_technique=p_meta.get("attack_technique", ""),
                    objective=p.value,
                    converter_chain=p_meta.get("converter_chain"),
                ))
            return PromptItem(
                id=str(getattr(prompts[0], "prompt_group_alias", "")) or str(getattr(prompts[0], "id", "")) or prompts[0].value[:50],
                objective=objective_value or prompts[0].value,
                attack_mode=AttackMode.SEQUENTIAL,
                owasp_id=owasp_id_resolved,
                source_id=dataset_name,
                category=first_meta.get("category"),
                sequential_steps=steps,
                metadata=meta,
            )

        else:
            # 单轮或转换增强：每个 prompt 独立处理
            if not prompts:
                # 纯 objective seed（无 prompt）
                if objective:
                    return PromptItem(
                        id=str(getattr(objective, "id", "")) or objective.value[:50],
                        objective=objective.value,
                        attack_mode=attack_mode,
                        owasp_id=owasp_id_resolved,
                        source_id=dataset_name,
                        category=first_meta.get("category"),
                        converter_chains=first_meta.get("converter_chains", []),
                        metadata=meta,
                    )
                return None

            # 每个 prompt 生成独立 item
            p = prompts[0]
            p_meta = p.metadata or {}
            return PromptItem(
                id=str(getattr(p, "id", "")) or p.value[:50],
                objective=p.value,
                attack_mode=attack_mode,
                owasp_id=owasp_id_resolved,
                source_id=dataset_name,
                category=p_meta.get("category"),
                converter_chains=p_meta.get("converter_chains", []),
                metadata={
                    **p_meta,
                    "has_objective": objective_value is not None,
                    "objective_value": objective_value,
                    "role": getattr(p, "role", "user"),
                },
            )

    @staticmethod
    def _extract_simulated_config(sim: SeedSimulatedConversation) -> dict[str, Any]:
        """
        从 SeedSimulatedConversation 提取配置字典
        """
        return {
            "num_turns": sim.num_turns,
            "sequence": sim.sequence,
            "adversarial_chat_system_prompt_path": str(sim.adversarial_chat_system_prompt_path),
            "simulated_target_system_prompt_path": str(sim.simulated_target_system_prompt_path),
            "next_message_system_prompt_path": str(sim.next_message_system_prompt_path) if sim.next_message_system_prompt_path else None,
        }

    @staticmethod
    def item_to_objective(item: PromptItem) -> SeedObjective:
        """
        将项目 PromptItem 转换为 PyRIT SeedObjective

        用于将项目数据写入 PyRIT CentralMemory 或与 PyRIT 原生组件交互。
        """
        metadata = dict(item.metadata or {})
        if item.owasp_id:
            metadata["owasp_id"] = item.owasp_id
        metadata["attack_mode"] = item.attack_mode.value

        return SeedObjective(
            value=item.objective,
            dataset_name=item.source_id or "owasp_custom",
            metadata=metadata,
            harm_categories=metadata.get("harm_categories", []),
        )

    @staticmethod
    def items_to_dataset(
        items: List[PromptItem],
        dataset_name: str = "owasp_custom",
        description: str = "",
        harm_categories: Optional[List[str]] = None,
    ) -> SeedDataset:
        """
        将项目 PromptItem 列表转换为 PyRIT SeedDataset

        用于将项目数据导出为 PyRIT 原生格式。
        """
        seeds: list = []
        group_counter = 0

        for item in items:
            metadata = dict(item.metadata or {})
            if item.owasp_id:
                metadata["owasp_id"] = item.owasp_id
            metadata["attack_mode"] = item.attack_mode.value

            if item.attack_mode == AttackMode.MULTI_TURN and item.multi_turn_steps:
                group_counter += 1
                alias = f"{item.id}_group_{group_counter}"
                for i, turn_value in enumerate(item.multi_turn_steps):
                    seeds.append(SeedObjective(
                        value=turn_value,
                        dataset_name=dataset_name,
                        prompt_group_alias=alias,
                        metadata={**metadata, "sequence": i + 1},
                        harm_categories=harm_categories or [],
                    ))

            elif item.attack_mode == AttackMode.SEQUENTIAL and item.sequential_steps:
                group_counter += 1
                alias = f"{item.id}_group_{group_counter}"
                for i, step in enumerate(item.sequential_steps):
                    step_meta = {**metadata, "attack_technique": step.attack_technique}
                    if step.converter_chain:
                        step_meta["converter_chain"] = step.converter_chain
                    seeds.append(SeedObjective(
                        value=step.objective,
                        dataset_name=dataset_name,
                        prompt_group_alias=alias,
                        metadata=step_meta,
                        harm_categories=harm_categories or [],
                    ))

            else:
                seeds.append(SeedObjective(
                    value=item.objective,
                    dataset_name=dataset_name,
                    metadata=metadata,
                    harm_categories=harm_categories or [],
                ))

        return SeedDataset(
            seeds=seeds,
            dataset_name=dataset_name,
            description=description,
        )

    @staticmethod
    def remote_datasets_to_batches(
        datasets: List[SeedDataset],
    ) -> List[PromptBatch]:
        """
        将多个 PyRIT SeedDataset（如远程数据集）批量转换为 PromptBatch

        用于集成 PyRIT 60+ 远程数据集到当前管道。
        """
        all_batches: List[PromptBatch] = []
        for dataset in datasets:
            batches = SeedPromptAdapter.dataset_to_batches(dataset)
            all_batches.extend(batches)
        return all_batches

    @staticmethod
    def seed_groups_to_batches(
        seed_groups: Sequence[SeedGroup],
    ) -> List[PromptBatch]:
        """
        将 CentralMemory 查询出的 SeedGroup 列表转换为 PromptBatch

        桥接 ②数据管理层 → 现有 ④攻击执行层。
        每个 SeedGroup 转换为一个 PromptItem，按 dataset_name 聚合为 PromptBatch。

        Args:
            seed_groups: CentralMemory get_seed_groups() 返回的 SeedGroup 列表

        Returns:
            PromptBatch 列表
        """
        items_by_dataset: dict[str, List[PromptItem]] = {}

        for seed_group in seed_groups:
            # 构建临时 SeedDataset 以复用现有转换逻辑
            dataset_name = ""
            for seed in seed_group.seeds:
                if hasattr(seed, "dataset_name") and seed.dataset_name:
                    dataset_name = seed.dataset_name
                    break
            if not dataset_name:
                dataset_name = "central_memory"

            item = SeedPromptAdapter._seed_group_to_item(
                seed_group, owasp_id=None, dataset_name=dataset_name
            )
            if item is not None:
                items_by_dataset.setdefault(dataset_name, []).append(item)

        batches: List[PromptBatch] = []
        for ds_name, items in items_by_dataset.items():
            if items:
                batches.append(PromptBatch(
                    source_id=ds_name,
                    owasp_id=None,
                    prompts=items,
                ))

        return batches

    @staticmethod
    def create_simulated_conversation_objective(
        objective: str,
        num_turns: int = 3,
        owasp_id: Optional[str] = None,
        technique: str = "red_teaming",
    ) -> SeedSimulatedConversation:
        """
        以编程方式创建 SeedSimulatedConversation 配置

        用于动态生成模拟对话场景（PrependedConversationConfig），
        无需在 YAML 中硬编码路径。

        Args:
            objective: 攻击目标描述
            num_turns: 对话轮数
            owasp_id: OWASP ID
            technique: 攻击技术

        Returns:
            SeedSimulatedConversation 实例
        """
        from pyrit.common.path import EXECUTOR_RED_TEAM_PATH

        adversarial_prompt_path = EXECUTOR_RED_TEAM_PATH / "attack_prompt_gen_template.yaml"

        return SeedSimulatedConversation(
            num_turns=num_turns,
            sequence=0,
            adversarial_chat_system_prompt_path=adversarial_prompt_path,
            metadata={
                "owasp_id": owasp_id or "",
                "technique": technique,
                "objective": objective,
            },
        )
