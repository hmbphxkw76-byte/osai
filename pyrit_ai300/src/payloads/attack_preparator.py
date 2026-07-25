"""
Attack Preparator
=================

③ 攻击准备层 - SeedGroup → AttackSeedGroup

对齐 PyRIT 1.0.0 五层架构：
  ① 数据准备层 → DatasetManager.load_*()
  ② 数据管理层 → CentralMemory (dataset_manager.py)
  ③ 攻击准备层 → AttackPreparator (本模块)
  ④ 攻击执行层 → AttackExecutor.execute_attack_from_seed_groups_async()
  ⑤ 评估与追踪层 → Scorer + Memory

核心功能：
1. 将 CentralMemory 查询出的 SeedGroup 转化为 AttackSeedGroup
2. 为无 objective 的种子组自动创建合成 objective
3. 条件分派：根据种子组特征推荐攻击技术

PyRIT 原生 API（L5 对齐）：
  AttackSeedGroup(seeds=[...])  → 强制恰好一个 objective
  attack_group.objective         → SeedObjective
  attack_group.next_message      → Message (最后一轮 user 消息)
  attack_group.prepended_conversation → list[Message] (前置对话历史)
  attack_group.harm_categories   → list[str]
  attack_group.has_simulated_conversation → bool

  AttackParameters.from_seed_group_async(seed_group=..., **overrides)
    → 自动提取 objective / next_message / prepended_conversation
    → 不再需要中间 AttackExecutionParams 层

设计变更（L5 优化）：
  旧版: prepare() → AttackExecutionParams (冗余中间层，重复 AttackParameters 字段)
  新版: prepare() → AttackSeedGroup (原生对象，让 from_seed_group_async 自动提取)
"""

import logging
import warnings
from typing import Any, Dict, List, Optional, Sequence

from pyrit.models import (
    AttackSeedGroup,
    Seed,
    SeedGroup,
    SeedObjective,
    SeedPrompt,
)

logger = logging.getLogger(__name__)


# ============================================================
# 向后兼容：AttackExecutionParams (已废弃，保留为过渡层)
# ============================================================


class _AttackExecutionParamsDeprecated:
    """
    .. deprecated::
        AttackExecutionParams 已废弃。AttackPreparator.prepare() 现在直接返回
        AttackSeedGroup，由原生 AttackParameters.from_seed_group_async() 自动提取
        objective / next_message / prepended_conversation。

        保留此类仅为向后兼容，新代码应直接使用 AttackSeedGroup。
    """

    def __init__(self, **kwargs):
        warnings.warn(
            "AttackExecutionParams is deprecated. Use AttackSeedGroup directly "
            "and let AttackParameters.from_seed_group_async() extract fields.",
            DeprecationWarning,
            stacklevel=2,
        )
        for k, v in kwargs.items():
            setattr(self, k, v)


# 向后兼容别名
AttackExecutionParams = _AttackExecutionParamsDeprecated


# ============================================================
# 攻击准备器
# ============================================================


class AttackPreparator:
    """
    攻击准备器 - 将 CentralMemory 查询出的 SeedGroup 转化为 AttackSeedGroup

    ③层职责（L5 对齐）：
    1. SeedGroup → AttackSeedGroup（确保恰好一个 objective）
    2. 为无 objective 的种子组创建合成 objective
    3. 条件分派：根据 AttackSeedGroup 特征推荐攻击技术

    PyRIT 原生管道：
        seed_group = AttackPreparator.prepare(raw_group)
        # → AttackSeedGroup (原生对象)
        # → AttackExecutor.execute_attack_from_seed_groups_async(seed_groups=[seed_group])
        # → AttackParameters.from_seed_group_async() 自动提取三要素

    用法示例：
        preparator = AttackPreparator()

        # 从 CentralMemory 查询种子组
        seed_groups = manager.get_seed_groups(harm_categories=["prompt_injection"])

        # 转化为 AttackSeedGroup（原生对象）
        attack_groups = await preparator.prepare_batch(seed_groups)

        # 条件分派
        for ag in attack_groups:
            technique = preparator.select_attack_technique(ag)
            # technique → "prompt_sending" / "crescendo" / "red_teaming"
    """

    # ------------------------------------------------------------------
    # 核心方法
    # ------------------------------------------------------------------

    @staticmethod
    async def prepare(
        seed_group: SeedGroup,
        *,
        adversarial_chat: Any = None,
        objective_scorer: Any = None,
    ) -> AttackSeedGroup:
        """
        将 SeedGroup 转化为 AttackSeedGroup

        PyRIT 原生管道：返回 AttackSeedGroup，让
        AttackParameters.from_seed_group_async() 自动提取三要素。

        流程：
        1. 检查 seed_group 是否有 objective
        2. 无 objective → 从第一个 prompt 创建合成 objective
        3. 构建 AttackSeedGroup（PyRIT 原生，强制恰好一个 objective）

        Args:
            seed_group: CentralMemory 查询出的 SeedGroup
            adversarial_chat: 对抗 LLM target（用于 SeedSimulatedConversation 生成，
                由 from_seed_group_async 在执行时使用，此处仅透传）
            objective_scorer: 评分器（同上）

        Returns:
            AttackSeedGroup 实例（PyRIT 原生对象）
        """
        seeds = list(seed_group.seeds)

        # 1. 确保有 objective
        has_objective = any(isinstance(s, SeedObjective) for s in seeds)
        if not has_objective:
            seeds = AttackPreparator._create_synthetic_objective(seeds, seed_group)

        # 2. 构建 AttackSeedGroup（PyRIT 原生，强制恰好一个 objective）
        return AttackSeedGroup(seeds=seeds)

    @staticmethod
    async def prepare_batch(
        seed_groups: Sequence[SeedGroup],
        *,
        adversarial_chat: Any = None,
        objective_scorer: Any = None,
    ) -> List[AttackSeedGroup]:
        """
        批量转化种子组 → AttackSeedGroup

        Args:
            seed_groups: SeedGroup 列表
            adversarial_chat: 对抗 LLM target
            objective_scorer: 评分器

        Returns:
            AttackSeedGroup 列表（PyRIT 原生对象）
        """
        results: List[AttackSeedGroup] = []
        for sg in seed_groups:
            try:
                attack_group = await AttackPreparator.prepare(
                    sg,
                    adversarial_chat=adversarial_chat,
                    objective_scorer=objective_scorer,
                )
                results.append(attack_group)
            except Exception as e:
                logger.warning(f"Failed to prepare seed group: {e}")
        return results

    # ------------------------------------------------------------------
    # 条件分派 - 根据 AttackSeedGroup 特征选择攻击策略
    # ------------------------------------------------------------------

    @staticmethod
    def select_attack_technique(attack_group: AttackSeedGroup) -> str:
        """
        根据 AttackSeedGroup 特征自动选择攻击技术

        选择逻辑（对齐 PyRIT 原生条件执行模式）：
        - 有 prepended_conversation → 多轮攻击（crescendo）
        - 有 next_message 但无 prepended → 单轮直接攻击（prompt_sending）
        - 无 next_message 且无 prepended → 目标导向攻击（red_teaming）

        Args:
            attack_group: AttackSeedGroup（PyRIT 原生对象）

        Returns:
            攻击技术名称（对应 ATTACK_CLASS_MAP 的键）
        """
        # 有前置对话 → 多轮渐进攻击
        if attack_group.prepended_conversation:
            return "crescendo"

        # 有 next_message → 单轮直接发送
        if attack_group.next_message is not None:
            return "prompt_sending"

        # 无 next_message 且无 prepended → 目标导向多轮
        return "red_teaming"

    @staticmethod
    def is_multi_turn(attack_group: AttackSeedGroup) -> bool:
        """判断是否为多轮攻击"""
        return bool(attack_group.prepended_conversation)

    @staticmethod
    def is_single_turn(attack_group: AttackSeedGroup) -> bool:
        """判断是否为单轮攻击"""
        return not attack_group.prepended_conversation and attack_group.next_message is not None

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _create_synthetic_objective(
        seeds: List[Seed],
        seed_group: SeedGroup,
    ) -> List[Seed]:
        """
        为无 objective 的种子组创建合成 objective

        策略：从第一个 SeedPrompt 的 value 创建 SeedObjective，
        保留原始 metadata 和 harm_categories。

        Args:
            seeds: 原始种子列表
            seed_group: 源种子组

        Returns:
            包含合成 objective 的新种子列表
        """
        prompts = [s for s in seeds if isinstance(s, SeedPrompt)]
        if not prompts:
            # 纯 objective 组（不应该到这里，但防御性处理）
            return seeds

        first_prompt = prompts[0]

        # 从种子组提取 harm_categories
        harm_cats = seed_group.harm_categories if hasattr(seed_group, "harm_categories") else []

        # 创建合成 objective
        synthetic = SeedObjective(
            value=first_prompt.value,
            dataset_name=getattr(first_prompt, "dataset_name", "synthetic"),
            harm_categories=harm_cats,
            metadata={
                "synthetic_objective": True,
                "source_prompt_id": str(getattr(first_prompt, "id", "")),
            },
        )

        return [synthetic, *seeds]

    @staticmethod
    def extract_metadata(seed_group: SeedGroup) -> Dict[str, Any]:
        """
        从种子组提取元数据（用于日志/调试）

        Args:
            seed_group: SeedGroup 或 AttackSeedGroup

        Returns:
            元数据字典
        """
        meta: Dict[str, Any] = {}

        # 从第一个有种子的 metadata 提取
        for seed in seed_group.seeds:
            if hasattr(seed, "metadata") and seed.metadata:
                meta.update(dict(seed.metadata))
                break

        # 标记是否有 simulated conversation
        meta["has_simulated_conversation"] = seed_group.has_simulated_conversation

        # 标记是否有 objective
        meta["has_objective"] = seed_group.objective is not None

        # 种子数量
        meta["seed_count"] = len(seed_group.seeds)

        return meta
