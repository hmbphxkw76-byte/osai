"""
Native Pipeline
================

原生管道快捷路径 — 减少 AttackPlan 中间层依赖

对齐 PyRIT 1.0.0 原生管道：
  SeedDataset → SeedGroup → AttackSeedGroup → AttackExecutor

本模块提供两种管道模式：

模式 A（原生管道 — P3 新增）：
  适用于简单场景，跳过 PromptItem/PromptBatch/AttackPlan 中间层，
  直接从 CentralMemory 的 SeedGroup 构建 AttackSeedGroup 并执行。

  流程：CentralMemory.get_seed_groups() → AttackPreparator.prepare()
        → AttackExecutor.execute_attack_from_seed_groups_async()

模式 B（兼容管道 — 现有）：
  适用于需要策略匹配、Jailbreak 增强、Converter 展开、优先级排序的复杂场景。

  流程：load_payloads_async() → PromptBatch → PayloadPlanner.plan_attacks()
        → AttackPlan → SeedGroupBuilder.build() → AttackExecutor

何时使用哪种模式：
- 原生管道：快速测试、单一技术执行、已知 SeedGroup 结构、CI/CD 自动化
- 兼容管道：批量多 OWASP 攻击、策略自动匹配、Jailbreak 增强、顺序组合攻击

AI-300 考试知识点：
- PyRIT 1.0.0 原生管道：SeedGroup → AttackSeedGroup → AttackExecutor
- AttackParameters.from_seed_group_async() 自动提取三要素
- AttackExecutor.execute_attack_from_seed_groups_async() 批量并行执行
"""

import logging
from typing import Any, Dict, List, Optional, Sequence

from pyrit.models import (
    AttackSeedGroup,
    SeedGroup,
)

from src.payloads.attack_preparator import AttackPreparator

logger = logging.getLogger(__name__)


# ============================================================
# 原生管道执行器
# ============================================================


class NativePipelineExecutor:
    """
    原生管道执行器 — 直接从 SeedGroup 到 AttackExecutor

    跳过 PromptItem/PromptBatch/AttackPlan 中间层，
    直接使用 PyRIT 原生 AttackSeedGroup + AttackExecutor。

    优势：
    - 无中间层转换开销
    - 完全使用原生 API，最大化兼容性
    - 适合简单场景和快速测试

    限制：
    - 无策略自动匹配（需手动指定技术/scorer/converter）
    - 无 Jailbreak 增强
    - 无优先级排序
    - 无顺序组合攻击支持

    用法：
        pipeline = NativePipelineExecutor(executor=native_executor)
        result = await pipeline.execute(
            seed_groups=seed_groups,
            attack=attack_instance,
            objective_target=target,
            adversarial_chat=judge,
            objective_scorer=scorer,
        )
    """

    def __init__(self, executor: Any = None):
        """
        初始化原生管道执行器

        Args:
            executor: NativeAttackExecutor 实例。
                如果为 None，使用 get_direct_executor() 单例。
        """
        if executor is None:
            from src.executor.attack.core.native_executor import get_direct_executor
            executor = get_direct_executor()
        self._executor = executor

    async def execute(
        self,
        *,
        seed_groups: Sequence[SeedGroup],
        attack: Any,
        adversarial_chat: Any = None,
        objective_scorer: Any = None,
        memory_labels: Optional[Dict[str, str]] = None,
        return_partial_on_failure: bool = True,
    ) -> Any:
        """
        原生管道执行 — 从 SeedGroup 直接到 AttackExecutor

        流程：
        1. AttackPreparator.prepare() 将 SeedGroup → AttackSeedGroup
        2. AttackExecutor.execute_attack_from_seed_groups_async() 执行

        Args:
            seed_groups: CentralMemory 查询出的 SeedGroup 列表
            attack: 已创建的 AttackStrategy 实例
            adversarial_chat: 对抗 LLM target（多轮攻击 + SeedSimulatedConversation 需要）
            objective_scorer: TrueFalseScorer 评分器
            memory_labels: 可选的 memory_labels
            return_partial_on_failure: 部分失败时是否返回部分结果

        Returns:
            AttackExecutorResult
        """
        # 1. 准备：SeedGroup → AttackSeedGroup
        attack_seed_groups = await AttackPreparator.prepare_batch(
            seed_groups,
            adversarial_chat=adversarial_chat,
            objective_scorer=objective_scorer,
        )

        if not attack_seed_groups:
            logger.warning("No attack seed groups after preparation")
            from pyrit.executor.attack import AttackExecutorResult
            return AttackExecutorResult(completed_results=[], incomplete_objectives=[])

        logger.info(
            f"Native pipeline: executing {len(attack_seed_groups)} seed groups "
            f"with attack={type(attack).__name__}"
        )

        # 2. 执行：AttackExecutor.execute_attack_from_seed_groups_async()
        broadcast_fields: Dict[str, Any] = {}
        if memory_labels:
            broadcast_fields["memory_labels"] = memory_labels

        result = await self._executor.execute_batch_same_technique(
            attack=attack,
            seed_groups=attack_seed_groups,
            adversarial_chat=adversarial_chat,
            objective_scorer=objective_scorer,
            memory_labels=memory_labels,
            return_partial_on_failure=return_partial_on_failure,
        )

        return result

    async def execute_from_central_memory(
        self,
        *,
        memory: Any,
        attack: Any,
        harm_categories: Optional[List[str]] = None,
        owasp_ids: Optional[List[str]] = None,
        multi_turn_only: bool = False,
        adversarial_chat: Any = None,
        objective_scorer: Any = None,
        memory_labels: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        从 CentralMemory 查询种子组并执行

        便捷方法：直接从 CentralMemory 查询 SeedGroup，跳过 PromptBatch/AttackPlan。

        Args:
            memory: CentralMemory 实例
            attack: AttackStrategy 实例
            harm_categories: 危害类别过滤
            owasp_ids: OWASP ID 过滤（通过 metadata）
            multi_turn_only: 仅查询多轮种子组
            adversarial_chat: 对抗 LLM target
            objective_scorer: 评分器
            memory_labels: memory_labels

        Returns:
            AttackExecutorResult
        """
        # 查询种子组
        seed_groups = memory.get_seed_groups(
            harm_categories=harm_categories,
        )

        # 可选过滤
        if owasp_ids:
            owasp_set = {oid.upper() for oid in owasp_ids}
            seed_groups = [
                sg for sg in seed_groups
                if any(
                    s.metadata and s.metadata.get("owasp_id", "").upper() in owasp_set
                    for s in sg.seeds
                )
            ]

        if multi_turn_only:
            seed_groups = [
                sg for sg in seed_groups
                if sg.prepended_conversation is not None
            ]

        logger.info(f"CentralMemory query: {len(seed_groups)} seed groups matched")

        return await self.execute(
            seed_groups=seed_groups,
            attack=attack,
            adversarial_chat=adversarial_chat,
            objective_scorer=objective_scorer,
            memory_labels=memory_labels,
        )


# ============================================================
# 便捷函数
# ============================================================


_native_pipeline: Optional[NativePipelineExecutor] = None


def get_native_pipeline() -> NativePipelineExecutor:
    """获取 NativePipelineExecutor 单例"""
    global _native_pipeline
    if _native_pipeline is None:
        _native_pipeline = NativePipelineExecutor()
    return _native_pipeline


async def execute_native_async(
    *,
    seed_groups: Sequence[SeedGroup],
    attack: Any,
    adversarial_chat: Any = None,
    objective_scorer: Any = None,
    memory_labels: Optional[Dict[str, str]] = None,
) -> Any:
    """
    原生管道便捷函数 — 从 SeedGroup 直接执行

    Args:
        seed_groups: SeedGroup 列表
        attack: AttackStrategy 实例
        adversarial_chat: 对抗 LLM target
        objective_scorer: 评分器
        memory_labels: memory_labels

    Returns:
        AttackExecutorResult
    """
    return await get_native_pipeline().execute(
        seed_groups=seed_groups,
        attack=attack,
        adversarial_chat=adversarial_chat,
        objective_scorer=objective_scorer,
        memory_labels=memory_labels,
    )


# ============================================================
# AttackPlan 中间层评估工具
# ============================================================


def evaluate_attack_plan_necessity(seed_group: SeedGroup) -> Dict[str, Any]:
    """
    评估 AttackPlan 中间层对指定 SeedGroup 的必要性

    分析 SeedGroup 的特征，判断是否需要 AttackPlan 中间层，
    还是可以直接使用原生管道。

    判断规则：
    - 需要 AttackPlan：
      - 有 converter_chains metadata（需要 Converter 展开）
      - 有 sequential_steps（顺序组合攻击）
      - 有多个 OWASP ID 需要策略匹配
      - 需要 Jailbreak 增强
    - 可用原生管道：
      - 单一技术执行
      - 无 Converter 需求
      - 已有明确的 objective + prompts

    Args:
        seed_group: 要评估的 SeedGroup

    Returns:
        评估结果字典：
        - needs_attack_plan: bool
        - reasons: List[str]
        - recommended_pipeline: "native" | "compat"
    """
    reasons: List[str] = []
    needs_plan = False

    # 检查 metadata 中的 converter_chains
    for seed in seed_group.seeds:
        meta = getattr(seed, "metadata", {}) or {}
        if meta.get("converter_chains"):
            reasons.append("Has converter_chains in metadata")
            needs_plan = True
            break

    # 检查 sequential attack_mode
    for seed in seed_group.seeds:
        meta = getattr(seed, "metadata", {}) or {}
        if meta.get("attack_mode") == "sequential":
            reasons.append("Sequential attack mode requires step planning")
            needs_plan = True
            break

    # 检查是否需要 Jailbreak 增强
    for seed in seed_group.seeds:
        meta = getattr(seed, "metadata", {}) or {}
        if meta.get("needs_jailbreak"):
            reasons.append("Jailbreak enhancement requested")
            needs_plan = True
            break

    # 检查多 OWASP ID
    owasp_ids = set()
    for seed in seed_group.seeds:
        meta = getattr(seed, "metadata", {}) or {}
        oid = meta.get("owasp_id")
        if oid:
            owasp_ids.add(oid)
    if len(owasp_ids) > 1:
        reasons.append(f"Multiple OWASP IDs ({len(owasp_ids)}) require strategy matching")
        needs_plan = True

    return {
        "needs_attack_plan": needs_plan,
        "reasons": reasons,
        "recommended_pipeline": "compat" if needs_plan else "native",
        "owasp_ids": list(owasp_ids),
        "has_objective": seed_group.objective is not None,
        "has_simulated_conversation": seed_group.has_simulated_conversation,
        "prompt_count": len(seed_group.prompts),
    }
