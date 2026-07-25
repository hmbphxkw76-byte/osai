"""
Sequential Attack Executor (Compound Layer 3)
=============================================

顺序组合攻击执行器 — 对齐 pyrit.executor.attack.compound.SequentialAttack

Layer 3: 策略编排层
"1 个 objective × N 个攻击策略（fallback chain）"

功能：
- 支持异构技术链（每步可以是不同的 Attack 技术）
- completion_policy 可配置（FIRST_SUCCESS / FIRST_DECISIVE / STRICT_ALL / EXHAUSTIVE / LAST_RESULT）
- 每步通过 AttackExecutor 执行，自动持久化
"""

import logging
from typing import Any, Dict, List, Optional

from pyrit.executor.attack import (
    AttackConverterConfig,
    SequentialAttack,
    SequentialChildAttack,
    SequenceCompletionPolicy,
)
from pyrit.executor.attack.core.attack_result_attribution import AttackResultAttribution
from pyrit.models import AttackSeedGroup, SeedObjective

from src.payloads.models import AttackPlan
from src.executor.attack.core.constants import (
    MULTI_TURN_TECHNIQUES,
    MAX_TURNS_ATTACKS,
    TREE_DEPTH_ATTACKS,
)
from src.executor.attack.core.attack_builder import (
    ATTACK_CLASS_MAP,
    create_attack_instance,
    create_attack_adversarial_config,
)
from src.converters import load_preset_converter_chain

logger = logging.getLogger(__name__)


class SequentialExecutor:
    """
    顺序组合攻击执行器

    执行流程：
    1. 遍历 sequential_steps，为每步创建 AttackStrategy
    2. 构建 SequentialChildAttack（每步可异构技术）
    3. 创建 SequentialAttack + completion_policy
    4. 执行并返回 SequentialAttackResult

    completion_policy 支持：
    - FIRST_SUCCESS    第一个成功即停止
    - FIRST_DECISIVE   第一个明确结果即停止
    - STRICT_ALL       全部成功才停止
    - EXHAUSTIVE       全部执行
    - LAST_RESULT      取最后一个结果
    """

    def __init__(self, native_executor, seed_builder, scoring_config_factory, adversarial_techniques):
        """
        Args:
            native_executor: PyRIT 原生 AttackExecutor 实例
            seed_builder: SeedGroupBuilder 实例
            scoring_config_factory: 可调用的评分配置创建工厂
            adversarial_techniques: 需要 adversarial 配置的技术集合
        """
        self._native_executor = native_executor
        self._seed_builder = seed_builder
        self._create_scoring_config = scoring_config_factory
        self._adversarial_techniques = adversarial_techniques

    async def execute(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
        completion_policy: SequenceCompletionPolicy = SequenceCompletionPolicy.FIRST_SUCCESS,
        attribution: Optional[AttackResultAttribution] = None,
    ) -> Any:
        """
        执行顺序组合攻击

        Args:
            plan: 攻击计划（SEQUENTIAL 模式）
            objective_target: 目标 PromptTarget
            judge_target: 评审用 LLM Target
            completion_policy: 完成策略
            attribution: AttackResultAttribution

        Returns:
            SequentialAttackResult
        """
        steps = plan.prompt_item.sequential_steps
        if not steps:
            # 无步骤时退化为单次攻击（委托 NativeAttackExecutor）
            from src.executor.attack.core.native_executor import NativeAttackExecutor
            # 使用模块级便捷函数避免循环依赖
            return await self._fallback_single_attack(
                plan, objective_target, judge_target, attribution=attribution
            )

        child_attacks: List[SequentialChildAttack] = []

        for i, step in enumerate(steps):
            step_technique = step.attack_technique or "prompt_sending"
            if step_technique not in ATTACK_CLASS_MAP:
                step_technique = "prompt_sending"

            # 为每步创建 AttackStrategy
            step_scoring_config = self._create_scoring_config(
                plan.scorer_type, judge_target, plan, step_technique
            )

            step_converter_config: Optional[AttackConverterConfig] = None
            if step.converter_chain:
                step_converter_config = load_preset_converter_chain(
                    step.converter_chain, converter_target=judge_target
                )

            step_attack_kwargs: Dict[str, Any] = {}
            if step_converter_config:
                step_attack_kwargs["attack_converter_config"] = step_converter_config

            # 多轮步骤需要 adversarial config
            needs_adversarial = step_technique in MULTI_TURN_TECHNIQUES
            if needs_adversarial:
                step_attack_kwargs["attack_adversarial_config"] = create_attack_adversarial_config(
                    judge_target=judge_target,
                    metadata=plan.prompt_item.metadata or {},
                )

            # max_turns / tree_depth
            if step_technique in MAX_TURNS_ATTACKS:
                step_attack_kwargs["max_turns"] = plan.max_turns
            elif step_technique in TREE_DEPTH_ATTACKS:
                step_attack_kwargs["tree_depth"] = plan.max_turns

            strategy = create_attack_instance(
                technique_name=step_technique,
                objective_target=objective_target,
                attack_scoring_config=step_scoring_config,
                **step_attack_kwargs,
            )

            # 构建 AttackSeedGroup
            seed_group = AttackSeedGroup(seeds=[SeedObjective(value=step.objective)])

            # 构建 SequentialChildAttack
            child_kwargs: Dict[str, Any] = {
                "strategy": strategy,
                "seed_group": seed_group,
                "memory_labels": {
                    **plan.memory_labels,
                    "sequential_step": str(i + 1),
                    "step_technique": step_technique,
                },
            }
            if needs_adversarial:
                child_kwargs["adversarial_chat"] = judge_target
                if step_scoring_config and step_scoring_config.objective_scorer:
                    child_kwargs["objective_scorer"] = step_scoring_config.objective_scorer

            child_attacks.append(SequentialChildAttack(**child_kwargs))

        # 创建 SequentialAttack
        sequential_attack = SequentialAttack(
            objective_target=objective_target,
            child_attacks=child_attacks,
            completion_policy=completion_policy,
        )

        # 执行
        return await sequential_attack.execute_async(
            objective=steps[-1].objective,
            memory_labels=plan.memory_labels,
        )

    async def _fallback_single_attack(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
        attribution: Optional[AttackResultAttribution] = None,
    ) -> Any:
        """无 sequential_steps 时退化为单次攻击"""
        from src.executor.attack.core.native_executor import get_direct_executor
        executor = get_direct_executor()
        return await executor.execute_single_attack(
            plan, objective_target, judge_target, attribution=attribution
        )
