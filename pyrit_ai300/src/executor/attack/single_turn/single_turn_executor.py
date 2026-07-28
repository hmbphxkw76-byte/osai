"""
Single-Turn Attack Executor
============================

单轮攻击执行器（直发型）— 对齐 pyrit.executor.attack.single_turn

覆盖技术：prompt_sending / multi_prompt_sending / many_shot / skeleton / chunked_request

核心不变量 🟢：1 个 objective → 1 个 AttackResult（无军师迭代）
特点：不接受 attack_adversarial_config，不需要 adversarial_chat
"""

import logging
from typing import Any, Dict, Optional

from pyrit.executor.attack import AttackConverterConfig
from pyrit.executor.attack.core.attack_result_attribution import AttackResultAttribution

from src.payloads.models import AttackPlan
from src.executor.attack.core.attack_builder import (
    create_attack_instance,
)
from src.converters import load_preset_converter_chain

logger = logging.getLogger(__name__)


class SingleTurnExecutor:
    """
    单轮攻击执行器

    执行流程：
    1. 创建 AttackScoringConfig（剥离 refusal_scorer）
    2. 创建 AttackConverterConfig（如有 Converter 链）
    3. 创建 Attack 实例（无 adversarial_config）
    4. 构建 AttackSeedGroup（纯 objective，无 prepended_conversation）
    5. 调用原生 execute_attack_from_seed_groups_async()
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
        objective_override: Optional[str] = None,
        memory_labels_override: Optional[Dict[str, str]] = None,
        converter_chain_override: Optional[str] = None,
        attribution: Optional[AttackResultAttribution] = None,
    ) -> Any:
        """
        执行单轮攻击

        Args:
            plan: 攻击计划
            objective_target: 目标 PromptTarget
            judge_target: 评审用 LLM Target
            objective_override: 可选的 objective 覆盖
            memory_labels_override: 可选的 memory_labels 覆盖
            converter_chain_override: 可选的 converter 链名覆盖
            attribution: 可选的 AttackResultAttribution

        Returns:
            PyRIT AttackResult
        """
        technique = plan.attack_technique

        # 1. 创建评分配置（单轮攻击剥离 refusal_scorer）
        scoring_config = self._create_scoring_config(
            plan.scorer_type, judge_target, plan, technique
        )

        # 2. 创建 Converter 配置
        converter_config: Optional[AttackConverterConfig] = None
        chain_name = converter_chain_override or plan.converter_chain_name
        if chain_name:
            converter_config = load_preset_converter_chain(
                chain_name, converter_target=judge_target
            )

        # 3. 构建 Attack 构造参数（单轮攻击不需要 adversarial_config）
        attack_kwargs: Dict[str, Any] = {}
        if converter_config:
            attack_kwargs["attack_converter_config"] = converter_config

        # 4. 创建 Attack 实例
        attack = create_attack_instance(
            technique_name=technique,
            objective_target=objective_target,
            attack_scoring_config=scoring_config,
            **attack_kwargs,
        )

        # 5. 构建 AttackSeedGroup（单轮攻击不编码对话序列）
        objective_value = objective_override or plan.prompt_item.objective
        include_conversation = objective_override is None
        seed_group = self._seed_builder.build(
            plan, objective_value, include_conversation=include_conversation
        )

        # 6. 构建 broadcast fields
        broadcast_fields: Dict[str, Any] = {
            "memory_labels": memory_labels_override or plan.memory_labels,
        }
        if plan.prompt_item.metadata:
            harm_categories = plan.prompt_item.metadata.get("targeted_harm_categories")
            if harm_categories and isinstance(harm_categories, list):
                broadcast_fields["targeted_harm_categories"] = harm_categories

        # 7. 执行（单轮攻击不需要 adversarial_chat）
        objective_scorer = None
        if scoring_config and scoring_config.objective_scorer:
            objective_scorer = scoring_config.objective_scorer

        executor_result = await self._native_executor.execute_attack_from_seed_groups_async(
            attack=attack,
            seed_groups=[seed_group],
            adversarial_chat=None,
            objective_scorer=objective_scorer,
            attribution=attribution,
            **broadcast_fields,
        )

        # 返回第一个完成的结果
        if executor_result.completed_results:
            return executor_result.completed_results[0]
        if executor_result.incomplete_objectives:
            raise executor_result.incomplete_objectives[0][1]
        raise RuntimeError("AttackExecutor returned neither completed nor incomplete results.")
