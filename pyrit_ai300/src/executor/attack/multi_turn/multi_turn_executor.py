"""
Multi-Turn Attack Executor
==========================

多轮攻击执行器（军师迭代型）— 对齐 pyrit.executor.attack.multi_turn

覆盖技术：red_teaming / crescendo / tap / pair / tree_of_attacks_pruned

核心不变量 🟢：1 个 objective → 1 个 AttackResult（军师多轮迭代）
特点：需要 attack_adversarial_config + adversarial_chat

参数映射：
- max_turns: red_teaming / crescendo / crescendo_simulated
- tree_depth: tap / pair / tree_of_attacks_pruned
- tree_width / branching_factor / batch_size: TAP 家族高级参数
"""

import logging
from typing import Any, Dict, Optional

from pyrit.executor.attack import AttackConverterConfig
from pyrit.executor.attack.core.attack_result_attribution import AttackResultAttribution

from src.payloads.models import AttackPlan
from src.executor.attack.core.constants import (
    TAP_FAMILY_ATTACKS,
    MAX_TURNS_ATTACKS,
    TREE_DEPTH_ATTACKS,
)
from src.executor.attack.core.attack_builder import (
    ATTACK_METADATA,
    create_attack_instance,
    create_attack_adversarial_config,
    create_prepended_conversation_config,
)
from src.converters import load_preset_converter_chain

logger = logging.getLogger(__name__)


class MultiTurnExecutor:
    """
    多轮攻击执行器

    执行流程：
    1. 创建 AttackScoringConfig（TAP 家族用 TAPAttackScoringConfig）
    2. 创建 AttackAdversarialConfig（system_prompt / first_message / template）
    3. 参数映射：max_turns vs tree_depth vs tree_width / branching_factor / batch_size
    4. PrependedConversationConfig（当有 multi_turn_steps > 1）
    5. 构建 AttackSeedGroup（编码 SeedPrompt 序列 + 角色交替）
    6. 调用原生 execute_attack_from_seed_groups_async(adversarial_chat=judge_target)
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
        执行多轮攻击

        Args:
            plan: 攻击计划
            objective_target: 目标 PromptTarget
            judge_target: 评审用 LLM Target
            objective_override: 可选的 objective 覆盖（用于多轮显式 turns）
            memory_labels_override: 可选的 memory_labels 覆盖
            converter_chain_override: 可选的 converter 链名覆盖
            attribution: 可选的 AttackResultAttribution

        Returns:
            PyRIT AttackResult
        """
        technique = plan.attack_technique

        # 1. 创建评分配置
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

        # 3. 构建 Attack 构造参数
        attack_kwargs: Dict[str, Any] = {}
        if converter_config:
            attack_kwargs["attack_converter_config"] = converter_config

        # 多轮攻击需要 attack_adversarial_config（完整配置）
        if technique in self._adversarial_techniques:
            yaml_metadata = plan.prompt_item.metadata or {}
            attack_kwargs["attack_adversarial_config"] = create_attack_adversarial_config(
                judge_target=judge_target,
                metadata=yaml_metadata,
            )

        # 传递 max_turns / tree_depth 参数
        if technique in MAX_TURNS_ATTACKS:
            attack_kwargs["max_turns"] = plan.max_turns
        elif technique in TREE_DEPTH_ATTACKS:
            attack_kwargs["tree_depth"] = plan.max_turns

        # CrescendoAttack 支持 max_backtracks
        tech_metadata = ATTACK_METADATA.get(technique, {})
        if tech_metadata.get("supports_max_backtracks", False):
            max_backtracks = (plan.prompt_item.metadata or {}).get("max_backtracks")
            if max_backtracks is not None:
                attack_kwargs["max_backtracks"] = max_backtracks

        # TAP/PAIR 高级参数（tree_width / branching_factor / batch_size）
        if technique in TAP_FAMILY_ATTACKS:
            tap_metadata = plan.prompt_item.metadata or {}
            for param_key in ("tree_width", "branching_factor", "batch_size"):
                param_value = tap_metadata.get(param_key)
                if param_value is not None and isinstance(param_value, int) and param_value > 0:
                    attack_kwargs[param_key] = param_value

        # PrependedConversationConfig（当有前置对话时）
        if plan.prompt_item.multi_turn_steps and len(plan.prompt_item.multi_turn_steps) > 1:
            apply_roles = (plan.prompt_item.metadata or {}).get("prepended_converter_roles")
            if apply_roles:
                attack_kwargs["prepended_conversation_config"] = create_prepended_conversation_config(
                    apply_converters_to_roles=apply_roles
                )

        # 4. 创建 Attack 实例
        attack = create_attack_instance(
            technique_name=technique,
            objective_target=objective_target,
            attack_scoring_config=scoring_config,
            **attack_kwargs,
        )

        # 5. 构建 AttackSeedGroup
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

        # 7. 执行（多轮攻击需要 adversarial_chat）
        adversarial_chat = judge_target if technique in self._adversarial_techniques else None

        objective_scorer = None
        if scoring_config and scoring_config.objective_scorer:
            objective_scorer = scoring_config.objective_scorer

        executor_result = await self._native_executor.execute_attack_from_seed_groups_async(
            attack=attack,
            seed_groups=[seed_group],
            adversarial_chat=adversarial_chat,
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
