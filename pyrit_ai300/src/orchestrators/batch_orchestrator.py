"""
Batch Attack Orchestrator
=========================

本模块负责按攻击计划批量执行攻击。

核心改进（回归 PyRIT 原生框架）：
1. 使用 create_attack_instance() 创建 plan.attack_technique 对应的真实 Attack 类
   （不再硬编码 PromptSendingAttack）
2. 对需要 adversarial chat 的攻击（red_teaming/crescendo/pair/tap/context_compliance），
   自动创建 AttackAdversarialConfig，使用 judge_target 作为对抗 LLM
3. 根据 plan.scorer_type 创建场景适配的 Scorer（不再硬编码 SelfAskTrueFalseScorer）
4. 顺序组合攻击的每一步使用 step.attack_technique 对应的真实 Attack 类
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from pyrit.executor.attack import (
    PromptSendingAttack,
    AttackScoringConfig,
    AttackConverterConfig,
    AttackAdversarialConfig,
)

from src.payloads.models import (
    AttackMode,
    AttackPlan,
    BatchAttackResult,
)
from src.orchestrators.attack_builder import create_attack_instance, ATTACK_CLASS_MAP
from src.converters import load_preset_converter_chain
from src.scorers import (
    create_general_scorer,
    create_leakage_scorer,
    create_injection_scorer,
    create_composite_scorer,
)
from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


# ============================================================
# 批量攻击编排器
# ============================================================


class BatchAttackOrchestrator:
    """批量攻击编排器 - 按计划批量执行攻击"""

    def __init__(self):
        """初始化批量攻击编排器"""
        self.config_loader = get_config_loader()
        # 从 YAML 加载 adversarial 技术列表
        attack_techniques = self.config_loader.get_strategy_config().get("attack_techniques", {})
        self.adversarial_techniques = {
            tech for tech, config in attack_techniques.items()
            if config.get("requires_adversarial", False)
        }

    async def execute_batch(
        self,
        attack_plans: List[AttackPlan],
        objective_target: Any,
        judge_target: Any,
        max_concurrency: int = 4,
        fail_fast: bool = False,
        per_attack_timeout: int = 300,
    ) -> BatchAttackResult:
        """
        批量执行攻击计划

        执行策略：
        - 按优先级排序后执行
        - 使用 asyncio.Semaphore 控制并发度
        - 单个计划失败不影响其他计划（除非 fail_fast=True）
        - 每个 plan 使用其 attack_technique 对应的真实 PyRIT Attack 类
        - 每个 plan 使用其 scorer_type 对应的场景适配 Scorer

        Args:
            attack_plans: 攻击计划列表
            objective_target: 目标 PromptTarget
            judge_target: 评审用 LLM Target（同时用作 adversarial chat）
            max_concurrency: 最大并发数
            fail_fast: 单个攻击失败是否终止全部
            per_attack_timeout: 单次攻击超时（秒）

        Returns:
            批量攻击结果
        """
        result = BatchAttackResult(total_plans=len(attack_plans))
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _run_one(plan: AttackPlan) -> None:
            async with semaphore:
                try:
                    attack_result = await asyncio.wait_for(
                        self._execute_single_plan(
                            plan, objective_target, judge_target
                        ),
                        timeout=per_attack_timeout,
                    )
                    result.executed += 1
                    result.results.append(attack_result)

                    # 判断成功/失败
                    outcome = getattr(attack_result, "outcome", None)
                    if outcome is not None:
                        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
                        if outcome_str == "SUCCESS":
                            result.succeeded += 1
                        else:
                            result.failed += 1
                            # 反馈循环：攻击失败，尝试升级重试
                            upgraded_plans = self._generate_upgrade_plans(plan, attack_result)
                            for upgraded_plan in upgraded_plans:
                                result.upgrade_attempts += 1
                                try:
                                    upgraded_result = await asyncio.wait_for(
                                        self._execute_single_plan(
                                            upgraded_plan, objective_target, judge_target
                                        ),
                                        timeout=per_attack_timeout,
                                    )
                                    result.executed += 1
                                    result.results.append(upgraded_result)
                                    upgraded_outcome = getattr(upgraded_result, "outcome", None)
                                    if upgraded_outcome is not None:
                                        upgraded_outcome_str = str(upgraded_outcome.value).upper() if hasattr(upgraded_outcome, "value") else str(upgraded_outcome).upper()
                                        if upgraded_outcome_str == "SUCCESS":
                                            result.succeeded += 1
                                            result.upgrade_success += 1
                                        else:
                                            result.failed += 1
                                except Exception as upgrade_error:
                                    result.errored += 1
                                    result.errors.append({
                                        "plan_id": upgraded_plan.plan_id,
                                        "error": f"Upgrade failed: {upgrade_error}",
                                    })
                    else:
                        result.failed += 1

                except asyncio.TimeoutError:
                    result.executed += 1
                    result.errored += 1
                    result.errors.append({
                        "plan_id": plan.plan_id,
                        "error": f"Timeout after {per_attack_timeout}s",
                    })
                except Exception as e:
                    # 修复：评分器异常不中断流程，标记为 error 并继续
                    result.executed += 1
                    result.errored += 1
                    error_msg = str(e)
                    result.errors.append({
                        "plan_id": plan.plan_id,
                        "error": error_msg,
                    })
                    logger.warning(f"Plan {plan.plan_id} failed (non-fatal): {e}")

                    if fail_fast:
                        raise

        # 并发执行所有计划
        tasks = [_run_one(plan) for plan in attack_plans]
        await asyncio.gather(*tasks, return_exceptions=not fail_fast)

        return result

    # -----------------------------------------------------------------
    # 单计划执行分派
    # -----------------------------------------------------------------

    async def _execute_single_plan(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
    ) -> Any:
        """
        根据 attack_mode 和 attack_technique 分派到不同的执行路径

        每条路径都使用 plan.attack_technique 对应的真实 PyRIT Attack 类，
        并使用 plan.scorer_type 对应的场景适配 Scorer。
        """
        mode = plan.prompt_item.attack_mode

        if mode == AttackMode.SINGLE_TURN:
            return await self._execute_single_turn(plan, objective_target, judge_target)

        elif mode == AttackMode.MULTI_TURN:
            return await self._execute_multi_turn(plan, objective_target, judge_target)

        elif mode == AttackMode.CONVERTER_ENHANCED:
            return await self._execute_converter_enhanced(plan, objective_target, judge_target)

        elif mode == AttackMode.SEQUENTIAL:
            return await self._execute_sequential(plan, objective_target, judge_target)

        # 默认回退到单轮
        return await self._execute_single_turn(plan, objective_target, judge_target)

    # -----------------------------------------------------------------
    # Scorer 创建（场景适配）
    # -----------------------------------------------------------------

    def _create_scoring_config(
        self,
        scorer_type: str,
        judge_target: Any,
        plan: Optional[AttackPlan] = None,
    ) -> AttackScoringConfig:
        """
        根据 scorer_type 创建场景适配的 AttackScoringConfig

        如果载荷 metadata 中包含自定义 scorer_question，则使用自定义评分标准。

        Args:
            scorer_type: 评分器类型 (general/leakage_detection/injection_detection/code_safety)
            judge_target: 评审用 LLM Target
            plan: 攻击计划（可选，用于获取自定义评分问题）

        Returns:
            AttackScoringConfig 实例
        """
        # 检查是否有自定义评分问题
        custom_question = None
        if plan and plan.prompt_item.metadata:
            custom_question = plan.prompt_item.metadata.get("scorer_question")

        if custom_question:
            # 使用自定义评分问题创建 SelfAskTrueFalseScorer
            from pyrit.score import SelfAskTrueFalseScorer
            from pyrit.executor.attack import AttackScoringConfig
            scorer = SelfAskTrueFalseScorer(
                chat_target=judge_target,
                true_false_question=custom_question,
            )
            return AttackScoringConfig(objective_scorer=scorer)

        # 默认：根据 scorer_type 创建评分器
        if scorer_type == "leakage_detection":
            return create_leakage_scorer(judge_target)
        elif scorer_type == "injection_detection":
            return create_injection_scorer(judge_target)
        elif scorer_type == "code_safety":
            return create_composite_scorer(
                judge_target,
                include_leakage=False,
                include_injection=True,
                include_refusal=False,
            )
        else:
            return create_general_scorer(judge_target)

    # -----------------------------------------------------------------
    # Adversarial Config 创建
    # -----------------------------------------------------------------

    def _create_adversarial_config(
        self,
        judge_target: Any,
    ) -> AttackAdversarialConfig:
        """
        创建 AttackAdversarialConfig

        使用 judge_target 作为对抗 LLM（adversarial chat），
        让 PyRIT 原生多轮攻击（RedTeamingAttack/CrescendoAttack 等）
        自动生成对抗性对话。

        Args:
            judge_target: 评审用 LLM Target（同时用作 adversarial chat）

        Returns:
            AttackAdversarialConfig 实例
        """
        return AttackAdversarialConfig(target=judge_target)

    # -----------------------------------------------------------------
    # 各攻击模式执行
    # -----------------------------------------------------------------

    async def _execute_single_turn(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
    ) -> Any:
        """
        单轮直接攻击

        使用 plan.attack_technique 对应的真实 PyRIT Attack 类执行。
        对于需要 adversarial chat 的技术（如 red_teaming），自动创建 adversarial config。
        """
        technique = plan.attack_technique
        scoring_config = self._create_scoring_config(plan.scorer_type, judge_target, plan)

        # 构建 kwargs
        kwargs: Dict[str, Any] = {}

        # 如果是需要 adversarial chat 的技术，创建 adversarial config（从 YAML 加载）
        if technique in self.adversarial_techniques:
            kwargs["attack_adversarial_config"] = self._create_adversarial_config(judge_target)

        # 创建 Attack 实例（使用真实 Attack 类）
        attack = create_attack_instance(
            technique_name=technique,
            objective_target=objective_target,
            attack_scoring_config=scoring_config,
            **kwargs,
        )

        return await attack.execute_async(
            objective=plan.prompt_item.objective,
            memory_labels=plan.memory_labels,
        )

    async def _execute_multi_turn(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
    ) -> Any:
        """
        多轮渐进攻击

        两种模式：
        1. 如果 prompt 有显式 turns，按顺序逐轮发送（每轮使用 PromptSendingAttack）
        2. 如果 prompt 无显式 turns 且 attack_technique 是 red_teaming/crescendo 等，
           使用 PyRIT 原生多轮 Attack 类（自动生成对抗对话）
        """
        turns = plan.prompt_item.multi_turn_steps
        scoring_config = self._create_scoring_config(plan.scorer_type, judge_target, plan)

        if turns:
            # 模式 1：显式 turns，手动逐轮发送
            last_result = None
            for i, turn_objective in enumerate(turns):
                turn_labels = {
                    **plan.memory_labels,
                    "multi_turn_step": str(i + 1),
                    "total_turns": str(len(turns)),
                }
                attack = PromptSendingAttack(
                    objective_target=objective_target,
                    attack_scoring_config=scoring_config,
                )
                last_result = await attack.execute_async(
                    objective=turn_objective,
                    memory_labels=turn_labels,
                )
            return last_result
        else:
            # 模式 2：使用 PyRIT 原生多轮 Attack 类
            technique = plan.attack_technique
            kwargs: Dict[str, Any] = {
                "max_turns": plan.max_turns,
            }

            if technique in self.adversarial_techniques:
                kwargs["attack_adversarial_config"] = self._create_adversarial_config(judge_target)

            attack = create_attack_instance(
                technique_name=technique,
                objective_target=objective_target,
                attack_scoring_config=scoring_config,
                **kwargs,
            )

            return await attack.execute_async(
                objective=plan.prompt_item.objective,
                memory_labels=plan.memory_labels,
            )

    async def _execute_converter_enhanced(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
    ) -> Any:
        """
        编码转换增强攻击

        使用 plan.attack_technique 对应的 Attack 类 + 指定 Converter 链执行。
        """
        technique = plan.attack_technique
        scoring_config = self._create_scoring_config(plan.scorer_type, judge_target, plan)

        # 加载 Converter 链
        converter_config: Optional[AttackConverterConfig] = None
        if plan.converter_chain_name:
            converter_config = load_preset_converter_chain(plan.converter_chain_name)

        # 构建 kwargs
        kwargs: Dict[str, Any] = {}

        # 如果是需要 adversarial chat 的技术，创建 adversarial config
        if technique in self.adversarial_techniques:
            kwargs["attack_adversarial_config"] = self._create_adversarial_config(judge_target)

        # 创建 Attack 实例
        attack = create_attack_instance(
            technique_name=technique,
            objective_target=objective_target,
            attack_scoring_config=scoring_config,
            attack_converter_config=converter_config,
            **kwargs,
        )

        return await attack.execute_async(
            objective=plan.prompt_item.objective,
            memory_labels=plan.memory_labels,
        )

    async def _execute_sequential(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
    ) -> Any:
        """
        顺序组合攻击

        按 sequential_steps 依次执行多个攻击步骤，
        每步使用 step.attack_technique 对应的真实 PyRIT Attack 类。
        前一步建立上下文，后一步利用上下文提取信息。
        """
        scoring_config = self._create_scoring_config(plan.scorer_type, judge_target, plan)
        last_result = None

        for i, step in enumerate(plan.prompt_item.sequential_steps):
            # 加载该步骤的 Converter 链（如果有）
            converter_config: Optional[AttackConverterConfig] = None
            if step.converter_chain:
                converter_config = load_preset_converter_chain(step.converter_chain)

            step_labels = {
                **plan.memory_labels,
                "sequential_step": str(i + 1),
                "step_technique": step.attack_technique,
            }

            # 使用步骤指定的 attack_technique 创建 Attack 实例
            step_technique = step.attack_technique

            # 确保技术名称在 ATTACK_CLASS_MAP 中
            if step_technique not in ATTACK_CLASS_MAP:
                step_technique = "prompt_sending"

            kwargs: Dict[str, Any] = {}
            if step_technique in self.adversarial_techniques:
                kwargs["attack_adversarial_config"] = self._create_adversarial_config(judge_target)

            attack = create_attack_instance(
                technique_name=step_technique,
                objective_target=objective_target,
                attack_scoring_config=scoring_config,
                attack_converter_config=converter_config,
                **kwargs,
            )

            last_result = await attack.execute_async(
                objective=step.objective,
                memory_labels=step_labels,
            )

        return last_result

    # -----------------------------------------------------------------
    # 反馈循环：攻击升级策略
    # -----------------------------------------------------------------

    def _generate_upgrade_plans(
        self,
        original_plan: AttackPlan,
        failed_result: Any,
    ) -> List[AttackPlan]:
        """
        根据失败结果生成升级的攻击计划

        升级策略（从 YAML 加载）：
        1. 单轮失败 → 多轮对抗性攻击 (red_teaming/crescendo/pair)
        2. 基础多轮失败 → 高级多轮 (crescendo/pair/tap)
        3. 单轮失败 → 添加 Converter 链重试
        """
        upgrade_strategies = self.config_loader.get_strategy_config().get("attack_upgrade_strategies", {})
        current_technique = original_plan.attack_technique
        current_mode = original_plan.prompt_item.attack_mode
        upgraded_plans = []

        # 策略 1: 单轮 → 多轮升级
        if current_mode in (AttackMode.SINGLE_TURN, AttackMode.CONVERTER_ENHANCED):
            strategy = upgrade_strategies.get("single_turn_to_multi_turn", {})
            if current_technique in strategy.get("from", []):
                # 尝试升级到多轮技术
                for tech in strategy.get("to", [])[:1]:  # 限制为 1 个升级尝试
                    upgraded_plan = self._create_upgraded_plan(
                        original_plan,
                        new_technique=tech,
                        new_mode=AttackMode.MULTI_TURN,
                        reason=strategy.get("reason", ""),
                    )
                    upgraded_plans.append(upgraded_plan)
                    break

        # 策略 2: 基础多轮 → 高级多轮升级
        elif current_mode == AttackMode.MULTI_TURN and not original_plan.prompt_item.multi_turn_steps:
            strategy = upgrade_strategies.get("multi_turn_upgrade", {})
            if current_technique in strategy.get("from", []):
                for tech in strategy.get("to", [])[:1]:
                    upgraded_plan = self._create_upgraded_plan(
                        original_plan,
                        new_technique=tech,
                        new_mode=AttackMode.MULTI_TURN,
                        reason=strategy.get("reason", ""),
                    )
                    upgraded_plans.append(upgraded_plan)
                    break

        # 策略 3: 添加 Converter 链（仅对单轮且原计划无 Converter 链的情况）
        if not original_plan.converter_chain_name and current_mode == AttackMode.SINGLE_TURN:
            strategy = upgrade_strategies.get("add_converter", {})
            if current_technique in strategy.get("from", []):
                for chain in strategy.get("converter_chains", [])[:1]:
                    upgraded_plan = self._create_upgraded_plan(
                        original_plan,
                        new_technique=current_technique,
                        new_mode=AttackMode.CONVERTER_ENHANCED,
                        converter_chain=chain,
                        reason=strategy.get("reason", ""),
                    )
                    upgraded_plans.append(upgraded_plan)
                    break

        return upgraded_plans

    def _create_upgraded_plan(
        self,
        original_plan: AttackPlan,
        new_technique: str,
        new_mode: AttackMode,
        converter_chain: Optional[str] = None,
        reason: str = "",
    ) -> AttackPlan:
        """
        创建升级的攻击计划

        修复点：
        1. 多轮升级时 max_turns 设为合理值（3），而非继承单轮的 1
        2. converter_chain_name 写入 memory_labels，供报告统计
        3. PromptItem 完整复制所有字段
        """
        # 更新内存标签
        new_labels = {
            **original_plan.memory_labels,
            "upgraded_from": original_plan.attack_technique,
            "upgrade_reason": reason,
        }
        if converter_chain:
            new_labels["converter_chain_name"] = converter_chain

        # 完整复制 PromptItem
        from src.payloads.models import PromptItem
        new_prompt_item = PromptItem(
            id=original_plan.prompt_item.id,
            objective=original_plan.prompt_item.objective,
            owasp_id=original_plan.prompt_item.owasp_id,
            attack_mode=new_mode,
            source_id=original_plan.prompt_item.source_id,
            category=original_plan.prompt_item.category,
            converter_chains=original_plan.prompt_item.converter_chains.copy() if original_plan.prompt_item.converter_chains else [],
            multi_turn_steps=original_plan.prompt_item.multi_turn_steps.copy() if original_plan.prompt_item.multi_turn_steps else [],
            sequential_steps=original_plan.prompt_item.sequential_steps.copy() if original_plan.prompt_item.sequential_steps else [],
            metadata=original_plan.prompt_item.metadata.copy(),
        )

        # 修复：多轮升级时设置合理的 max_turns
        if new_mode == AttackMode.MULTI_TURN:
            upgraded_max_turns = 3  # 默认 3 轮多轮对抗
        else:
            upgraded_max_turns = 1

        return AttackPlan(
            plan_id=f"{original_plan.plan_id}_upgrade",
            prompt_item=new_prompt_item,
            attack_technique=new_technique,
            converter_chain_name=converter_chain,
            memory_labels=new_labels,
            max_turns=upgraded_max_turns,
            priority=original_plan.priority - 5,  # 降低优先级，避免无限递归
            owasp_id=original_plan.owasp_id,
            scorer_type=original_plan.scorer_type,
            scenario_name=original_plan.scenario_name,
        )


# ============================================================
# 工厂函数
# ============================================================


async def execute_batch_attacks(
    attack_plans: List[AttackPlan],
    objective_target: Any,
    judge_target: Any,
    max_concurrency: int = 4,
    fail_fast: bool = False,
    per_attack_timeout: int = 300,
) -> BatchAttackResult:
    """
    批量执行攻击计划（工厂函数）

    Args:
        attack_plans: 攻击计划列表
        objective_target: 目标 PromptTarget
        judge_target: 评审用 LLM Target（同时用作 adversarial chat）
        max_concurrency: 最大并发数
        fail_fast: 单个攻击失败是否终止全部
        per_attack_timeout: 单次攻击超时（秒）

    Returns:
        批量攻击结果
    """
    orchestrator = BatchAttackOrchestrator()
    return await orchestrator.execute_batch(
        attack_plans,
        objective_target,
        judge_target,
        max_concurrency,
        fail_fast,
        per_attack_timeout,
    )
