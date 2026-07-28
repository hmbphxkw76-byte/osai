"""
Native Attack Executor (Facade)
===============================

统一攻击执行引擎 — 对齐 pyrit.executor.attack.core.attack_executor

架构职责（PyRIT 架构师视角）：
- 唯一的攻击执行入口：所有非顺序攻击模式统一走此模块
- 使用原生 AttackExecutor.execute_attack_from_seed_groups_async() 执行攻击
- 根据技术类型分派到单轮/多轮子执行器
- 不负责批量调度、进度跟踪、升级重试（那些在 ScenarioOrchestrator）

核心不变量 🟢：one-objective → one-result
核心 shape 🟢：configured by → consumes Context → produces Result

PyRIT 1.0.0 原生 API 对齐：
- AttackExecutor: 原生并行执行器，使用 asyncio.Semaphore 并发控制
- AttackExecutor.execute_attack_from_seed_groups_async(): 从 AttackSeedGroup 提取参数并执行
- AttackParameters.from_seed_group_async(): 自动提取 objective/next_message/prepended_conversation
- AttackResultAttribution: 父级编排器关联，持久化到 AttackResultEntry
"""

import logging
from typing import Any, Dict, List, Optional, Sequence

from pyrit.executor.attack import (
    AttackExecutor,
    AttackExecutorResult,
    AttackScoringConfig,
    AttackStrategy,
)
from pyrit.executor.attack.core.attack_result_attribution import AttackResultAttribution

from src.payloads.models import AttackPlan
from src.executor.attack.core.constants import (
    SINGLE_TURN_ATTACKS,
    TAP_FAMILY_ATTACKS,
    NO_REFUSAL_SCORER_ATTACKS,
)
from src.executor.attack.core.attack_builder import (
    ATTACK_CLASS_MAP,
    ATTACK_METADATA,
)
from src.executor.attack.single_turn.single_turn_executor import SingleTurnExecutor
from src.executor.attack.multi_turn.multi_turn_executor import MultiTurnExecutor
from src.executor.attack.compound.sequential_executor import SequentialExecutor
from src.executor.attack.component.seed_group_builder import SeedGroupBuilder
from src.scorers import (
    create_general_scorer,
    create_leakage_scorer,
    create_injection_scorer,
    create_composite_scorer,
    create_tap_scoring_config,
    create_refusal_scorer,
)
from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


class NativeAttackExecutor:
    """
    原生攻击执行器（Facade）— 使用 PyRIT 原生 AttackExecutor 执行攻击

    所有非顺序攻击模式的统一执行入口。
    ScenarioOrchestrator 委托此类执行单个攻击计划。

    核心设计：
    1. 使用原生 AttackExecutor 替代手动 execute_async(**kwargs)
    2. 根据技术类型分派到 SingleTurnExecutor 或 MultiTurnExecutor
    3. SequentialAttack 委托 SequentialExecutor
    4. 共享 _create_scoring_config() 和 SeedGroupBuilder
    5. 支持 AttackResultAttribution 父级编排器关联

    L5 事件循环安全：
    原生 AttackExecutor 使用延迟信号量创建（_get_semaphore），
    在首次 await 时绑定到当前事件循环，并在检测到事件循环变更时自动重建。
    因此 NativeAttackExecutor 实例可安全跨 asyncio.run() 调用复用。
    模块级单例 (get_direct_executor) 同样安全。
    如需强制重建，调用 reset_executor() 即可。
    """

    def __init__(self, max_concurrency: int = 1):
        """
        初始化原生攻击执行器

        Args:
            max_concurrency: 原生 AttackExecutor 的并发数（默认 1，由 ScenarioOrchestrator 控制并发）
        """
        self.config_loader = get_config_loader()
        attack_techniques = self.config_loader.get_strategy_config().get("attack_techniques", {})
        self.adversarial_techniques = {
            tech for tech, config in attack_techniques.items()
            if config.get("requires_adversarial", False)
        }
        # PyRIT 原生 AttackExecutor 实例
        # L5: 原生 AttackExecutor 的信号量是延迟创建的（_get_semaphore），
        # 在首次 await 时绑定到当前事件循环。跨事件循环复用时自动重建。
        self._native_executor = AttackExecutor(max_concurrency=max_concurrency)
        self._max_concurrency = max_concurrency
        # SeedGroup 构建器
        self._seed_builder = SeedGroupBuilder()
        # 子执行器
        self._single_turn = SingleTurnExecutor(
            native_executor=self._native_executor,
            seed_builder=self._seed_builder,
            scoring_config_factory=self._create_scoring_config,
            adversarial_techniques=self.adversarial_techniques,
        )
        self._multi_turn = MultiTurnExecutor(
            native_executor=self._native_executor,
            seed_builder=self._seed_builder,
            scoring_config_factory=self._create_scoring_config,
            adversarial_techniques=self.adversarial_techniques,
        )
        self._sequential = SequentialExecutor(
            native_executor=self._native_executor,
            seed_builder=self._seed_builder,
            scoring_config_factory=self._create_scoring_config,
            adversarial_techniques=self.adversarial_techniques,
        )

    def reset(self) -> None:
        """
        L5: 重置原生 AttackExecutor — 丢弃旧的信号量绑定

        原生 AttackExecutor 的信号量在首次 await 时绑定到事件循环。
        正常情况下跨事件循环复用会自动重建信号量（_get_semaphore 检测 loop 变更）。
        此方法提供显式重置接口，用于:
        - 测试场景中确保每次测试使用独立执行器
        - 长时间运行的服务中定期清理
        - 怀疑信号量泄漏时的手动干预
        """
        self._native_executor = AttackExecutor(max_concurrency=self._max_concurrency)
        self._single_turn._native_executor = self._native_executor
        self._multi_turn._native_executor = self._native_executor
        self._sequential._native_executor = self._native_executor
        logger.debug("NativeAttackExecutor reset: recreated AttackExecutor")

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    async def execute_single_attack(
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
        执行单次攻击 — 根据技术类型分派到单轮/多轮执行器

        Args:
            plan: 攻击计划
            objective_target: 目标 PromptTarget
            judge_target: 评审用 LLM Target
            objective_override: 可选的 objective 覆盖（用于多轮显式 turns）
            memory_labels_override: 可选的 memory_labels 覆盖
            converter_chain_override: 可选的 converter 链名覆盖（用于顺序步骤）
            attribution: 可选的 AttackResultAttribution（父级编排器关联）

        Returns:
            PyRIT AttackResult
        """
        technique = plan.attack_technique

        if technique in SINGLE_TURN_ATTACKS:
            return await self._single_turn.execute(
                plan=plan,
                objective_target=objective_target,
                judge_target=judge_target,
                objective_override=objective_override,
                memory_labels_override=memory_labels_override,
                converter_chain_override=converter_chain_override,
                attribution=attribution,
            )
        else:
            return await self._multi_turn.execute(
                plan=plan,
                objective_target=objective_target,
                judge_target=judge_target,
                objective_override=objective_override,
                memory_labels_override=memory_labels_override,
                converter_chain_override=converter_chain_override,
                attribution=attribution,
            )

    async def execute_batch_same_technique(
        self,
        attack: AttackStrategy,
        seed_groups: Sequence,
        adversarial_chat: Any = None,
        objective_scorer: Any = None,
        memory_labels: Optional[Dict[str, str]] = None,
        attribution: Optional[AttackResultAttribution] = None,
        return_partial_on_failure: bool = True,
    ) -> AttackExecutorResult:
        """
        批量执行相同技术的攻击 - 使用原生 AttackExecutor 并行执行

        这是 PyRIT 原生的批量执行入口，用于同一 Attack 实例处理多个 objective。
        ScenarioOrchestrator 可按技术分组后调用此方法提升效率。

        Args:
            attack: 已创建的 AttackStrategy 实例
            seed_groups: AttackSeedGroup 列表
            adversarial_chat: 对抗 LLM target（多轮攻击需要）
            objective_scorer: 评分器（SeedSimulatedConversation 需要）
            memory_labels: 广播到所有攻击的 memory_labels
            attribution: AttackResultAttribution（父级关联）
            return_partial_on_failure: 部分失败时是否返回部分结果

        Returns:
            AttackExecutorResult 包含所有完成的结果
        """
        broadcast_fields: Dict[str, Any] = {}
        if memory_labels:
            broadcast_fields["memory_labels"] = memory_labels

        return await self._native_executor.execute_attack_from_seed_groups_async(
            attack=attack,
            seed_groups=seed_groups,
            adversarial_chat=adversarial_chat,
            objective_scorer=objective_scorer,
            attribution=attribution,
            return_partial_on_failure=return_partial_on_failure,
            **broadcast_fields,
        )

    async def execute_sequential_attack(
        self,
        plan: AttackPlan,
        objective_target: Any,
        judge_target: Any,
        completion_policy=None,
        attribution: Optional[AttackResultAttribution] = None,
    ) -> Any:
        """
        执行顺序组合攻击 — 委托 SequentialExecutor
        """
        return await self._sequential.execute(
            plan=plan,
            objective_target=objective_target,
            judge_target=judge_target,
            completion_policy=completion_policy,
            attribution=attribution,
        )

    # ------------------------------------------------------------------
    # 共享辅助方法
    # ------------------------------------------------------------------

    def _create_scoring_config(
        self,
        scorer_type: str,
        judge_target: Any,
        plan: Optional[AttackPlan] = None,
        technique: Optional[str] = None,
    ) -> AttackScoringConfig:
        """
        根据 scorer_type 创建场景适配的 AttackScoringConfig

        PyRIT 1.0.0 三层评分架构：
        - objective_scorer: TrueFalseScorer 类型
        - refusal_scorer: TrueFalseScorer 类型（检测目标拒绝）
        - auxiliary_scorers: 辅助评分列表
        - use_score_as_feedback: 评分作为迭代反馈（默认 True）
        """
        # TAP 家族需要专用 TAPAttackScoringConfig
        if technique and technique in TAP_FAMILY_ATTACKS:
            custom_question = None
            if plan and plan.prompt_item.metadata:
                custom_question = plan.prompt_item.metadata.get("scorer_question")
            return create_tap_scoring_config(judge_target, custom_question=custom_question)

        # 自定义评分问题
        custom_question = None
        refusal_scorer_name = None
        if plan and plan.prompt_item.metadata:
            custom_question = plan.prompt_item.metadata.get("scorer_question")
            refusal_scorer_name = plan.prompt_item.metadata.get("refusal_scorer_name")

        if custom_question:
            from pyrit.score import SelfAskTrueFalseScorer
            scorer = SelfAskTrueFalseScorer(chat_target=judge_target, question=custom_question)
            # 单轮攻击和 red_teaming 不接受 refusal_scorer（PyRIT warn_if_set）
            if technique and technique in NO_REFUSAL_SCORER_ATTACKS:
                return AttackScoringConfig(objective_scorer=scorer)
            if refusal_scorer_name:
                from src.scorers import create_scorer_instance
                refusal_scorer = create_scorer_instance(refusal_scorer_name, chat_target=judge_target)
            else:
                refusal_scorer = create_refusal_scorer(judge_target)
            return AttackScoringConfig(
                objective_scorer=scorer,
                refusal_scorer=refusal_scorer,
            )

        # 默认：根据 scorer_type 创建
        if scorer_type == "leakage_detection":
            config = create_leakage_scorer(judge_target)
        elif scorer_type == "injection_detection":
            config = create_injection_scorer(judge_target)
        elif scorer_type == "code_safety":
            config = create_composite_scorer(
                judge_target, include_leakage=False,
                include_injection=True, include_refusal=True,
            )
        else:
            config = create_general_scorer(judge_target)

        # 单轮攻击和 red_teaming 不接受 refusal_scorer（PyRIT warn_if_set）
        if technique and technique in NO_REFUSAL_SCORER_ATTACKS and config.refusal_scorer is not None:
            return AttackScoringConfig(
                objective_scorer=config.objective_scorer,
                auxiliary_scorers=config.auxiliary_scorers,
            )
        return config

    def _build_attack_seed_group(
        self,
        plan: AttackPlan,
        objective: str,
        *,
        include_conversation: bool = True,
    ):
        """构建 AttackSeedGroup — 委托 SeedGroupBuilder"""
        return self._seed_builder.build(
            plan, objective, include_conversation=include_conversation
        )


# ============================================================
# 向后兼容：保留旧名称
# ============================================================

# DirectAttackExecutor 作为 NativeAttackExecutor 的别名（向后兼容）
DirectAttackExecutor = NativeAttackExecutor


# ============================================================
# 模块级便捷函数
# ============================================================

_executor_instance: Optional[NativeAttackExecutor] = None


def get_direct_executor() -> NativeAttackExecutor:
    """
    获取 NativeAttackExecutor 单例

    L5 事件循环安全：
    单例在首次调用时创建，后续复用。原生 AttackExecutor 的信号量
    是延迟创建的，跨事件循环复用时自动重建。因此单例可安全跨
    asyncio.run() 调用复用。如需强制重建，调用 reset_executor()。
    """
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = NativeAttackExecutor()
    return _executor_instance


def reset_executor() -> None:
    """
    L5: 重置模块级 NativeAttackExecutor 单例

    丢弃现有单例并置为 None，下次调用 get_direct_executor() 时重建。
    用于:
    - 测试场景中确保每个测试套件使用独立执行器
    - 事件循环变更后强制重建
    - 信号量泄漏排查
    """
    global _executor_instance
    if _executor_instance is not None:
        _executor_instance.reset()
    _executor_instance = None


async def execute_single_attack(
    plan: AttackPlan,
    objective_target: Any,
    judge_target: Any,
    objective_override: Optional[str] = None,
    memory_labels_override: Optional[Dict[str, str]] = None,
    converter_chain_override: Optional[str] = None,
    attribution: Optional[AttackResultAttribution] = None,
) -> Any:
    """执行单次攻击（便捷函数）"""
    return await get_direct_executor().execute_single_attack(
        plan, objective_target, judge_target,
        objective_override=objective_override,
        memory_labels_override=memory_labels_override,
        converter_chain_override=converter_chain_override,
        attribution=attribution,
    )


# ============================================================
# PyRIT 1.0.0 API 对齐验证
# ============================================================


def validate_attack_plan(plan: AttackPlan) -> List[str]:
    """
    验证 AttackPlan 与 PyRIT 1.0.0 API 的兼容性

    在执行前检查 AttackPlan 配置是否与 PyRIT 1.0.0 API 对齐，
    返回警告列表（空列表表示无问题）。
    """
    warnings: List[str] = []
    technique = plan.attack_technique

    # 1. 单轮攻击不应配置 max_turns > 1
    if technique in SINGLE_TURN_ATTACKS and plan.max_turns > 1:
        warnings.append(
            f"单轮攻击 '{technique}' 配置了 max_turns={plan.max_turns}，"
            f"PyRIT 1.0.0 中单轮攻击不接受 max_turns 参数（将被忽略）"
        )

    # 2. TAP 家族攻击应使用 TAPAttackScoringConfig
    if technique in TAP_FAMILY_ATTACKS:
        if plan.scorer_type not in ("float_scale", "tap_scoring", "general"):
            warnings.append(
                f"TAP 家族攻击 '{technique}' 应使用 TAPAttackScoringConfig，"
                f"当前 scorer_type='{plan.scorer_type}' 可能不兼容"
            )

    # 3. 已弃用的攻击技术
    metadata = ATTACK_METADATA.get(technique, {})
    if metadata.get("deprecated", False):
        warnings.append(
            f"攻击技术 '{technique}' 在 PyRIT 1.0.0 中已弃用，"
            f"将回退到 '{metadata.get('fallback', 'prompt_sending')}'"
        )

    # 4. tree_depth vs max_turns 参数映射
    from src.executor.attack.core.constants import TREE_DEPTH_ATTACKS
    if technique in TREE_DEPTH_ATTACKS and plan.max_turns > 0:
        warnings.append(
            f"攻击 '{technique}' 使用 tree_depth 参数（非 max_turns），"
            f"plan.max_turns={plan.max_turns} 将映射为 tree_depth"
        )

    return warnings


def get_attack_execution_summary(plan: AttackPlan) -> Dict[str, Any]:
    """
    获取攻击执行配置摘要（用于日志/调试）

    返回 AttackPlan 的 PyRIT 1.0.0 执行配置摘要，
    包含技术名、参数映射、Scorer/Converter 配置等。
    """
    from src.executor.attack.core.constants import (
        MAX_TURNS_ATTACKS, TREE_DEPTH_ATTACKS,
    )
    technique = plan.attack_technique
    return {
        "plan_id": plan.plan_id,
        "technique": technique,
        "attack_class": ATTACK_CLASS_MAP.get(technique, type(None)).__name__,
        "is_single_turn": technique in SINGLE_TURN_ATTACKS,
        "is_tap_family": technique in TAP_FAMILY_ATTACKS,
        "uses_max_turns": technique in MAX_TURNS_ATTACKS,
        "uses_tree_depth": technique in TREE_DEPTH_ATTACKS,
        "max_turns": plan.max_turns,
        "scorer_type": plan.scorer_type,
        "converter_chain": plan.converter_chain_name,
        "owasp_id": plan.owasp_id,
        "scenario_name": plan.scenario_name,
        "attack_mode": plan.prompt_item.attack_mode.value,
    }
