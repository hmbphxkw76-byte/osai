"""
AI-300 Adaptive Scenario — 原生 AdaptiveScenario + FailureTypeRoutingSelector
============================================================================

P0+P2: 用原生 AdaptiveScenario 替代自建 AttackUpgradeStrategy

原生 AdaptiveTechniqueDispatcher 构建 SequentialAttack(FIRST_SUCCESS)：
  - 自动按 selector 排序尝试多个技术
  - 成功即停止（提前停止）
  - epsilon-greedy 跨 objective 学习

P2 增强：Converter 变体感知 + extra_request_converters 渐进式升级
  - 覆盖 _build_techniques_dict() 添加 Converter 变体 bundles
  - 原生 FIRST_SUCCESS 自动在首个成功变体处停止
  - 利用 AttackTechniqueFactory.create(extra_request_converters=...) 实现渐进式追加

L5 增强：ModalityRouter 集成 + Target-Aware 自动推断
  - _build_techniques_dict() 中调用 ModalityRouter.route_attack() 过滤不支持的技术
  - 自动从 objective_target 推断 target_type（无需手动传入）
  - _get_attack_technique_factories() 中按 Target 类型过滤不适用的 Converter 变体
  - 原生 TargetCapabilities 驱动的模态感知技术筛选

FailureTypeRoutingSelector 增加失败类型路由：
  - model_refusal → Converter 变体优先（编码/混淆绕过）
  - timeout → 基础单轮技术优先（减少执行时间）
  - objective_not_achieved → 强技术 + Converter 变体优先

移除自建 AttackUpgradeStrategy 的多候选递归逻辑，
依赖原生 SequentialAttack(FIRST_SUCCESS) 天然实现。

保留自建：per_attack_timeout（考试时间约束优化）
"""

import logging
import re
from typing import Any

from pyrit.common import apply_defaults
from pyrit.models import Parameter
from pyrit.scenario import DatasetAttackConfiguration
from pyrit.scenario.core.scenario_technique import ScenarioTechnique
from pyrit.scenario.scenarios.adaptive import (
    AdaptiveScenario,
    EpsilonGreedyTechniqueSelector,
    TechniqueSelector,
)

from src.scenarios.ai300_technique import AI300Technique
from src.scenarios.failure_type_selector import FailureTypeRoutingSelector

logger = logging.getLogger(__name__)


# ============================================================
# L5: Target 类型自动推断映射
# ============================================================

# PyRIT Target 类名 → target_type 映射
# 用于从 objective_target 实例自动推断 target_type，无需手动传入
_TARGET_CLASS_NAME_MAP: dict[str, str] = {
    "OpenAIChatTarget": "openai_chat",
    "OpenAIResponseTarget": "openai_responses",
    "LiteLLMChatTarget": "litellm",
    "AzureMLChatTarget": "azure_ml",
    "PromptShieldTarget": "prompt_shield",
    "PlaywrightTarget": "playwright",
    "PlaywrightCopilotTarget": "playwright_copilot",
    "CopilotTarget": "websocket_copilot",
    "WebSocketCopilotTarget": "websocket_copilot",
    "HTTPTarget": "http_api",
    "AzureBlobStorageTarget": "azure_blob",
    "OpenAIImageTarget": "openai_image",
    "OpenAIVideoTarget": "openai_video",
    "OpenAITTSTarget": "openai_tts",
}


class AI300EpsilonGreedySelector(FailureTypeRoutingSelector):
    """
    AI-300 Epsilon-Greedy 技术选择器（增强版）

    继承 FailureTypeRoutingSelector，在 EpsilonGreedyTechniqueSelector 基础上增加：
    1. 失败类型路由（替代自建 AttackUpgradeStrategy 的失败类型分析）
    2. 考试最优参数预设（epsilon=0.2, random_seed=42）
    3. Converter 变体感知排序（P1 增强）
    4. 编码攻击优先策略（考试快速高成功率）
    5. Target 类型感知优先级（P3 增强）
    6. OWASP 策略映射初始偏好（v2.0 — 消除双轨风险）

    原生替代说明：
    - 自建 AttackUpgradeStrategy 的多候选递归 → 原生 SequentialAttack(FIRST_SUCCESS)
    - 自建 extract_failure_type → FailureTypeRoutingSelector.update_failure_type
    - 自建 generate_upgrade_plans → 原生 AdaptiveTechniqueDispatcher 自动构建
    - 自建 add_converter 策略 → Converter 变体预注册 + extra_request_converters
    """

    def __init__(
        self,
        epsilon: float = 0.2,
        random_seed: int | None = 42,
        target_type: str | None = None,
        owasp_id: str | None = None,
    ) -> None:
        super().__init__(
            epsilon=epsilon,
            random_seed=random_seed,
            target_type=target_type,
            owasp_id=owasp_id,
        )


class AI300AdaptiveScenario(AdaptiveScenario):
    """
    AI-300 自适应 Scenario — 原生 AdaptiveScenario + 失败类型路由 + Converter 变体

    用原生 AdaptiveScenario 替代自建 AttackUpgradeStrategy + ScenarioOrchestrator 升级重试。
    原生 AdaptiveTechniqueDispatcher 自动构建 SequentialAttack(FIRST_SUCCESS)：
      - 按 selector 排序尝试多个技术（含 Converter 变体）
      - 成功即停止（提前停止）
      - 成本 O(max_attempts x objectives) 而非 O(techniques x objectives)

    P2 增强：Converter 变体感知
      - 覆盖 _build_techniques_dict() 在原生技术池基础上追加 Converter 变体
      - 每个变体将 AttackConverterConfig 烘焙到 AttackTechniqueFactory
      - 原生 FIRST_SUCCESS 自动在首个成功变体处停止
      - 利用 extra_request_converters 实现渐进式 Converter 升级链

    FailureTypeRoutingSelector 在 epsilon-greedy 基础上增加失败类型路由：
      - model_refusal → Converter 变体优先
      - timeout → 基础单轮技术优先
      - objective_not_achieved → 强技术 + Converter 变体优先

    保留自建 per_attack_timeout（考试时间约束优化）。

    Usage:
        scenario = AI300AdaptiveScenario()
        scenario.set_params_from_args(args={
            "objective_target": target,
            "max_attempts_per_objective": 3,
        })
        await scenario.initialize_async()
        result = await scenario.run_async()
        # 原生 tqdm 进度条自动显示
        # 原生 max_retries 自动重试
        # 原生自动恢复（中断后可 resume）
    """

    VERSION: int = 1

    # ------------------------------------------------------------------
    # Abstract method implementations (required by AdaptiveScenario)
    # ------------------------------------------------------------------

    @classmethod
    def _atomic_attack_prefix(cls) -> str:
        """Return the prefix for per-objective atomic-attack names."""
        return "ai300_adaptive"

    @classmethod
    def get_technique_class(cls) -> type[ScenarioTechnique]:
        """Return the scenario's technique enum."""
        return AI300Technique

    @classmethod
    def default_dataset_config(cls) -> DatasetAttackConfiguration:
        """Return the default DatasetAttackConfiguration for AI-300 adaptive runs."""
        return DatasetAttackConfiguration(
            dataset_names=[
                "airt_hate",
                "airt_violence",
                "airt_harassment",
                "airt_misinformation",
                "airt_leakage",
            ],
            max_dataset_size=4,
        )

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    @apply_defaults
    def __init__(
        self,
        *,
        selector: TechniqueSelector | None = None,
        objective_scorer=None,
        converter_target: Any = None,
        target_type: str | None = None,
        owasp_id: str | None = None,
        scenario_result_id: str | None = None,
    ) -> None:
        """
        初始化 AI-300 自适应 Scenario

        Args:
            selector: 技术选择器，None 时使用 AI300EpsilonGreedySelector（含失败类型路由）
            objective_scorer: 目标评分器
            converter_target: LLM 辅助 Converter 所需的目标 PromptTarget（通常为 judge_target）
            target_type: PyRIT Target 类型名（如 "openai_chat"），用于 Target 感知排序
            owasp_id: OWASP ID（如 "LLM01"），用于 v2.0 策略偏好初始排序
            scenario_result_id: 恢复 ID
        """
        # P2: 保存 converter_target 用于构建 Converter 变体（在 super().__init__ 之前）
        self._converter_target = converter_target
        # L5: 保存 target_type 用于后续自动推断和过滤
        self._target_type = target_type
        # R2: objective_target 在 _build_techniques_dict 时存储
        self._objective_target: Any = None

        # P3: 如果没有传入 selector，创建带 target_type 和 owasp_id 的 AI300EpsilonGreedySelector
        if selector is None:
            selector = AI300EpsilonGreedySelector(
                target_type=target_type,
                owasp_id=owasp_id,
            )
        else:
            if target_type and hasattr(selector, "set_target_type"):
                selector.set_target_type(target_type)
            if owasp_id and hasattr(selector, "set_owasp_id"):
                selector.set_owasp_id(owasp_id)

        # 使用 FailureTypeRoutingSelector 替代自建 AttackUpgradeStrategy
        super().__init__(
            objective_scorer=objective_scorer,
            selector=selector,
            scenario_result_id=scenario_result_id,
        )

    @staticmethod
    def _infer_target_type(objective_target: Any) -> str | None:
        """
        L5: 从 objective_target 实例自动推断 target_type

        按优先级依次尝试：
        1. 目标实例的 _target_type 属性
        2. 目标类名在 _TARGET_CLASS_NAME_MAP 中的映射
        3. CamelCase → snake_case 转换后匹配已知 target_type

        Args:
            objective_target: PyRIT PromptTarget 实例

        Returns:
            target_type 字符串（如 "openai_chat"），无法推断时返回 None
        """
        if objective_target is None:
            return None

        # 1. 检查 _target_type 属性
        target_type = getattr(objective_target, "_target_type", None)
        if target_type:
            return target_type

        # 2. 类名直接映射
        class_name = type(objective_target).__name__
        if class_name in _TARGET_CLASS_NAME_MAP:
            return _TARGET_CLASS_NAME_MAP[class_name]

        # 3. CamelCase → snake_case 转换
        snake_name = re.sub(
            r"([A-Z]+)([A-Z][a-z])", r"\1_\2",
            re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", class_name)
        ).lower().replace("_target", "")
        # 检查是否匹配已知 target type
        from src.converters.target_aware_router import TARGET_TYPE_GROUPS
        if snake_name in TARGET_TYPE_GROUPS:
            return snake_name

        logger.debug(f"Could not infer target_type from class '{class_name}'")
        return None

    @classmethod
    def additional_parameters(cls) -> list[Parameter]:
        """
        P3: 声明自适应专用参数

        保留自建：per_attack_timeout（考试时间约束优化）
        其余参数（max_retries, max_concurrency 等）由原生 Scenario 基类提供。

        Returns:
            - max_attempts_per_objective: 每个 objective 最大尝试次数（默认 3）
            - per_attack_timeout: 单次攻击超时（默认 300）— 自建保留
        """
        return [
            Parameter(
                name="max_attempts_per_objective",
                description="Max techniques tried per objective. Defaults to 3.",
                param_type=int,
                default=3,
            ),
            Parameter(
                name="per_attack_timeout",
                description="Per-attack timeout in seconds. Exam optimization.",
                param_type=int,
                default=300,
            ),
        ]

    def _get_attack_technique_factories(self) -> dict[str, Any]:
        """
        P2+L5: 覆盖原生方法，在原生技术池基础上追加 Converter 变体工厂

        原生方法从 catalog + registry 获取基础技术工厂。
        本方法在原生结果基础上，追加 Converter 变体工厂
        （为每个基础技术注册多个 Converter 变体，烘焙 AttackConverterConfig）。

        L5 增强：当 target_type 已知时，按 Target 类型过滤不适用的 Converter 变体，
        仅保留 target_aware_router 推荐的链。这减少了不必要的技术池膨胀，
        提升 FIRST_SUCCESS 的效率。

        Returns:
            技术名 → AttackTechniqueFactory 映射（含 Converter 变体）
        """
        # 获取原生基础技术工厂
        base_factories = super()._get_attack_technique_factories()

        # P2+R0+R2: 追加 Converter 变体工厂（Target 感知 + 模态过滤）
        # R0: target_type 驱动动态链选择（替代 post-build L5 过滤）
        # R2: objective_target 驱动模态兼容性检测
        from src.scenarios.technique_factories import build_converter_variant_factories

        variant_factories = build_converter_variant_factories(
            converter_target=self._converter_target,
            target_type=self._target_type,
            objective_target=self._objective_target,
        )

        for factory in variant_factories:
            # 不覆盖已有的（幂等）
            if factory.name not in base_factories:
                base_factories[factory.name] = factory

        logger.info(
            f"AI300AdaptiveScenario: {len(base_factories)} total factories "
            f"({len(variant_factories)} converter variants)"
        )
        return base_factories

    def _build_techniques_dict(
        self,
        *,
        objective_target: Any,
    ) -> dict[str, Any]:
        """
        P0+L5: 覆盖原生方法，在基础技术之外追加 Converter 变体 TechniqueBundle

        原生 _build_techniques_dict 只遍历 self._scenario_techniques（枚举值），
        但 Converter 变体名（如 "prompt_sending+stealth_evasion"）不在枚举中，
        导致变体工厂虽已注册但从未被选中。

        本方法：
        1. L5: 自动推断 target_type（如未手动传入）
        2. 调用 super() 获取基础技术的 TechniqueBundle dict
        3. L5: ModalityRouter 过滤 — 移除 Target 不支持的技术
        4. 从 _get_attack_technique_factories() 获取含变体的工厂池
        5. 为已解析基础技术对应的 Converter 变体创建 TechniqueBundle
        6. 返回合并后的 dict（含基础 + 变体）

        这样原生 AdaptiveTechniqueDispatcher 的 SequentialAttack(FIRST_SUCCESS)
        就能按 selector 排序尝试 Converter 变体，成功即停止。
        """
        # L5: 自动推断 target_type（如未手动传入）
        if not self._target_type:
            inferred_type = self._infer_target_type(objective_target)
            if inferred_type:
                self._target_type = inferred_type
                # 同步到 selector
                selector = getattr(self, "_selector", None)
                if selector and hasattr(selector, "set_target_type"):
                    selector.set_target_type(inferred_type)
                logger.info(f"L5: Auto-inferred target_type='{inferred_type}' "
                            f"from {type(objective_target).__name__}")

        # R2: 存储 objective_target 供 _get_attack_technique_factories 使用
        self._objective_target = objective_target

        # 1. 获取基础技术 bundles（原生枚举驱动）
        base_techniques = super()._build_techniques_dict(
            objective_target=objective_target,
        )

        # L5: ModalityRouter 过滤 — 移除 Target 不支持的技术
        base_techniques = self._filter_by_modality(
            base_techniques, objective_target
        )

        # 2. 获取含 Converter 变体的工厂池
        factories = self._get_attack_technique_factories()

        # 3. 找出已解析的基础技术名
        from src.scenarios.technique_factories import (
            is_converter_variant,
            get_base_technique_from_variant,
        )
        from pyrit.scenario.scenarios.adaptive.adaptive_scenario import (
            compute_inner_attack_eval_hash,
        )
        from pyrit.scenario.scenarios.adaptive import TechniqueBundle

        resolved_base_names = {b.name for b in base_techniques.values()}

        # 4. 为已解析基础技术追加 Converter 变体 bundles
        variant_count = 0
        for factory_name, factory in factories.items():
            if not is_converter_variant(factory_name):
                continue

            base_tech = get_base_technique_from_variant(factory_name)
            if base_tech not in resolved_base_names:
                continue

            scoring_config = self._build_scoring_config_for_factory(factory=factory)
            if scoring_config is None:
                continue

            try:
                technique = factory.create(
                    objective_target=objective_target,
                    attack_scoring_config=scoring_config,
                )
            except (TypeError, ValueError) as exc:
                logger.warning(
                    f"Skipping converter variant '{factory_name}': {exc}"
                )
                continue

            eval_hash = compute_inner_attack_eval_hash(attack=technique.attack)

            # 不覆盖已有的（幂等）
            if eval_hash in base_techniques:
                continue

            adversarial_chat = factory.adversarial_chat
            if adversarial_chat is None and factory.uses_adversarial:
                try:
                    from pyrit.executor.attack.core.attack_config import (
                        get_default_adversarial_target,
                    )
                    adversarial_chat = get_default_adversarial_target()
                except Exception:
                    pass

            base_techniques[eval_hash] = TechniqueBundle(
                attack=technique.attack,
                name=factory_name,
                seed_technique=technique.seed_technique,
                adversarial_chat=adversarial_chat,
            )
            variant_count += 1

        logger.info(
            f"AI300AdaptiveScenario._build_techniques_dict: "
            f"{len(base_techniques)} total techniques "
            f"({variant_count} converter variants added)"
        )
        return base_techniques

    def _filter_by_modality(
        self,
        techniques: dict[str, Any],
        objective_target: Any,
    ) -> dict[str, Any]:
        """
        L5: ModalityRouter 过滤 — 移除 Target 不支持的技术

        使用原生 TargetCapabilities 检查：
        - 多轮攻击技术 → 检查 supports_multi_turn
        - 不支持的技术被移除，避免无效执行

        Args:
            techniques: eval_hash → TechniqueBundle 映射
            objective_target: 目标 PromptTarget 实例

        Returns:
            过滤后的 techniques dict
        """
        try:
            from src.executor.attack.core.modality_router import ModalityRouter
            from pyrit.prompt_target.common.target_capabilities import CapabilityName

            caps = ModalityRouter.get_capabilities(objective_target)
            supports_multi_turn = caps.includes(capability=CapabilityName.MULTI_TURN)
        except Exception as e:
            logger.debug(f"ModalityRouter check skipped: {e}")
            return techniques

        if supports_multi_turn:
            # 支持多轮，无需过滤
            return techniques

        # 不支持多轮 — 过滤掉多轮技术
        from src.scenarios.failure_type_selector import _MULTI_TURN_TECHNIQUES
        from src.scenarios.technique_factories import get_base_technique_from_variant

        filtered: dict[str, Any] = {}
        skipped_count = 0
        for eval_hash, bundle in techniques.items():
            tech_name = bundle.name
            base_tech = get_base_technique_from_variant(tech_name)
            if base_tech in _MULTI_TURN_TECHNIQUES:
                skipped_count += 1
                logger.debug(
                    f"ModalityRouter: skipping '{tech_name}' "
                    f"(target doesn't support multi_turn)"
                )
            else:
                filtered[eval_hash] = bundle

        if skipped_count > 0:
            logger.info(
                f"L5 ModalityRouter: filtered out {skipped_count} multi-turn techniques "
                f"(target doesn't support multi_turn)"
            )

        return filtered

    # ------------------------------------------------------------------
    # Converter 变体展示
    # ------------------------------------------------------------------

    @staticmethod
    def get_converter_variants_summary() -> list[dict[str, Any]]:
        """
        获取所有可用 Converter 变体的摘要信息

        返回每个变体的基础技术、链名、描述、是否需要 LLM、优先级等信息。
        用于在执行前展示 executor 将使用的 Converter 类型/组合。

        Returns:
            变体信息列表，每项包含:
            - variant_name: 变体全名（如 "prompt_sending+stealth_evasion"）
            - base_technique: 基础技术名
            - converter_chain: Converter 链名
            - description: 描述
            - requires_llm: 是否需要 LLM
            - priority: 优先级（数字越小越优先）
        """
        from src.scenarios.technique_factories import (
            BASE_TECHNIQUES_FOR_VARIANTS,
            CONVERTER_VARIANT_CHAINS,
            AI300_TECHNIQUE_METADATA,
        )

        summary: list[dict[str, Any]] = []
        for base_tech, chain_names in BASE_TECHNIQUES_FOR_VARIANTS.items():
            meta = AI300_TECHNIQUE_METADATA.get(base_tech, {})
            for chain_name in chain_names:
                chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name, {})
                summary.append({
                    "variant_name": f"{base_tech}+{chain_name}",
                    "base_technique": base_tech,
                    "converter_chain": chain_name,
                    "description": f"{meta.get('description', '')} + {chain_info.get('description', '')}",
                    "requires_llm": chain_info.get("requires_llm", False),
                    "priority": chain_info.get("priority", 99),
                })
        return summary

    @staticmethod
    def display_converter_variants(*, verbose: bool = True) -> int:
        """
        展示所有可用的 Converter 变体类型/组合

        在 pipeline 执行前调用，让用户了解 executor 将使用哪些 Converter 组合。
        原生 AdaptiveTechniqueDispatcher 会按 selector 排序尝试这些变体，
        FIRST_SUCCESS 策略在首个成功变体处自动停止。

        Args:
            verbose: True 时打印格式化表格，False 时仅返回数量

        Returns:
            可用变体总数
        """
        summary = AI300AdaptiveScenario.get_converter_variants_summary()
        if not verbose:
            return len(summary)

        print("\n" + "=" * 72)
        print("  Converter 变体技术池 (AdaptiveTechniqueDispatcher FIRST_SUCCESS)")
        print("=" * 72)
        print(f"  {'#':<4} {'变体名称':<45} {'LLM':<5} {'优先级'}")
        print("-" * 72)
        for i, v in enumerate(summary, 1):
            llm_tag = "是" if v["requires_llm"] else "否"
            print(f"  {i:<4} {v['variant_name']:<45} {llm_tag:<5} P{v['priority']}")
        print("-" * 72)
        print(f"  共 {len(summary)} 个 Converter 变体 "
              f"(非 LLM: {sum(1 for v in summary if not v['requires_llm'])}, "
              f"LLM: {sum(1 for v in summary if v['requires_llm'])})")
        print("  策略: epsilon-greedy 选择 + 失败类型路由 + FIRST_SUCCESS 提前停止")
        print("=" * 72 + "\n")
        return len(summary)


