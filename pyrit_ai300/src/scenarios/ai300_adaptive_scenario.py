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

FailureTypeRoutingSelector 增加失败类型路由：
  - model_refusal → Converter 变体优先（编码/混淆绕过）
  - timeout → 基础单轮技术优先（减少执行时间）
  - objective_not_achieved → 强技术 + Converter 变体优先

移除自建 AttackUpgradeStrategy 的多候选递归逻辑，
依赖原生 SequentialAttack(FIRST_SUCCESS) 天然实现。

保留自建：per_attack_timeout（考试时间约束优化）
"""

import logging
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


class AI300EpsilonGreedySelector(FailureTypeRoutingSelector):
    """
    AI-300 Epsilon-Greedy 技术选择器（增强版）

    继承 FailureTypeRoutingSelector，在 EpsilonGreedyTechniqueSelector 基础上增加：
    1. 失败类型路由（替代自建 AttackUpgradeStrategy 的失败类型分析）
    2. 考试最优参数预设（epsilon=0.2, random_seed=42）
    3. Converter 变体感知排序（P1 增强）
    4. 编码攻击优先策略（考试快速高成功率）
    5. Target 类型感知优先级（P3 增强）

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
    ) -> None:
        super().__init__(
            epsilon=epsilon,
            random_seed=random_seed,
            target_type=target_type,
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
        scenario_result_id: str | None = None,
    ) -> None:
        """
        初始化 AI-300 自适应 Scenario

        Args:
            selector: 技术选择器，None 时使用 AI300EpsilonGreedySelector（含失败类型路由）
            objective_scorer: 目标评分器
            converter_target: LLM 辅助 Converter 所需的目标 PromptTarget（通常为 judge_target）
            target_type: PyRIT Target 类型名（如 "openai_chat"），用于 Target 感知排序
            scenario_result_id: 恢复 ID
        """
        # P2: 保存 converter_target 用于构建 Converter 变体（在 super().__init__ 之前）
        self._converter_target = converter_target

        # P3: 如果没有传入 selector，创建带 target_type 的 AI300EpsilonGreedySelector
        if selector is None:
            selector = AI300EpsilonGreedySelector(target_type=target_type)
        elif target_type and hasattr(selector, "set_target_type"):
            selector.set_target_type(target_type)

        # 使用 FailureTypeRoutingSelector 替代自建 AttackUpgradeStrategy
        super().__init__(
            objective_scorer=objective_scorer,
            selector=selector,
            scenario_result_id=scenario_result_id,
        )

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
        P2: 覆盖原生方法，在原生技术池基础上追加 Converter 变体工厂

        原生方法从 catalog + registry 获取基础技术工厂。
        本方法在原生结果基础上，追加 Converter 变体工厂
        （为每个基础技术注册多个 Converter 变体，烘焙 AttackConverterConfig）。

        Returns:
            技术名 → AttackTechniqueFactory 映射（含 Converter 变体）
        """
        # 获取原生基础技术工厂
        base_factories = super()._get_attack_technique_factories()

        # P2: 追加 Converter 变体工厂
        from src.scenarios.technique_factories import build_converter_variant_factories

        variant_factories = build_converter_variant_factories(
            converter_target=self._converter_target,
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

    @staticmethod
    def extract_used_converters_from_result(native_result: Any) -> list[dict[str, Any]]:
        """
        从执行结果中提取实际使用的 Converter 变体信息

        执行后调用，展示哪些 Converter 变体被实际使用及其成功/失败状态。

        Args:
            native_result: 原生 ScenarioResult

        Returns:
            使用记录列表，每项包含:
            - technique_name: 技术名称
            - is_converter_variant: 是否为 Converter 变体
            - base_technique: 基础技术名（仅变体）
            - converter_chain: Converter 链名（仅变体）
            - outcome: 结果（success/failed/error）
        """
        from src.scenarios.technique_factories import (
            is_converter_variant,
            get_base_technique_from_variant,
            get_converter_chain_from_variant,
        )

        records: list[dict[str, Any]] = []
        if native_result is None:
            return records

        display_groups = {}
        if hasattr(native_result, "get_display_groups"):
            display_groups = native_result.get_display_groups()
        elif hasattr(native_result, "attack_results"):
            display_groups = {"_all": native_result.attack_results}
        else:
            return records

        for group_name, results in display_groups.items():
            for r in results:
                if r is None:
                    continue
                identifier = (
                    r.get_attack_strategy_identifier()
                    if hasattr(r, "get_attack_strategy_identifier")
                    else None
                )
                tech_name = ""
                if identifier is not None:
                    tech_name = getattr(identifier, "unique_name", "") or ""

                outcome = getattr(r, "outcome", None)
                outcome_str = ""
                if outcome is not None:
                    outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()

                is_variant = is_converter_variant(tech_name) if tech_name else False
                record = {
                    "technique_name": tech_name,
                    "is_converter_variant": is_variant,
                    "base_technique": get_base_technique_from_variant(tech_name) if is_variant else tech_name,
                    "converter_chain": get_converter_chain_from_variant(tech_name) if is_variant else None,
                    "outcome": outcome_str,
                    "group": group_name,
                }
                records.append(record)

        return records

    @staticmethod
    def display_used_converters(native_result: Any) -> None:
        """
        展示执行后实际使用的 Converter 变体及其结果

        Args:
            native_result: 原生 ScenarioResult
        """
        records = AI300AdaptiveScenario.extract_used_converters_from_result(native_result)
        if not records:
            print("  [ADAPT] 无执行结果可展示")
            return

        variant_records = [r for r in records if r["is_converter_variant"]]
        base_records = [r for r in records if not r["is_converter_variant"]]

        print("\n" + "=" * 72)
        print("  执行结果: Converter 变体使用情况")
        print("=" * 72)

        if variant_records:
            print(f"\n  Converter 变体 ({len(variant_records)} 次):")
            print(f"  {'#':<4} {'变体名称':<45} {'结果':<10} {'数据集'}")
            print("  " + "-" * 68)
            for i, r in enumerate(variant_records, 1):
                print(f"  {i:<4} {r['technique_name']:<45} {r['outcome']:<10} {r['group']}")

        if base_records:
            print(f"\n  基础技术 ({len(base_records)} 次):")
            print(f"  {'#':<4} {'技术名称':<45} {'结果':<10} {'数据集'}")
            print("  " + "-" * 68)
            for i, r in enumerate(base_records, 1):
                print(f"  {i:<4} {r['technique_name']:<45} {r['outcome']:<10} {r['group']}")

        # 汇总
        total = len(records)
        succeeded = sum(1 for r in records if r["outcome"] == "SUCCESS")
        failed = sum(1 for r in records if r["outcome"] not in ("SUCCESS", "ERROR"))
        errored = sum(1 for r in records if r["outcome"] == "ERROR")
        variant_succeeded = sum(1 for r in variant_records if r["outcome"] == "SUCCESS")

        print("\n  " + "-" * 68)
        print(f"  汇总: {succeeded}/{total} 成功 | {failed} 失败 | {errored} 错误")
        if variant_records:
            print(f"  Converter 变体: {variant_succeeded}/{len(variant_records)} 成功 "
                  f"({variant_succeeded / len(variant_records) * 100:.0f}%)")
        print("=" * 72 + "\n")
