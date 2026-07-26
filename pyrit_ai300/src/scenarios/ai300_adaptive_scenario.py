"""
AI-300 Adaptive Scenario — 原生 AdaptiveScenario + FailureTypeRoutingSelector
============================================================================

P0+P2: 用原生 AdaptiveScenario 替代自建 AttackUpgradeStrategy

原生 AdaptiveTechniqueDispatcher 构建 SequentialAttack(FIRST_SUCCESS)：
  - 自动按 selector 排序尝试多个技术
  - 成功即停止（提前停止）
  - epsilon-greedy 跨 objective 学习

FailureTypeRoutingSelector 增加失败类型路由：
  - model_refusal → 编码攻击优先（Converter 绕过）
  - timeout → 单轮攻击优先（减少执行时间）
  - objective_not_achieved → 强技术优先（多轮升级）

移除自建 AttackUpgradeStrategy 的多候选递归逻辑，
依赖原生 SequentialAttack(FIRST_SUCCESS) 天然实现。

保留自建：per_attack_timeout（考试时间约束优化）
"""

import logging
from typing import Any

from pyrit.common import apply_defaults
from pyrit.models import Parameter
from pyrit.scenario import DatasetAttackConfiguration
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
    3. 编码攻击优先策略（考试快速高成功率）

    原生替代说明：
    - 自建 AttackUpgradeStrategy 的多候选递归 → 原生 SequentialAttack(FIRST_SUCCESS)
    - 自建 extract_failure_type → FailureTypeRoutingSelector.update_failure_type
    - 自建 generate_upgrade_plans → 原生 AdaptiveTechniqueDispatcher 自动构建
    """

    def __init__(self, epsilon: float = 0.2, random_seed: int | None = 42) -> None:
        super().__init__(epsilon=epsilon, random_seed=random_seed)


class AI300AdaptiveScenario(AdaptiveScenario):
    """
    AI-300 自适应 Scenario — 原生 AdaptiveScenario + 失败类型路由

    用原生 AdaptiveScenario 替代自建 AttackUpgradeStrategy + ScenarioOrchestrator 升级重试。
    原生 AdaptiveTechniqueDispatcher 自动构建 SequentialAttack(FIRST_SUCCESS)：
      - 按 selector 排序尝试多个技术
      - 成功即停止（提前停止）
      - 成本 O(max_attempts x objectives) 而非 O(techniques x objectives)

    FailureTypeRoutingSelector 在 epsilon-greedy 基础上增加失败类型路由：
      - model_refusal → 编码攻击优先
      - timeout → 单轮攻击优先
      - objective_not_achieved → 强技术优先

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

    @apply_defaults
    def __init__(
        self,
        *,
        selector: TechniqueSelector | None = None,
        objective_scorer=None,
        scenario_result_id: str | None = None,
    ) -> None:
        """
        初始化 AI-300 自适应 Scenario

        Args:
            selector: 技术选择器，None 时使用 AI300EpsilonGreedySelector（含失败类型路由）
            objective_scorer: 目标评分器
            scenario_result_id: 恢复 ID
        """
        # 使用 FailureTypeRoutingSelector 替代自建 AttackUpgradeStrategy
        self._selector = selector or AI300EpsilonGreedySelector()
        self._objective_scorer = (
            objective_scorer if objective_scorer else self._get_default_objective_scorer()
        )

        super().__init__(
            version=self.VERSION,
            objective_scorer=self._objective_scorer,
            technique_class=AI300Technique,
            default_dataset_config=DatasetAttackConfiguration(
                dataset_names=[
                    "airt_hate", "airt_violence", "airt_harassment",
                    "airt_misinformation", "airt_leakage",
                ],
                max_dataset_size=4,
            ),
            selector=self._selector,
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
