"""
AI-300 Adaptive Scenario — 对齐 pyrit.scenario.scenarios.adaptive
==================================================================

P2: Adaptive Scenario 集成 — AdaptiveScenario + EpsilonGreedyTechniqueSelector

AI300AdaptiveScenario 是 PyRIT 原生 AdaptiveScenario 的 AI-300 考试适配子类。
自适应 Scenario 不对每个 objective 运行所有攻击技术，而是：
  1. 按 objective 选择下一个要尝试的技术
  2. 从有效结果中学习（epsilon-greedy）
  3. 成功时立即停止

这使考试花费集中在实际有效的技术上。

核心参数：
  - max_attempts_per_objective: 每个 objective 尝试的最大技术数（默认 3）
  - epsilon: 探索概率（默认 0.2）
  - random_seed: 随机种子（可复现）

考试策略映射：
  Phase 1 (探索): 尝试 rot13/base64（快速编码攻击）
  Phase 2 (利用): 尝试 role_play（角色扮演）
  Phase 3 (升级): 尝试 crescendo/red_teaming（多轮渐进）
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

logger = logging.getLogger(__name__)


class AI300EpsilonGreedySelector(EpsilonGreedyTechniqueSelector):
    """
    AI-300 Epsilon-Greedy 技术选择器

    对齐 PyRIT 1.0.0 EpsilonGreedyTechniqueSelector，
    预设 AI-300 考试最优参数。

    考试推荐：
      - epsilon=0.2（20% 探索，80% 利用）
      - random_seed=42（可复现）
    """

    def __init__(self, epsilon: float = 0.2, random_seed: int | None = 42) -> None:
        super().__init__(epsilon=epsilon, random_seed=random_seed)


class AI300AdaptiveScenario(AdaptiveScenario):
    """
    AI-300 自适应 Scenario

    对齐 PyRIT 1.0.0 AdaptiveScenario 基类 + TextAdaptive 子类。
    使用 epsilon-greedy 策略按 objective 选择技术，成功即停止。

    考试优势：
      - 成本 O(max_attempts x objectives) 而非 O(techniques x objectives)
      - 自动学习哪些技术对当前目标最有效
      - 未尝试的技术优先尝试（前几个 objective 轮询所有技术）

    Usage:
        scenario = AI300AdaptiveScenario()
        scenario.set_params_from_args(args={
            "objective_target": target,
            "max_attempts_per_objective": 3,
        })
        await scenario.initialize_async()
        result = await scenario.run_async()
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
            selector: 技术选择器，None 时使用 AI300EpsilonGreedySelector(epsilon=0.2)
            objective_scorer: 目标评分器
            scenario_result_id: 恢复 ID
        """
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

        Returns:
            - max_attempts_per_objective: 每个 objective 最大尝试次数（默认 3）
            - per_attack_timeout: 单次攻击超时（默认 300）
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
                description="Per-attack timeout in seconds.",
                param_type=int,
                default=300,
            ),
        ]
