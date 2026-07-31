"""
AI-300 Scenario Base Class — 对齐 pyrit.scenario.Scenario
============================================================

P0: 原生 Scenario 基类集成 — Scenario/AtomicAttack/ScenarioResult 三层体系

AI300Scenario 是 PyRIT 原生 Scenario 基类的 AI-300 考试适配子类。
它桥接 PyRIT 原生 Scenario 体系和当前项目的 ScenarioOrchestrator 自建优势。

核心设计：
1. 继承 PyRIT 原生 Scenario 基类，获得完整的 initialize_async / run_async 生命周期
2. 实现 _build_atomic_attacks_async(context) 使用 build_matrix_atomic_attacks
3. 设置 BASELINE_ATTACK_POLICY = Enabled（基线默认前置）
4. 通过 additional_parameters() 声明考试专用参数
5. 保留与 ScenarioOrchestrator 的桥接接口

预置子类：
  - AI300RapidResponseScenario: 快速响应（编码 + 角色扮演，考试首选）
  - AI300JailbreakScenario: 越狱测试（prompt_sending + many_shot + skeleton + role_play）
  - AI300EncodingScenario: 编码攻击（17 种编码技术，快速冒烟测试）
"""

import logging

from pyrit.common import apply_defaults
from pyrit.prompt_target.common.target_requirements import TargetRequirements
from pyrit.models.target.target_capabilities import CapabilityName
from pyrit.scenario import (
    BaselineAttackPolicy,
    DatasetAttackConfiguration,
    Scenario,
)
from pyrit.scenario.core.matrix_atomic_attack_builder import build_matrix_atomic_attacks
from pyrit.models import Parameter

from src.scenarios.ai300_technique import AI300Technique

logger = logging.getLogger(__name__)


class AI300Scenario(Scenario):
    """
    AI-300 考试通用 Scenario 基类

    对齐 PyRIT 1.0.0 Scenario 基类，提供：
    - 原生 initialize_async / run_async 生命周期
    - build_matrix_atomic_attacks 矩阵构建
    - BASELINE_ATTACK_POLICY = Enabled
    - TARGET_REQUIREMENTS 能力验证（MULTI_TURN + SYSTEM_PROMPT）
    - 考试专用参数声明（max_turns, timeout_overrides）
    - 与 ScenarioOrchestrator 桥接接口

    子类需覆盖：
    - VERSION 类属性
    - default_dataset_config
    - 可选：additional_parameters()
    """

    VERSION: int = 1

    BASELINE_ATTACK_POLICY = BaselineAttackPolicy.Enabled

    # L5: 能力需求 — 通用 Scenario 需要目标支持多轮对话 + 系统提示词
    # 初始化时由原生 Scenario.initialize_async() 验证，不兼容则报 ValueError
    TARGET_REQUIREMENTS: TargetRequirements = TargetRequirements(
        required=frozenset({CapabilityName.MULTI_TURN, CapabilityName.SYSTEM_PROMPT})
    )

    @apply_defaults
    def __init__(
        self,
        *,
        objective_scorer=None,
        scenario_result_id: str | None = None,
    ) -> None:
        """
        初始化 AI-300 Scenario

        Args:
            objective_scorer: 目标评分器，None 时使用默认（TrueFalseInverter + RefusalScorer）
            scenario_result_id: 可选的已有 ScenarioResult ID（用于恢复）
        """
        self._objective_scorer = (
            objective_scorer if objective_scorer else self._get_default_objective_scorer()
        )

        super().__init__(
            version=self.VERSION,
            objective_scorer=self._objective_scorer,
            technique_class=AI300Technique,
            default_dataset_config=self._get_default_dataset_config(),
            scenario_result_id=scenario_result_id,
        )

    def _get_default_dataset_config(self) -> DatasetAttackConfiguration:
        """子类覆盖：返回默认数据集配置"""
        return DatasetAttackConfiguration(dataset_names=["harmbench"], max_dataset_size=4)

    @classmethod
    def additional_parameters(cls) -> list[Parameter]:
        """
        P3: 声明 AI-300 考试专用参数

        Returns:
            考试专用参数列表：
            - max_turns: 多轮攻击最大轮数（默认 3，P3 降低以减少超时风险）
            - per_attack_timeout: 单次攻击超时秒数（默认 300）
        """
        return [
            Parameter(
                name="max_turns",
                description="Maximum conversation turns for multi-turn attacks.",
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

    async def _build_atomic_attacks_async(self, *, context) -> list:
        """
        P0 + P1: 构建原子攻击列表 — 使用 build_matrix_atomic_attacks

        矩阵形 Scenario 的标准实现：从已注册的攻击技术自动构建 AtomicAttack。
        按数据集分组结果（display_group_fn）。
        """
        return build_matrix_atomic_attacks(
            context=context,
            objective_scorer=self._objective_scorer,
            display_group_fn=lambda combo: combo.dataset_name,
        )

    # ------------------------------------------------------------------
    # 桥接接口：与 ScenarioOrchestrator 集成
    # ------------------------------------------------------------------

    def get_attack_plans_for_orchestrator(self) -> list:
        """
        桥接方法：将 Scenario 的 AtomicAttack 列表转换为 AttackPlan 列表

        用于与现有 ScenarioOrchestrator.execute_batch() 集成。
        如果 Scenario 已通过 initialize_async() 初始化，则返回对应的 AttackPlan。

        Returns:
            AttackPlan 列表（可能为空，如果未初始化）
        """
        from src.payloads.models import AttackPlan, AttackMode, PromptItem

        plans = []
        for aa in self._atomic_attacks:
            for sg in aa._seed_groups:
                objective = ""
                if hasattr(sg, "objective") and sg.objective:
                    obj = sg.objective
                    objective = obj.value if hasattr(obj, "value") else str(obj)

                technique_name = aa.atomic_attack_name

                item = PromptItem(
                    objective=objective,
                    attack_mode=AttackMode.SINGLE_TURN,
                )
                plan = AttackPlan(
                    prompt_item=item,
                    attack_technique=technique_name,
                    scorer_type="general",
                )
                plans.append(plan)
        return plans


# ============================================================
# 预置子类
# ============================================================


class AI300RapidResponseScenario(AI300Scenario):
    """
    AI-300 快速响应 Scenario

    考试首选 Scenario：编码攻击 + 角色扮演 + crescendo
    覆盖 7 个 AIRT 危害类别（hate/fairness/violence/sexual/harassment/misinformation/leakage）

    对齐 PyRIT 原生 airt.rapid_response Scenario。
    """

    VERSION: int = 1
    BASELINE_ATTACK_POLICY = BaselineAttackPolicy.Enabled

    def _get_default_dataset_config(self) -> DatasetAttackConfiguration:
        return DatasetAttackConfiguration(
            dataset_names=[
                "airt_hate", "airt_violence", "airt_harassment",
                "airt_misinformation", "airt_leakage",
            ],
            max_dataset_size=4,
        )


class AI300JailbreakScenario(AI300Scenario):
    """
    AI-300 越狱测试 Scenario

    测试模型对越狱攻击的防御：prompt_sending + many_shot + skeleton + role_play
    对齐 PyRIT 原生 airt.jailbreak Scenario。

    BASELINE_ATTACK_POLICY = Disabled（越狱 Scenario 已被模板主导）
    """

    VERSION: int = 1
    BASELINE_ATTACK_POLICY = BaselineAttackPolicy.Disabled

    def _get_default_dataset_config(self) -> DatasetAttackConfiguration:
        return DatasetAttackConfiguration(
            dataset_names=["airt_harms"],
            max_dataset_size=4,
        )


class AI300EncodingScenario(AI300Scenario):
    """
    AI-300 编码攻击 Scenario

    17 种编码技术快速测试：rot13, base64, caesar, binary, morse 等
    对齐 PyRIT 原生 garak.encoding Scenario。

    适用于考试中快速冒烟测试，编码攻击成功率 50-100%。

    编码攻击仅需文本能力，不需要多轮对话。
    """

    VERSION: int = 1
    BASELINE_ATTACK_POLICY = BaselineAttackPolicy.Enabled

    # L5: 编码攻击仅需 SYSTEM_PROMPT，不需要 MULTI_TURN
    TARGET_REQUIREMENTS: TargetRequirements = TargetRequirements(
        required=frozenset({CapabilityName.SYSTEM_PROMPT})
    )

    def _get_default_dataset_config(self) -> DatasetAttackConfiguration:
        return DatasetAttackConfiguration(
            dataset_names=["garak_slur_terms_en", "garak_web_html_js"],
            max_dataset_size=3,
        )
