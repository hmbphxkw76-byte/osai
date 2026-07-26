"""
Failure-Type Routing Technique Selector — 用原生 AdaptiveScenario 替代智能升级重试
=============================================================================

P0: 实现 FailureTypeRoutingSelector(TechniqueSelector)

用 PyRIT 原生 AdaptiveScenario + AdaptiveTechniqueDispatcher 替代自建 AttackUpgradeStrategy。
原生的 SequentialAttack(FIRST_SUCCESS) 天然实现 "尝试不同技术直到成功" 的逻辑。

本 Selector 在 EpsilonGreedyTechniqueSelector 基础上增加失败类型分析：
  - model_refusal → 优先编码攻击技术（Converter 绕过内容过滤）
  - timeout → 优先单轮攻击技术（减少多轮深度）
  - scorer_validation_error → 保持技术多样性
  - objective_not_achieved → 优先升级到更强技术

Selector 是无状态的：它查询 memory 获取历史成功率，而非维护内部计数。
"""

import logging
import random
from typing import Sequence

from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector

from src.scenarios.technique_factories import AI300_TECHNIQUE_METADATA

logger = logging.getLogger(__name__)


# 失败类型常量（对齐自建 upgrade_strategy.py）
FAILURE_MODEL_REFUSAL = "model_refusal"
FAILURE_TIMEOUT = "timeout"
FAILURE_SCORER_VALIDATION_ERROR = "scorer_validation_error"
FAILURE_OBJECTIVE_NOT_ACHIEVED = "objective_not_achieved"
FAILURE_UNKNOWN = "unknown"

# 技术优先级分组（考试策略映射）
_ENCODING_TECHNIQUES = {
    "rot13", "base64", "caesar", "binary", "morse", "leetspeak",
    "flip", "char_swap", "diacritic", "character_space",
    "string_join", "suffix_append", "atbash", "url",
}
_SINGLE_TURN_TECHNIQUES = {
    "prompt_sending", "role_play_movie_script", "role_play_persuasion",
    "role_play_persuasion_written", "role_play_trivia_game", "role_play_video_game",
    "crescendo_simulated", "crescendo_movie_director", "crescendo_history_lecture",
    "crescendo_journalist_interview", "context_compliance", "skeleton_key",
    "multi_prompt_sending", "chunked_request",
    *_ENCODING_TECHNIQUES,
}
_MULTI_TURN_TECHNIQUES = {
    "red_teaming", "crescendo", "tap", "pair", "tree_of_attacks_pruned", "many_shot",
}
_STRONG_TECHNIQUES = {
    "crescendo", "red_teaming", "tap", "pair", "tree_of_attacks_pruned",
    "many_shot", "crescendo_simulated",
}


class FailureTypeRoutingSelector(EpsilonGreedyTechniqueSelector):
    """
    失败类型路由技术选择器

    在 EpsilonGreedyTechniqueSelector 基础上增加失败类型分析。
    当检测到特定失败类型时，重新排列技术优先级：

    策略路由：
      model_refusal     → 编码攻击优先（Converter 绕过内容过滤）
      timeout           → 单轮攻击优先（减少执行时间）
      scorer_validation → 保持 epsilon-greedy 默认排序
      objective_not_achieved → 强技术优先（多轮升级）

    考试策略：
      Phase 1 (探索): 编码攻击（快速高成功率 50-100%）
      Phase 2 (利用): 角色扮演（中等成本 71-100%）
      Phase 3 (升级): 多轮渐进（高成本兜底）
    """

    def __init__(
        self,
        *,
        epsilon: float = 0.2,
        random_seed: int | None = 42,
    ) -> None:
        super().__init__(epsilon=epsilon, random_seed=random_seed)
        self._last_failure_type: str | None = None

    def update_failure_type(self, failure_type: str) -> None:
        """
        更新最近失败类型（由外部调用，如 AttackResult 分析后）

        Args:
            failure_type: 失败类型字符串
        """
        self._last_failure_type = failure_type
        logger.debug(f"FailureTypeRoutingSelector: failure_type updated to {failure_type}")

    async def select_async(
        self,
        *,
        technique_identifiers: Sequence[str],
        objective: str,
        num_top_techniques: int = 1,
        scenario_result_id: str | None = None,
    ) -> Sequence[str]:
        """
        选择技术，考虑失败类型路由

        1. 先调用父类 epsilon-greedy 获取基础排序
        2. 根据最近失败类型重新排列优先级
        3. 返回前 num_top_techniques 个技术

        Args:
            technique_identifiers: 可用技术标识符列表
            objective: 目标文本
            num_top_techniques: 返回的最大技术数
            scenario_result_id: Scenario 结果 ID

        Returns:
            按优先级排序的技术标识符列表
        """
        # 调用父类 epsilon-greedy 获取基础排序
        base_order = await super().select_async(
            technique_identifiers=technique_identifiers,
            objective=objective,
            num_top_techniques=len(technique_identifiers),  # 获取全部排序
            scenario_result_id=scenario_result_id,
        )

        # 根据失败类型重新排列
        reordered = self._reorder_by_failure_type(base_order)

        # 返回前 N 个
        return reordered[:num_top_techniques]

    def _reorder_by_failure_type(self, techniques: Sequence[str]) -> list[str]:
        """
        根据最近失败类型重新排列技术优先级

        Args:
            techniques: 原始排序的技术列表

        Returns:
            重新排序的技术列表
        """
        tech_list = list(techniques)
        failure_type = self._last_failure_type

        if failure_type is None:
            # 无失败类型 → 默认考试策略：编码攻击优先
            return self._reorder_by_priority(
                tech_list,
                priority_set=_ENCODING_TECHNIQUES,
            )

        if failure_type == FAILURE_MODEL_REFUSAL:
            # 模型拒绝 → 编码攻击优先（Converter 绕过内容过滤）
            logger.info("FailureTypeRouting: model_refusal → prioritizing encoding techniques")
            return self._reorder_by_priority(
                tech_list,
                priority_set=_ENCODING_TECHNIQUES,
            )

        if failure_type == FAILURE_TIMEOUT:
            # 超时 → 单轮攻击优先（减少执行时间）
            logger.info("FailureTypeRouting: timeout → prioritizing single_turn techniques")
            return self._reorder_by_priority(
                tech_list,
                priority_set=_SINGLE_TURN_TECHNIQUES,
            )

        if failure_type == FAILURE_OBJECTIVE_NOT_ACHIEVED:
            # 目标未达成 → 强技术优先（多轮升级）
            logger.info("FailureTypeRouting: objective_not_achieved → prioritizing strong techniques")
            return self._reorder_by_priority(
                tech_list,
                priority_set=_STRONG_TECHNIQUES,
            )

        if failure_type == FAILURE_SCORER_VALIDATION_ERROR:
            # 评分器验证错误 → 保持 epsilon-greedy 默认排序
            logger.info("FailureTypeRouting: scorer_validation_error → keeping epsilon-greedy order")
            return tech_list

        # 未知失败类型 → 保持默认排序
        return tech_list

    @staticmethod
    def _reorder_by_priority(
        techniques: list[str],
        priority_set: set[str],
    ) -> list[str]:
        """
        将优先集合中的技术排到前面，其余保持原顺序

        Args:
            techniques: 原始技术列表
            priority_set: 优先技术名称集合

        Returns:
            重新排序的技术列表
        """
        prioritized = [t for t in techniques if t in priority_set]
        others = [t for t in techniques if t not in priority_set]
        return prioritized + others


def extract_failure_type_from_result(failed_result) -> str:
    """
    从失败的 AttackResult 提取失败类型

    对齐自建 upgrade_strategy.py 的 extract_failure_type 函数，
    供 FailureTypeRoutingSelector 使用。

    Args:
        failed_result: 失败的 AttackResult 实例

    Returns:
        失败类型字符串
    """
    if failed_result is None:
        return FAILURE_UNKNOWN

    def _safe_get(obj, attr, default=None):
        try:
            return getattr(obj, attr, default)
        except Exception:
            return default

    raw_error = str(
        _safe_get(failed_result, "error_message", "")
        or _safe_get(failed_result, "outcome_reason", "")
    )

    if not raw_error:
        outcome = _safe_get(failed_result, "outcome")
        if outcome is not None:
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
            if outcome_str == "ERROR":
                return FAILURE_OBJECTIVE_NOT_ACHIEVED
        return FAILURE_OBJECTIVE_NOT_ACHIEVED

    if "ValidationError" in raw_error or "score_rationale" in raw_error:
        return FAILURE_SCORER_VALIDATION_ERROR
    elif "Timeout" in raw_error or "timeout" in raw_error.lower():
        return FAILURE_TIMEOUT
    elif "Refusal" in raw_error or "refused" in raw_error.lower():
        return FAILURE_MODEL_REFUSAL
    else:
        return FAILURE_OBJECTIVE_NOT_ACHIEVED
