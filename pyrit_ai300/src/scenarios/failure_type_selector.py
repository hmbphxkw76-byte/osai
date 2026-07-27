"""
Failure-Type Routing Technique Selector — 原生 AdaptiveScenario 替代智能升级重试
=============================================================================

P0: 实现 FailureTypeRoutingSelector(TechniqueSelector)
P1: 增强 Converter 变体感知排序
P3: 增强 Target 类型感知优先级

用 PyRIT 原生 AdaptiveScenario + AdaptiveTechniqueDispatcher 替代自建 AttackUpgradeStrategy。
原生的 SequentialAttack(FIRST_SUCCESS) 天然实现 "尝试不同技术直到成功" 的逻辑。

本 Selector 在 EpsilonGreedyTechniqueSelector 基础上增加失败类型分析：
  - model_refusal -> 优先 Converter 变体（编码/混淆绕过内容过滤）
  - timeout -> 优先无 Converter 的基础技术（减少开销）
  - scorer_validation_error -> 保持技术多样性
  - objective_not_achieved -> 优先强技术 + Converter 变体

P1 增强：Converter 变体感知
  - 技术名称中含 "+" 的为 Converter 变体（如 "prompt_sending+stealth_evasion"）
  - model_refusal 路由：优先 Converter 变体，按 Converter 链优先级排序
  - timeout 路由：优先基础技术（无 Converter），减少转换开销
  - 首次尝试（无失败记录）：优先编码变体（快速高成功率）

P3 增强：Target 类型感知
  - 设置 target_type 后，Converter 变体按 Target 类型对应的 ASR 优先级排序
  - 不同 Target 类型（LLM Direct / Agent / RAG / Multimodal）使用不同的链优先级
  - 未设置 target_type 时回退到全局 CONVERTER_VARIANT_CHAINS 优先级

Selector 是无状态的：它查询 memory 获取历史成功率，而非维护内部计数。

v2.0 改进（消除双轨风险）：
  - 集成 owasp_strategy_map 初始偏好权重
  - 首次尝试（无失败记录）时，优先 owasp_strategy_map 的 default_attack_technique
  - 使 Adaptive 路径的初始技术排序与 Legacy 路径（PayloadStrategyMatcher）一致
"""

import logging
import random
from typing import Sequence

from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector

from src.scenarios.technique_factories import (
    AI300_TECHNIQUE_METADATA,
    CONVERTER_VARIANT_CHAINS,
    is_converter_variant,
    get_converter_chain_from_variant,
)
from src.converters.target_aware_router import (
    get_target_group,
    get_chain_priority_for_target,
)

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

# P1: Converter 链全局优先级（当 target_type 未设置时的回退值）
_CONVERTER_CHAIN_PRIORITY: dict[str, int] = {
    chain_name: info.get("priority", 99)
    for chain_name, info in CONVERTER_VARIANT_CHAINS.items()
}


class FailureTypeRoutingSelector(EpsilonGreedyTechniqueSelector):
    """
    失败类型路由技术选择器

    在 EpsilonGreedyTechniqueSelector 基础上增加失败类型分析。
    当检测到特定失败类型时，重新排列技术优先级：

    策略路由（P1 增强 Converter 感知 + P3 Target 感知）：
      model_refusal     -> Converter 变体优先（按 Target 感知优先级排序）+ 编码技术
      timeout           -> 基础单轮技术优先（无 Converter，减少开销）
      scorer_validation -> 保持 epsilon-greedy 默认排序
      objective_not_achieved -> 强技术 + Converter 变体优先

    考试策略：
      Phase 1 (探索): 编码攻击 + Converter 变体（快速高成功率 50-100%）
      Phase 2 (利用): 角色扮演（中等成本 71-100%）
      Phase 3 (升级): 多轮渐进（高成本兜底）
    """

    def __init__(
        self,
        *,
        epsilon: float = 0.2,
        random_seed: int | None = 42,
        target_type: str | None = None,
        owasp_id: str | None = None,
    ) -> None:
        super().__init__(epsilon=epsilon, random_seed=random_seed)
        self._last_failure_type: str | None = None
        # P3: Target 类型感知
        self._target_type: str | None = target_type
        self._target_group: str | None = (
            get_target_group(target_type) if target_type else None
        )
        # v2.0: OWASP 策略映射初始偏好
        self._owasp_id: str | None = owasp_id
        self._owasp_default_technique: str | None = None
        self._owasp_upgrade_techniques: list[str] = []
        self._load_owasp_strategy()

    def _load_owasp_strategy(self) -> None:
        """
        v2.0: 从 owasp_strategy_map 加载 OWASP 策略偏好

        读取 default_attack_technique 和 upgrade_techniques 作为初始偏好权重，
        使首次尝试时优先 owasp_strategy_map 推荐的技术。
        """
        if not self._owasp_id:
            return
        try:
            from src.core.config_loader import get_config_loader
            strategy_config = get_config_loader().get_strategy_config()
            owasp_map = strategy_config.get("owasp_strategy_map", {})
            owasp_strategy = owasp_map.get(self._owasp_id, {})
            self._owasp_default_technique = owasp_strategy.get("default_attack_technique")
            self._owasp_upgrade_techniques = owasp_strategy.get("upgrade_techniques", [])
            if self._owasp_default_technique:
                logger.debug(
                    f"FailureTypeRoutingSelector: OWASP {self._owasp_id} "
                    f"default_technique={self._owasp_default_technique}, "
                    f"upgrades={self._owasp_upgrade_techniques}"
                )
        except Exception as e:
            logger.debug(f"OWASP strategy loading failed: {e}")

    def set_owasp_id(self, owasp_id: str) -> None:
        """
        v2.0: 设置 OWASP ID，加载策略偏好

        Args:
            owasp_id: OWASP ID（如 "LLM01", "ASI05"）
        """
        self._owasp_id = owasp_id
        self._load_owasp_strategy()

    def set_target_type(self, target_type: str) -> None:
        """
        P3: 设置 Target 类型，启用 Target 感知排序

        设置后，Converter 变体将按 Target 类型对应的 ASR 优先级排序，
        而非使用全局静态优先级。

        Args:
            target_type: PyRIT Target 类型名（如 "openai_chat", "playwright"）
        """
        self._target_type = target_type
        self._target_group = get_target_group(target_type)
        logger.debug(
            f"FailureTypeRoutingSelector: target_type={target_type}, "
            f"group={self._target_group}"
        )

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

    def _target_aware_sort_key(self, technique_name: str) -> int:
        """
        P3: 计算技术名称的 Target 感知排序键

        如果设置了 target_type，使用 Target 感知优先级；
        否则回退到全局 CONVERTER_VARIANT_CHAINS 优先级。

        Args:
            technique_name: 技术名称（可能含 "+" 变体）

        Returns:
            排序键（数字越小越优先）
        """
        chain_name = get_converter_chain_from_variant(technique_name)
        if chain_name is None:
            return 99

        # P3: 如果有 target_type，使用 Target 感知优先级
        if self._target_type:
            return get_chain_priority_for_target(chain_name, self._target_type)

        # 回退到全局优先级
        return _CONVERTER_CHAIN_PRIORITY.get(chain_name, 99)

    def _reorder_by_failure_type(self, techniques: Sequence[str]) -> list[str]:
        """
        根据最近失败类型重新排列技术优先级

        P1 增强：Converter 变体感知
        P3 增强：Target 类型感知优先级
        - 技术名称中含 "+" 的为 Converter 变体
        - model_refusal: 优先 Converter 变体（按 Target 感知优先级排序）+ 编码技术
        - timeout: 优先无 Converter 的基础技术（减少转换开销）
        - objective_not_achieved: 优先强技术 + Converter 变体
        - None（首次）: 按 Target 类型感知优先级排序

        Args:
            techniques: 原始排序的技术列表

        Returns:
            重新排序的技术列表
        """
        tech_list = list(techniques)
        failure_type = self._last_failure_type

        if failure_type is None:
            # 无失败类型 -> v2.0: OWASP 偏好 + Target 感知默认排序
            # 优先 owasp_strategy_map 的 default_attack_technique
            owasp_preferred: list[str] = []
            if self._owasp_default_technique:
                owasp_preferred = [
                    t for t in tech_list
                    if t == self._owasp_default_technique
                    or (is_converter_variant(t) and 
                        t.startswith(self._owasp_default_technique + "+"))
                ]
            # Target 感知 Converter 变体排序
            converter_variants = [t for t in tech_list if is_converter_variant(t)]
            encoding_base = [t for t in tech_list if t in _ENCODING_TECHNIQUES]
            others = [
                t for t in tech_list
                if not is_converter_variant(t) and t not in _ENCODING_TECHNIQUES
                and t not in owasp_preferred
            ]
            # P3: Target 感知优先级排序
            converter_variants.sort(
                key=lambda t: self._target_aware_sort_key(t)
            )
            # v2.0: OWASP 偏好优先，然后 Converter 变体，然后编码，最后其他
            return owasp_preferred + converter_variants + encoding_base + others

        if failure_type == FAILURE_MODEL_REFUSAL:
            # 模型拒绝 -> Converter 变体优先（编码/混淆绕过内容过滤）
            logger.info("FailureTypeRouting: model_refusal -> prioritizing converter variants + encoding")
            converter_variants = [t for t in tech_list if is_converter_variant(t)]
            encoding_base = [t for t in tech_list if t in _ENCODING_TECHNIQUES]
            others = [
                t for t in tech_list
                if not is_converter_variant(t) and t not in _ENCODING_TECHNIQUES
            ]
            # P3: Target 感知优先级排序
            converter_variants.sort(
                key=lambda t: self._target_aware_sort_key(t)
            )
            return converter_variants + encoding_base + others

        if failure_type == FAILURE_TIMEOUT:
            # 超时 -> 优先无 Converter 的基础单轮技术（减少转换开销和执行时间）
            logger.info("FailureTypeRouting: timeout -> prioritizing base single_turn (no converter)")
            # 先取无 Converter 的单轮技术
            base_single = [
                t for t in tech_list
                if not is_converter_variant(t) and t in _SINGLE_TURN_TECHNIQUES
            ]
            # 再取 Converter 变体（作为后备）
            converter_variants = [t for t in tech_list if is_converter_variant(t)]
            # 最后是多轮和其他
            others = [
                t for t in tech_list
                if not is_converter_variant(t) and t not in _SINGLE_TURN_TECHNIQUES
            ]
            return base_single + converter_variants + others

        if failure_type == FAILURE_OBJECTIVE_NOT_ACHIEVED:
            # 目标未达成 -> 强技术 + Converter 变体优先
            logger.info("FailureTypeRouting: objective_not_achieved -> prioritizing strong techniques + converter variants")
            # 强技术（多轮升级）
            strong = [t for t in tech_list if t in _STRONG_TECHNIQUES]
            # Converter 变体（编码绕过）
            converter_variants = [t for t in tech_list if is_converter_variant(t)]
            # P3: Target 感知优先级排序
            converter_variants.sort(
                key=lambda t: self._target_aware_sort_key(t)
            )
            others = [
                t for t in tech_list
                if not is_converter_variant(t) and t not in _STRONG_TECHNIQUES
            ]
            return strong + converter_variants + others

        if failure_type == FAILURE_SCORER_VALIDATION_ERROR:
            # 评分器验证错误 -> 保持 epsilon-greedy 默认排序
            logger.info("FailureTypeRouting: scorer_validation_error -> keeping epsilon-greedy order")
            return tech_list

        # 未知失败类型 -> 保持默认排序
        return tech_list


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
