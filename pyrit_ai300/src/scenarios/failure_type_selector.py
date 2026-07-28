"""
Failure-Type Routing Technique Selector — 原生 AdaptiveScenario 替代智能升级重试
=============================================================================

ASR引导策略 v4.0: 学术+PyRIT 融合优化
- 策略级优先排序（多轮迭代攻击 >> LLM辅助 > 编码兜底）
- JailbreakBench 学术先验 Q 值初始化（消除首次运行纯随机探索）
- Converter 增强高 ASR 多轮技术（crescendo+encoding, pair+persuasion）
- strategy_mode 切换（academic/exam/balanced）

用 PyRIT 原生 AdaptiveScenario + AdaptiveTechniqueDispatcher 替代自建 AttackUpgradeStrategy。
原生的 SequentialAttack(FIRST_SUCCESS) 天然实现 "尝试不同技术直到成功" 的逻辑。

学术依据:
- JailbreakBench (arXiv:2402.01135): GPT-4o 上 Crescendo ASR 82%, PAIR 53%, TAP 62%
- HarmBench (arXiv:2402.04249): 编码攻击在 GPT-4o 上 ASR 3-12%
- Zeng et al. (arXiv:2402.19181): 说服策略 ASR 30-40%
- 关键发现: 策略级变换(多轮迭代) >> 表示级变换(编码/混淆)

v4.0 排序策略（academic 模式, 默认）:
  Tier S (ASR >= 0.70): crescendo, red_teaming — 多轮迭代
  Tier A (ASR 0.40-0.70): tap, pair, many_shot, crescendo_simulated
  Tier B (ASR 0.15-0.40): persuasion, role_play, context_compliance, wrapping
  Tier C (ASR < 0.15): encoding, prompt_sending — 兜底

v4.0 排序策略（exam 模式）:
  编码优先（快速验证）→ 角色扮演 → 多轮兜底
  适用于弱过滤模型或考试时间受限场景

v4.0 排序策略（balanced 模式）:
  策略 + 编码交替，兼顾 ASR 和速度

失败类型路由:
  model_refusal -> 策略升级优先（换策略比换编码有效 10x）
  timeout -> 基础单轮技术优先（减少执行时间）
  objective_not_achieved -> 强技术 + Converter 变体优先
  scorer_validation_error -> 保持 epsilon-greedy 默认排序
  None（首次）-> 学术先验排序（JailbreakBench Q 值）
"""

import logging
from typing import Sequence

from pyrit.scenario.scenarios.adaptive import EpsilonGreedyTechniqueSelector
from pyrit.scenario.scenarios.adaptive.selectors import SelectorScope

from src.scenarios.technique_factories import (
    CONVERTER_VARIANT_CHAINS,
    is_converter_variant,
    get_converter_chain_from_variant,
    get_base_technique_from_variant,
)
from src.converters.target_aware_router import (
    get_target_group,
    get_chain_priority_for_target,
)

logger = logging.getLogger(__name__)


# ============================================================
# 失败类型常量
# ============================================================

FAILURE_MODEL_REFUSAL = "model_refusal"
FAILURE_TIMEOUT = "timeout"
FAILURE_SCORER_VALIDATION_ERROR = "scorer_validation_error"
FAILURE_OBJECTIVE_NOT_ACHIEVED = "objective_not_achieved"
FAILURE_UNKNOWN = "unknown"


# ============================================================
# ASR引导策略: 学术 ASR 分层（基于 JailbreakBench GPT-4o 数据）
# ============================================================

# Tier S: ASR >= 0.70 — 多轮迭代攻击（学术验证最高 ASR）
_TIER_S_TECHNIQUES = {
    "crescendo", "red_teaming",
}

# Tier A: ASR 0.40-0.70 — 树搜索/迭代/模拟对话
_TIER_A_TECHNIQUES = {
    "tap", "pair", "tree_of_attacks_pruned",
    "many_shot", "best_of_n_jailbreak",
    "crescendo_simulated", "context_compliance",
}

# Tier B: ASR 0.15-0.40 — 说服/角色扮演/包装
_TIER_B_TECHNIQUES = {
    "skeleton_key", "bad_likert_judge",
    "persuasion_authority", "decomposition_chain",
    "role_play_movie_script", "role_play_persuasion",
    "role_play_persuasion_written", "role_play_trivia_game",
    "role_play_video_game",
    "crescendo_movie_director", "crescendo_history_lecture",
    "crescendo_journalist_interview",
    "wrapping_attack", "agent_injection_chain",
    "direct_injection", "direct_injection_expanded",
}

# 合并: 所有非 Tier-C 技术（用于快速判断）
_HIGH_ASR_TECHNIQUES = _TIER_S_TECHNIQUES | _TIER_A_TECHNIQUES | _TIER_B_TECHNIQUES

# 编码技术（Tier C: 对现代商业模型 ASR < 15%）
_ENCODING_TECHNIQUES = {
    "rot13", "base64", "caesar", "binary", "morse", "leetspeak",
    "flip", "char_swap", "diacritic", "character_space",
    "string_join", "suffix_append", "atbash", "url",
}

# 单轮技术集合（用于 timeout 路由）
_SINGLE_TURN_TECHNIQUES = {
    "prompt_sending", "role_play_movie_script", "role_play_persuasion",
    "role_play_persuasion_written", "role_play_trivia_game", "role_play_video_game",
    "crescendo_simulated", "crescendo_movie_director", "crescendo_history_lecture",
    "crescendo_journalist_interview", "context_compliance", "skeleton_key",
    "multi_prompt_sending", "chunked_request",
    *_ENCODING_TECHNIQUES,
}

# 多轮技术集合（用于模态过滤）
_MULTI_TURN_TECHNIQUES = {
    "red_teaming", "crescendo", "tap", "pair", "tree_of_attacks_pruned", "many_shot",
}

# 强技术（用于 objective_not_achieved 路由）
_STRONG_TECHNIQUES = _TIER_S_TECHNIQUES | _TIER_A_TECHNIQUES

# P1: Converter 链全局优先级（当 target_type 未设置时的回退值）
_CONVERTER_CHAIN_PRIORITY: dict[str, int] = {
    chain_name: info.get("priority", 99)
    for chain_name, info in CONVERTER_VARIANT_CHAINS.items()
}


# ============================================================
# Strategy Mode 枚举
# ============================================================

STRATEGY_ACADEMIC = "academic"    # 策略级优先, JailbreakBench 先验 (默认)
STRATEGY_EXAM = "exam"            # 编码优先, 快速验证
STRATEGY_BALANCED = "balanced"    # 策略 + 编码交替

_VALID_STRATEGIES = {STRATEGY_ACADEMIC, STRATEGY_EXAM, STRATEGY_BALANCED}


class FailureTypeRoutingSelector(EpsilonGreedyTechniqueSelector):
    """
    失败类型路由技术选择器（ASR引导策略 v4.0）

    在 EpsilonGreedyTechniqueSelector 基础上增加:
    1. 学术 ASR 先验排序（首次运行用 JailbreakBench 数据初始化）
    2. 策略级优先排序（多轮迭代 >> LLM辅助 > 编码兜底）
    3. 失败类型路由（model_refusal → 策略升级, 非 Converter 变换）
    4. strategy_mode 切换（academic/exam/balanced）
    5. Target 类型感知 Converter 变体排序

    排序策略 (academic 模式, 默认):
      None（首次）→ JailbreakBench 先验排序
      model_refusal → 策略升级优先（crescendo/PAIR/TAP 多轮迭代绕过单轮拒绝）
      timeout → 基础单轮技术优先（减少执行时间）
      objective_not_achieved → 强技术 + Converter 变体优先
      scorer_validation_error → 保持 epsilon-greedy 默认排序
    """

    def __init__(
        self,
        *,
        epsilon: float = 0.2,
        random_seed: int | None = 42,
        target_type: str | None = None,
        owasp_id: str | None = None,
        scope: SelectorScope | None = None,
        strategy_mode: str = STRATEGY_ACADEMIC,
        model_name: str = "gpt-4o",
        model_tier: str = "unknown",
    ) -> None:
        """
        Args:
            epsilon: 探索概率
            random_seed: 随机种子
            target_type: PyRIT Target 类型名
            owasp_id: OWASP ID（如 "LLM01"）
            scope: SelectorScope 限定学习范围
            strategy_mode: 策略模式
                - "academic": 策略级优先, JailbreakBench 先验 (默认)
                - "exam": 编码优先, 快速验证
                - "balanced": 策略 + 编码交替
            model_name: 目标模型名称（影响 ASR 先验值）
        """
        if strategy_mode not in _VALID_STRATEGIES:
            raise ValueError(
                f"Invalid strategy_mode '{strategy_mode}'. "
                f"Must be one of {_VALID_STRATEGIES}"
            )

        super().__init__(epsilon=epsilon, scope=scope, random_seed=random_seed)
        self._last_failure_type: str | None = None
        self._target_type: str | None = target_type
        self._target_group: str | None = (
            get_target_group(target_type) if target_type else None
        )
        self._owasp_id: str | None = owasp_id
        self._owasp_default_technique: str | None = None
        self._owasp_upgrade_techniques: list[str] = []
        self._strategy_mode: str = strategy_mode
        self._model_name: str = model_name
        self._model_tier: str = model_tier
        self._load_owasp_strategy()

    def _load_owasp_strategy(self) -> None:
        """从 owasp_strategy_map 加载 OWASP 策略偏好"""
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
        """设置 OWASP ID，加载策略偏好"""
        self._owasp_id = owasp_id
        self._load_owasp_strategy()

    def set_target_type(self, target_type: str) -> None:
        """设置 Target 类型，启用 Target 感知排序"""
        self._target_type = target_type
        self._target_group = get_target_group(target_type)
        logger.debug(
            f"FailureTypeRoutingSelector: target_type={target_type}, "
            f"group={self._target_group}"
        )

    def set_strategy_mode(self, mode: str) -> None:
        """设置策略模式"""
        if mode not in _VALID_STRATEGIES:
            raise ValueError(f"Invalid strategy_mode '{mode}'")
        self._strategy_mode = mode

    def set_model_tier(self, tier: str) -> None:
        """设置模型分层（影响初始技术偏好）"""
        self._model_tier = tier
        logger.debug(f"FailureTypeRoutingSelector: model_tier={tier}")

    def update_failure_type(self, failure_type: str) -> None:
        """更新最近失败类型"""
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
        选择技术，考虑失败类型路由 + 学术先验

        1. 调用父类 epsilon-greedy 获取基础排序
        2. 根据策略模式和失败类型重新排列优先级
        3. 返回前 num_top_techniques 个技术
        """
        base_order = await super().select_async(
            technique_identifiers=technique_identifiers,
            objective=objective,
            num_top_techniques=len(technique_identifiers),
            scenario_result_id=scenario_result_id,
        )

        reordered = self._reorder_by_failure_type(base_order)

        return reordered[:num_top_techniques]

    def _target_aware_sort_key(self, technique_name: str) -> int:
        """计算技术名称的 Target 感知排序键"""
        chain_name = get_converter_chain_from_variant(technique_name)
        if chain_name is None:
            return 99

        if self._target_type:
            return get_chain_priority_for_target(chain_name, self._target_type)

        return _CONVERTER_CHAIN_PRIORITY.get(chain_name, 99)

    def _prior_sort_key(self, technique_name: str) -> float:
        """
        ASR引导策略 P4: 使用学术 ASR 先验计算排序键

        优先级:
        1. 实测 ASR（运行后更新）
        2. 学术先验 ASR（JailbreakBench/HarmBench）
        3. 中性先验 0.3

        Returns:
            ASR 值 (越高越优先)
        """
        from src.payloads.asr_prior_registry import get_initial_q_value
        return get_initial_q_value(technique_name, self._model_name)

    def _reorder_by_failure_type(self, techniques: Sequence[str]) -> list[str]:
        """
        根据策略模式 + 失败类型重新排列技术优先级

        ASR引导策略 v4.0 排序逻辑:
        - academic 模式: 策略级优先（多轮迭代 >> LLM辅助 > 编码兜底）
        - exam 模式: 编码优先 → 角色扮演 → 多轮兜底
        - balanced 模式: 学术先验排序

        失败类型路由（覆盖策略模式）:
        - model_refusal → 策略升级优先（学术: 换策略比换编码有效 10x）
        - timeout → 基础单轮技术优先
        - objective_not_achieved → 强技术 + Converter 变体优先
        """
        tech_list = list(techniques)
        failure_type = self._last_failure_type

        # ── 失败类型路由（覆盖策略模式）──

        if failure_type == FAILURE_MODEL_REFUSAL:
            return self._reorder_for_model_refusal(tech_list)

        if failure_type == FAILURE_TIMEOUT:
            return self._reorder_for_timeout(tech_list)

        if failure_type == FAILURE_OBJECTIVE_NOT_ACHIEVED:
            return self._reorder_for_objective_not_achieved(tech_list)

        if failure_type == FAILURE_SCORER_VALIDATION_ERROR:
            return tech_list  # 保持 epsilon-greedy 默认排序

        # ── 无失败类型（首次运行或重置后）──

        if self._strategy_mode == STRATEGY_ACADEMIC:
            # model_tier 影响初始技术偏好:
            # - strong: 多轮迭代优先 (Tier S→A→B→encoding, 当前行为)
            # - moderate: 策略+编码交替 (Tier S→A→encoding→B)
            # - weak: 编码优先 (encoding→Tier B→A→S, 类似 exam 模式)
            if self._model_tier == "weak":
                return self._reorder_exam(tech_list)
            elif self._model_tier == "moderate":
                return self._reorder_academic_moderate(tech_list)
            else:
                return self._reorder_academic(tech_list)
        elif self._strategy_mode == STRATEGY_EXAM:
            return self._reorder_exam(tech_list)
        else:  # STRATEGY_BALANCED
            return self._reorder_balanced(tech_list)

    # ------------------------------------------------------------------
    # 策略模式排序
    # ------------------------------------------------------------------

    def _reorder_academic(self, tech_list: list[str]) -> list[str]:
        """
        academic 模式: 策略级优先 — JailbreakBench 学术 ASR 排序

        Tier S (多轮迭代) → Tier A (树搜索/模拟) → Tier B (说服/角色)
        → Converter(高ASR技术) → 编码 → Converter(低ASR) → 基线
        """
        # OWASP 偏好
        owasp_preferred = self._get_owasp_preferred(tech_list)

        # 分层
        tier_s = [t for t in tech_list if t in _TIER_S_TECHNIQUES and t not in owasp_preferred]
        tier_a = [t for t in tech_list if t in _TIER_A_TECHNIQUES and t not in owasp_preferred]
        tier_b = [t for t in tech_list if t in _TIER_B_TECHNIQUES and t not in owasp_preferred]

        # Converter 变体: 挂载在高 ASR 技术上的优先
        converter_on_high = [
            t for t in tech_list
            if is_converter_variant(t)
            and get_base_technique_from_variant(t) in _HIGH_ASR_TECHNIQUES
        ]
        converter_on_high.sort(key=lambda t: self._target_aware_sort_key(t))

        converter_on_low = [
            t for t in tech_list
            if is_converter_variant(t)
            and get_base_technique_from_variant(t) not in _HIGH_ASR_TECHNIQUES
        ]
        converter_on_low.sort(key=lambda t: self._target_aware_sort_key(t))

        # 编码技术（对现代模型 ASR 低, 作为兜底）
        encoding_base = [t for t in tech_list if t in _ENCODING_TECHNIQUES]

        # 其他（含 prompt_sending 基线）
        used = set(owasp_preferred + tier_s + tier_a + tier_b +
                   converter_on_high + converter_on_low + encoding_base)
        others = [t for t in tech_list if t not in used]

        # 在每个 Tier 内使用学术先验排序
        tier_s.sort(key=lambda t: -self._prior_sort_key(t))
        tier_a.sort(key=lambda t: -self._prior_sort_key(t))
        tier_b.sort(key=lambda t: -self._prior_sort_key(t))

        return owasp_preferred + tier_s + tier_a + tier_b + converter_on_high + encoding_base + converter_on_low + others

    def _reorder_academic_moderate(self, tech_list: list[str]) -> list[str]:
        """
        academic + moderate 模式: 策略+编码交替

        Tier S → Tier A → 编码 → Tier B → Converter → 基线
        中等过滤模型: 多轮策略可能失效, 编码也有一定 ASR
        """
        owasp_preferred = self._get_owasp_preferred(tech_list)

        tier_s = [t for t in tech_list if t in _TIER_S_TECHNIQUES and t not in owasp_preferred]
        tier_a = [t for t in tech_list if t in _TIER_A_TECHNIQUES and t not in owasp_preferred]
        tier_b = [t for t in tech_list if t in _TIER_B_TECHNIQUES and t not in owasp_preferred]

        converter_variants = [t for t in tech_list if is_converter_variant(t)]
        converter_variants.sort(key=lambda t: self._target_aware_sort_key(t))

        encoding_base = [t for t in tech_list if t in _ENCODING_TECHNIQUES]

        used = set(owasp_preferred + tier_s + tier_a + tier_b + converter_variants + encoding_base)
        others = [t for t in tech_list if t not in used]

        tier_s.sort(key=lambda t: -self._prior_sort_key(t))
        tier_a.sort(key=lambda t: -self._prior_sort_key(t))
        tier_b.sort(key=lambda t: -self._prior_sort_key(t))

        # moderate: 编码提前到 Tier B 之前
        return owasp_preferred + tier_s + tier_a + encoding_base + tier_b + converter_variants + others

    def _reorder_exam(self, tech_list: list[str]) -> list[str]:
        """
        exam 模式: 编码优先 → 角色扮演 → 多轮兜底

        适用于弱过滤模型或考试时间受限场景。
        编码攻击对弱过滤模型 ASR 50-100%，速度快（15s/plan）。
        """
        owasp_preferred = self._get_owasp_preferred(tech_list)

        # OWASP 偏好 → 编码 → Converter 变体 → 角色扮演 → 多轮 → 基线
        encoding_base = [t for t in tech_list if t in _ENCODING_TECHNIQUES and t not in owasp_preferred]
        converter_variants = [t for t in tech_list if is_converter_variant(t)]
        converter_variants.sort(key=lambda t: self._target_aware_sort_key(t))

        role_play = [
            t for t in tech_list
            if t in _TIER_B_TECHNIQUES and t not in owasp_preferred
        ]
        multi_turn = [
            t for t in tech_list
            if t in (_TIER_S_TECHNIQUES | _TIER_A_TECHNIQUES) and t not in owasp_preferred
        ]
        used = set(owasp_preferred + encoding_base + converter_variants + role_play + multi_turn)
        others = [t for t in tech_list if t not in used]

        return owasp_preferred + encoding_base + converter_variants + role_play + multi_turn + others

    def _reorder_balanced(self, tech_list: list[str]) -> list[str]:
        """
        balanced 模式: 学术先验排序（全局 Q 值排序）

        直接使用 JailbreakBench ASR 先验对全部技术排序，
        不区分 Tier，让 Q 值自然排列。
        """
        owasp_preferred = self._get_owasp_preferred(tech_list)
        remaining = [t for t in tech_list if t not in owasp_preferred]
        remaining.sort(key=lambda t: -self._prior_sort_key(t))
        return owasp_preferred + remaining

    # ------------------------------------------------------------------
    # 失败类型路由排序
    # ------------------------------------------------------------------

    def _reorder_for_model_refusal(self, tech_list: list[str]) -> list[str]:
        """
        model_refusal → 策略升级优先

        学术依据: 换策略比换编码有效 10x
        - Crescendo/PAIR/TAP 的多轮迭代天然绕过单轮拒绝
        - 编码只改变输入表示, 不改变模型拒绝决策
        """
        logger.info("FailureTypeRouting: model_refusal -> prioritizing strategy escalation")

        # 策略升级: Tier S + Tier A 优先
        tier_s = [t for t in tech_list if t in _TIER_S_TECHNIQUES]
        tier_a = [t for t in tech_list if t in _TIER_A_TECHNIQUES]
        tier_b = [t for t in tech_list if t in _TIER_B_TECHNIQUES]

        # Converter 变体（挂载在高 ASR 技术上的）
        converter_on_high = [
            t for t in tech_list
            if is_converter_variant(t)
            and get_base_technique_from_variant(t) in _HIGH_ASR_TECHNIQUES
        ]
        converter_on_high.sort(key=lambda t: self._target_aware_sort_key(t))

        # 编码兜底
        encoding_base = [t for t in tech_list if t in _ENCODING_TECHNIQUES]
        converter_on_low = [
            t for t in tech_list
            if is_converter_variant(t)
            and get_base_technique_from_variant(t) not in _HIGH_ASR_TECHNIQUES
        ]
        converter_on_low.sort(key=lambda t: self._target_aware_sort_key(t))

        used = set(tier_s + tier_a + tier_b + converter_on_high + encoding_base + converter_on_low)
        others = [t for t in tech_list if t not in used]

        return tier_s + tier_a + tier_b + converter_on_high + encoding_base + converter_on_low + others

    def _reorder_for_timeout(self, tech_list: list[str]) -> list[str]:
        """timeout → 基础单轮技术优先（减少执行时间）"""
        logger.info("FailureTypeRouting: timeout -> prioritizing base single_turn (no converter)")

        base_single = [
            t for t in tech_list
            if not is_converter_variant(t) and t in _SINGLE_TURN_TECHNIQUES
        ]
        converter_variants = [t for t in tech_list if is_converter_variant(t)]
        others = [
            t for t in tech_list
            if not is_converter_variant(t) and t not in _SINGLE_TURN_TECHNIQUES
        ]
        return base_single + converter_variants + others

    def _reorder_for_objective_not_achieved(self, tech_list: list[str]) -> list[str]:
        """objective_not_achieved → 强技术 + Converter 变体优先"""
        logger.info("FailureTypeRouting: objective_not_achieved -> prioritizing strong techniques + converter variants")

        strong = [t for t in tech_list if t in _STRONG_TECHNIQUES]
        strong.sort(key=lambda t: -self._prior_sort_key(t))

        converter_variants = [t for t in tech_list if is_converter_variant(t)]
        converter_variants.sort(key=lambda t: self._target_aware_sort_key(t))

        others = [
            t for t in tech_list
            if not is_converter_variant(t) and t not in _STRONG_TECHNIQUES
        ]
        return strong + converter_variants + others

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _get_owasp_preferred(self, tech_list: list[str]) -> list[str]:
        """获取 OWASP 策略偏好技术"""
        if not self._owasp_default_technique:
            return []
        return [
            t for t in tech_list
            if t == self._owasp_default_technique
            or (is_converter_variant(t) and
                t.startswith(self._owasp_default_technique + "+"))
        ]


def extract_failure_type_from_result(failed_result) -> str:
    """
    从失败的 AttackResult 提取失败类型

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
