"""
Attack Upgrade Strategy
=======================

攻击升级重试策略模块 �?�?ScenarioOrchestrator 提取

自研功能（PyRIT 原生不支持）�?
  攻击失败后自动升级到更强的攻击技术�?

P1-1 增强：数据驱动的智能升级策略
  1. 失败类型提取与分类（model_refusal / timeout / scorer_validation_error / objective_not_achieved�?
  2. 按失败类型路由升级策略（拒绝→Converter绕过 / 超时→降�?/ 评分错误→换scorer / 未达成→升级技术）
  3. 返回多个候选方案（不再仅取第一个）
  4. 升级历史追踪（避免重复尝试已失败的技�?模式组合�?

升级策略类型�?
  1. 单轮 �?多轮升级 (single_turn_to_multi_turn)
     �? prompt_sending �?crescendo
  2. 基础多轮 �?高级多轮升级 (multi_turn_upgrade)
     �? red_teaming �?tap
  3. 添加 Converter �?(add_converter)
     �? 添加 stealth_evasion 编码�?
  4. 失败类型路由升级 (failure_type_routing) �?P1-1 新增
     �? model_refusal �?优先添加 Converter �?

策略配置来源: src/core/defaults/payload_strategy_matrix.yaml �?attack_upgrade_strategies
  （config/ 下同名文件可覆盖系统默认�?

设计原则:
  - 纯函数设计：不依�?orchestrator 实例状�?
  - 配置驱动：策略从配置文件读取
  - 向后兼容：ScenarioOrchestrator 委托此模�?
  - 安全限制：最大升级深�?max_upgrade_depth 防止无限递归
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from src.core.config_loader import get_config_loader
from src.payloads.models import AttackMode, AttackPlan, PromptItem

logger = logging.getLogger(__name__)


# ============================================================
# 失败类型常量
# ============================================================

# 失败类型枚举（字符串常量，避免引�?Enum 依赖�?
FAILURE_MODEL_REFUSAL = "model_refusal"
FAILURE_TIMEOUT = "timeout"
FAILURE_SCORER_VALIDATION_ERROR = "scorer_validation_error"
FAILURE_MODEL_RESPONSE_ERROR = "model_response_error"
FAILURE_OBJECTIVE_NOT_ACHIEVED = "objective_not_achieved"
FAILURE_UNKNOWN = "unknown"

# 最大升级深度（防止无限递归�?
MAX_UPGRADE_DEPTH = 1

# Maximum upgrade candidates per depth level (prevent upgrade chain bloat)
MAX_UPGRADE_CANDIDATES = 3

# Per-plan total upgrade time budget (seconds)
# If cumulative upgrade time exceeds this, stop upgrading
MAX_UPGRADE_TOTAL_TIME = 600  # 10 minutes


# ============================================================
# 失败类型提取
# ============================================================


def extract_failure_type(failed_result: Any) -> str:
    """
    从失败的 AttackResult 中提取失败类�?

    分类逻辑（与 report_generator.py 的失败分析对齐）�?
    - ValidationError / score_rationale �?scorer_validation_error
    - Timeout �?timeout
    - Status Code: 500 / finish_reason �?model_response_error
    - Refusal / refused �?model_refusal
    - 其他 �?objective_not_achieved

    Args:
        failed_result: 失败�?AttackResult 实例

    Returns:
        失败类型字符串（见上方常量定义）
    """
    if failed_result is None:
        return FAILURE_UNKNOWN

    # 安全提取属�?
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
        # 检�?outcome 是否�?error
        outcome = _safe_get(failed_result, "outcome")
        if outcome is not None:
            outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()
            if outcome_str == "ERROR":
                return FAILURE_MODEL_RESPONSE_ERROR
        return FAILURE_OBJECTIVE_NOT_ACHIEVED

    if "ValidationError" in raw_error or "score_rationale" in raw_error:
        return FAILURE_SCORER_VALIDATION_ERROR
    elif "Timeout" in raw_error or "timeout" in raw_error.lower():
        return FAILURE_TIMEOUT
    elif "Status Code: 500" in raw_error or "finish_reason" in raw_error:
        return FAILURE_MODEL_RESPONSE_ERROR
    elif "Refusal" in raw_error or "refused" in raw_error.lower():
        return FAILURE_MODEL_REFUSAL
    else:
        return FAILURE_OBJECTIVE_NOT_ACHIEVED


# ============================================================
# 升级策略生成�?
# ============================================================


class AttackUpgradeStrategy:
    """
    攻击升级策略 �?根据失败结果生成升级的攻击计�?

    P1-1 增强�?
    - 按失败类型路由不同升级策�?
    - 返回多个候选方案（按优先级排序�?
    - 支持升级历史追踪（避免重复尝试）

    �?payload_strategy_matrix.yaml �?attack_upgrade_strategies 段读取策略配�?
  （系统默�? src/core/defaults/，用户覆�? config/）�?

    用法�?
        strategy = AttackUpgradeStrategy()
        upgraded_plans = strategy.generate_upgrade_plans(
            original_plan=failed_plan,
            failed_result=attack_result,
            tried_combinations={("prompt_sending", "single_turn")},
        )
    """

    def __init__(self, config_loader=None):
        """
        初始化升级策�?

        Args:
            config_loader: 配置加载器（可选，默认使用全局单例�?
        """
        self._config_loader = config_loader or get_config_loader()

    @property
    def _upgrade_strategies(self) -> dict:
        """获取升级策略配置"""
        return self._config_loader.get_strategy_config().get(
            "attack_upgrade_strategies", {}
        )

    @property
    def _failure_type_routing(self) -> dict:
        """获取失败类型路由配置"""
        return self._upgrade_strategies.get("failure_type_routing", {})

    def generate_upgrade_plans(
        self,
        original_plan: AttackPlan,
        failed_result: Any,
        tried_combinations: Optional[Set[Tuple[str, str]]] = None,
        current_depth: int = 0,
    ) -> List[AttackPlan]:
        """
        根据失败结果生成升级的攻击计划列�?

        P1-1 增强�?
        1. 提取失败类型，按类型路由优先策略
        2. 返回多个候选方案（不再仅取第一个）
        3. 过滤已尝试过的技�?模式组合
        4. 检查升级深度限�?

        Args:
            original_plan: 原始（失败的）攻击计�?
            failed_result: 失败�?AttackResult（用于提取失败类型）
            tried_combinations: 已尝试过�?(technique, mode) 组合集合
            current_depth: 当前升级深度�?=首次升级�?

        Returns:
            按优先级排序的升级攻击计划列表（可能为空�?
        """
        if current_depth >= MAX_UPGRADE_DEPTH:
            logger.debug(
                f"Upgrade skipped: max depth ({MAX_UPGRADE_DEPTH}) reached "
                f"for plan {original_plan.plan_id}"
            )
            return []

        tried = tried_combinations or set()
        current_technique = original_plan.attack_technique
        current_mode = original_plan.prompt_item.attack_mode
        failure_type = extract_failure_type(failed_result)

        logger.info(
            f"Upgrade analysis: technique='{current_technique}', "
            f"mode={current_mode.value}, failure_type={failure_type}, "
            f"depth={current_depth}, tried={len(tried)} combinations"
        )

        # 生成候选方案（按优先级排序�?
        candidates: List[AttackPlan] = []

        # P1-1: 按失败类型路由优先策�?
        routed_plans = self._generate_failure_type_routed_plans(
            original_plan, failure_type, tried
        )
        candidates.extend(routed_plans)

        # 策略 1: 单轮 �?多轮升级
        if current_mode in (AttackMode.SINGLE_TURN, AttackMode.CONVERTER_ENHANCED):
            candidates.extend(
                self._generate_single_turn_upgrades(original_plan, tried)
            )

        # 策略 2: 基础多轮 �?高级多轮升级
        elif current_mode == AttackMode.MULTI_TURN and not original_plan.prompt_item.multi_turn_steps:
            candidates.extend(
                self._generate_multi_turn_upgrades(original_plan, tried)
            )

        # 策略 3: 添加 Converter �?
        if not original_plan.converter_chain_name and current_mode == AttackMode.SINGLE_TURN:
            candidates.extend(
                self._generate_converter_upgrades(original_plan, tried)
            )

        # 去重：移除已尝试过的 (technique, mode) 组合
        unique_candidates = self._filter_tried_combinations(candidates, tried)

        # 去重：按 (technique, mode, converter) 去重
        seen: Set[Tuple[str, str, Optional[str]]] = set()
        final_candidates: List[AttackPlan] = []
        for plan in unique_candidates:
            key = (
                plan.attack_technique,
                plan.prompt_item.attack_mode.value,
                plan.converter_chain_name,
            )
            if key not in seen:
                seen.add(key)
                final_candidates.append(plan)

        if final_candidates:
            logger.info(
                f"Upgrade strategy: {len(final_candidates)} candidate plan(s) generated "
                f"for technique='{current_technique}', mode={current_mode.value}, "
                f"failure_type={failure_type}"
            )

        # Cap the number of candidates to prevent upgrade chain bloat
        if len(final_candidates) > MAX_UPGRADE_CANDIDATES:
            logger.info(
                f"Upgrade strategy: capping from {len(final_candidates)} to "
                f"{MAX_UPGRADE_CANDIDATES} candidates"
            )
            final_candidates = final_candidates[:MAX_UPGRADE_CANDIDATES]

        return final_candidates

    # ------------------------------------------------------------------
    # 失败类型路由策略（P1-1 新增�?
    # ------------------------------------------------------------------

    def _generate_failure_type_routed_plans(
        self,
        original_plan: AttackPlan,
        failure_type: str,
        tried: Set[Tuple[str, str]],
    ) -> List[AttackPlan]:
        """
        按失败类型生成优先升级方�?

        路由逻辑�?
        - model_refusal �?优先添加 Converter 链（编码绕过�?
        - timeout �?降级到更简单的技术（减少多轮深度�?
        - scorer_validation_error �?保持技术但标记�?scorer
        - objective_not_achieved �?升级到更强的攻击技�?
        """
        candidates: List[AttackPlan] = []
        routing_config = self._failure_type_routing.get(failure_type, {})

        if not routing_config:
            return candidates

        # 优先策略：添�?Converter
        if failure_type == FAILURE_MODEL_REFUSAL:
            converter_chains = routing_config.get("prefer_converter_chains", [])
            current_technique = original_plan.attack_technique
            for chain in converter_chains:
                if chain != original_plan.converter_chain_name:
                    plan = self.create_upgraded_plan(
                        original_plan,
                        new_technique=current_technique,
                        new_mode=AttackMode.CONVERTER_ENHANCED,
                        converter_chain=chain,
                        reason=f"Failure type '{failure_type}': add converter to bypass refusal",
                    )
                    candidates.append(plan)

        # 超时：降级到更简单的技�?
        elif failure_type == FAILURE_TIMEOUT:
            downgrade_techniques = routing_config.get("downgrade_to", [])
            for tech in downgrade_techniques:
                if tech != original_plan.attack_technique:
                    plan = self.create_upgraded_plan(
                        original_plan,
                        new_technique=tech,
                        new_mode=AttackMode.SINGLE_TURN,
                        reason=f"Failure type '{failure_type}': downgrade to simpler technique",
                    )
                    candidates.append(plan)

        # 评分验证错误：换技术但保持简单模�?
        elif failure_type == FAILURE_SCORER_VALIDATION_ERROR:
            alternative_techniques = routing_config.get("alternative_techniques", [])
            for tech in alternative_techniques:
                if tech != original_plan.attack_technique:
                    plan = self.create_upgraded_plan(
                        original_plan,
                        new_technique=tech,
                        new_mode=original_plan.prompt_item.attack_mode,
                        reason=f"Failure type '{failure_type}': switch technique to avoid scorer validation issues",
                    )
                    candidates.append(plan)

        # 目标未达成：升级到更强的技�?
        elif failure_type == FAILURE_OBJECTIVE_NOT_ACHIEVED:
            upgrade_to = routing_config.get("upgrade_to", [])
            for tech in upgrade_to:
                if tech != original_plan.attack_technique:
                    plan = self.create_upgraded_plan(
                        original_plan,
                        new_technique=tech,
                        new_mode=AttackMode.MULTI_TURN,
                        reason=f"Failure type '{failure_type}': escalate to stronger attack",
                    )
                    candidates.append(plan)

        return candidates

    # ------------------------------------------------------------------
    # 基础升级策略（保留原有逻辑，移�?[:1] 限制�?
    # ------------------------------------------------------------------

    def _generate_single_turn_upgrades(
        self,
        original_plan: AttackPlan,
        tried: Set[Tuple[str, str]],
    ) -> List[AttackPlan]:
        """单轮 �?多轮升级"""
        candidates: List[AttackPlan] = []
        current_technique = original_plan.attack_technique
        strategy = self._upgrade_strategies.get("single_turn_to_multi_turn", {})

        if current_technique in strategy.get("from", []):
            for tech in strategy.get("to", []):
                combo = (tech, AttackMode.MULTI_TURN.value)
                if combo not in tried:
                    plan = self.create_upgraded_plan(
                        original_plan,
                        new_technique=tech,
                        new_mode=AttackMode.MULTI_TURN,
                        reason=strategy.get("reason", ""),
                    )
                    candidates.append(plan)

        return candidates

    def _generate_multi_turn_upgrades(
        self,
        original_plan: AttackPlan,
        tried: Set[Tuple[str, str]],
    ) -> List[AttackPlan]:
        """基础多轮 �?高级多轮升级"""
        candidates: List[AttackPlan] = []
        current_technique = original_plan.attack_technique
        strategy = self._upgrade_strategies.get("multi_turn_upgrade", {})

        if current_technique in strategy.get("from", []):
            for tech in strategy.get("to", []):
                combo = (tech, AttackMode.MULTI_TURN.value)
                if combo not in tried:
                    plan = self.create_upgraded_plan(
                        original_plan,
                        new_technique=tech,
                        new_mode=AttackMode.MULTI_TURN,
                        reason=strategy.get("reason", ""),
                    )
                    candidates.append(plan)

        return candidates

    def _generate_converter_upgrades(
        self,
        original_plan: AttackPlan,
        tried: Set[Tuple[str, str]],
    ) -> List[AttackPlan]:
        """添加 Converter �?""
        candidates: List[AttackPlan] = []
        current_technique = original_plan.attack_technique
        strategy = self._upgrade_strategies.get("add_converter", {})

        if current_technique in strategy.get("from", []):
            for chain in strategy.get("converter_chains", []):
                combo = (current_technique, AttackMode.CONVERTER_ENHANCED.value)
                if combo not in tried:
                    plan = self.create_upgraded_plan(
                        original_plan,
                        new_technique=current_technique,
                        new_mode=AttackMode.CONVERTER_ENHANCED,
                        converter_chain=chain,
                        reason=strategy.get("reason", ""),
                    )
                    candidates.append(plan)

        return candidates

    # ------------------------------------------------------------------
    # 过滤与去�?
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_tried_combinations(
        plans: List[AttackPlan],
        tried: Set[Tuple[str, str]],
    ) -> List[AttackPlan]:
        """过滤掉已尝试过的 (technique, mode) 组合"""
        if not tried:
            return plans

        filtered: List[AttackPlan] = []
        for plan in plans:
            combo = (plan.attack_technique, plan.prompt_item.attack_mode.value)
            if combo not in tried:
                filtered.append(plan)
            else:
                logger.debug(
                    f"Upgrade filtered: ({plan.attack_technique}, "
                    f"{plan.prompt_item.attack_mode.value}) already tried"
                )

        return filtered

    # ------------------------------------------------------------------
    # 创建升级计划（保留原有静态方法）
    # ------------------------------------------------------------------

    @staticmethod
    def create_upgraded_plan(
        original_plan: AttackPlan,
        new_technique: str,
        new_mode: AttackMode,
        converter_chain: Optional[str] = None,
        reason: str = "",
    ) -> AttackPlan:
        """
        创建升级的攻击计�?

        保留原始计划�?objective/owasp_id/scenario_name�?
        更新攻击技术、模式和 Converter 链�?
        标记 upgraded_from �?upgrade_reason �?memory_labels�?

        Args:
            original_plan: 原始攻击计划
            new_technique: 新的攻击技术名�?
            new_mode: 新的攻击模式
            converter_chain: 可选的 Converter 链名�?
            reason: 升级原因

        Returns:
            升级后的 AttackPlan
        """
        new_labels = {
            **original_plan.memory_labels,
            "upgraded_from": original_plan.attack_technique,
            "upgrade_reason": reason,
        }
        if converter_chain:
            new_labels["converter_chain_name"] = converter_chain

        new_prompt_item = PromptItem(
            id=original_plan.prompt_item.id,
            objective=original_plan.prompt_item.objective,
            owasp_id=original_plan.prompt_item.owasp_id,
            attack_mode=new_mode,
            source_id=original_plan.prompt_item.source_id,
            category=original_plan.prompt_item.category,
            converter_chains=(
                original_plan.prompt_item.converter_chains.copy()
                if original_plan.prompt_item.converter_chains else []
            ),
            multi_turn_steps=(
                original_plan.prompt_item.multi_turn_steps.copy()
                if original_plan.prompt_item.multi_turn_steps else []
            ),
            sequential_steps=(
                original_plan.prompt_item.sequential_steps.copy()
                if original_plan.prompt_item.sequential_steps else []
            ),
            metadata=original_plan.prompt_item.metadata.copy(),
        )

        upgraded_max_turns = 3 if new_mode == AttackMode.MULTI_TURN else 1

        return AttackPlan(
            plan_id=f"{original_plan.plan_id}_upgrade",
            prompt_item=new_prompt_item,
            attack_technique=new_technique,
            converter_chain_name=converter_chain,
            memory_labels=new_labels,
            max_turns=upgraded_max_turns,
            priority=original_plan.priority - 5,
            owasp_id=original_plan.owasp_id,
            scorer_type=original_plan.scorer_type,
            scenario_name=original_plan.scenario_name,
        )
