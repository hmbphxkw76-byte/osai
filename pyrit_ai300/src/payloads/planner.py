"""
Payload Planner
===============

本模块负责将原始提示词批次转化为可执行的攻击计划。

根据提示词的 attack_mode、OWASP ID 和策略选择结果（StrategySelection），
为每个提示词分配攻击技术、Scorer 配置和 Converter 配置。

核心改进（回归 PyRIT 原生框架 + 策略自动匹配）：
1. 消费 StrategySelection 中的 attack_techniques 列表，作为可选技术池
2. 使用 PayloadStrategyMatcher 自动匹配最佳 Scorer、Attack 技术、Converter 链
3. 根据 OWASP ID 从 owasp_strategy_map 映射到合适的 Scorer 类型
4. 根据载荷 metadata 中的 technique 字段智能匹配最优攻击技术
5. 为 CONVERTER_ENHANCED 模式自动匹配最佳 Converter 链（向后兼容 YAML 显式声明）
6. 将 scenario_name 传递到执行层，供 Orchestrator 使用

向后兼容：
- YAML 中显式声明的 attack_mode / converter_chains / step.attack_technique 仍被优先使用
- 未显式声明时，由 PayloadStrategyMatcher 自动匹配
"""

from typing import Any, Dict, List, Optional

from src.payloads.models import (
    AttackMode,
    AttackPlan,
    PromptBatch,
    PromptItem,
    SequentialStep,
)
from src.core.config_loader import get_config_loader
from src.analysis.strategy_matcher import PayloadStrategyMatcher


# ============================================================
# 载荷规划器
# ============================================================


class PayloadPlanner:
    """载荷规划器 - 将提示词批次转化为攻击执行计划"""

    def __init__(self):
        """初始化载荷规划器"""
        self.config_loader = get_config_loader()
        # 从 YAML 加载映射表（向后兼容）
        self.owasp_scorer_map = self.config_loader.get_strategy_config().get("ownasp_scorer_map", {})
        self.technique_hint_map = self.config_loader.get_strategy_config().get("technique_hint_map", {})
        # 策略自动匹配器
        self.strategy_matcher = PayloadStrategyMatcher()

    def plan_attacks(
        self,
        prompt_batches: List[PromptBatch],
        strategy_selection: Any = None,
    ) -> List[AttackPlan]:
        """
        根据策略选择，为每个提示词生成攻击计划

        规划逻辑：
        1. 消费 strategy_selection 中的 attack_techniques 作为可选技术池
        2. 使用 PayloadStrategyMatcher 自动匹配最佳策略
        3. 根据 owasp_id 映射到合适的 Scorer 类型
        4. 为 CONVERTER_ENHANCED 模式展开 Converter 链组合
           （YAML 显式声明优先，否则使用自动匹配的链）
        5. 为 SEQUENTIAL 模式的步骤自动匹配攻击技术
        6. 计算优先级排序

        Args:
            prompt_batches: 提示词批次列表
            strategy_selection: 策略选择结果（StrategySelection），包含
                               attack_techniques、scenario_name 等

        Returns:
            AttackPlan 列表
        """
        plans: List[AttackPlan] = []
        plan_counter = 0

        # 从 strategy_selection 提取可用技术池和 scenario 信息
        available_techniques: List[str] = []
        scenario_name: str = ""
        if strategy_selection is not None:
            available_techniques = getattr(strategy_selection, "attack_techniques", [])
            scenario_name = getattr(strategy_selection, "scenario_name", "")

        for batch in prompt_batches:
            # 加载该 OWASP 分类的元数据
            meta = self._load_owasp_meta(batch.owasp_id)

            # 使用策略匹配器自动匹配 OWASP 策略
            matched = self.strategy_matcher.match(
                owasp_id=batch.owasp_id,
            )

            # 确定 scorer_type（优先使用 owasp_scorer_map，回退到 owasp_strategy_map）
            scorer_type = self.owasp_scorer_map.get(
                batch.owasp_id or "",
                matched.scorer_type,
            )

            for item in batch.prompts:
                if item.attack_mode == AttackMode.CONVERTER_ENHANCED:
                    # 编码增强模式
                    if item.converter_chains:
                        # YAML 显式声明了 converter_chains → 展开每个链（向后兼容）
                        for chain_name in item.converter_chains:
                            plan_counter += 1
                            plan = self._create_plan(
                                plan_id=f"plan_{plan_counter:04d}",
                                item=item,
                                meta=meta,
                                converter_chain_name=chain_name,
                                available_techniques=available_techniques,
                                scenario_name=scenario_name,
                                scorer_type=scorer_type,
                            )
                            plans.append(plan)
                    elif matched.converter_chain:
                        # YAML 未声明 → 使用自动匹配的 converter_chain
                        plan_counter += 1
                        plan = self._create_plan(
                            plan_id=f"plan_{plan_counter:04d}",
                            item=item,
                            meta=meta,
                            converter_chain_name=matched.converter_chain,
                            available_techniques=available_techniques,
                            scenario_name=scenario_name,
                            scorer_type=scorer_type,
                        )
                        plans.append(plan)
                else:
                    plan_counter += 1
                    plan = self._create_plan(
                        plan_id=f"plan_{plan_counter:04d}",
                        item=item,
                        meta=meta,
                        available_techniques=available_techniques,
                        scenario_name=scenario_name,
                        scorer_type=scorer_type,
                    )
                    plans.append(plan)

        # 按优先级排序（高优先级先执行）
        plans.sort(key=lambda p: p.priority, reverse=True)

        return plans

    def _create_plan(
        self,
        plan_id: str,
        item: PromptItem,
        meta: Dict[str, Any],
        converter_chain_name: Optional[str] = None,
        available_techniques: Optional[List[str]] = None,
        scenario_name: str = "",
        scorer_type: str = "general",
    ) -> AttackPlan:
        """创建单个攻击计划"""

        # 根据攻击模式和策略选择攻击技术
        attack_technique = self._select_attack_technique(
            item, meta, available_techniques or []
        )

        # 顺序组合攻击：为未声明技术的步骤自动匹配
        if item.attack_mode == AttackMode.SEQUENTIAL:
            self._auto_match_sequential_steps(item, meta)

        # 计算优先级
        priority = self._calculate_priority(item, meta)

        # 多轮攻击的最大轮次
        max_turns = 1
        if item.attack_mode == AttackMode.MULTI_TURN:
            max_turns = item.metadata.get("max_turns", len(item.multi_turn_steps))

        # 构建内存标签
        memory_labels = {
            "owasp_id": item.owasp_id or "",
            "attack_mode": item.attack_mode.value,
            "source_id": item.source_id or "",
            "prompt_id": item.id,
            "attack_technique": attack_technique,
            "scorer_type": scorer_type,
        }
        if converter_chain_name:
            memory_labels["converter_chain_name"] = converter_chain_name
        if scenario_name:
            memory_labels["scenario_name"] = scenario_name

        return AttackPlan(
            plan_id=plan_id,
            prompt_item=item,
            attack_technique=attack_technique,
            converter_chain_name=converter_chain_name,
            memory_labels=memory_labels,
            max_turns=max_turns,
            priority=priority,
            owasp_id=item.owasp_id,
            scorer_type=scorer_type,
            scenario_name=scenario_name,
        )

    def _select_attack_technique(
        self,
        item: PromptItem,
        meta: Dict[str, Any],
        available_techniques: List[str],
    ) -> str:
        """
        根据攻击模式和策略选择攻击技术

        选择逻辑（优先级从高到低）：
        1. technique_hint_map 中的映射
        2. owasp_strategy_map 中的 default_attack_technique
        3. attack_mode 固定逻辑（SEQUENTIAL → "sequential"）
        4. 全局默认 "prompt_sending"

        向后兼容：如果 available_techniques 非空，优先选择在池中的技术
        """

        if item.attack_mode == AttackMode.SEQUENTIAL:
            return "sequential"

        # 使用策略匹配器获取技术提示
        technique_hint = item.metadata.get("technique", "").lower()

        # 1. 尝试 technique_hint_map
        if technique_hint:
            hinted_technique = self.technique_hint_map.get(technique_hint)
            if hinted_technique:
                # 如果暗示的技术在可用技术池中，或者技术池为空，使用它
                if not available_techniques or hinted_technique in available_techniques:
                    return hinted_technique

        # 2. MULTI_TURN 模式特殊处理
        if item.attack_mode == AttackMode.MULTI_TURN:
            if item.multi_turn_steps:
                # 有显式 turns → 逐轮发送
                return "prompt_sending"
            # 无显式 turns → 如果策略推荐了 red_teaming，使用它
            if "red_teaming" in available_techniques:
                return "red_teaming"
            # 回退到 owasp_strategy_map 的默认技术
            owasp_strategy = self.strategy_matcher.owasp_strategy_map.get(
                item.owasp_id or "", {}
            )
            return owasp_strategy.get("default_attack_technique", "prompt_sending")

        # 3. 尝试 owasp_strategy_map 的默认技术
        owasp_strategy = self.strategy_matcher.owasp_strategy_map.get(
            item.owasp_id or "", {}
        )
        default_tech = owasp_strategy.get("default_attack_technique")
        if default_tech:
            if not available_techniques or default_tech in available_techniques:
                return default_tech

        # 4. 全局默认
        return "prompt_sending"

    def _auto_match_sequential_steps(
        self,
        item: PromptItem,
        meta: Dict[str, Any],
    ) -> None:
        """
        为顺序组合攻击的步骤自动匹配攻击技术

        优先级：
        1. YAML 显式声明的 step.attack_technique（向后兼容）
        2. PayloadStrategyMatcher.match_step_technique 自动匹配
        """
        technique_hint = item.metadata.get("technique", "")
        total_steps = len(item.sequential_steps)

        for i, step in enumerate(item.sequential_steps):
            # 如果步骤已声明 attack_technique 且不为空，跳过（向后兼容）
            if step.attack_technique:
                continue

            # 自动匹配步骤技术
            matched_tech = self.strategy_matcher.match_step_technique(
                owasp_id=item.owasp_id,
                technique_hint=technique_hint,
                step_index=i,
                total_steps=total_steps,
            )
            # 直接修改步骤（Pydantic 模型允许赋值）
            step.attack_technique = matched_tech

    def _calculate_priority(
        self,
        item: PromptItem,
        meta: Dict[str, Any],
    ) -> int:
        """计算攻击优先级 (0-100)"""

        priority = 50  # 基础优先级

        # 根据 OWASP 严重程度调整
        severity = meta.get("severity", "MEDIUM").upper()
        severity_boost = {
            "CRITICAL": 30,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
        }
        priority += severity_boost.get(severity, 10)

        # 根据攻击模式调整
        mode_boost = {
            AttackMode.SINGLE_TURN: 10,      # 快速覆盖优先
            AttackMode.MULTI_TURN: 5,
            AttackMode.CONVERTER_ENHANCED: 0,
            AttackMode.SEQUENTIAL: -5,        # 顺序攻击耗时较长，降低优先级
        }
        priority += mode_boost.get(item.attack_mode, 0)

        # 根据元数据中的 severity 调整
        item_severity = item.metadata.get("severity", "").lower()
        if item_severity == "high":
            priority += 5
        elif item_severity == "critical":
            priority += 10

        return max(0, min(100, priority))

    def _load_owasp_meta(self, owasp_id: Optional[str]) -> Dict[str, Any]:
        """从 OWASP 映射配置加载元数据"""
        if not owasp_id:
            return {}

        details = self.config_loader.get_owasp_details(owasp_id)
        if details is None:
            return {}

        return {
            "owasp_id": owasp_id,
            "name": details.get("name", ""),
            "severity": details.get("severity", "MEDIUM"),
            "cvss_base": details.get("cvss_base", 5.0),
        }


# ============================================================
# 工厂函数
# ============================================================


def plan_attacks(
    prompt_batches: List[PromptBatch],
    strategy_selection: Any = None,
) -> List[AttackPlan]:
    """
    将提示词批次转化为攻击计划（工厂函数）

    Args:
        prompt_batches: 提示词批次列表
        strategy_selection: 策略选择结果（StrategySelection）

    Returns:
        AttackPlan 列表
    """
    planner = PayloadPlanner()
    return planner.plan_attacks(prompt_batches, strategy_selection)
