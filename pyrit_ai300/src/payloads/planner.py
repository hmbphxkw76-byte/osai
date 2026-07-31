"""
Payload Planner
===============

本模块负责将原始提示词批次转化为可执行的攻击计划。

根据提示词的 attack_mode、OWASP ID 和策略选择结果（StrategySelection），
为每个提示词分配攻击技术、Scorer 配置和 Converter 配置。

核心改进（回归 PyRIT 原生框架 + 策略自动匹配 + Jailbreak 集成）：
1. 消费 StrategySelection 中的 attack_techniques 列表，作为可选技术池
2. 使用 PayloadStrategyMatcher 自动匹配最佳 Scorer、Attack 技术、Converter 链
3. 根据 OWASP ID 从 owasp_strategy_map 映射到合适的 Scorer 类型
4. 根据载荷 metadata 中的 technique 字段智能匹配最优攻击技术
5. 为 CONVERTER_ENHANCED 模式自动匹配最佳 Converter 链（向后兼容 YAML 显式声明）
6. 将 scenario_name 传递到执行层，供 Orchestrator 使用
7. 集成 PyRIT 1.0.0 TextJailBreak（160+ 越狱模板），可选增强提示词

向后兼容：
- YAML 中显式声明的 attack_mode / converter_chains / step.attack_technique 仍被优先使用
- 未显式声明时，由 PayloadStrategyMatcher 自动匹配
"""

import logging
from typing import Any, Dict, List, Optional

from src.payloads.models import (
    AttackMode,
    AttackPlan,
    PromptBatch,
    PromptItem,
)
from src.core.config_loader import get_config_loader
from src.analysis.strategy_matcher import PayloadStrategyMatcher

logger = logging.getLogger(__name__)


# ============================================================
# 载荷规划器
# ============================================================


class PayloadPlanner:
    """载荷规划器 - 将提示词批次转化为攻击执行计划

    v2.0 改进：支持 target_type 参数，传递给 PayloadStrategyMatcher
    启用 Target 感知 Converter 链选择（与 Adaptive 路径统一）
    """

    def __init__(self, target_type: Optional[str] = None):
        """初始化载荷规划器

        Args:
            target_type: PyRIT Target 类型名（v2.0 — Target 感知）
        """
        self.config_loader = get_config_loader()
        # 从 YAML 加载映射表（向后兼容）
        self.owasp_scorer_map = self.config_loader.get_strategy_config().get("owasp_scorer_map", {})
        self.technique_hint_map = self.config_loader.get_strategy_config().get("technique_hint_map", {})
        # 策略自动匹配器（v2.0 — Target 感知）
        self.strategy_matcher = PayloadStrategyMatcher(target_type=target_type)

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

            # 检查是否有 objective 类型的 seed（来自 SeedObjective）
            # objective seed 适用于目标导向攻击（RedTeaming/Crescendo/PAIR/TAP）
            _has_objective_seeds = any(
                item.metadata.get("is_objective_seed") or item.metadata.get("seed_type") == "objective"
                for item in batch.prompts
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
        P2-2: ASR 驱动的攻击技术选择器

        选择逻辑（优先级从高到低）：
        1. technique_hint_map 中的映射（如果暗示技术在可用技术池中）
        2. attack_mode 固定逻辑（SEQUENTIAL → "sequential"）
        3. ASR 驱动选择：从 available_techniques 中选择 ASR 最高的技术
        4. owasp_strategy_map 中的 default_attack_technique
        5. 全局默认 "crescendo_simulated"（ASR 驱动）

        P2-2 核心改进：available_techniques 不再仅作为过滤器，
        而是按 ASR 降序排序选择最优技术。这确保高 ASR 技术（如 crescendo）
        优先于低 ASR 技术（如 prompt_sending）被选中。
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
            # 如果是 objective seed（来自 SeedObjective），优先使用目标导向攻击
            is_objective = item.metadata.get("is_objective_seed") or item.metadata.get("seed_type") == "objective"
            has_objective = item.metadata.get("has_objective", False)
            if is_objective or (has_objective and not item.multi_turn_steps):
                # P2-2: ASR 驱动 — 从可用技术池中选择 ASR 最高的多轮技术
                if available_techniques:
                    best_multi = self._select_highest_asr_technique(
                        available_techniques, prefer_multi_turn=True
                    )
                    if best_multi:
                        return best_multi
                # 回退到固定优先级
                if "red_teaming" in available_techniques or not available_techniques:
                    return "red_teaming"
                if "crescendo" in available_techniques:
                    return "crescendo"
                if "pair" in available_techniques:
                    return "pair"
            if item.multi_turn_steps:
                # 有显式 turns → 逐轮发送
                return "prompt_sending"
            # 无显式 turns → ASR 驱动选择
            if available_techniques:
                best = self._select_highest_asr_technique(
                    available_techniques, prefer_multi_turn=True
                )
                if best:
                    return best
            if "red_teaming" in available_techniques:
                return "red_teaming"
            # 回退到 owasp_strategy_map 的默认技术
            owasp_strategy = self.strategy_matcher.owasp_strategy_map.get(
                item.owasp_id or "", {}
            )
            return owasp_strategy.get("default_attack_technique", "crescendo_simulated")

        # 3. P2-2: ASR 驱动选择 — 从可用技术池中选择 ASR 最高的技术
        if available_techniques:
            best_tech = self._select_highest_asr_technique(
                available_techniques, prefer_multi_turn=False
            )
            if best_tech:
                return best_tech

        # 4. 尝试 owasp_strategy_map 的默认技术
        owasp_strategy = self.strategy_matcher.owasp_strategy_map.get(
            item.owasp_id or "", {}
        )
        default_tech = owasp_strategy.get("default_attack_technique")
        if default_tech:
            if not available_techniques or default_tech in available_techniques:
                return default_tech

        # 5. 全局默认（P2-1: ASR 驱动）
        return "crescendo_simulated"

    @staticmethod
    def _select_highest_asr_technique(
        techniques: List[str],
        prefer_multi_turn: bool = False,
    ) -> str | None:
        """
        P2-2: 从技术列表中选择 ASR 最高的技术

        使用 asr_prior_registry 中的学术 ASR 先验数据进行排序。
        如果 prefer_multi_turn=True，优先选择多轮技术。

        Args:
            techniques: 可用技术名列表
            prefer_multi_turn: 是否优先选择多轮技术

        Returns:
            ASR 最高的技术名，或 None 如果列表为空
        """
        if not techniques:
            return None

        try:
            from src.payloads.asr_prior_registry import get_asr_prior

            # 多轮技术集合（用于 prefer_multi_turn 过滤）
            multi_turn_techniques = {
                "crescendo", "red_teaming", "tap", "pair",
                "many_shot", "violent_durian",
            }

            # 如果优先多轮且有可用多轮技术，仅从多轮技术中选择
            candidates = techniques
            if prefer_multi_turn:
                multi_turn_available = [t for t in techniques if t in multi_turn_techniques]
                if multi_turn_available:
                    candidates = multi_turn_available

            # 按 ASR 降序排序
            def asr_key(tech_name: str) -> float:
                prior = get_asr_prior(tech_name)
                return prior.asr_percent if prior else 0.0

            sorted_techs = sorted(candidates, key=asr_key, reverse=True)
            return sorted_techs[0] if sorted_techs else None
        except Exception:
            # 回退：返回第一个技术
            return techniques[0] if techniques else None

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


    # -----------------------------------------------------------------
    # Jailbreak 模板增强（PyRIT 1.0.0 TextJailBreak 集成）
    # -----------------------------------------------------------------

    def enhance_with_jailbreak(
        self,
        prompt_batches: List[PromptBatch],
        template_file_name: Optional[str] = None,
        random_template: bool = False,
        template_types: Optional[List[str]] = None,
        max_batches_per_template: Optional[int] = None,
    ) -> List[PromptBatch]:
        """
        使用 PyRIT 1.0.0 TextJailBreak 模板增强提示词

        将每个单轮提示词包装在越狱模板中（DAN, AIM 等 100+ 模板），
        绕过 LLM 安全过滤。仅对 single_turn 模式应用。

        PyRIT 1.0.0 TextJailBreak 支持的模板来源：
        - template_file_name: 指定模板文件名（如 "aim.yaml"）
        - random_template: 从 100+ 模板中随机选择
        - template_types: 按模板名称关键词过滤（如 ["dan", "aim"]），
          然后从匹配的模板中随机选择

        ⚠️ 重要：不要将 template_types 作为 **kwargs 传给 TextJailBreak.__init__，
          因为 PyRIT 会将其当作 Jinja 模板变量而非过滤器。
          本方法在调用 TextJailBreak 之前完成模板过滤。

        增强逻辑：
        - 跳过已包含 jailbreak 标记的提示词
        - 保留原始 objective 到 metadata，便于溯源
        - 可选限制每个模板增强的批次数量

        Args:
            prompt_batches: 原始提示词批次列表
            template_file_name: 指定模板文件名（如 "aim.yaml"），None = 不指定
            random_template: 是否随机选择模板
            template_types: 按名称关键词过滤模板类型（如 ["dan", "aim", "role_play"]），
                           从匹配的模板中随机选择。优先级低于 template_file_name。
            max_batches_per_template: 每个模板最多增强的批次数量

        Returns:
            增强后的 PromptBatch 列表
        """
        if not template_file_name and not random_template and not template_types:
            return prompt_batches

        try:
            from pyrit.datasets import TextJailBreak
        except ImportError:
            logger.warning("TextJailBreak not available, skipping jailbreak enhancement")
            return prompt_batches

        # template_types 过滤：在调用 TextJailBreak 之前筛选模板
        # PyRIT TextJailBreak.__init__ 不支持类型过滤参数，
        # 传入的 **kwargs 会被当作 Jinja 模板变量而非过滤器
        if template_types and not template_file_name:
            try:
                all_templates = TextJailBreak.get_jailbreak_templates()
                # 按名称关键词过滤（大小写不敏感）
                matched = [
                    name for name in all_templates
                    if any(t.lower() in name.lower() for t in template_types)
                ]
                if not matched:
                    logger.warning(
                        f"No jailbreak templates matched types {template_types}, "
                        f"falling back to random_template"
                    )
                    random_template = True
                else:
                    import random as _random
                    template_file_name = _random.choice(matched)
                    logger.info(
                        f"Template type filter {template_types} matched {len(matched)} templates, "
                        f"selected: {template_file_name}"
                    )
            except Exception as e:
                logger.warning(f"Failed to filter templates by types: {e}, using random_template")
                random_template = True

        enhanced_batches: List[PromptBatch] = []
        template_count = {}

        for batch in prompt_batches:
            enhanced_items: List[PromptItem] = []

            for item in batch.prompts:
                if item.attack_mode == AttackMode.SINGLE_TURN:
                    # 跳过已增强的提示词
                    if item.metadata and "jailbreak_enhanced" in item.metadata:
                        enhanced_items.append(item)
                        continue

                    try:
                        # 使用 PyRIT 1.0.0 原生 TextJailBreak API
                        jb = TextJailBreak(
                            template_file_name=template_file_name,
                            random_template=random_template,
                        )
                        enhanced_objective = jb.get_jailbreak(item.objective)
                        template_source = getattr(jb, "template_source", "unknown")

                        # 可选：限制每个模板使用次数
                        if max_batches_per_template:
                            count = template_count.get(template_source, 0)
                            if count >= max_batches_per_template:
                                enhanced_items.append(item)
                                continue
                            template_count[template_source] = count + 1

                        new_item = PromptItem(
                            id=f"{item.id}_jb",
                            objective=enhanced_objective,
                            attack_mode=item.attack_mode,
                            owasp_id=item.owasp_id,
                            source_id=item.source_id,
                            category=item.category,
                            converter_chains=item.converter_chains.copy() if item.converter_chains else [],
                            multi_turn_steps=item.multi_turn_steps.copy() if item.multi_turn_steps else [],
                            sequential_steps=item.sequential_steps.copy() if item.sequential_steps else [],
                            metadata={
                                **item.metadata,
                                "jailbreak_template": template_source,
                                "original_objective": item.objective,
                                "jailbreak_enhanced": True,
                            },
                        )
                        enhanced_items.append(new_item)

                    except Exception as e:
                        logger.warning(f"Failed to enhance item {item.id} with jailbreak: {e}")
                        enhanced_items.append(item)
                else:
                    enhanced_items.append(item)

            enhanced_batches.append(PromptBatch(
                source_id=batch.source_id,
                owasp_id=batch.owasp_id,
                category=batch.category,
                description=batch.description,
                prompts=enhanced_items,
            ))

        return enhanced_batches


# ============================================================
# 工厂函数
# ============================================================


def plan_attacks(
    prompt_batches: List[PromptBatch],
    strategy_selection: Any = None,
    jailbreak_template: Optional[str] = None,
    jailbreak_random: bool = False,
    jailbreak_template_types: Optional[List[str]] = None,
    jailbreak_max_batches: Optional[int] = None,
    target_type: Optional[str] = None,
) -> List[AttackPlan]:
    """
    将提示词批次转化为攻击计划（工厂函数）

    Args:
        prompt_batches: 提示词批次列表
        strategy_selection: 策略选择结果（StrategySelection）
        jailbreak_template: 可选的 Jailbreak 模板文件名（如 "aim.yaml"）
        jailbreak_random: 是否随机选择 Jailbreak 模板
        jailbreak_template_types: 按名称关键词过滤模板类型（如 ["dan", "aim"]）
        jailbreak_max_batches: 每个模板最多增强的批次数量
        target_type: PyRIT Target 类型名（v2.0 — Target 感知 Converter 链选择）

    Returns:
        AttackPlan 列表
    """
    planner = PayloadPlanner(target_type=target_type)

    # Jailbreak 模板增强（可选）
    if jailbreak_template or jailbreak_random or jailbreak_template_types:
        prompt_batches = planner.enhance_with_jailbreak(
            prompt_batches,
            template_file_name=jailbreak_template,
            random_template=jailbreak_random,
            template_types=jailbreak_template_types,
            max_batches_per_template=jailbreak_max_batches,
        )

    return planner.plan_attacks(prompt_batches, strategy_selection)
