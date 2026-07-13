"""载荷桥接模块 — 连接 config/payloads/ 高质量载荷库与 config/scenarios/ 攻击剧本。

解决 Scenarios 内嵌简陋占位符、不引用外部载荷库的断裂问题：
  1. 从 config/payloads/ 按 OWASP 类别 + 策略过滤加载高质量载荷
  2. 将库载荷转换为场景 PayloadTemplate 格式
  3. 合并库载荷与场景内嵌载荷（去重 + ID 冲突优先场景本地）
  4. 支持 extends 跨场景继承（通用阶段/载荷复用）

Library-First: 场景即配置，载荷即数据，桥接即适配器。
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from redteam.attack.core.payload_loader import PayloadLoader

from .schema import AttackScenario, AttackStrategy, AttackTargetType, PayloadTemplate

logger = logging.getLogger(__name__)

# ── 策略 → OWASP 载荷库类别映射 ──────────────────────────────────────
# 每个 AttackStrategy 可能对应多个 config/payloads/ 下的类别
STRATEGY_TO_PAYLOAD_CATEGORIES: dict[AttackStrategy, list[str]] = {
    # LLM01: 提示注入
    AttackStrategy.DIRECT_INJECT: ["llm01"],
    AttackStrategy.INDIRECT_INJECT: ["llm01"],
    AttackStrategy.JAILBREAK: ["llm01"],
    AttackStrategy.ROLEPLAY: ["llm01"],
    AttackStrategy.STEALTH: ["llm01"],
    AttackStrategy.ACADEMIC: ["llm01"],
    AttackStrategy.TRANSLATION: ["llm01"],
    AttackStrategy.CRESCENDO: ["llm01"],
    AttackStrategy.TAP: ["llm01"],
    AttackStrategy.PAIR: ["llm01"],
    AttackStrategy.FLIP: ["llm01"],
    AttackStrategy.FRONTIER: ["llm01"],

    # LLM02: 不安全输出处理
    AttackStrategy.GOAL_HIJACK: ["llm02"],
    AttackStrategy.TOOL_HIJACK: ["llm02", "llm06"],

    # LLM03: 训练数据投毒 (供应链接入)
    AttackStrategy.PARAMETER_POLLUTION: ["llm03"],
    AttackStrategy.DATASET_POISON: ["llm03"],
    AttackStrategy.DEPENDENCY_TROJAN: ["llm03"],

    # LLM04: 模型拒绝服务 (RAG 投毒)
    AttackStrategy.RAG_POISON: ["llm04"],
    AttackStrategy.RETRIEVAL_LEAK: ["llm04", "llm05"],

    # LLM05: 供应链漏洞
    AttackStrategy.MEMORY_POISON: ["llm01", "llm06", "llm09"],
    AttackStrategy.SYSTEM_PROMPT_EXTRACT: ["llm01", "llm07"],
    AttackStrategy.CROSS_AGENT: ["llm06"],

    # LLM06/LLM07/LLM08/LLM09/LLM10
    AttackStrategy.VECTOR_DB_ATTACK: ["llm08"],
    AttackStrategy.CLOUD_MISCONFIG: ["llm05", "llm10"],

    # 编码类策略无对应库载荷（由 converter 层处理）
    AttackStrategy.BASE64: [],
    AttackStrategy.ROT13: [],
    AttackStrategy.UNICODE: [],
    AttackStrategy.LEETSPEAK: [],
    AttackStrategy.MORSE: [],
    AttackStrategy.PROBE: [],
}


# ── 策略 → 库载荷 technique 过滤映射 ─────────────────────────────────
# 库载荷中 technique 字段的值 → 对应的 AttackStrategy
LIBRARY_TECHNIQUE_TO_STRATEGY: dict[str, list[AttackStrategy]] = {
    "instruction_override": [AttackStrategy.DIRECT_INJECT],
    "context_poisoning": [AttackStrategy.INDIRECT_INJECT],
    "system_prompt_extraction": [AttackStrategy.SYSTEM_PROMPT_EXTRACT],
    "translation_trick": [AttackStrategy.TRANSLATION],
    "completion_lure": [AttackStrategy.SYSTEM_PROMPT_EXTRACT],
    "roleplay": [AttackStrategy.ROLEPLAY, AttackStrategy.JAILBREAK],
    "impersonation": [AttackStrategy.ROLEPLAY],
    "emotional_manipulation": [AttackStrategy.JAILBREAK],
    "hypothetical_framing": [AttackStrategy.STEALTH],
    "chain_of_thought_exploit": [AttackStrategy.ACADEMIC],
    "memory_poison": [AttackStrategy.MEMORY_POISON],
    "goal_hijack": [AttackStrategy.GOAL_HIJACK],
    "tool_hijack": [AttackStrategy.TOOL_HIJACK],
    "rag_poison": [AttackStrategy.RAG_POISON],
    "retrieval_leak": [AttackStrategy.RETRIEVAL_LEAK],
    "vector_db_attack": [AttackStrategy.VECTOR_DB_ATTACK],
    "parameter_pollution": [AttackStrategy.PARAMETER_POLLUTION],
    "cross_agent": [AttackStrategy.CROSS_AGENT],
    "crescendo": [AttackStrategy.CRESCENDO],
    "many_shot": [AttackStrategy.TAP],
    "adversarial_suffix": [AttackStrategy.PAIR],
    # 供应链
    "dependency_confusion": [AttackStrategy.DEPENDENCY_TROJAN],
    "deserialization_rce": [AttackStrategy.DATASET_POISON],
    "jailbreak": [AttackStrategy.JAILBREAK],
    "multimodal_injection": [AttackStrategy.DIRECT_INJECT, AttackStrategy.INDIRECT_INJECT],
    "hallucination_exploitation": [AttackStrategy.MEMORY_POISON],
    # 通用技术
    "encoding": [AttackStrategy.BASE64, AttackStrategy.ROT13],
    "language_switch": [AttackStrategy.TRANSLATION],
    "context_window_abuse": [AttackStrategy.STEALTH],
    "api_hammer": [AttackStrategy.CLOUD_MISCONFIG],
}


class PayloadBridge:
    """载荷桥接器 — 连接 config/payloads/ 与 config/scenarios/。

    使用方式：
        bridge = PayloadBridge()
        scenario = bridge.enrich_scenario(scenario_yaml_data)
    """

    def __init__(
        self,
        payload_dir: str = "config/payloads",
        scenario_dir: str = "config/scenarios",
    ):
        self._payload_loader = PayloadLoader(payload_dir=payload_dir)
        self._scenario_dir = Path(scenario_dir)
        # 类别级缓存：{category: [raw_payload_dicts]}
        self._category_cache: dict[str, list[dict[str, Any]]] = {}

    def enrich_scenario(
        self,
        scenario: AttackScenario,
        raw_yaml: dict[str, Any],
    ) -> AttackScenario:
        """丰富场景：合并库载荷 + 处理 extends 继承。

        Args:
            scenario: 已解析的场景模型
            raw_yaml: 原始 YAML 字典（含 extends/payload_sources 等扩展字段）

        Returns:
            丰富后的 AttackScenario（原场景不变，返回新实例）
        """
        merged_payloads: list[PayloadTemplate] = list(scenario.payloads)

        # ── Step 1: 处理 extends 跨场景继承 ──
        extends_name = raw_yaml.get("extends", "").strip()
        if extends_name:
            logger.info("场景 %s 继承自 %s", scenario.id, extends_name)
            base_scenario, base_raw = self._load_base_scenario(extends_name)
            if base_scenario:
                # 合并阶段：当前阶段在前，基础阶段在后（去重）
                current_phase_names = {p.name for p in scenario.phases}
                inherited_phases = [p for p in base_scenario.phases if p.name not in current_phase_names]
                scenario = scenario.model_copy(update={
                    "phases": list(scenario.phases) + inherited_phases,
                })
                # 合并载荷：当前载荷优先
                current_payload_ids = {p.id for p in merged_payloads}
                for bp in base_scenario.payloads:
                    if bp.id not in current_payload_ids:
                        merged_payloads.append(bp)

        # ── Step 2: 处理 payload_sources 库载荷引用 ──
        library_sources = raw_yaml.get("payload_sources", [])
        if library_sources:
            library_payloads = self._load_library_payloads(library_sources, scenario)
            current_ids = {p.id for p in merged_payloads}
            for lp in library_payloads:
                if lp.id not in current_ids:
                    merged_payloads.append(lp)
                    current_ids.add(lp.id)

        if (extends_name or library_sources) and len(merged_payloads) > len(scenario.payloads):
            logger.info(
                "载荷桥接完成: 原有 %d 条 + 继承/库 %d 条 = 合并 %d 条",
                len(scenario.payloads),
                len(merged_payloads) - len(scenario.payloads),
                len(merged_payloads),
            )

        return scenario.model_copy(update={"payloads": merged_payloads})

    def load_library_payloads_for_scenario(
        self,
        scenario: AttackScenario,
        payload_sources: list[dict[str, Any]],
    ) -> list[PayloadTemplate]:
        """为场景加载库载荷（公开接口，供外部调用）。"""
        return self._load_library_payloads(payload_sources, scenario)

    # ── private ──────────────────────────────────────────────────────

    def _load_base_scenario(self, name: str) -> tuple[Optional[AttackScenario], dict]:
        """加载基场景（用于 extends）。"""
        # 尝试多种文件名形式
        candidates = [
            self._scenario_dir / f"{name}.yaml",
            self._scenario_dir / f"_{name}.yaml",
        ]
        for cand in candidates:
            if cand.exists():
                try:
                    import yaml
                    with open(cand, encoding="utf-8") as f:
                        raw = yaml.safe_load(f)
                    scenario = AttackScenario(**{k: v for k, v in raw.items() if k not in ("extends", "payload_sources")})
                    return scenario, raw
                except Exception as e:
                    logger.warning("加载基场景失败 %s: %s", cand, e)

        logger.info("基场景 %s 未找到，跳过继承", name)
        return None, {}

    def _load_library_payloads(
        self,
        sources: list[dict[str, Any]],
        scenario: AttackScenario,
    ) -> list[PayloadTemplate]:
        """从 payload_sources 配置加载库载荷。

        两种模式：
          - 指定 strategies: 只加载匹配策略的载荷（精准匹配）
          - 未指定 strategies: 加载类别下全部载荷（广度覆盖模式）

        Args:
            sources: payload_sources 列表
            scenario: 当前场景

        Returns:
            转换后的 PayloadTemplate 列表
        """
        results: list[PayloadTemplate] = []
        seen_ids: set[str] = set()

        for source_config in sources:
            source_type = source_config.get("source", "library")
            categories: list[str] = source_config.get("categories", [])
            strategies: list[str] = source_config.get("strategies", [])

            if source_type != "library":
                continue

            if not categories:
                categories = self._derive_categories_from_scenario(scenario)

            # 判断模式：指定 strategies 则精准匹配，否则全量加载
            if strategies:
                strategy_set: set[AttackStrategy] = set()
                for s in strategies:
                    try:
                        strategy_set.add(AttackStrategy(s))
                    except ValueError:
                        logger.debug("跳过未知策略: %s", s)

                for category in categories:
                    for strategy in strategy_set:
                        for pt in self._convert_category_payloads(category, strategy):
                            if pt.id not in seen_ids:
                                results.append(pt)
                                seen_ids.add(pt.id)
            else:
                # 全量加载模式：加载类别下所有 payload
                for category in categories:
                    for pt in self._convert_all_category_payloads(category, scenario):
                        if pt.id not in seen_ids:
                            results.append(pt)
                            seen_ids.add(pt.id)

        return results

    def _derive_categories_from_scenario(self, scenario: AttackScenario) -> list[str]:
        """从场景配置自动推导需要加载的 OWASP 类别。"""
        categories: set[str] = set()
        for phase in scenario.phases:
            for strategy in phase.strategies:
                cats = STRATEGY_TO_PAYLOAD_CATEGORIES.get(strategy, [])
                categories.update(cats)
        return sorted(categories) if categories else ["llm01"]

    def _get_category_raw_payloads(self, category: str) -> list[dict[str, Any]]:
        """获取类别下所有原始载荷（带缓存）。

        Args:
            category: OWASP 类别名

        Returns:
            原始载荷字典列表
        """
        if category not in self._category_cache:
            self._category_cache[category] = self._payload_loader.load_by_category(category)
        return self._category_cache[category]

    def _convert_category_payloads(
        self,
        category: str,
        strategy: AttackStrategy,
    ) -> list[PayloadTemplate]:
        """从库加载指定类别 + 策略的载荷并转换（精准匹配模式）。

        匹配逻辑：
          1. 按 technique → AttackStrategy 映射过滤
          2. 映射表未命中时使用关键词宽松匹配
        """
        raw_payloads = self._get_category_raw_payloads(category)
        results: list[PayloadTemplate] = []
        idx = 0

        for raw in raw_payloads:
            technique = raw.get("technique", "")
            matched_strategies = LIBRARY_TECHNIQUE_TO_STRATEGY.get(technique, [])

            if not matched_strategies:
                matched_strategies = self._fuzzy_match_strategy(technique, strategy)

            if strategy not in matched_strategies:
                continue

            pt = self._raw_to_template(raw, category, strategy, idx)
            if pt:
                results.append(pt)
                idx += 1

        if results:
            logger.debug("库类别 %s 策略 %s: 加载 %d 条载荷", category, strategy.value, len(results))
        return results

    def _convert_all_category_payloads(
        self,
        category: str,
        scenario: AttackScenario,
    ) -> list[PayloadTemplate]:
        """加载类别下全部载荷，自动推导策略分配（全量加载模式）。

        每个载荷通过 technique → strategy 映射自动分配到场景中对应的策略。
        无法映射的载荷分配到第一个匹配的场景策略或默认为 direct_inject。
        """
        raw_payloads = self._get_category_raw_payloads(category)
        results: list[PayloadTemplate] = []

        # 收集场景中所有启用的策略作为回退目标
        scenario_strategies: set[AttackStrategy] = set()
        for phase in scenario.phases:
            scenario_strategies.update(phase.strategies)

        idx = 0
        for raw in raw_payloads:
            technique = raw.get("technique", "")
            matched_strategies = LIBRARY_TECHNIQUE_TO_STRATEGY.get(technique, [])

            if not matched_strategies:
                # 宽匹配：尝试所有场景策略
                for s in scenario_strategies:
                    matched = self._fuzzy_match_strategy(technique, s)
                    if matched:
                        matched_strategies = matched
                        break

            if not matched_strategies:
                # 最终回退：映射到场景第一个非编码策略
                fallback = next(
                    (s for s in scenario_strategies if s not in (
                        AttackStrategy.BASE64, AttackStrategy.ROT13, AttackStrategy.PROBE
                    )),
                    AttackStrategy.DIRECT_INJECT,
                )
                matched_strategies = [fallback]

            # 为每个匹配的策略创建一个 PayloadTemplate
            for strategy in matched_strategies:
                if strategy in scenario_strategies or not scenario_strategies:
                    pt = self._raw_to_template(raw, category, strategy, idx)
                    if pt:
                        results.append(pt)
                        idx += 1

        logger.info("库类别 %s 全量加载: %d 条载荷 (原始 %d 条)",
                     category, len(results), len(raw_payloads))
        return results

    def _raw_to_template(
        self,
        raw: dict[str, Any],
        category: str,
        strategy: AttackStrategy,
        idx: int,
    ) -> Optional[PayloadTemplate]:
        """将原始载荷字典转换为 PayloadTemplate。

        Args:
            raw: 原始载荷字典
            category: OWASP 类别
            strategy: 目标策略
            idx: 索引号

        Returns:
            PayloadTemplate 或 None（如果载荷为空）
        """
        technique = raw.get("technique", "")
        name = raw.get("name", f"{category}_{technique}_{idx}")
        payload_text = raw.get("payload", "") or raw.get("payload_template", "")

        if not payload_text:
            return None

        payload_id = f"lib_{category}_{technique}_{idx}"

        return PayloadTemplate(
            id=payload_id,
            name=name,
            description=raw.get("description", raw.get("name", "")),
            payload=payload_text,
            technique=technique,
            difficulty=raw.get("difficulty", "medium"),
            strategy=strategy,
            category=category,
            success_patterns=raw.get("success_patterns", []),
            failure_patterns=raw.get("failure_patterns", []),
            tags=raw.get("tags", []) + [f"source:library", f"category:{category}"],
        )

    def _fuzzy_match_strategy(self, technique: str, target_strategy: AttackStrategy) -> list[AttackStrategy]:
        """宽松匹配 — 当 technique 不在精确映射表中时的回退逻辑。"""
        technique_lower = technique.lower()
        strategy_value = target_strategy.value.lower()

        # 关键词语义匹配
        keyword_mapping: dict[str, list[AttackStrategy]] = {
            "inject": [AttackStrategy.DIRECT_INJECT, AttackStrategy.INDIRECT_INJECT],
            "jailbreak": [AttackStrategy.JAILBREAK],
            "extract": [AttackStrategy.SYSTEM_PROMPT_EXTRACT],
            "poison": [AttackStrategy.MEMORY_POISON, AttackStrategy.RAG_POISON],
            "hijack": [AttackStrategy.GOAL_HIJACK, AttackStrategy.TOOL_HIJACK],
            "retriev": [AttackStrategy.RETRIEVAL_LEAK],
            "bypass": [AttackStrategy.JAILBREAK, AttackStrategy.STEALTH],
            "roleplay": [AttackStrategy.ROLEPLAY],
            "stealth": [AttackStrategy.STEALTH],
            "crescendo": [AttackStrategy.CRESCENDO],
            "adversarial": [AttackStrategy.PAIR],
            "many_shot": [AttackStrategy.TAP],
        }

        for keyword, strategies in keyword_mapping.items():
            if keyword in technique_lower and target_strategy in strategies:
                return [target_strategy]

        return []


# ── 公开工具函数 ────────────────────────────────────────────────────


def enrich_scenario_from_yaml(
    scenario: AttackScenario,
    raw_yaml: dict[str, Any],
    payload_dir: str = "config/payloads",
    scenario_dir: str = "config/scenarios",
) -> AttackScenario:
    """便捷函数：从原始 YAML 字典丰富场景。

    Args:
        scenario: 已解析的场景
        raw_yaml: 原始 YAML 字典
        payload_dir: 载荷库目录
        scenario_dir: 场景目录

    Returns:
        丰富后的场景
    """
    bridge = PayloadBridge(payload_dir=payload_dir, scenario_dir=scenario_dir)
    return bridge.enrich_scenario(scenario, raw_yaml)


__all__ = [
    "PayloadBridge",
    "STRATEGY_TO_PAYLOAD_CATEGORIES",
    "LIBRARY_TECHNIQUE_TO_STRATEGY",
    "enrich_scenario_from_yaml",
]
