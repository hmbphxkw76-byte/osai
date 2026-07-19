# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Orchestrator v3.1
攻击编排器：使用 PyRIT 原生攻击策略执行

v3.1 重构改进：
- 拆分为 5 个子模块，遵循单一职责原则
  - pyrit_initializer.py: PyRIT 内存初始化
  - target_builder.py: PromptTarget 构建（含 Playwright）
  - converter_builder.py: 转换器配置构建
  - scorer_builder.py: 评分器构建（含 LLM 后端）
  - template_renderer.py: 三级占位符渲染（位于 payloads/）
- 消除 UTF-8 重复代码（utils/platform.py 统一处理）
- ASI_SCORER_MAP 外置到 config/scores/asi_mapping.yaml

核心改进（v3.0）：
- 不再手动循环执行，全部使用 PyRIT 原生攻击
- PromptSendingAttack: 单轮 + 内置重试 (max_attempts_on_failure)
- CrescendoAttack: 渐进升级 + 自动回退 (role_play / complex)
- TreeOfAttacksWithPruningAttack: 树搜索 + 剪枝 (context_overflow / adversarial)
- SequentialAttack: 多 preset 早停 (FIRST_SUCCESS)

PyRIT 0.14.0 API 说明：
- 内存：SQLiteMemory + CentralMemory.set_memory_instance()
- 攻击：直接使用 PyRIT 攻击类 + execute_async()
- 转换器：AttackConverterConfig 包装
- 评分器：AttackScoringConfig 包装
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..utils.async_helper import run_async

# PyRIT 0.14.0 核心组件导入
from pyrit.memory import CentralMemory, SQLiteMemory
from pyrit.executor.attack import (
    PromptSendingAttack,
    AttackConverterConfig,
    AttackScoringConfig,
    AttackAdversarialConfig,
)
from pyrit.prompt_converter import PromptConverter
from pyrit.prompt_normalizer.prompt_converter_configuration import PromptConverterConfiguration
from pyrit.prompt_target import PromptTarget, OpenAIChatTarget
from pyrit.score import Scorer

# 子模块导入（v3.1 拆分）
from .pyrit_initializer import PyRITInitializer
from .target_builder import TargetBuilder
from .converter_builder import ConverterBuilder
from .scorer_builder import ScorerBuilder
from .component_registry import (
    CONVERTER_MAP,
    SCORER_MAP,
    SPECIAL_PRESETS,
    LLM_BACKEND_SCORERS,
    CONVERTER_NAME_MAP,
    SCORER_NAME_MAP,
    CONVERTERS_NEEDING_TARGET,
)

# 速率控制器
from .rate_controller import RateController, create_rate_controller

# 模板渲染器
from ..payloads.template_renderer import TemplateRenderer

logger = logging.getLogger(__name__)

# 模板渲染器实例
_template_renderer = TemplateRenderer()


def _extract_payload_text(
    payload: Any,
    objective: Optional[str] = None,
    placeholders: Optional[Dict[str, str]] = None,
) -> str:
    """
    从载荷中提取文本并渲染占位符（委托给 TemplateRenderer）

    Args:
        payload: 载荷（字符串或字典）
        objective: 用户指定的攻击目标（替换 {objective} 占位符）
        placeholders: 用户自定义占位符字典

    Returns:
        渲染后的载荷文本字符串
    """
    return _template_renderer.render(payload, objective=objective, placeholders=placeholders)


def _import_class(fqn: str) -> type:
    """从全限定名导入类"""
    module_path, class_name = fqn.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


class AttackOrchestrator:
    """
    攻击编排器 v3.1

    职责（精简后）：
    1. 编排攻击执行流程
    2. 协调子模块：PyRITInitializer, TargetBuilder, ConverterBuilder, ScorerBuilder
    3. 执行 PyRIT 原生攻击并收集结果

    不再承担的职责（已拆分）：
    - PyRIT 内存初始化 → PyRITInitializer
    - 目标构建 → TargetBuilder
    - 转换器构建 → ConverterBuilder
    - 评分器构建 → ScorerBuilder
    - 模板渲染 → TemplateRenderer
    """

    # 评分器配置目录（多文件模式：config/scores/*.yaml）
    SCORER_CONFIG_PATH = "config/scores/"

    # 数据目录路径（payload_refs 解析用）
    DATA_DIR = "data"

    # 类级别 PayloadManager 实例（共享缓存）
    _payload_manager: Optional[Any] = None

    # ASI/LLM 类别 → 评分器类型自动映射（v3.1: 从 config/scores/asi_mapping.yaml 加载）
    _ASI_SCORER_MAP: Dict[str, str] = {
        "ASI01": "refusal", "ASI02": "true_false", "ASI03": "category",
        "ASI04": "true_false", "ASI05": "substring", "ASI06": "refusal",
        "ASI07": "true_false", "ASI08": "category", "ASI09": "refusal",
        "ASI10": "category",
        "LLM01": "refusal", "LLM02": "refusal", "LLM03": "true_false",
        "LLM04": "substring", "LLM05": "category", "LLM06": "true_false",
        "LLM07": "substring", "LLM08": "category", "LLM09": "refusal",
        "LLM10": "true_false",
    }

    # OWASP ID（小写）→ 默认评分器列表
    _DEFAULT_SCORERS: Dict[str, list] = {
        "llm01": ["refusal", "substring"], "llm02": ["true_false"],
        "llm03": ["true_false"], "llm04": ["true_false"],
        "llm05": ["refusal", "true_false"], "llm06": ["true_false", "substring"],
        "llm07": ["refusal", "true_false"], "llm08": ["substring"],
        "llm09": ["refusal"], "llm10": ["true_false"],
        "asi01": ["refusal", "substring"], "asi02": ["refusal", "true_false"],
        "asi03": ["refusal", "true_false"], "asi04": ["refusal", "true_false"],
        "asi05": ["refusal", "true_false"], "asi06": ["true_false", "substring"],
        "asi07": ["refusal", "true_false"], "asi08": ["true_false", "substring"],
        "asi09": ["refusal", "true_false"], "asi10": ["refusal", "true_false"],
    }

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_dict: Optional[Dict[str, Any]] = None,
        memory_type: str = "in_memory",
        scorer_config_path: Optional[str] = None,
        data_dir: Optional[str] = None,
        scorer_url: Optional[str] = None,
        scorer_key: Optional[str] = None,
        scorer_model: Optional[str] = None,
    ):
        self.config = self._load_config(config_path, config_dict)
        self.memory_type = memory_type
        self._components_initialized = False
        self._results: List[Dict[str, Any]] = []
        self._data_dir = data_dir or self.DATA_DIR
        self._rate_controller: Optional[RateController] = None

        # 初始化子模块（v3.1 拆分）
        self._pyrit_initializer = PyRITInitializer(memory_type=memory_type)
        self._target_builder = TargetBuilder()
        self._converter_builder = ConverterBuilder()
        self._scorer_builder = ScorerBuilder(
            scorer_config_path=scorer_config_path or self.SCORER_CONFIG_PATH,
            scorer_url=scorer_url,
            scorer_key=scorer_key,
            scorer_model=scorer_model,
        )

        # 初始化 PayloadManager
        self._init_payload_manager()
        # 初始化 PyRIT 内存
        self._initialize_pyrit()
        # 加载评分器配置
        self._scorer_builder.load_config()
        # 加载 ASI 映射配置（v3.1 外置）
        self._load_asi_scorer_map()

    def _init_payload_manager(self) -> None:
        """初始化 PayloadManager（类级别单例）"""
        if AttackOrchestrator._payload_manager is None:
            from ..payloads.payload_manager import PayloadManager
            AttackOrchestrator._payload_manager = PayloadManager()
            AttackOrchestrator._payload_manager.load_data_dir(self._data_dir)
        self._payload_mgr = AttackOrchestrator._payload_manager

    def _load_asi_scorer_map(self) -> None:
        """
        加载 ASI 评分器映射（v3.1: 从 config/scores/asi_mapping.yaml 加载）

        优先级：
        1. config/scores/asi_mapping.yaml
        2. 内置默认值（_ASI_SCORER_MAP / _DEFAULT_SCORERS）
        """
        mapping_path = Path("config/scores/asi_mapping.yaml")
        if mapping_path.exists():
            try:
                with open(mapping_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                external_map = data.get("asi_scorer_map", {})
                if external_map:
                    self._ASI_SCORER_MAP = external_map
                    logger.info("ASI scorer map loaded from %s (%d entries)", mapping_path, len(external_map))
                external_defaults = data.get("default_scorers", {})
                if external_defaults:
                    self._DEFAULT_SCORERS = external_defaults
                    logger.info("Default scorers loaded from %s (%d entries)", mapping_path, len(external_defaults))
                if external_map or external_defaults:
                    return
            except Exception as e:
                logger.warning("Failed to load ASI scorer map from %s: %s, using defaults", mapping_path, e)
        logger.debug("Using built-in ASI scorer map (%d entries)", len(self._ASI_SCORER_MAP))

    def resolve_payload_refs(self, refs: List[str]) -> List[str]:
        """解析 payload_refs 为实际载荷列表"""
        return self._payload_mgr.resolve_refs(refs)

    def _load_config(
        self,
        config_path: Optional[str],
        config_dict: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """加载配置"""
        if config_dict:
            return config_dict
        if config_path:
            path = Path(config_path)
            if path.suffix in (".yaml", ".yml"):
                with open(path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            raise ValueError(f"Unsupported config format: {path.suffix}")
        return {}

    def _initialize_pyrit(self):
        """初始化 PyRIT 0.14.0 内存（委托给 PyRITInitializer）"""
        self._pyrit_initializer.initialize()
        self._components_initialized = self._pyrit_initializer.is_initialized

    def build_target(self, target_config: Dict[str, Any]) -> PromptTarget:
        """
        根据配置构建 PyRIT PromptTarget（委托给 TargetBuilder）

        同时创建速率控制器（RateController），基于目标类型自动选择最优并发值。
        """
        target = self._target_builder.build(target_config)
        self._rate_controller = self._target_builder.rate_controller
        return target

    def build_converters(
        self,
        converter_configs: List[Dict[str, Any]],
        converter_target: Optional[PromptTarget] = None,
    ) -> List[PromptConverterConfiguration]:
        """
        根据配置列表构建转换器配置（委托给 ConverterBuilder）
        """
        return self._converter_builder.build(converter_configs, converter_target)

    def build_scorers(
        self,
        scorer_configs: List[Dict[str, Any]],
        objective_target: Optional[PromptTarget] = None,
        asi_category: str = "",
    ) -> List[Scorer]:
        """
        构建评分器（委托给 ScorerBuilder，ASI 自动选择 + 外部 LLM 后端）
        """
        return self._scorer_builder.build(
            scorer_configs=scorer_configs,
            objective_target=objective_target,
            asi_category=asi_category,
            asi_scorer_map=self._ASI_SCORER_MAP,
        )

    def _check_adversarial_available(self) -> bool:
        """检查是否有可用的对抗性 LLM（委托给 ScorerBuilder）"""
        return self._scorer_builder.check_adversarial_available()

    def _build_adversarial_config(self, objective_target: PromptTarget) -> Optional[AttackAdversarialConfig]:
        """构建对抗性配置（委托给 ScorerBuilder）"""
        return self._scorer_builder.build_adversarial_config(objective_target)

    # ──────────────────────────────────────────────────────────────────────────
    # 执行接口：使用 PyRIT 原生攻击
    # ──────────────────────────────────────────────────────────────────────────

    def execute_attack(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        converters: Optional[List[PromptConverter]] = None,
        scorers: Optional[List[Scorer]] = None,
        tracker: Optional[Any] = None,
        profile_params: Optional[Dict[str, Any]] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        执行单次攻击（同步接口）

        根据 mode 选择执行策略：
        - smart_match: SmartMatcher 选择 PyRIT 原生攻击（支持侦察驱动）
        - presets: SequentialAttack (FIRST_SUCCESS) 或 PromptSendingAttack
        - chain: PromptSendingAttack (带重试)

        REV-1 集成：基于侦察画像攻击面过滤不相关攻击
        """
        mode = attack_config.get("mode", "chain")
        attack_name = attack_config.get("name", "unnamed_attack")
        logger.info("\n######## 执行攻击: %s (mode=%s) ########", attack_name, mode)

        # REV-1: 侦察→载荷过滤闭环 (GAP-1)
        # 基于侦察检测到的攻击面，跳过不相关的 OWASP 类别
        if profile_params:
            owasp_id = attack_config.get("owasp_id", attack_config.get("asi_category", ""))
            surfaces = profile_params.get("surfaces", [])
            if surfaces and owasp_id:
                from ..payloads.payload_filter import PayloadFilter
                _pf = PayloadFilter()
                if _pf.should_skip_attack(owasp_id, surfaces):
                    required = PayloadFilter.OWASP_SURFACE_MAP.get(owasp_id.upper(), {"prompt"})
                    skip_reason = (
                        f"Surface mismatch: {owasp_id} requires {required}, "
                        f"target has {surfaces}"
                    )
                    logger.info("REV-1 Filter: Skipping '%s' — %s", attack_name, skip_reason)
                    if tracker:
                        tracker.log_execution({
                            "payload": f"[SKIPPED] {attack_name}",
                            "status": "skipped",
                            "outcome": "SURFACE_MISMATCH",
                            "response": skip_reason,
                        })
                    return {
                        "attack_name": attack_name,
                        "mode": mode,
                        "severity": attack_config.get("severity", ""),
                        "status": "skipped",
                        "reason": skip_reason,
                        "payloads_tested": 0,
                        "success_count": 0,
                        "failure_count": 0,
                        "results": [],
                        "best_combinations": [],
                    }

        if mode == "smart_match":
            return self._execute_smart_match_v3(
                attack_config, target, scorers, tracker,
                profile_params=profile_params,
                objective=objective,
                placeholders=placeholders,
            )
        elif mode == "presets":
            return self._execute_presets_v3(
                attack_config, target, scorers, tracker,
                objective=objective,
                placeholders=placeholders,
            )
        else:
            return self._execute_chain_v3(
                attack_config, target, converters, scorers, tracker,
                objective=objective,
                placeholders=placeholders,
            )

    def _execute_chain_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        converters: Optional[List[PromptConverter]],
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """chain 模式 v3.4：使用 SmartMatcher 策略选择 + 逐载荷转换器 + ASR 排序"""
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        asi_category = attack_config.get("asi_category", "")
        owasp_id = attack_config.get("owasp_id", attack_config.get("id", ""))

        # REV-2: ASR-aware 载荷排序 (GAP-2)
        # 高 ASR 载荷优先执行，早停时低 ASR 载荷被跳过
        target_model = attack_config.get("target_model", "")
        if target_model and len(payloads) > 1:
            from ..payloads.asr_ranker import ASRRanker
            payloads = ASRRanker.rank_payloads(payloads, target_model)
            logger.info("REV-2 Ranker: %d payloads sorted by ASR for '%s'",
                        len(payloads), target_model)

        # REV-3: 模型特定载荷选择 (GAP-6)
        # 基于目标模型家族过滤不兼容载荷，选择最优变体
        if target_model and len(payloads) > 1:
            from ..payloads.model_specific_selector import ModelSpecificSelector
            original_count = len(payloads)
            payloads = ModelSpecificSelector.select_payloads(payloads, target_model)
            if len(payloads) < original_count:
                logger.info("REV-3 Selector: %d/%d payloads selected for '%s'",
                            len(payloads), original_count, target_model)

        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        logger.info(
            "Executing attack (chain v3.3): %s with %d payloads (concurrency=%d)",
            attack_name, len(payloads), concurrency,
        )

        results = {
            "attack_name": attack_name,
            "mode": "chain",
            "severity": attack_config.get("severity", ""),
            "payloads_tested": len(payloads),
            "results": [],
            "success_count": 0,
            "failure_count": 0,
            "best_combinations": [],
        }

        # v3.3: chain 模式也使用 SmartMatcher 进行策略选择
        from ..orchestrators.smart_matcher import SmartMatcher
        has_adversarial = self._check_adversarial_available()
        matcher = SmartMatcher(
            target_model=attack_config.get("target_model", ""),
            has_adversarial=has_adversarial,
        )
        converter_presets = attack_config.get("converter_presets", {})
        plan = matcher.build_attack_plan(
            payloads, converter_presets,
            asi_category=asi_category,
            owasp_id=owasp_id,
        )

        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        if tracker and scorers:
            scorer_type = type(scorers[0]).__name__ if scorers else ""
            tracker.log_scorer_selection(
                asi_category=asi_category,
                scorer_type=scorer_type,
                reason=f"ASI {asi_category} 自动选择评分器",
            )

        # v3.3+: 全链路追踪（chain 模式补全 payload 级别追踪）
        if tracker:
            for idx, item in enumerate(plan):
                payload_text = _extract_payload_text(item["payload"], objective=objective, placeholders=placeholders)
                tracker.start_payload(payload_text)
                tracker.log_load(payload_text, source=attack_name)
                profile_dict = item.get("payload_profile", {})
                if profile_dict:
                    from ..payloads.models import PayloadProfile
                    profile = PayloadProfile.from_dict(profile_dict)
                    tracker.log_classify(profile)
                selected_converters = item.get("selected_converters", [])
                if selected_converters:
                    tracker.log_converter_selection(
                        payload_idx=idx,
                        language=profile_dict.get("language", "en"),
                        technique=profile_dict.get("technique", "direct"),
                        owasp_id=owasp_id,
                        candidates_count=len(selected_converters),
                        selected_converters=selected_converters,
                    )
                strategy = {
                    "class": item.get("attack_class", ""),
                    "family": item.get("attack_family", ""),
                    "reason": item.get("attack_reason", ""),
                    "confidence": item.get("attack_confidence", 1.0),
                    "params": item.get("attack_params", {}),
                    "fallback_chain": item.get("attack_fallback_chain", []),
                }
                tracker.log_strategy(strategy)
                fallback_chain = item.get("attack_fallback_chain", [])
                if fallback_chain:
                    tracker.log_fallback_enrich(
                        payload_idx=idx,
                        fallback_count=len(fallback_chain),
                        converter_combos=len(selected_converters),
                    )

        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None

            async def _execute_one(item: Dict[str, Any]) -> Dict[str, Any]:
                payload = _extract_payload_text(item["payload"], objective=objective, placeholders=placeholders)
                if semaphore:
                    await semaphore.acquire()
                try:
                    logger.info("  Running: %.80s", payload)
                    attempt_result = await self._execute_with_fallback_async(
                        payload=payload,
                        primary_class_fqn=item["attack_class"],
                        primary_params=item["attack_params"],
                        fallback_chain=item.get("attack_fallback_chain", []),
                        target=target,
                        attack_scoring_config=attack_scoring_config,
                        converter_presets=converter_presets,
                        selected_converters=item.get("selected_converters"),
                    )

                    is_success = attempt_result["status"] == "success"
                    payload_short = payload[:60]
                    logger.info(
                        "  [%s] %s → %s (%.100s)",
                        "✓ PASS" if is_success else "✗ BLOCK",
                        payload_short,
                        attempt_result["outcome"],
                        attempt_result["response"],
                    )

                    return {
                        "payload": payload[:100],
                        "payload_category": item["payload_category"],
                        "attack_class": attempt_result["attack_class"],
                        "attack_family": item.get("attack_family", ""),
                        "attack_reason": item.get("attack_reason", ""),
                        "attack_confidence": item.get("attack_confidence", 1.0),
                        "status": attempt_result["status"],
                        "outcome": attempt_result["outcome"],
                        "response": attempt_result["response"],
                        "is_success": is_success,
                    }
                except Exception as e:
                    logger.error("Attack failed for payload '%s': %s", _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:50], str(e))
                    return {
                        "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                        "status": "error",
                        "error": str(e)[:200],
                        "is_success": False,
                    }
                finally:
                    if semaphore:
                        semaphore.release()

            tasks = [_execute_one(item) for item in plan]
            return await asyncio.gather(*tasks)

        all_results = run_async(_run_all())

        for r in all_results:
            is_success = r.pop("is_success", False)
            results["results"].append(r)
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

            if tracker:
                tracker.log_execution(r)

            if tracker and scorers and r.get("response"):
                score_label = "bypass" if is_success else "blocked"
                tracker.log_scoring_result(
                    scorer_name=type(scorers[0]).__name__,
                    score_value="1.0" if is_success else "0.0",
                    score_label=score_label,
                    reason=f"Attack {'succeeded' if is_success else 'failed'} → {score_label}",
                    response_snippet=r.get("response", ""),
                )

        logger.info(
            "  Summary: %d/%d passed (%.0f%%)",
            results["success_count"],
            len(all_results),
            (results["success_count"] / len(all_results) * 100) if all_results else 0,
        )

        # P0-C: 计算高成功率组合
        results["best_combinations"] = self._compute_best_combinations(all_results)

        if tracker and results["best_combinations"]:
            tracker.log_best_combinations(results["best_combinations"])

        if tracker:
            tracker.show_full_report()

        self._results.append(results)
        return results

    def _execute_presets_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """presets 模式 v3.0：使用 SequentialAttack (FIRST_SUCCESS)"""
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        asi_category = attack_config.get("asi_category", "")

        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        logger.info(
            "Executing attack (presets v3.0): %s with %d payloads, %d presets (concurrency=%d)",
            attack_name, len(payloads), len(converter_presets), concurrency,
        )

        results = {
            "attack_name": attack_name,
            "mode": "presets",
            "severity": attack_config.get("severity", ""),
            "payloads_tested": len(payloads) * len(converter_presets),
            "results": [],
            "success_count": 0,
            "failure_count": 0,
            "preset_stats": {},
        }

        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        if tracker and scorers:
            scorer_type = type(scorers[0]).__name__ if scorers else ""
            tracker.log_scorer_selection(
                asi_category=asi_category,
                scorer_type=scorer_type,
                reason=f"ASI {asi_category} 自动选择评分器",
            )

        preset_names = list(converter_presets.keys())

        # P1-D: 如果有 TargetProfile，按 pass_rate 降序排列 preset
        target_profile = getattr(self, "_target_profile", None)
        if target_profile and target_profile.is_built:
            def _preset_pass_rate(name):
                converters = converter_presets.get(name, [])
                if not converters:
                    return 0.0
                rates = [target_profile.converter_pass_rates.get(c, 0.0) for c in converters]
                return sum(rates) / len(rates) if rates else 0.0

            preset_names.sort(key=_preset_pass_rate, reverse=True)
            logger.info("Presets sorted by target profile pass rate: %s", preset_names)

        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None

            async def _execute_one(payload: str) -> Dict[str, Any]:
                if semaphore:
                    await semaphore.acquire()
                try:
                    payload_text = _extract_payload_text(payload, objective=objective, placeholders=placeholders)
                    logger.info("  Running: %.80s", payload_text)
                    if len(preset_names) == 1:
                        preset_name = preset_names[0]
                        converter_names = converter_presets[preset_name]
                        preset_converters = self.build_converters(
                            [{"name": c} for c in converter_names],
                            converter_target=target,
                        )
                        attack_converter_config = AttackConverterConfig(request_converters=preset_converters)

                        attack = PromptSendingAttack(
                            objective_target=target,
                            attack_converter_config=attack_converter_config,
                            attack_scoring_config=attack_scoring_config,
                            max_attempts_on_failure=1,
                        )
                        attack_result = await attack.execute_async(objective=payload_text)
                        is_success = attack_result.outcome.name == "SUCCESS"

                        payload_short = payload_text[:60]
                        logger.info(
                            "  [%s] %s → preset=%s, %s (%.100s)",
                            "✓ PASS" if is_success else "✗ BLOCK",
                            payload_short,
                            preset_name,
                            attack_result.outcome.name,
                            str(attack_result)[:200],
                        )

                        return {
                            "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                            "preset": preset_name,
                            "status": "success" if is_success else "failed",
                            "outcome": attack_result.outcome.name,
                            "response": str(attack_result)[:200],
                            "is_success": is_success,
                        }
                    else:
                        from pyrit.executor.attack.compound.sequential_attack import (
                            SequentialAttack,
                            SequentialChildAttack,
                            SequenceCompletionPolicy,
                        )
                        from pyrit.models import SeedPrompt, SeedPromptGroup

                        child_attacks = []
                        for p_name in preset_names:
                            converter_names = converter_presets[p_name]
                            preset_converters = self.build_converters(
                                [{"name": c} for c in converter_names],
                                converter_target=target,
                            )

                            child_attack = PromptSendingAttack(
                                objective_target=target,
                                attack_converter_config=AttackConverterConfig(request_converters=preset_converters),
                                attack_scoring_config=attack_scoring_config,
                                max_attempts_on_failure=1,
                            )
                            child_attacks.append(
                                SequentialChildAttack(
                                    strategy=child_attack,
                                    seed_group=SeedPromptGroup(
                                        prompts=[SeedPrompt(value=_extract_payload_text(payload, objective=objective, placeholders=placeholders), data_type="text")]
                                    ),
                                )
                            )

                        sequential = SequentialAttack(
                            objective_target=target,
                            child_attacks=child_attacks,
                            completion_policy=SequenceCompletionPolicy.FIRST_SUCCESS,
                        )

                        seq_result = await sequential.execute_async(objective=payload_text)
                        is_success = seq_result.outcome.name == "SUCCESS"

                        successful_preset = "unknown"
                        for i, child_result in enumerate(seq_result.child_results):
                            if child_result and child_result.outcome.name == "SUCCESS":
                                successful_preset = preset_names[i] if i < len(preset_names) else "unknown"
                                break

                        payload_short = payload_text[:60]
                        logger.info(
                            "  [%s] %s → preset=%s, %s (%.100s)",
                            "✓ PASS" if is_success else "✗ BLOCK",
                            payload_short,
                            successful_preset if is_success else "all_failed",
                            seq_result.outcome.name,
                            str(seq_result)[:200],
                        )

                        return {
                            "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                            "preset": successful_preset if is_success else "all_failed",
                            "status": "success" if is_success else "failed",
                            "outcome": seq_result.outcome.name,
                            "response": str(seq_result)[:200],
                            "is_success": is_success,
                        }
                except Exception as e:
                    logger.error("Attack failed for payload '%s': %s", _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:50], str(e))
                    return {
                        "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                        "preset": "error",
                        "status": "error",
                        "error": str(e)[:200],
                        "is_success": False,
                    }
                finally:
                    if semaphore:
                        semaphore.release()

            tasks = [_execute_one(p) for p in payloads]
            return await asyncio.gather(*tasks)

        all_results = run_async(_run_all())

        for r in all_results:
            is_success = r.pop("is_success", False)
            results["results"].append(r)
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

        logger.info(
            "  Summary: %d/%d passed (%.0f%%)",
            results["success_count"],
            len(all_results),
            (results["success_count"] / len(all_results) * 100) if all_results else 0,
        )

        self._results.append(results)
        return results

    @staticmethod
    async def _probe_target_model(target: PromptTarget) -> str:
        """运行时模型探测：发送自识别 prompt 获取目标模型名称"""
        probe_prompt = (
            "What is your model name? Respond with just the model name "
            "and nothing else (e.g., 'gpt-4o', 'claude-3-5-sonnet', 'qwen3:0.6b')."
        )

        try:
            attack = PromptSendingAttack(
                objective_target=target,
                max_attempts_on_failure=0,
            )
            result = await attack.execute_async(objective=probe_prompt)

            if result.outcome.name != "SUCCESS":
                logger.debug("Model probe: attack outcome=%s", result.outcome.name)
                return ""

            response_text = str(result).strip()
            if not response_text:
                return ""

            first_line = response_text.split("\n")[0].strip()
            for prefix in ["I am ", "I'm ", "Model:", "model:", "My name is "]:
                if first_line.startswith(prefix):
                    first_line = first_line[len(prefix):].strip()

            from ..payloads.payload_classifier import MODEL_CONTEXT_WINDOWS
            first_line_lower = first_line.lower()
            for model_key in MODEL_CONTEXT_WINDOWS:
                if model_key != "default" and model_key in first_line_lower:
                    logger.info("Model probe: detected '%s' from response '%s'", model_key, first_line[:80])
                    return model_key

            logger.info("Model probe: unknown model '%s', using as-is", first_line[:80])
            return first_line[:100]

        except Exception as e:
            logger.debug("Model probe failed: %s", str(e))
            return ""

    def _execute_smart_match_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
        profile_params: Optional[Dict[str, Any]] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """smart_match 模式 v3.4：PyRIT 原生攻击 + 两层策略 + Fallback + ASR 排序"""
        from ..orchestrators.smart_matcher import SmartMatcher

        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        target_model = attack_config.get("target_model", "")
        asi_category = attack_config.get("asi_category", "")

        # REV-2: ASR-aware 载荷排序 (GAP-2)
        # 高 ASR 载荷优先执行，早停时低 ASR 载荷被跳过
        if target_model and len(payloads) > 1:
            from ..payloads.asr_ranker import ASRRanker
            payloads = ASRRanker.rank_payloads(payloads, target_model)
            logger.info("REV-2 Ranker: %d payloads sorted by ASR for '%s'",
                        len(payloads), target_model)

        if not target_model:
            logger.info("Target model unknown, probing...")
            target_model = run_async(self._probe_target_model(target))
            if target_model:
                logger.info("Model probe result: '%s'", target_model)
            else:
                logger.info("Model probe: could not detect model, using defaults")

        # REV-3: 模型特定载荷选择 (GAP-6)
        # 基于目标模型家族过滤不兼容载荷，选择最优变体
        if target_model and len(payloads) > 1:
            from ..payloads.model_specific_selector import ModelSpecificSelector
            original_count = len(payloads)
            payloads = ModelSpecificSelector.select_payloads(payloads, target_model)
            if len(payloads) < original_count:
                logger.info("REV-3 Selector: %d/%d payloads selected for '%s'",
                            len(payloads), original_count, target_model)

        logger.info(
            "Executing attack (smart_match v3.0): %s with %d payloads, target=%s",
            attack_name, len(payloads), target_model or "unknown",
        )

        has_adversarial = self._check_adversarial_available()

        preferred_families = None
        aggression_level = "medium"
        if profile_params:
            preferred_families = profile_params.get("preferred_probe_families")
            aggression_level = profile_params.get("aggression_level", "medium")
            profile_model = profile_params.get("target_model")
            if profile_model:
                target_model = profile_model

        matcher = SmartMatcher(
            target_model=target_model,
            has_adversarial=has_adversarial,
            preferred_probe_families=preferred_families,
            aggression_level=aggression_level,
        )
        owasp_id = attack_config.get("owasp_id", attack_config.get("id", ""))
        plan = matcher.build_attack_plan(
            payloads, converter_presets, asi_category=asi_category,
            owasp_id=owasp_id,
        )
        plan_summary = matcher.get_plan_summary(plan)

        logger.info("Attack plan (v3.0): %s", plan_summary)

        if tracker:
            for idx, item in enumerate(plan):
                tracker.start_payload(_extract_payload_text(item["payload"], objective=objective, placeholders=placeholders))
                tracker.log_load(_extract_payload_text(item["payload"], objective=objective, placeholders=placeholders), source=attack_name)
                profile_dict = item.get("payload_profile", {})
                if profile_dict:
                    from ..payloads.models import PayloadProfile
                    profile = PayloadProfile.from_dict(profile_dict)
                    tracker.log_classify(profile)
                selected_converters = item.get("selected_converters", [])
                if selected_converters:
                    tracker.log_converter_selection(
                        payload_idx=idx,
                        language=profile_dict.get("language", "en"),
                        technique=profile_dict.get("technique", "direct"),
                        owasp_id=owasp_id,
                        candidates_count=len(selected_converters),
                        selected_converters=selected_converters,
                    )
                strategy = {
                    "class": item.get("attack_class", ""),
                    "family": item.get("attack_family", ""),
                    "reason": item.get("attack_reason", ""),
                    "confidence": item.get("attack_confidence", 1.0),
                    "params": item.get("attack_params", {}),
                    "fallback_chain": item.get("attack_fallback_chain", []),
                }
                tracker.log_strategy(strategy)
                fallback_chain = item.get("attack_fallback_chain", [])
                if fallback_chain:
                    tracker.log_fallback_enrich(
                        payload_idx=idx,
                        fallback_count=len(fallback_chain),
                        converter_combos=len(selected_converters),
                    )

        if tracker and scorers:
            scorer_type = type(scorers[0]).__name__ if scorers else ""
            tracker.log_scorer_selection(
                asi_category=asi_category,
                scorer_type=scorer_type,
                reason=f"ASI {asi_category} 自动选择评分器",
            )

        results = {
            "attack_name": attack_name,
            "mode": "smart_match",
            "severity": attack_config.get("severity", ""),
            "total_executions": len(plan),
            "plan_summary": plan_summary,
            "plan": plan,
            "results": [],
            "success_count": 0,
            "failure_count": 0,
            "category_stats": {},
            "best_combinations": [],
        }

        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        logger.info("Smart match concurrency: %d", concurrency)

        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None
            early_stop_triggered = False
            consecutive_failures = 0
            max_consecutive_failures = 5

            async def _execute_one(item: Dict[str, Any]) -> Dict[str, Any]:
                nonlocal early_stop_triggered, consecutive_failures
                payload = _extract_payload_text(item["payload"], objective=objective, placeholders=placeholders)
                if early_stop_triggered:
                    return {
                        "payload": payload[:100],
                        "payload_category": item["payload_category"],
                        "attack_class": item["attack_class"],
                        "attack_family": item.get("attack_family", ""),
                        "attack_reason": item.get("attack_reason", ""),
                        "attack_confidence": item.get("attack_confidence", 1.0),
                        "status": "skipped",
                        "outcome": "SKIPPED",
                        "response": "Early stop: consecutive failures",
                        "attempts_used": 0,
                    }
                if semaphore:
                    await semaphore.acquire()
                try:
                    logger.info("  Running: %.80s", payload)
                    attempt_result = await self._execute_with_fallback_async(
                        payload=payload,
                        primary_class_fqn=item["attack_class"],
                        primary_params=item["attack_params"],
                        fallback_chain=item.get("attack_fallback_chain", []),
                        target=target,
                        attack_scoring_config=attack_scoring_config,
                        converter_presets=converter_presets,
                        selected_converters=item.get("selected_converters"),
                    )

                    is_success = attempt_result["status"] == "success"
                    payload_short = _extract_payload_text(payload)[:60]
                    attack_class_short = attempt_result["attack_class"].split(".")[-1]
                    logger.info(
                        "  [%s] %s → %s (attempts=%d, %.100s)",
                        "✓ PASS" if is_success else "✗ BLOCK",
                        payload_short,
                        attack_class_short,
                        attempt_result.get("attempts_used", 1),
                        attempt_result["response"],
                    )

                    is_success = attempt_result["status"] == "success"
                    if is_success:
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                        if consecutive_failures >= max_consecutive_failures:
                            early_stop_triggered = True
                            remaining = len(plan) - (plan.index(item) + 1)
                            logger.warning(
                                "Early stop triggered: %d consecutive failures, skipping %d payloads",
                                consecutive_failures,
                                remaining,
                            )
                            if tracker:
                                tracker.log_early_stop(
                                    consecutive_failures=consecutive_failures,
                                    skipped_count=remaining,
                                    threshold=max_consecutive_failures,
                                )

                    return {
                        "payload": _extract_payload_text(payload)[:100],
                        "payload_category": item["payload_category"],
                        "attack_class": attempt_result["attack_class"],
                        "attack_family": item.get("attack_family", ""),
                        "attack_reason": item.get("attack_reason", ""),
                        "attack_confidence": item.get("attack_confidence", 1.0),
                        "status": attempt_result["status"],
                        "outcome": attempt_result["outcome"],
                        "response": attempt_result["response"],
                        "attempts_used": attempt_result.get("attempts_used", 1),
                    }
                finally:
                    if semaphore:
                        semaphore.release()

            tasks = [_execute_one(item) for item in plan]
            return await asyncio.gather(*tasks)

        all_results = run_async(_run_all())

        for r in all_results:
            results["results"].append(r)
            is_success = r["status"] == "success"
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

            category = r.get("payload_category", "unknown")
            if category not in results["category_stats"]:
                results["category_stats"][category] = {"success": 0, "failure": 0}
            results["category_stats"][category]["success" if is_success else "failure"] += 1

            if tracker:
                tracker.log_execution(r)
                if scorers and r.get("response"):
                    score_label = "bypass" if is_success else "blocked"
                    tracker.log_scoring_result(
                        scorer_name=type(scorers[0]).__name__ if scorers else "none",
                        score_value="1.0" if is_success else "0.0",
                        score_label=score_label,
                        reason=f"Attack {'succeeded' if is_success else 'failed'} → {score_label}",
                        response_snippet=r.get("response", ""),
                    )

        logger.info(
            "  Summary: %d/%d passed (%.0f%%)",
            results["success_count"],
            len(all_results),
            (results["success_count"] / len(all_results) * 100) if all_results else 0,
        )

        # P0-C: 计算高成功率组合
        results["best_combinations"] = self._compute_best_combinations(all_results)

        if tracker:
            if results["best_combinations"]:
                tracker.log_best_combinations(results["best_combinations"])
            tracker.show_full_report()

        self._results.append(results)
        return results

    def _compute_best_combinations(self, all_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """P0-C: 从执行结果中提取高成功率组合

        分析 payload_category x attack_family x attack_class 的成功率，
        返回 Top-10 组合，供 FeedbackAnalyzer 使用。
        """
        combo_stats: Dict[str, Dict[str, Any]] = {}

        for r in all_results:
            category = r.get("payload_category", "unknown")
            attack_class = r.get("attack_class", "PromptSendingAttack")
            attack_family = r.get("attack_family", "unknown")

            combo_key = f"{category}|{attack_family}|{attack_class}"

            if combo_key not in combo_stats:
                combo_stats[combo_key] = {
                    "category": category,
                    "attack_family": attack_family,
                    "attack_class": attack_class,
                    "success": 0,
                    "failure": 0,
                    "total": 0,
                    "rate": 0.0,
                }

            is_success = r.get("status") == "success"
            if is_success:
                combo_stats[combo_key]["success"] += 1
            else:
                combo_stats[combo_key]["failure"] += 1
            combo_stats[combo_key]["total"] += 1
            combo_stats[combo_key]["rate"] = (
                combo_stats[combo_key]["success"] / combo_stats[combo_key]["total"]
            )

        best = sorted(combo_stats.values(), key=lambda x: x["rate"], reverse=True)
        return best[:10]

    async def _execute_single_attack_async(
        self,
        payload: str,
        attack_class_fqn: str,
        attack_params: Dict[str, Any],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
        selected_converters: Optional[List[str]] = None,
        converter_override: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """执行单次 PyRIT 攻击（异步版本 v3.3）

        v3.3: 支持逐载荷转换器选择 (selected_converters)
              支持 fallback 中的转换器覆盖 (converter_override)
        """
        try:
            attack_class = _import_class(attack_class_fqn)

            common_kwargs = {
                "objective_target": target,
                "attack_scoring_config": attack_scoring_config,
            }

            if attack_class_fqn.endswith("CrescendoAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for Crescendo, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("TreeOfAttacksWithPruningAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for TAP, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("PAIRAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for PAIR, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("RedTeamingAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for RedTeaming, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("PromptSendingAttack"):
                # v3.3: 优先使用逐载荷选择的转换器，其次 fallback 的 converter_override
                if selected_converters:
                    converter_names = selected_converters
                elif converter_override:
                    converter_names = converter_override
                else:
                    converter_names = list(converter_presets.values())[0] if converter_presets else []
                preset_converters = self.build_converters(
                    [{"name": c} for c in converter_names],
                    converter_target=target,
                )
                common_kwargs["attack_converter_config"] = AttackConverterConfig(request_converters=preset_converters)

            common_kwargs.update(attack_params)

            attack = attack_class(**common_kwargs)
            attack_result = await attack.execute_async(objective=_extract_payload_text(payload))

            outcome = attack_result.outcome
            is_success = outcome.name == "SUCCESS"

            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "success" if is_success else "failed",
                "outcome": outcome.name,
                "response": str(attack_result)[:200],
            }

        except Exception as e:
            logger.error(
                "Attack failed (class=%s): %s",
                attack_class_fqn.split(".")[-1], str(e),
            )
            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "error",
                "outcome": "ERROR",
                "response": str(e)[:200],
            }

    async def _execute_with_fallback_async(
        self,
        payload: str,
        primary_class_fqn: str,
        primary_params: Dict[str, Any],
        fallback_chain: List[Dict[str, Any]],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
        selected_converters: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """执行攻击（支持 Fallback 链，异步版本 v3.3）

        v3.3: 支持逐载荷转换器选择 + fallback 中的 converter_override
        """
        result = await self._execute_single_attack_async(
            payload=payload,
            attack_class_fqn=primary_class_fqn,
            attack_params=primary_params,
            target=target,
            attack_scoring_config=attack_scoring_config,
            converter_presets=converter_presets,
            selected_converters=selected_converters,
        )

        if result["status"] == "success":
            result["attempts_used"] = 1
            return result

        for fallback_idx, fallback in enumerate(fallback_chain, 2):
            logger.info(
                "Primary attack failed, trying fallback %d/%d: %s",
                fallback_idx - 1, len(fallback_chain),
                fallback["class"].split(".")[-1],
            )

            fallback_result = await self._execute_single_attack_async(
                payload=payload,
                attack_class_fqn=fallback["class"],
                attack_params=fallback.get("params", {}),
                target=target,
                attack_scoring_config=attack_scoring_config,
                converter_presets=converter_presets,
                converter_override=fallback.get("converter_override"),
            )

            if fallback_result["status"] == "success":
                fallback_result["attempts_used"] = fallback_idx
                return fallback_result

        result["attempts_used"] = 1 + len(fallback_chain)
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # 静态工具方法
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def load_yaml(path: str) -> Dict[str, Any]:
        """加载 YAML 文件（支持多文档分隔符 ---）"""
        from pathlib import Path
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Config file not found: %s", path)
            return {}
        with open(file_path, "r", encoding="utf-8") as f:
            import yaml
            docs = list(yaml.safe_load_all(f))
            return docs[0] if docs else {}

    @classmethod
    def build_attack_list_from_refs(
        cls,
        refs: List[str],
        payload_mgr: "PayloadManager",
        target_model: str = "",
        surfaces: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """从 OWASP ref 列表构建攻击列表

        REV-1 集成：当 surfaces 参数提供时，自动过滤不相关的 OWASP 类别。
        例如：surfaces=["prompt"] 时跳过 LLM04(RAG)/LLM08(Vector)/ASI01-10(Agent)。
        """
        from .encoding_selector import get_converter_candidates

        registered = set(CONVERTER_MAP.keys())

        # REV-1: 初始化载荷过滤器
        from ..payloads.payload_filter import PayloadFilter
        _pf = PayloadFilter()
        skipped_by_filter = []

        attacks = []
        for ref in refs:
            data = payload_mgr.get_payload_file(ref)
            if not data:
                continue

            owasp_id = data.get("id", ref.split(":")[-1]).lower()
            owasp_id_upper = data.get("id", ref.split(":")[-1]).upper()

            # REV-1: 攻击面过滤
            if surfaces and _pf.should_skip_attack(owasp_id_upper, surfaces):
                skipped_by_filter.append(f"{owasp_id_upper}({data.get('name', ref)})")
                continue

            smart_converters = get_converter_candidates(
                owasp_id=owasp_id_upper,
                language="en",
                registered_converters=registered,
            )

            converters = smart_converters if smart_converters else ["base64"]

            scorers = cls._DEFAULT_SCORERS.get(owasp_id, ["refusal"])

            scorer_configs = []
            for sname in scorers:
                if sname == "substring":
                    scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                else:
                    scorer_configs.append({"name": sname})

            attacks.append({
                "name": data.get("name", ref),
                "description": data.get("description", ""),
                "mode": "smart_match",
                "severity": data.get("severity", "medium"),
                "payloads": data.get("payloads", []),
                "converter_presets": {"default": converters},
                "scorers": scorer_configs,
                "asi_category": data.get("id", ""),
                "target_model": target_model,
            })

        if skipped_by_filter:
            logger.info(
                "REV-1 build_attack_list: %d/%d refs retained, skipped %d (%s)",
                len(attacks), len(refs), len(skipped_by_filter),
                ", ".join(skipped_by_filter[:5]),
            )

        return attacks
