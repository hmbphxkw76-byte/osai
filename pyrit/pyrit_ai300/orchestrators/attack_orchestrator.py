# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Orchestrator v3.0
攻击编排器：使用 PyRIT 原生攻击策略执行

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
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# PyRIT 0.14.0 核心组件导入
from pyrit.memory import CentralMemory, SQLiteMemory
from pyrit.executor.attack import (
    PromptSendingAttack,
    AttackConverterConfig,
    AttackScoringConfig,
    AttackAdversarialConfig,
)
from pyrit.prompt_converter import (
    PromptConverter,
    Base64Converter,
    ROT13Converter,
    UnicodeConfusableConverter,
    LeetspeakConverter,
    MaliciousQuestionGeneratorConverter,
    AddTextImageConverter,
    PDFConverter,
    WordDocConverter,
    PersuasionConverter,
    SearchReplaceConverter,
    TextJailbreakConverter,
    AsciiSmugglerConverter,
    ZeroWidthConverter,
    DiacriticConverter,
    TranslationConverter,
    VariationConverter,
)
from pyrit.prompt_target import (
    PromptTarget,
    OpenAIChatTarget,
)
from pyrit.score import (
    Scorer,
    SelfAskRefusalScorer,
    SelfAskTrueFalseScorer,
    SubStringScorer,
    SelfAskCategoryScorer,
    PromptShieldScorer,
    InsecureCodeScorer,
    ShellCommandOutputScorer,
    SQLInjectionOutputScorer,
    XSSOutputScorer,
    PathTraversalOutputScorer,
    GandalfScorer,
    CredentialLeakScorer,
    AzureContentFilterScorer,
    StaticPromptInjectionScorer,
)

logger = logging.getLogger(__name__)


# PyRIT 组件映射表 - 配置名称到实际类的映射
# 对齐 OffSec AI-300 考试技术：编码混淆 + Token走私 + 视觉欺骗 + 越狱模板 + 多模态
CONVERTER_MAP: Dict[str, type] = {
    # 编码混淆（ASI01 基础编码技术）
    "base64": Base64Converter,
    "rot13": ROT13Converter,
    "unicode_confusable": UnicodeConfusableConverter,
    "leetspeak": LeetspeakConverter,
    # 越狱模板（ASI01/ASI06 高级越狱）
    "persuasion": PersuasionConverter,
    "text_jailbreak": TextJailbreakConverter,
    "malicious_question_generator": MaliciousQuestionGeneratorConverter,
    # Token 走私（ASI01/ASI05 绕过过滤）
    "ascii_smuggler": AsciiSmugglerConverter,
    "zero_width": ZeroWidthConverter,
    "diacritic": DiacriticConverter,
    # 搜索替换（ASI02 工具参数操纵）
    "search_replace": SearchReplaceConverter,
    # 翻译混淆（ASI01/ASI09 多语言绕过）
    "translation": TranslationConverter,
    # 变异生成（通用变异测试）
    "variation": VariationConverter,
    # 多模态注入（ASI02/RAG 文档载荷）
    "add_text_image": AddTextImageConverter,
    "pdf": PDFConverter,
    "word_doc": WordDocConverter,
}

# 特殊 preset 处理（不映射到单一 converter，需要特殊逻辑）
SPECIAL_PRESETS = {"identity", "context_wrap", "chunked_delivery"}

SCORER_MAP: Dict[str, type] = {
    # SelfAsk 系列（需要 LLM 后端）
    "refusal": SelfAskRefusalScorer,
    "true_false": SelfAskTrueFalseScorer,
    "category": SelfAskCategoryScorer,
    # 规则匹配系列（无需 LLM）
    "substring": SubStringScorer,
    "prompt_shield": PromptShieldScorer,
    "insecure_code": InsecureCodeScorer,
    "shell_command": ShellCommandOutputScorer,
    "sql_injection": SQLInjectionOutputScorer,
    "xss": XSSOutputScorer,
    "path_traversal": PathTraversalOutputScorer,
    "credential_leak": CredentialLeakScorer,
    "static_prompt_injection": StaticPromptInjectionScorer,
    # Float Scale 系列
    "gandalf": GandalfScorer,
    "azure_content_filter": AzureContentFilterScorer,
}

# 需要 LLM 后端的评分器类型（SelfAsk 系列）
LLM_BACKEND_SCORERS = {"refusal", "true_false", "category"}

# 规则匹配评分器（无需 LLM，纯 regex/关键词）
RULE_BASED_SCORERS = {
    "substring", "prompt_shield", "insecure_code", "shell_command",
    "sql_injection", "xss", "path_traversal", "credential_leak",
    "static_prompt_injection", "gandalf", "azure_content_filter",
}

# 非 LLM 评分器类型（规则匹配系列）
RULE_BASED_SCORERS = {"substring"}


def _import_class(fqn: str) -> type:
    """从全限定名导入类"""
    module_path, class_name = fqn.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


class AttackOrchestrator:
    """
    攻击编排器 v3.0

    功能：
    1. 从配置加载攻击策略
    2. 自动组合 PyRIT 转换器链
    3. 使用 PyRIT 原生攻击执行（不再手动循环）
    4. 自动评分和结果存储
    5. 支持外部 LLM 评分器后端（config/scorers.yaml）

    核心改进：
    - SmartMatcher 选择 PyRIT 攻击策略
    - 执行全部交给 PyRIT 原生攻击
    - 继承 PyRIT 的全部能力（重试、升级、回退、剪枝、早停）
    """

    # 评分器配置文件路径
    SCORER_CONFIG_PATH = "config/scorers.yaml"

    # 数据目录路径（payload_refs 解析用）
    DATA_DIR = "data"

    # 类级别 PayloadManager 实例（共享缓存）
    _payload_manager: Optional[Any] = None

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_dict: Optional[Dict[str, Any]] = None,
        memory_type: str = "in_memory",
        scorer_config_path: Optional[str] = None,
        data_dir: Optional[str] = None,
    ):
        self.config = self._load_config(config_path, config_dict)
        self.memory_type = memory_type
        self._components_initialized = False
        self._results: List[Dict[str, Any]] = []
        self._scorer_config: Dict[str, Any] = {}
        self._scorer_config_path = scorer_config_path or self.SCORER_CONFIG_PATH
        self._data_dir = data_dir or self.DATA_DIR

        # 初始化 PayloadManager
        self._init_payload_manager()
        # 初始化 PyRIT 内存
        self._initialize_pyrit()
        # 加载评分器配置
        self._load_scorer_config()

    def _init_payload_manager(self) -> None:
        """初始化 PayloadManager（类级别单例）"""
        if AttackOrchestrator._payload_manager is None:
            from ..payloads.payload_manager import PayloadManager
            AttackOrchestrator._payload_manager = PayloadManager()
            AttackOrchestrator._payload_manager.load_data_dir(self._data_dir)
        self._payload_mgr = AttackOrchestrator._payload_manager

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

    def _load_scorer_config(self) -> None:
        """加载评分器配置文件（config/scorers.yaml）"""
        path = Path(self._scorer_config_path)
        if not path.exists():
            logger.warning("Scorer config not found: %s, using defaults", self._scorer_config_path)
            self._scorer_config = {"scorer_llm_backends": {}, "scorer_definitions": {}}
            return
        with open(path, "r", encoding="utf-8") as f:
            self._scorer_config = yaml.safe_load(f) or {}
        logger.info(
            "Scorer config loaded: %d backends, %d definitions",
            len(self._scorer_config.get("scorer_llm_backends", {})),
            len(self._scorer_config.get("scorer_definitions", {})),
        )

    def _build_scorer_llm_target(self, backend_name: str) -> Optional[PromptTarget]:
        """根据后端名称创建 LLM 评分器目标"""
        backends = self._scorer_config.get("scorer_llm_backends", {})
        backend = backends.get(backend_name)
        if not backend:
            logger.warning("Scorer LLM backend '%s' not found", backend_name)
            return None

        api_key = backend.get("api_key", "not-needed")
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, "")
            if not api_key:
                logger.warning("Environment variable %s not set for backend '%s'", env_var, backend_name)

        base_url = backend.get("base_url", "http://localhost:11434/v1")
        model_name = backend.get("model_name", "qwen3:0.6b")

        return OpenAIChatTarget(
            endpoint=base_url,
            api_key=api_key,
            model_name=model_name,
        )

    def _initialize_pyrit(self):
        """初始化 PyRIT 0.14.0 内存"""
        if self.memory_type == "in_memory":
            memory = SQLiteMemory(db_path=":memory:")
        else:
            memory = SQLiteMemory()
        CentralMemory.set_memory_instance(memory)
        self._components_initialized = True
        logger.info("PyRIT 0.14.0 initialized with %s memory", self.memory_type)

    def build_target(self, target_config: Dict[str, Any]) -> PromptTarget:
        """根据配置构建 PyRIT PromptTarget"""
        target_type = target_config.get("type", "openai")
        connection = target_config.get("connection", {})

        if target_type in ("ollama", "openai"):
            return OpenAIChatTarget(
                endpoint=connection.get("endpoint", "http://localhost:11434/v1"),
                api_key=connection.get("api_key", "not-needed"),
                model_name=connection.get("model", "llama3.2:latest"),
            )
        elif target_type == "http":
            from pyrit.prompt_target.http_target.http_target import HTTPTarget
            http_request = connection.get("http_request")
            if not http_request:
                raise ValueError(
                    "HTTPTarget requires 'http_request' in connection config."
                )
            return HTTPTarget(
                http_request=http_request,
                prompt_regex_string=connection.get("prompt_regex_string", "{PROMPT}"),
                use_tls=connection.get("use_tls", True),
            )
        else:
            raise ValueError(f"Unsupported target type: {target_type}")

    def build_converters(
        self,
        converter_configs: List[Dict[str, Any]],
    ) -> List[PromptConverter]:
        """根据配置列表构建转换器链"""
        converters = []
        for config in converter_configs:
            name = config.get("name") if isinstance(config, dict) else config
            params = config.get("params", {}) if isinstance(config, dict) else {}

            if name in SPECIAL_PRESETS:
                logger.debug("Special preset '%s' - skipping converter creation", name)
                continue

            converter_class = CONVERTER_MAP.get(name)
            if converter_class:
                try:
                    converters.append(converter_class(**params))
                    logger.debug("Added converter: %s", name)
                except TypeError as e:
                    logger.warning("Converter %s requires params: %s", name, e)
            else:
                logger.warning("Unknown converter: %s", name)
        return converters

    def build_scorers(
        self,
        scorer_configs: List[Dict[str, Any]],
        objective_target: Optional[PromptTarget] = None,
    ) -> List[Scorer]:
        """根据配置列表构建评分器"""
        scorers = []
        for config in scorer_configs:
            if isinstance(config, str):
                config = {"name": config}
            name = config.get("name", "")
            backend_name = config.get("backend")
            definition_name = config.get("definition")
            params = config.get("params", {})

            if definition_name:
                definition = self._scorer_config.get("scorer_definitions", {}).get(definition_name)
                if definition:
                    name = definition.get("type", name)
                    backend_name = definition.get("backend", backend_name)
                    def_params = definition.get("params", {})
                    def_params.update(params)
                    params = def_params
                else:
                    logger.warning("Scorer definition '%s' not found", definition_name)
                    continue

            scorer_class = SCORER_MAP.get(name)
            if not scorer_class:
                logger.warning("Unknown scorer: %s", name)
                continue

            try:
                if name in LLM_BACKEND_SCORERS:
                    chat_target = None
                    if backend_name:
                        chat_target = self._build_scorer_llm_target(backend_name)
                    if chat_target is None and objective_target:
                        chat_target = objective_target
                    if chat_target:
                        params.setdefault("chat_target", chat_target)

                scorers.append(scorer_class(**params))
                logger.debug("Added scorer: %s (backend=%s)", name, backend_name or "objective_target")
            except TypeError as e:
                logger.warning("Scorer %s requires params: %s", name, e)

        return scorers

    def get_scorer_info(self, scorer_configs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """获取评分器展示信息"""
        info = []
        for config in scorer_configs:
            if isinstance(config, str):
                config = {"name": config}
            name = config.get("name", "")
            backend_name = config.get("backend")
            definition_name = config.get("definition")

            description = ""
            if definition_name:
                definition = self._scorer_config.get("scorer_definitions", {}).get(definition_name)
                if definition:
                    name = definition.get("type", name)
                    backend_name = definition.get("backend")
                    description = definition.get("description", "")

            backend_info = ""
            if backend_name:
                backends = self._scorer_config.get("scorer_llm_backends", {})
                backend = backends.get(backend_name, {})
                backend_info = f"{backend.get('model_name', '')} @ {backend.get('base_url', '')}"

            info.append({
                "name": name,
                "type": name,
                "backend": backend_name or "objective_target",
                "backend_info": backend_info,
                "description": description,
            })
        return info

    # ──────────────────────────────────────────────────────────────────────────
    # 执行接口：使用 PyRIT 原生攻击
    # ──────────────────────────────────────────────────────────────────────────

    def execute_attack(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        converters: Optional[List[PromptConverter]] = None,
        scorers: Optional[List[Scorer]] = None,
        visualizer: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        执行单次攻击（同步接口）

        根据 mode 选择执行策略：
        - smart_match: SmartMatcher 选择 PyRIT 原生攻击
        - presets: SequentialAttack (FIRST_SUCCESS) 或 PromptSendingAttack
        - chain: PromptSendingAttack (带重试)
        """
        mode = attack_config.get("mode", "chain")

        if mode == "smart_match":
            return self._execute_smart_match_v3(attack_config, target, scorers, visualizer)
        elif mode == "presets":
            return self._execute_presets_v3(attack_config, target, scorers)
        else:
            return self._execute_chain_v3(attack_config, target, converters, scorers)

    def _execute_chain_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        converters: Optional[List[PromptConverter]],
        scorers: Optional[List[Scorer]],
    ) -> Dict[str, Any]:
        """
        chain 模式 v3.0：使用 PromptSendingAttack 内置重试

        不再手动循环，而是利用 PyRIT 的 max_attempts_on_failure
        """
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])

        logger.info("Executing attack (chain v3.0): %s with %d payloads", attack_name, len(payloads))

        results = {
            "attack_name": attack_name,
            "mode": "chain",
            "payloads_tested": len(payloads),
            "results": [],
            "success_count": 0,
            "failure_count": 0,
        }

        # 构建 AttackConverterConfig
        attack_converter_config = AttackConverterConfig()
        if converters:
            attack_converter_config = AttackConverterConfig(request_converters=converters)

        # 构建 AttackScoringConfig
        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        for payload in payloads:
            try:
                # 使用 PromptSendingAttack + max_attempts_on_failure=2
                # PyRIT 内置重试逻辑，无需手动循环
                attack = PromptSendingAttack(
                    objective_target=target,
                    attack_converter_config=attack_converter_config,
                    attack_scoring_config=attack_scoring_config,
                    max_attempts_on_failure=2,  # PyRIT 内置重试
                )
                attack_result = asyncio.run(attack.execute_async(objective=payload))

                # 解析 PyRIT AttackResult
                outcome = attack_result.outcome
                is_success = outcome.name == "SUCCESS"

                results["results"].append({
                    "payload": payload[:100],
                    "status": "success" if is_success else "failed",
                    "outcome": outcome.name,
                    "response": str(attack_result)[:200],
                })
                if is_success:
                    results["success_count"] += 1
                else:
                    results["failure_count"] += 1

            except Exception as e:
                logger.error("Attack failed for payload '%s': %s", payload[:50], str(e))
                results["results"].append({
                    "payload": payload[:100],
                    "status": "error",
                    "error": str(e)[:200],
                })
                results["failure_count"] += 1

        self._results.append(results)
        return results

    def _execute_presets_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        scorers: Optional[List[Scorer]],
    ) -> Dict[str, Any]:
        """
        presets 模式 v3.0：使用 SequentialAttack (FIRST_SUCCESS)

        多 preset 时利用 PyRIT 的 SequentialAttack 实现早停：
        - 每个 preset 作为一个 child attack
        - 第一个成功后立即停止
        - 单 preset 时直接使用 PromptSendingAttack
        """
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})

        logger.info(
            "Executing attack (presets v3.0): %s with %d payloads, %d presets",
            attack_name, len(payloads), len(converter_presets),
        )

        results = {
            "attack_name": attack_name,
            "mode": "presets",
            "payloads_tested": len(payloads) * len(converter_presets),
            "results": [],
            "success_count": 0,
            "failure_count": 0,
            "preset_stats": {},
        }

        # 构建 AttackScoringConfig
        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        preset_names = list(converter_presets.keys())

        if len(preset_names) == 1:
            # 单 preset：直接使用 PromptSendingAttack
            preset_name = preset_names[0]
            converter_names = converter_presets[preset_name]
            preset_converters = self.build_converters([{"name": c} for c in converter_names])
            attack_converter_config = AttackConverterConfig(request_converters=preset_converters)

            for payload in payloads:
                try:
                    attack = PromptSendingAttack(
                        objective_target=target,
                        attack_converter_config=attack_converter_config,
                        attack_scoring_config=attack_scoring_config,
                        max_attempts_on_failure=1,
                    )
                    attack_result = asyncio.run(attack.execute_async(objective=payload))
                    is_success = attack_result.outcome.name == "SUCCESS"

                    results["results"].append({
                        "payload": payload[:100],
                        "preset": preset_name,
                        "status": "success" if is_success else "failed",
                        "outcome": attack_result.outcome.name,
                        "response": str(attack_result)[:200],
                    })
                    if is_success:
                        results["success_count"] += 1
                    else:
                        results["failure_count"] += 1
                except Exception as e:
                    results["results"].append({
                        "payload": payload[:100],
                        "preset": preset_name,
                        "status": "error",
                        "error": str(e)[:200],
                    })
                    results["failure_count"] += 1

        else:
            # 多 preset：使用 SequentialAttack (FIRST_SUCCESS)
            try:
                from pyrit.executor.attack.compound.sequential_attack import (
                    SequentialAttack,
                    SequentialChildAttack,
                    SequenceCompletionPolicy,
                )
                from pyrit.models import SeedPrompt, SeedPromptGroup

                for payload in payloads:
                    child_attacks = []
                    for preset_name in preset_names:
                        converter_names = converter_presets[preset_name]
                        preset_converters = self.build_converters([{"name": c} for c in converter_names])

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
                                    prompts=[SeedPrompt(value=payload, data_type="text")]
                                ),
                            )
                        )

                    sequential = SequentialAttack(
                        objective_target=target,
                        child_attacks=child_attacks,
                        completion_policy=SequenceCompletionPolicy.FIRST_SUCCESS,
                    )

                    seq_result = asyncio.run(sequential.execute_async(objective=payload))
                    is_success = seq_result.outcome.name == "SUCCESS"

                    # 确定哪个 preset 成功了
                    successful_preset = "unknown"
                    for i, child_result in enumerate(seq_result.child_results):
                        if child_result and child_result.outcome.name == "SUCCESS":
                            successful_preset = preset_names[i] if i < len(preset_names) else "unknown"
                            break

                    results["results"].append({
                        "payload": payload[:100],
                        "preset": successful_preset if is_success else "all_failed",
                        "status": "success" if is_success else "failed",
                        "outcome": seq_result.outcome.name,
                        "response": str(seq_result)[:200],
                    })
                    if is_success:
                        results["success_count"] += 1
                    else:
                        results["failure_count"] += 1

            except ImportError:
                # SequentialAttack 不可用，回退到逐个执行
                logger.warning("SequentialAttack not available, falling back to sequential execution")
                for preset_name in preset_names:
                    converter_names = converter_presets[preset_name]
                    preset_converters = self.build_converters([{"name": c} for c in converter_names])
                    attack_converter_config = AttackConverterConfig(request_converters=preset_converters)

                    for payload in payloads:
                        try:
                            attack = PromptSendingAttack(
                                objective_target=target,
                                attack_converter_config=attack_converter_config,
                                attack_scoring_config=attack_scoring_config,
                                max_attempts_on_failure=1,
                            )
                            attack_result = asyncio.run(attack.execute_async(objective=payload))
                            is_success = attack_result.outcome.name == "SUCCESS"

                            results["results"].append({
                                "payload": payload[:100],
                                "preset": preset_name,
                                "status": "success" if is_success else "failed",
                                "outcome": attack_result.outcome.name,
                                "response": str(attack_result)[:200],
                            })
                            if is_success:
                                results["success_count"] += 1
                            else:
                                results["failure_count"] += 1
                        except Exception as e:
                            results["results"].append({
                                "payload": payload[:100],
                                "preset": preset_name,
                                "status": "error",
                                "error": str(e)[:200],
                            })
                            results["failure_count"] += 1

        self._results.append(results)
        return results

    def _execute_smart_match_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        scorers: Optional[List[Scorer]],
        visualizer: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        smart_match 模式 v3.0：使用 PyRIT 原生攻击 + 两层策略选择 + Fallback 链

        核心改进：
        1. SmartMatcher 两层策略选择（快速规则筛选 → 精确模型匹配）
        2. 支持 Fallback 链（主策略失败时自动尝试备选）
        3. ASI 感知策略选择
        4. 动态参数计算
        """
        from ..orchestrators.smart_matcher import SmartMatcher
        from ..payloads.payload_classifier import classify_payloads, analyze_payloads

        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        target_model = attack_config.get("target_model", "")
        asi_category = attack_config.get("asi_category", "")

        # 提取评分器信息
        scorer_info_list = self.get_scorer_info(attack_config.get("scorers", []))

        logger.info(
            "Executing attack (smart_match v3.0): %s with %d payloads, target=%s",
            attack_name, len(payloads), target_model or "unknown",
        )

        # 1. SmartMatcher 构建攻击计划（两层策略选择）
        has_adversarial = self._check_adversarial_available()
        matcher = SmartMatcher(
            target_model=target_model,
            has_adversarial=has_adversarial,
        )
        plan = matcher.build_attack_plan(
            payloads, converter_presets, asi_category=asi_category
        )
        plan_summary = matcher.get_plan_summary(plan)

        logger.info("Attack plan (v3.0): %s", plan_summary)

        # 1.5 可视化
        if visualizer:
            categorized = classify_payloads(payloads)
            profiles = analyze_payloads(payloads)
            visualizer.show_classification(categorized)
            visualizer.show_scorer_info(scorer_info_list)
            visualizer.show_execution_plan(plan, plan_summary)
            visualizer.show_attack_start()

        # 2. 执行：使用 PyRIT 原生攻击（支持 Fallback 链）
        results = {
            "attack_name": attack_name,
            "mode": "smart_match",
            "total_executions": len(plan),
            "plan_summary": plan_summary,
            "plan": plan,
            "results": [],
            "success_count": 0,
            "failure_count": 0,
            "category_stats": {},
            "best_combinations": [],
        }

        # 构建 AttackScoringConfig
        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        total_plan = len(plan)

        for idx, item in enumerate(plan, 1):
            payload = item["payload"]
            category = item["payload_category"]
            attack_class_fqn = item["attack_class"]
            attack_params = item["attack_params"]
            fallback_chain = item.get("attack_fallback_chain", [])

            # 尝试主策略 + Fallback 链
            attempt_result = self._execute_with_fallback(
                payload=payload,
                primary_class_fqn=attack_class_fqn,
                primary_params=attack_params,
                fallback_chain=fallback_chain,
                target=target,
                attack_scoring_config=attack_scoring_config,
                converter_presets=converter_presets,
            )

            result_entry = {
                "payload": payload[:100],
                "payload_category": category,
                "attack_class": attempt_result["attack_class"],
                "attack_family": item.get("attack_family", ""),
                "attack_reason": item.get("attack_reason", ""),
                "attack_confidence": item.get("attack_confidence", 1.0),
                "status": attempt_result["status"],
                "outcome": attempt_result["outcome"],
                "response": attempt_result["response"],
                "attempts_used": attempt_result.get("attempts_used", 1),
            }
            results["results"].append(result_entry)

            is_success = attempt_result["status"] == "success"
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

            # 更新类别统计
            if category not in results["category_stats"]:
                results["category_stats"][category] = {"success": 0, "failure": 0}
            results["category_stats"][category]["success" if is_success else "failure"] += 1

            # 可视化
            if visualizer:
                visualizer.show_attack_progress(
                    index=idx,
                    total=total_plan,
                    category=category,
                    preset=attempt_result["attack_class"],
                    strategy="native",
                    status=attempt_result["status"],
                    response_preview=attempt_result["response"][:80],
                )

        # 3. 可视化：结果汇总
        if visualizer:
            visualizer.show_results_summary(results)

        self._results.append(results)
        return results

    def _execute_with_fallback(
        self,
        payload: str,
        primary_class_fqn: str,
        primary_params: Dict[str, Any],
        fallback_chain: List[Dict[str, Any]],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        执行攻击（支持 Fallback 链）

        先尝试主策略，失败时按 fallback_chain 依次尝试备选策略。
        """
        # 尝试主策略
        result = self._execute_single_attack(
            payload=payload,
            attack_class_fqn=primary_class_fqn,
            attack_params=primary_params,
            target=target,
            attack_scoring_config=attack_scoring_config,
            converter_presets=converter_presets,
        )

        if result["status"] == "success":
            result["attempts_used"] = 1
            return result

        # 主策略失败，尝试 Fallback 链
        for fallback_idx, fallback in enumerate(fallback_chain, 2):
            logger.info(
                "Primary attack failed, trying fallback %d/%d: %s",
                fallback_idx - 1, len(fallback_chain),
                fallback["class"].split(".")[-1],
            )

            fallback_result = self._execute_single_attack(
                payload=payload,
                attack_class_fqn=fallback["class"],
                attack_params=fallback.get("params", {}),
                target=target,
                attack_scoring_config=attack_scoring_config,
                converter_presets=converter_presets,
            )

            if fallback_result["status"] == "success":
                fallback_result["attempts_used"] = fallback_idx
                return fallback_result

        # 所有策略都失败，返回主策略结果
        result["attempts_used"] = 1 + len(fallback_chain)
        return result

    def _execute_single_attack(
        self,
        payload: str,
        attack_class_fqn: str,
        attack_params: Dict[str, Any],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        执行单次 PyRIT 攻击

        根据攻击类型自动构建所需参数（adversarial config, converter config 等）
        """
        try:
            # 动态导入 PyRIT 攻击类
            attack_class = _import_class(attack_class_fqn)

            # 构建通用参数
            common_kwargs = {
                "objective_target": target,
                "attack_scoring_config": attack_scoring_config,
            }

            # 根据攻击类型添加特定参数
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
                converter_names = list(converter_presets.values())[0] if converter_presets else []
                preset_converters = self.build_converters([{"name": c} for c in converter_names])
                common_kwargs["attack_converter_config"] = AttackConverterConfig(request_converters=preset_converters)

            # 合并动态参数
            common_kwargs.update(attack_params)

            # 创建攻击实例并执行
            attack = attack_class(**common_kwargs)
            attack_result = asyncio.run(attack.execute_async(objective=payload))

            # 解析结果
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

    def _check_adversarial_available(self) -> bool:
        """检查是否有可用的对抗性 LLM（Crescendo/TAP 需要）"""
        # 从 scorer 配置中检查是否有可用的 LLM 后端
        backends = self._scorer_config.get("scorer_llm_backends", {})
        # 排除 objective_target，检查是否有独立的评分器后端
        scorer_backends = {k: v for k, v in backends.items() if k != "objective_target"}
        return len(scorer_backends) > 0

    def _build_adversarial_config(self, objective_target: PromptTarget) -> Optional[AttackAdversarialConfig]:
        """构建对抗性配置（Crescendo/TAP 需要）"""
        backends = self._scorer_config.get("scorer_llm_backends", {})
        # 使用第一个可用的非 objective_target 后端
        for name, backend in backends.items():
            if name == "objective_target":
                continue
            try:
                target = self._build_scorer_llm_target(name)
                if target:
                    return AttackAdversarialConfig(target=target)
            except Exception:
                continue
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # 静态工具方法
    # ──────────────────────────────────────────────────────────────────────────

    # ──────────────────────────────────────────────────────────────────────────
    # 静态工具方法
    # ──────────────────────────────────────────────────────────────────────────

    # PyRIT 攻击策略映射（集中管理，单一数据源）
    _ATTACK_REGISTRY: Dict[str, Dict[str, str]] = {
        # Single-Turn Attacks
        "prompt_sending": {
            "class": "pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack",
            "category": "single_turn",
            "description": "基础提示发送攻击",
            "use_case": "直接提示注入、间接提示注入",
        },
        "context_compliance": {
            "class": "pyrit.executor.attack.single_turn.context_compliance.ContextComplianceAttack",
            "category": "single_turn",
            "description": "上下文合规攻击",
            "use_case": "利用上下文合规性绕过安全控制",
        },
        "flip_attack": {
            "class": "pyrit.executor.attack.single_turn.flip_attack.FlipAttack",
            "category": "single_turn",
            "description": "翻转攻击",
            "use_case": "字符/令牌翻转绕过过滤",
        },
        "role_play": {
            "class": "pyrit.executor.attack.single_turn.role_play.RolePlayAttack",
            "category": "single_turn",
            "description": "角色扮演攻击",
            "use_case": "角色扮演越狱、身份劫持",
        },
        "many_shot_jailbreak": {
            "class": "pyrit.executor.attack.single_turn.many_shot_jailbreak.ManyShotJailbreakAttack",
            "category": "single_turn",
            "description": "多轮越狱攻击",
            "use_case": "绕过安全过滤、角色扮演越狱",
        },
        "skeleton_key": {
            "class": "pyrit.executor.attack.single_turn.skeleton_key.SkeletonKeyAttack",
            "category": "single_turn",
            "description": "骨架密钥攻击",
            "use_case": "绕过模型级安全控制",
        },
        # Multi-Turn Attacks
        "tree_of_attacks": {
            "class": "pyrit.executor.attack.multi_turn.tree_of_attacks.TreeOfAttacksWithPruningAttack",
            "category": "multi_turn",
            "description": "树状攻击 (TAP)",
            "use_case": "复杂目标攻击、自适应攻击路径",
        },
        "crescendo": {
            "class": "pyrit.executor.attack.multi_turn.crescendo.CrescendoAttack",
            "category": "multi_turn",
            "description": "渐强攻击",
            "use_case": "渐进式绕过安全控制",
        },
        "pair": {
            "class": "pyrit.executor.attack.multi_turn.pair.PAIRAttack",
            "category": "multi_turn",
            "description": "提示自动迭代优化 (PAIR)",
            "use_case": "自动化攻击优化",
        },
        "red_teaming": {
            "class": "pyrit.executor.attack.multi_turn.red_teaming.RedTeamingAttack",
            "category": "multi_turn",
            "description": "红队攻击",
            "use_case": "综合红队评估",
        },
        "chunked_request": {
            "class": "pyrit.executor.attack.multi_turn.chunked_request.ChunkedRequestAttack",
            "category": "multi_turn",
            "description": "分块请求攻击",
            "use_case": "绕过上下文长度限制",
        },
        "multi_prompt_sending": {
            "class": "pyrit.executor.attack.multi_turn.multi_prompt_sending.MultiPromptSendingAttack",
            "category": "multi_turn",
            "description": "多提示发送攻击",
            "use_case": "批量提示测试",
        },
        "simulated_conversation": {
            "class": "pyrit.executor.attack.multi_turn.simulated_conversation.SimulatedConversationAttack",
            "category": "multi_turn",
            "description": "模拟对话攻击",
            "use_case": "多轮对话攻击",
        },
        # Compound Attacks
        "sequential": {
            "class": "pyrit.executor.attack.compound.sequential_attack.SequentialAttack",
            "category": "compound",
            "description": "顺序攻击",
            "use_case": "攻击链组合",
        },
        # Streaming Attacks
        "barge_in": {
            "class": "pyrit.executor.attack.streaming.barge_in.BargeInAttack",
            "category": "streaming",
            "description": "实时音频插入攻击",
            "use_case": "实时音频流绕过",
        },
    }

    @classmethod
    def list_attacks(cls, category: str = None) -> List[str]:
        """
        列出可用攻击（单一数据源，从注册表派生）

        Args:
            category: 攻击类别 ("single_turn", "multi_turn", "compound", "streaming")

        Returns:
            攻击名称列表
        """
        if category:
            return [
                name for name, info in cls._ATTACK_REGISTRY.items()
                if info["category"] == category
            ]
        return list(cls._ATTACK_REGISTRY.keys())

    @classmethod
    def get_attack_info(cls, name: str) -> Dict[str, str]:
        """
        获取攻击信息（单一数据源）

        Args:
            name: 攻击名称

        Returns:
            攻击信息字典
        """
        info = cls._ATTACK_REGISTRY.get(name)
        if info:
            return {
                "category": info["category"],
                "description": info["description"],
                "use_case": info["use_case"],
                "class": info["class"],
            }
        return {"category": "unknown", "description": "Unknown attack"}

    @classmethod
    def get_attack_class(cls, name: str) -> Optional[str]:
        """获取攻击类的全限定名"""
        info = cls._ATTACK_REGISTRY.get(name)
        return info["class"] if info else None

    @staticmethod
    def list_types() -> List[str]:
        """列出支持的目标类型"""
        return ["ollama", "openai", "http"]

    @staticmethod
    def load_yaml(path: str) -> Dict[str, Any]:
        """加载 YAML 文件（支持多文档分隔符 ---）"""
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Config file not found: %s", path)
            return {}
        with open(file_path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
            return docs[0] if docs else {}

    @classmethod
    def build_attack_list(cls, module_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从模块配置构建攻击列表"""
        attacks = []

        for key, value in module_config.items():
            if key in ("name", "owasp", "description", "owasp_agentic", "foundational_principles"):
                continue
            if not isinstance(value, dict):
                continue

            mode = value.get("mode", "chain")
            payloads = cls._resolve_payloads(value)

            if mode == "smart_match":
                if not payloads or "converter_presets" not in value:
                    logger.warning("smart_match mode requires payloads and 'converter_presets': %s", key)
                    continue

                scorer_configs = []
                for sname in cls._extract_scorer_names(value.get("pyrit_scorers", [])):
                    if sname == "substring":
                        scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                    else:
                        scorer_configs.append({"name": sname})

                attacks.append({
                    "name": value.get("name", key),
                    "description": value.get("description", ""),
                    "mode": "smart_match",
                    "payloads": payloads,
                    "converter_presets": value.get("converter_presets", {}),
                    "match_rules": value.get("match_rules", None),
                    "scorers": scorer_configs,
                    "asi_category": value.get("asi_category", ""),
                })

            elif mode == "presets":
                if not payloads:
                    continue

                scorer_configs = []
                for sname in cls._extract_scorer_names(value.get("pyrit_scorers", [])):
                    if sname == "substring":
                        scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                    else:
                        scorer_configs.append({"name": sname})

                attacks.append({
                    "name": value.get("name", key),
                    "description": value.get("description", ""),
                    "mode": "presets",
                    "payloads": payloads,
                    "converter_presets": value.get("converter_presets", {}),
                    "scorers": scorer_configs,
                })

            else:
                if not payloads:
                    continue

                converter_configs = []
                for cname in cls._extract_converter_names(value.get("pyrit_converters", [])):
                    converter_configs.append({"name": cname})

                scorer_configs = []
                for sname in cls._extract_scorer_names(value.get("pyrit_scorers", [])):
                    if sname == "substring":
                        scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                    else:
                        scorer_configs.append({"name": sname})

                attacks.append({
                    "name": value.get("name", key),
                    "description": value.get("description", ""),
                    "mode": "chain",
                    "payloads": payloads,
                    "converters": converter_configs,
                    "scorers": scorer_configs,
                })

        return attacks

    @classmethod
    def _resolve_payloads(cls, attack_data: Dict[str, Any]) -> List[str]:
        """解析攻击数据中的载荷"""
        if "payload_refs" in attack_data:
            refs = [r.lower() for r in attack_data["payload_refs"]]
            if cls._payload_manager is not None:
                return cls._payload_manager.resolve_refs(refs)
            try:
                from ..payloads.payload_manager import PayloadManager
                pm = PayloadManager()
                pm.load_data_dir(cls.DATA_DIR)
                return pm.resolve_refs(refs)
            except Exception as e:
                logger.error("Failed to resolve payload_refs: %s", str(e))
                return []

        return attack_data.get("payloads", [])

    @staticmethod
    def _extract_converter_names(pyrit_converters: List[str]) -> List[str]:
        """从 PyRIT 转换器全限定名提取简短名称（与 CONVERTER_MAP 保持一致）"""
        name_map = {
            # 编码混淆
            "Base64Converter": "base64",
            "ROT13Converter": "rot13",
            "UnicodeConfusableConverter": "unicode_confusable",
            "LeetspeakConverter": "leetspeak",
            # 越狱模板
            "PersuasionConverter": "persuasion",
            "TextJailbreakConverter": "text_jailbreak",
            "MaliciousQuestionGeneratorConverter": "malicious_question_generator",
            # Token 走私
            "AsciiSmugglerConverter": "ascii_smuggler",
            "ZeroWidthConverter": "zero_width",
            "DiacriticConverter": "diacritic",
            # 搜索替换
            "SearchReplaceConverter": "search_replace",
            # 翻译混淆
            "TranslationConverter": "translation",
            # 变异生成
            "VariationConverter": "variation",
            # 多模态
            "AddTextImageConverter": "add_text_image",
            "PDFConverter": "pdf",
            "WordDocConverter": "word_doc",
        }
        names = []
        for converter_fqn in pyrit_converters:
            class_name = converter_fqn.split(".")[-1]
            if class_name in name_map:
                names.append(name_map[class_name])
        return names

    @staticmethod
    def _extract_scorer_names(pyrit_scorers: List[str]) -> List[str]:
        """从 PyRIT 评分器全限定名提取简短名称"""
        name_map = {
            # SelfAsk 系列
            "SelfAskRefusalScorer": "refusal",
            "SelfAskTrueFalseScorer": "true_false",
            "SelfAskCategoryScorer": "category",
            # 规则匹配系列
            "SubStringScorer": "substring",
            "PromptShieldScorer": "prompt_shield",
            "InsecureCodeScorer": "insecure_code",
            "ShellCommandOutputScorer": "shell_command",
            "SQLInjectionOutputScorer": "sql_injection",
            "XSSOutputScorer": "xss",
            "PathTraversalOutputScorer": "path_traversal",
            "CredentialLeakScorer": "credential_leak",
            "StaticPromptInjectionScorer": "static_prompt_injection",
            # Float Scale 系列
            "GandalfScorer": "gandalf",
            "AzureContentFilterScorer": "azure_content_filter",
        }
        names = []
        for scorer_fqn in pyrit_scorers:
            class_name = scorer_fqn.split(".")[-1]
            if class_name in name_map:
                names.append(name_map[class_name])
        return names

    def _compute_best_combinations(self, category_stats: Dict) -> List[Dict[str, Any]]:
        """从统计结果中计算每个类别的最佳组合"""
        best = []
        for category, stats in category_stats.items():
            success = stats.get("success", 0)
            failure = stats.get("failure", 0)
            total = success + failure
            if total > 0:
                best.append({
                    "category": category,
                    "success_rate": success / total,
                    "total_tests": total,
                })
        best.sort(key=lambda x: x["success_rate"], reverse=True)
        return best
