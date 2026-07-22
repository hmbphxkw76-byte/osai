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
- ASI_SCORER_MAP 外置到 pyrit_ai300/attack/asi_mapping.yaml（包内部配置）

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
from ..utils.pyrit_log_adapter import PyRITLogAdapter

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
from .pyrit.initializer import PyRITInitializer
from .pyrit.target_builder import TargetBuilder
from .pyrit.converter_builder import ConverterBuilder
from .pyrit.scorer_builder import ScorerBuilder
from .pyrit.component_registry import (
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


# P1-6: 攻击类名 → 攻击成本映射（数据驱动：从 asi_mapping.yaml 加载）
_ATTACK_COST_MAP: Dict[str, str] = {
    "PromptSendingAttack": "SINGLE_TURN",
    "CrescendoAttack": "MULTI_TURN",
    "TreeOfAttacksWithPruningAttack": "TREE_SEARCH",
    "SequentialAttack": "SEQUENTIAL",
    "PAIRAttack": "MULTI_TURN",
    "RedTeamingAttack": "MULTI_TURN",
    "ManyShotJailbreakAttack": "SINGLE_TURN",
    "SkeletonKeyAttack": "SINGLE_TURN",
    "RolePlayAttack": "MULTI_TURN",
    "FlipAttack": "SINGLE_TURN",
    "ContextComplianceAttack": "MULTI_TURN",
    "ChunkedRequestAttack": "MULTI_TURN",
}


def _map_attack_class_to_cost(attack_class_fqn: str):
    """将攻击类全限定名映射到 AttackCost 枚举（数据驱动映射）"""
    from .feedback.adaptive_early_stopping import AttackCost
    class_name = attack_class_fqn.split(".")[-1] if attack_class_fqn else ""
    cost_name = _ATTACK_COST_MAP.get(class_name, "SINGLE_TURN")
    return getattr(AttackCost, cost_name, AttackCost.SINGLE_TURN)


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

    # ASI/LLM 类别 → 评分器类型自动映射（v3.2: 从 pyrit_ai300/attack/asi_mapping.yaml 加载）
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
        db_path: str = "",
    ):
        self.config = self._load_config(config_path, config_dict)
        self.memory_type = memory_type
        self._components_initialized = False
        self._results: List[Dict[str, Any]] = []
        self._data_dir = data_dir or self.DATA_DIR
        self._rate_controller: Optional[RateController] = None

        # REV-16: 保留 PyRIT 原生 AttackResult 对象，供 output 模块渲染
        self._pyrit_attack_results: List[Any] = []

        # P2-9: memory_labels 存储（跨攻击持久化标签）
        self._memory_labels: Dict[str, str] = {}

        # L5: PyRIT 原生日志适配器（对齐 PyRIT 0.14.0 原生日志格式）
        self._logger = logger  # 原始 logger（直接 info/error/warning 调用）
        self._log_adapter = PyRITLogAdapter(logger)  # 结构化日志适配器

        # 初始化子模块（v3.1 拆分）
        self._pyrit_initializer = PyRITInitializer(
            memory_type=memory_type,
            db_path=db_path,
        )
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
        加载 ASI 评分器映射和攻击成本映射（v3.2: 从包内部 asi_mapping.yaml 加载）

        优先级：
        1. pyrit_ai300/attack/asi_mapping.yaml（包内部配置）
        2. 内置默认值（_ASI_SCORER_MAP / _DEFAULT_SCORERS / _ATTACK_COST_MAP）
        """
        global _ATTACK_COST_MAP
        mapping_path = Path(__file__).parent / "asi_mapping.yaml"
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
                # L5: 数据驱动 — 从 YAML 加载攻击成本映射
                external_cost_map = data.get("attack_cost_map", {})
                if external_cost_map:
                    _ATTACK_COST_MAP = external_cost_map
                    logger.info("Attack cost map loaded from %s (%d entries)", mapping_path, len(external_cost_map))
                if external_map or external_defaults or external_cost_map:
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
        """加载配置（支持 ${VAR} 环境变量替换）"""
        if config_dict:
            return config_dict
        if config_path:
            path = Path(config_path)
            if path.suffix in (".yaml", ".yml"):
                with open(path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                # 环境变量替换（${VAR} → 实际值）
                from ..utils.env_loader import resolve_env_vars
                return resolve_env_vars(config)
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
        同时记录目标类型，用于后续转换器过滤（SPA 目标过滤 binary_path）。
        """
        self._target_type = target_config.get("type", "openai")
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
        自动传递当前目标类型，用于 SPA binary_path 过滤。
        """
        target_type = getattr(self, "_target_type", "")
        return self._converter_builder.build(
            converter_configs, converter_target, target_type=target_type
        )

    def build_stacked_converters(
        self,
        converter_names: List[str],
        converter_target: Optional[PromptTarget] = None,
        max_depth: int = 2,
        max_combinations: int = 5,
    ) -> List[PromptConverterConfiguration]:
        """
        P1-8: 构建堆叠转换器配置

        将多个转换器组合成堆叠配置，每个配置包含多个转换器
        按顺序应用于载荷（如 base64→rot13→unicode_confusable）。

        Args:
            converter_names: 基础转换器名称列表
            converter_target: 转换器目标（LLM 后端）
            max_depth: 最大堆叠深度（2-3 层）
            max_combinations: 最大组合数量

        Returns:
            PromptConverterConfiguration 列表，每个包含多个转换器
        """
        from .feedback.converter_stacker import ConverterStacker
        stacker = ConverterStacker(max_depth=max_depth, max_combinations=max_combinations)
        target_type = getattr(self, "_target_type", "")
        return stacker.build_stacked_converters(
            converter_names=converter_names,
            converter_builder=self._converter_builder,
            converter_target=converter_target,
            target_type=target_type,
        )

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

    @staticmethod
    def _check_converter_target_available(target: PromptTarget) -> bool:
        """
        检查 converter_target（LLM 后端）是否可用

        通过检查目标的 endpoint 是否为本地地址来判断。
        本地 Ollama/OpenAI 端点可能不可达（服务未启动），
        此时需要 LLM 后端的转换器（如 MaliciousQuestionGeneratorConverter）
        应被跳过，避免连接超时导致整个攻击失败。

        Args:
            target: PyRIT PromptTarget 对象

        Returns:
            bool: True 表示目标可能可用，False 表示不可用
        """
        try:
            # 从目标对象提取 endpoint
            endpoint = ""
            if hasattr(target, "_prompt_target"):
                inner = target._prompt_target
                if hasattr(inner, "_endpoint"):
                    endpoint = inner._endpoint or ""
            elif hasattr(target, "_endpoint"):
                endpoint = target._endpoint or ""

            # 本地端点（localhost/127.0.0.1）且非标准端口，可能不可达
            if "localhost" in endpoint or "127.0.0.1" in endpoint:
                # 尝试 TCP 连接检测
                import socket
                from urllib.parse import urlparse
                parsed = urlparse(endpoint)
                host = parsed.hostname or "localhost"
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result != 0:
                        logger.debug("Converter target %s:%d not reachable", host, port)
                        return False
                except Exception:
                    return False

            return True
        except Exception:
            # 无法判断时保守返回 True（不过滤）
            return True

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
        P2-9 集成：自动生成 memory_labels 用于跨攻击持久化
        """
        # P2-9: 生成 memory_labels
        self._memory_labels = {
            "owasp_id": attack_config.get("owasp_id", attack_config.get("asi_category", "")),
            "attack_name": attack_config.get("name", ""),
            "mode": attack_config.get("mode", "chain"),
        }
        target_model = attack_config.get("target_model", "")
        if target_model:
            self._memory_labels["target_model"] = target_model

        mode = attack_config.get("mode", "chain")
        attack_name = attack_config.get("name", "unnamed_attack")
        self._log_adapter.log_attack_config(
            attack_name, mode, len(attack_config.get("payloads", [])),
            concurrency=self._rate_controller.concurrency if self._rate_controller else 1,
            target_model=attack_config.get("target_model", ""),
            owasp_id=attack_config.get("owasp_id", attack_config.get("asi_category", "")),
        )

        # REV-1: 侦察→载荷过滤闭环 (GAP-1)
        # 基于侦察检测到的攻击面，跳过不相关的 OWASP 类别
        # 偏差⑤修复：若 attack_config 已标记 _surface_filtered，跳过冗余的双重过滤
        if profile_params and not attack_config.get("_surface_filtered"):
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
                    self._log_adapter.log_surface_filter(attack_name, owasp_id, required, surfaces)
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
                profile_params=profile_params,
                objective=objective,
                placeholders=placeholders,
            )
        else:
            return self._execute_chain_v3(
                attack_config, target, converters, scorers, tracker,
                profile_params=profile_params,
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
        profile_params: Optional[Dict[str, Any]] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """chain 模式 v3.4：使用 SmartMatcher 策略选择 + 逐载荷转换器 + ASR 排序"""
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        asi_category = attack_config.get("asi_category", "")
        owasp_id = attack_config.get("owasp_id", attack_config.get("id", ""))

        # REV-1: 载荷级别过滤（上下文窗口 + 模型能力）
        if profile_params and payloads:
            from ..payloads.payload_filter import PayloadFilter
            _pf = PayloadFilter()
            _orig_count = len(payloads)
            payloads = _pf.filter_payloads(payloads, profile_params)
            self._log_adapter.log_payload_filter(attack_name, _orig_count, len(payloads))
            if len(payloads) < _orig_count and tracker:
                tracker.log_execution({
                    "payload": f"[FILTER] {attack_name}",
                    "status": "filtered",
                    "outcome": f"{_orig_count - len(payloads)} payloads removed (context/capability)",
                    "response": f"{len(payloads)}/{_orig_count} retained",
                })

        # REV-2: ASR-aware 载荷排序 (GAP-2)
        # 高 ASR 载荷优先执行，早停时低 ASR 载荷被跳过
        target_model = attack_config.get("target_model", "")
        if target_model and len(payloads) > 1:
            from ..payloads.asr_ranker import ASRRanker
            payloads = ASRRanker.rank_payloads(payloads, target_model)
            self._log_adapter.log_asr_rank(len(payloads), target_model)

        # REV-3: 模型特定载荷选择 (GAP-6)
        # 基于目标模型家族过滤不兼容载荷，选择最优变体
        if target_model and len(payloads) > 1:
            from ..payloads.model_specific_selector import ModelSpecificSelector
            original_count = len(payloads)
            payloads = ModelSpecificSelector.select_payloads(payloads, target_model)
            self._log_adapter.log_model_specific_select(len(payloads), original_count, target_model)

        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        self._log_adapter.log_attack_config(
            attack_name, "chain", len(payloads),
            concurrency=concurrency, target_model=target_model,
            owasp_id=owasp_id,
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
        from .matching.smart_matcher import SmartMatcher
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
                    self._log_adapter.log_attack_start(
                        item["attack_class"], payload,
                        owasp_id=owasp_id, attack_family=item.get("attack_family", ""),
                    )
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
                    self._log_adapter.log_attack_result(
                        attempt_result["attack_class"],
                        attempt_result["outcome"],
                        execution_time_ms=attempt_result.get("execution_time_ms", 0),
                        conversation_id=attempt_result.get("conversation_id", ""),
                        executed_turns=attempt_result.get("executed_turns", 1),
                        owasp_id=owasp_id,
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
                    self._logger.error(f"Attack failed for payload: {str(e)[:200]}")
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

        # REV-16: AttackResult 已由 _execute_single_attack_async 存入 self._pyrit_attack_results
        results["pyrit_attack_results"] = self._pyrit_attack_results

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

        self._log_adapter.log_attack_summary(
            attack_name, len(all_results), results["success_count"], results["failure_count"],
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
        profile_params: Optional[Dict[str, Any]] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """presets 模式 v3.0：使用 SequentialAttack (FIRST_SUCCESS)"""
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        asi_category = attack_config.get("asi_category", "")

        # REV-1: 载荷级别过滤（上下文窗口 + 模型能力）
        if profile_params and payloads:
            from ..payloads.payload_filter import PayloadFilter
            _pf = PayloadFilter()
            _orig_count = len(payloads)
            payloads = _pf.filter_payloads(payloads, profile_params)
            self._log_adapter.log_payload_filter(attack_name, _orig_count, len(payloads))

        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        self._log_adapter.log_attack_config(
            attack_name, "presets", len(payloads),
            concurrency=concurrency, target_model="",
            preset_count=len(converter_presets),
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

        # REV-16: 保留 PyRIT AttackResult 对象列表
        pyrit_attack_results: List[Any] = []

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
                    self._log_adapter.log_attack_start("PromptSendingAttack", payload_text)
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

                        # REV-16: 保留 AttackResult 供 PyRIT output 模块渲染
                        pyrit_attack_results.append(attack_result)

                        self._log_adapter.log_attack_result(
                            "PromptSendingAttack", attack_result.outcome.name,
                            execution_time_ms=getattr(attack_result, "execution_time_ms", 0),
                            conversation_id=attack_result.conversation_id,
                            executed_turns=getattr(attack_result, "executed_turns", 1),
                            preset=preset_name,
                        )

                        return {
                            "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                            "preset": preset_name,
                            "status": "success" if is_success else "failed",
                            "outcome": attack_result.outcome.name,
                            "response": str(attack_result)[:200],
                            "conversation_id": attack_result.conversation_id,
                            "executed_turns": getattr(attack_result, "executed_turns", 1),
                            "execution_time_ms": getattr(attack_result, "execution_time_ms", 0),
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

                        # REV-16: 保留 SequentialAttack 的 AttackResult
                        pyrit_attack_results.append(seq_result)

                        successful_preset = "unknown"
                        for i, child_result in enumerate(seq_result.child_results):
                            if child_result and child_result.outcome.name == "SUCCESS":
                                successful_preset = preset_names[i] if i < len(preset_names) else "unknown"
                                break

                        self._log_adapter.log_attack_result(
                            "SequentialAttack", seq_result.outcome.name,
                            execution_time_ms=getattr(seq_result, "execution_time_ms", 0),
                            conversation_id=seq_result.conversation_id,
                            executed_turns=getattr(seq_result, "executed_turns", 1),
                            preset=successful_preset if is_success else "all_failed",
                        )

                        return {
                            "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                            "preset": successful_preset if is_success else "all_failed",
                            "status": "success" if is_success else "failed",
                            "outcome": seq_result.outcome.name,
                            "response": str(seq_result)[:200],
                            "conversation_id": seq_result.conversation_id,
                            "executed_turns": getattr(seq_result, "executed_turns", 1),
                            "execution_time_ms": getattr(seq_result, "execution_time_ms", 0),
                            "is_success": is_success,
                        }
                except Exception as e:
                    self._logger.error(f"Attack failed for payload: {str(e)[:200]}")
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

        # REV-16: 将保留的 AttackResult 存入实例和结果字典
        self._pyrit_attack_results.extend(pyrit_attack_results)
        results["pyrit_attack_results"] = pyrit_attack_results

        for r in all_results:
            is_success = r.pop("is_success", False)
            results["results"].append(r)
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

        self._log_adapter.log_attack_summary(
            attack_name, len(all_results), results["success_count"], results["failure_count"],
        )

        self._results.append(results)
        return results

    @staticmethod
    async def _probe_target_model(target: PromptTarget) -> str:
        """
        运行时模型探测：发送自识别 prompt 获取目标模型名称

        P2-11: 集成多策略行为指纹，优先使用增强探测
        """
        # P2-11: 尝试多策略指纹探测
        try:
            from .matching.model_fingerprinter import ModelFingerprinter
            fingerprinter = ModelFingerprinter(max_probes=3)
            fingerprint = await fingerprinter.probe(target)
            if fingerprint.model_name:
                logger.info(
                    "P2-11 Model fingerprint: %s (family=%s, safety=%s, confidence=%.0f%%)",
                    fingerprint.model_name,
                    fingerprint.model_family or "unknown",
                    fingerprint.safety_level,
                    fingerprint.confidence * 100,
                )
                return fingerprint.model_name
        except Exception as e:
            logger.debug("P2-11 Enhanced probe failed, falling back to simple: %s", e)

        # 回退：简单探测
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
        from .matching.smart_matcher import SmartMatcher

        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        target_model = attack_config.get("target_model", "")
        asi_category = attack_config.get("asi_category", "")

        # REV-1: 载荷级别过滤（上下文窗口 + 模型能力）
        if profile_params and payloads:
            from ..payloads.payload_filter import PayloadFilter
            _pf = PayloadFilter()
            _orig_count = len(payloads)
            payloads = _pf.filter_payloads(payloads, profile_params)
            self._log_adapter.log_payload_filter(attack_name, _orig_count, len(payloads))

        # REV-2: ASR-aware 载荷排序 (GAP-2)
        if target_model and len(payloads) > 1:
            from ..payloads.asr_ranker import ASRRanker
            payloads = ASRRanker.rank_payloads(payloads, target_model)
            self._log_adapter.log_asr_rank(len(payloads), target_model)

        if not target_model:
            self._logger.info("Target model unknown, probing...")
            target_model = run_async(self._probe_target_model(target))
            self._log_adapter.log_model_probe(target_model)

        # REV-3: 模型特定载荷选择 (GAP-6)
        if target_model and len(payloads) > 1:
            from ..payloads.model_specific_selector import ModelSpecificSelector
            original_count = len(payloads)
            payloads = ModelSpecificSelector.select_payloads(payloads, target_model)
            self._log_adapter.log_model_specific_select(len(payloads), original_count, target_model)

        self._log_adapter.log_attack_config(
            attack_name, "smart_match", len(payloads),
            concurrency=self._rate_controller.concurrency if self._rate_controller else 1,
            target_model=target_model or "unknown",
            owasp_id=attack_config.get("owasp_id", attack_config.get("id", "")),
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

        self._logger.info(
            f"Attack plan: {len(plan)} payloads → PyRIT native attacks "
            f"(target={target_model or 'unknown'}, adversarial={has_adversarial})",
            extra={"plan_summary": plan_summary},
        )

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
        self._logger.info(f"Smart match concurrency: {concurrency}")

        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None
            early_stop_triggered = False
            consecutive_failures = 0
            executed_count = 0

            # P1-6: 自适应早停器（替换固定 max_consecutive_failures=5）
            from .feedback.adaptive_early_stopping import AdaptiveEarlyStopper, AttackCost
            _attack_cost = _map_attack_class_to_cost(
                plan[0]["attack_class"] if plan else ""
            )
            _avg_asr = 0.3  # 默认 ASR
            if target_model:
                try:
                    from ..payloads.asr_ranker import ASRRanker
                    _asr_values = []
                    for item in plan:
                        profile = item.get("payload_profile", {})
                        _asr = ASRRanker.get_payload_asr(profile, target_model)
                        _asr_values.append(_asr)
                    if _asr_values:
                        _avg_asr = sum(_asr_values) / len(_asr_values)
                except Exception:
                    pass
            stopper = AdaptiveEarlyStopper(
                total_payloads=len(plan),
                avg_asr=_avg_asr,
                attack_cost=_attack_cost,
                aggression_level=aggression_level,
            )

            async def _execute_one(item: Dict[str, Any]) -> Dict[str, Any]:
                nonlocal early_stop_triggered, consecutive_failures, executed_count
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
                    self._log_adapter.log_attack_start(
                        item["attack_class"], payload,
                        owasp_id=owasp_id, attack_family=item.get("attack_family", ""),
                    )
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
                    self._log_adapter.log_attack_result(
                        attempt_result["attack_class"],
                        attempt_result["outcome"],
                        execution_time_ms=attempt_result.get("execution_time_ms", 0),
                        conversation_id=attempt_result.get("conversation_id", ""),
                        executed_turns=attempt_result.get("executed_turns", 1),
                        attempts_used=attempt_result.get("attempts_used", 1),
                        owasp_id=owasp_id,
                    )

                    executed_count += 1
                    if is_success:
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                        # P1-6: 自适应早停检查
                        recent_result = {
                            "status": "success" if is_success else "failed",
                            "payload": payload[:100],
                            "attack_class": attempt_result["attack_class"],
                        }
                        decision = stopper.should_stop(
                            consecutive_failures=consecutive_failures,
                            executed_count=executed_count,
                            recent_result=recent_result,
                        )
                        if decision.should_stop:
                            early_stop_triggered = True
                            remaining = len(plan) - (plan.index(item) + 1)
                            self._log_adapter.log_early_stop(
                                consecutive_failures, decision.adaptive_threshold,
                                remaining, decision.reason,
                            )
                            if tracker:
                                tracker.log_early_stop(
                                    consecutive_failures=consecutive_failures,
                                    skipped_count=remaining,
                                    threshold=decision.adaptive_threshold,
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

        # REV-16: AttackResult 已由 _execute_single_attack_async 存入 self._pyrit_attack_results
        results["pyrit_attack_results"] = self._pyrit_attack_results

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

        self._log_adapter.log_attack_summary(
            attack_name, len(all_results), results["success_count"], results["failure_count"],
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

            # P0-2: 新增攻击类型处理
            elif attack_class_fqn.endswith("ManyShotJailbreakAttack"):
                # ManyShot 是单轮攻击，不需要对抗性 LLM
                # example_count 参数已通过 attack_params 传入
                common_kwargs["attack_converter_config"] = AttackConverterConfig()

            elif attack_class_fqn.endswith("SkeletonKeyAttack"):
                # SkeletonKey 是单轮攻击，注入骨架密钥 prompt
                common_kwargs["attack_converter_config"] = AttackConverterConfig()

            elif attack_class_fqn.endswith("FlipAttack"):
                # Flip 是单轮攻击，反转 payload
                common_kwargs["attack_converter_config"] = AttackConverterConfig()

            elif attack_class_fqn.endswith("RolePlayAttack"):
                # RolePlay 需要对抗性 LLM + role_play_definition_path
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                    # 查找内置的 role_play 定义文件
                    role_play_path = attack_params.get("role_play_definition_path")
                    if not role_play_path:
                        import pyrit
                        pyrit_pkg_dir = Path(pyrit.__file__).parent
                        role_play_dir = pyrit_pkg_dir / "datasets" / "attack_strategies" / "role_play"
                        if role_play_dir.exists():
                            role_play_files = list(role_play_dir.glob("*.yaml"))
                            if role_play_files:
                                common_kwargs["role_play_definition_path"] = role_play_files[0]
                                logger.info("RolePlay using definition: %s", role_play_files[0].name)
                    else:
                        common_kwargs["role_play_definition_path"] = Path(role_play_path)
                else:
                    logger.warning("No adversarial LLM for RolePlay, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("ContextComplianceAttack"):
                # ContextCompliance 需要对抗性 LLM
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for ContextCompliance, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("ChunkedRequestAttack"):
                # ChunkedRequest 是多轮攻击，不需要对抗性 LLM
                # chunk_size / total_length 参数已通过 attack_params 传入
                common_kwargs["attack_converter_config"] = AttackConverterConfig()

            elif attack_class_fqn.endswith("PromptSendingAttack"):
                # v3.3: 优先使用逐载荷选择的转换器，其次 fallback 的 converter_override
                if selected_converters:
                    converter_names = selected_converters
                elif converter_override:
                    converter_names = converter_override
                else:
                    converter_names = list(converter_presets.values())[0] if converter_presets else []

                # 过滤掉需要 LLM 后端的转换器（当 converter_target 不可用时）
                # 避免 MaliciousQuestionGeneratorConverter 等转换器导致连接失败
                from .pyrit.component_registry import CONVERTERS_NEEDING_TARGET
                _has_converter_target = self._check_converter_target_available(target)
                if not _has_converter_target:
                    _filtered = [c for c in converter_names if c not in CONVERTERS_NEEDING_TARGET]
                    if len(_filtered) < len(converter_names):
                        logger.warning(
                            "Filtered out LLM-dependent converters (target unavailable): %s",
                            [c for c in converter_names if c in CONVERTERS_NEEDING_TARGET],
                        )
                    converter_names = _filtered

                if converter_names:
                    preset_converters = self.build_converters(
                        [{"name": c} for c in converter_names],
                        converter_target=target,
                    )
                    common_kwargs["attack_converter_config"] = AttackConverterConfig(request_converters=preset_converters)
                else:
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()

            common_kwargs.update(attack_params)

            attack = attack_class(**common_kwargs)
            # P2-9: 传递 memory_labels 用于跨攻击持久化
            _execute_kwargs = {"objective": _extract_payload_text(payload)}
            if self._memory_labels:
                _execute_kwargs["memory_labels"] = self._memory_labels
            attack_result = await attack.execute_async(**_execute_kwargs)

            outcome = attack_result.outcome
            is_success = outcome.name == "SUCCESS"

            # REV-16: 保留 AttackResult 供 PyRIT output 模块渲染
            self._pyrit_attack_results.append(attack_result)

            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "success" if is_success else "failed",
                "outcome": outcome.name,
                "response": str(attack_result)[:200],
                "conversation_id": attack_result.conversation_id,
                "executed_turns": getattr(attack_result, "executed_turns", 1),
                "execution_time_ms": getattr(attack_result, "execution_time_ms", 0),
            }

        except Exception as e:
            _err_msg = str(e)
            self._log_adapter.log_attack_result(
                attack_class_fqn.split(".")[-1], "ERROR",
                error=_err_msg[:200],
            )

            # 降级重试：当转换器导致失败时（连接错误/空文本），移除转换器重试
            if ("Connection error" in _err_msg
                    or "Please provide valid text_to_add" in _err_msg
                    or "text_to_add value" in _err_msg) and attack_class_fqn.endswith("PromptSendingAttack"):
                self._logger.info("Retrying without converters (degraded mode)")
                try:
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                    attack = attack_class(**common_kwargs)
                    _execute_kwargs = {"objective": _extract_payload_text(payload)}
                    if self._memory_labels:
                        _execute_kwargs["memory_labels"] = self._memory_labels
                    attack_result = await attack.execute_async(**_execute_kwargs)

                    self._pyrit_attack_results.append(attack_result)
                    outcome = attack_result.outcome
                    is_success = outcome.name == "SUCCESS"
                    return {
                        "attack_class": attack_class_fqn.split(".")[-1],
                        "status": "success" if is_success else "failed",
                        "outcome": outcome.name,
                        "response": str(attack_result)[:200],
                        "conversation_id": attack_result.conversation_id,
                        "executed_turns": getattr(attack_result, "executed_turns", 1),
                        "execution_time_ms": getattr(attack_result, "execution_time_ms", 0),
                    }
                except Exception as e2:
                    self._logger.error(f"Degraded retry also failed: {e2}")

            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "error",
                "outcome": "ERROR",
                "response": _err_msg[:200],
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
            self._log_adapter.log_fallback(
                primary_class_fqn, fallback["class"],
                fallback_idx - 1, len(fallback_chain),
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
        """加载 YAML 文件（支持多文档分隔符 --- 和 ${VAR} 环境变量替换）"""
        from pathlib import Path
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Config file not found: %s", path)
            return {}
        with open(file_path, "r", encoding="utf-8") as f:
            import yaml
            docs = list(yaml.safe_load_all(f))
            config = docs[0] if docs else {}
        # 环境变量替换（${VAR} → 实际值）
        from ..utils.env_loader import resolve_env_vars
        return resolve_env_vars(config)

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
        from .matching.encoding_selector import get_converter_candidates

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
                "_surface_filtered": True,  # REV-1 已在此处过滤，execute_attack 无需重复
            })

        if skipped_by_filter:
            self._log_adapter.log_payload_filter(
                f"build_attack_list ({len(refs)} refs)",
                len(refs), len(attacks),
                filter_type="surface mismatch",
            )

        return attacks
