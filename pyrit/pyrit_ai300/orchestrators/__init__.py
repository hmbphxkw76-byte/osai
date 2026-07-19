# -*- coding: utf-8 -*-
"""
AI-300 Framework - Orchestrators Module v3.1
攻击流程编排器，使用 PyRIT 原生攻击策略执行

子模块：
- component_registry: PyRIT 组件映射表（转换器 + 评分器）
- attack_registry: PyRIT 攻击注册表
- attack_orchestrator: 攻击编排器主类
- smart_matcher: 智能匹配引擎
- pyrit_initializer: PyRIT 内存初始化（v3.1 新增）
- target_builder: PromptTarget 构建（v3.1 新增）
- converter_builder: 转换器配置构建（v3.1 新增）
- scorer_builder: 评分器构建（v3.1 新增）
- plugin_loader: 插件动态加载器（v3.3 新增）
"""

from .attack_orchestrator import AttackOrchestrator
from .component_registry import (
    CONVERTER_MAP,
    SCORER_MAP,
    SPECIAL_PRESETS,
    LLM_BACKEND_SCORERS,
    CONVERTER_NAME_MAP,
    SCORER_NAME_MAP,
    CONVERTERS_NEEDING_TARGET,
)
from .attack_registry import (
    ATTACK_REGISTRY,
    list_attacks,
    get_attack_info,
    get_attack_class,
    list_types,
)
from .smart_matcher import (
    SmartMatcher,
    select_attack_strategy,
    select_preset_strategy,
    PyRITAttack,
    AttackProbeFamily,
)
from .encoding_selector import (
    TargetProfile,
    filter_converters_by_owasp,
    filter_converters_by_language,
    get_converter_candidates,
    select_encodings_for_payload,
    select_encodings_batch,
    build_profile_and_select,
    probe_target_model,
    CONVERTER_OWASP_COMPATIBILITY,
    LANGUAGE_INCOMPATIBLE_CONVERTERS,
)
# v3.1 新增子模块
from .pyrit_initializer import PyRITInitializer
from .target_builder import TargetBuilder
from .converter_builder import ConverterBuilder
from .scorer_builder import ScorerBuilder
from .ensemble_scorer import EnsembleScorer, create_ensemble_for_owasp
from .semantic_scorer import SemanticScorer, create_semantic_scorer, get_supported_owasp_ids
from .plugin_loader import PluginLoader, get_plugin_loader, load_plugins

__all__ = [
    # AttackOrchestrator
    "AttackOrchestrator",
    # Component Registry
    "CONVERTER_MAP",
    "SCORER_MAP",
    "SPECIAL_PRESETS",
    "LLM_BACKEND_SCORERS",
    "CONVERTER_NAME_MAP",
    "SCORER_NAME_MAP",
    "CONVERTERS_NEEDING_TARGET",
    # Attack Registry
    "ATTACK_REGISTRY",
    "list_attacks",
    "get_attack_info",
    "get_attack_class",
    "list_types",
    # Smart Matcher
    "SmartMatcher",
    "select_attack_strategy",
    "select_preset_strategy",
    "PyRITAttack",
    "AttackProbeFamily",
    # Encoding Selector
    "TargetProfile",
    "filter_converters_by_owasp",
    "filter_converters_by_language",
    "get_converter_candidates",
    "select_encodings_for_payload",
    "select_encodings_batch",
    "build_profile_and_select",
    "probe_target_model",
    "CONVERTER_OWASP_COMPATIBILITY",
    "LANGUAGE_INCOMPATIBLE_CONVERTERS",
    # v3.1 新增子模块
    "PyRITInitializer",
    "TargetBuilder",
    "ConverterBuilder",
    "ScorerBuilder",
    # v3.3 新增子模块
    "PluginLoader",
    "get_plugin_loader",
    "load_plugins",
    # REV-4: Ensemble Scorer
    "EnsembleScorer",
    "create_ensemble_for_owasp",
    # REV-5: Semantic Scorer
    "SemanticScorer",
    "create_semantic_scorer",
    "get_supported_owasp_ids",
]
