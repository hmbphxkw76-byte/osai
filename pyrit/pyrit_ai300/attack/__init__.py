# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Layer
攻击层：使用 PyRIT 原生攻击策略执行

子模块：
- engine: AttackOrchestrator 攻击编排器主类
- registry: PyRIT 攻击注册表
- pyrit/: PyRIT 专用组件（initializer, component_registry, converter_builder, scorer_builder, target_builder）
- matching/: 智能匹配与选择算法（smart_matcher, encoding_selector, model_fingerprinter）
- feedback/: 反馈闭环组件（adaptive_early_stopping, batch_cross_validator, converter_stacker）
- scoring/: 评分器组件（ensemble_scorer, semantic_scorer）
- auth/: 认证子模块（header_parser, playwright_injector）
- interactions/: 交互子模块（web_chat）
- profile_loader: 读取 TargetProfile → SmartMatcher 参数
- plugin_loader: 插件动态加载器
- rate_controller: 速率控制器
- ab_test_runner: A/B 测试运行器
- chain_orchestrator: 攻击链编排器
"""

from .engine import AttackOrchestrator
from .pyrit import (
    CONVERTER_MAP,
    SCORER_MAP,
    SPECIAL_PRESETS,
    LLM_BACKEND_SCORERS,
    CONVERTER_NAME_MAP,
    SCORER_NAME_MAP,
    CONVERTERS_NEEDING_TARGET,
    PyRITInitializer,
    ConverterBuilder,
    ScorerBuilder,
    TargetBuilder,
)
from .registry import (
    ATTACK_REGISTRY,
    list_attacks,
    get_attack_info,
    get_attack_class,
    list_types,
)
from .matching import (
    SmartMatcher,
    select_attack_strategy,
    select_preset_strategy,
    PyRITAttack,
    AttackProbeFamily,
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
    ModelFingerprinter,
    ModelFingerprint,
)
from .scoring import (
    EnsembleScorer,
    create_ensemble_for_owasp,
    SemanticScorer,
    create_semantic_scorer,
    get_supported_owasp_ids,
)
from .feedback import (
    AdaptiveEarlyStopper,
    AttackCost,
    EarlyStopDecision,
    BatchCrossValidator,
    CrossValidationReport,
    ConverterStacker,
)
from .plugin_loader import PluginLoader, get_plugin_loader, load_plugins
from .profile_loader import ProfileLoader

__all__ = [
    # AttackOrchestrator
    "AttackOrchestrator",
    # PyRIT Components
    "CONVERTER_MAP",
    "SCORER_MAP",
    "SPECIAL_PRESETS",
    "LLM_BACKEND_SCORERS",
    "CONVERTER_NAME_MAP",
    "SCORER_NAME_MAP",
    "CONVERTERS_NEEDING_TARGET",
    "PyRITInitializer",
    "ConverterBuilder",
    "ScorerBuilder",
    "TargetBuilder",
    # Attack Registry
    "ATTACK_REGISTRY",
    "list_attacks",
    "get_attack_info",
    "get_attack_class",
    "list_types",
    # Matching
    "SmartMatcher",
    "select_attack_strategy",
    "select_preset_strategy",
    "PyRITAttack",
    "AttackProbeFamily",
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
    "ModelFingerprinter",
    "ModelFingerprint",
    # Scoring
    "EnsembleScorer",
    "create_ensemble_for_owasp",
    "SemanticScorer",
    "create_semantic_scorer",
    "get_supported_owasp_ids",
    # Feedback
    "AdaptiveEarlyStopper",
    "AttackCost",
    "EarlyStopDecision",
    "BatchCrossValidator",
    "CrossValidationReport",
    "ConverterStacker",
    # Plugin Loader
    "PluginLoader",
    "get_plugin_loader",
    "load_plugins",
    # Profile Loader
    "ProfileLoader",
]
