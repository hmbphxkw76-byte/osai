"""
Scorers Module
==============

本模块负责 Scorer 的配置和注册（遵循开发规则 1.4.1）。

PyRIT 1.0.0 Scoring 架构完整对齐（L5）：
- ScorerPromptValidator 预设配置体系（7 种预设 + 自定义工厂）
- ResponseHandler 响应契约层（JSON Schema + Callable 逃生舱）
- TrueFalseCompositeScorer 组合评分器（AND/OR/MAJORITY 逻辑组合）
- TrueFalseInverterScorer 逻辑取反
- FloatScaleThresholdScorer + FloatScaleScoreAggregator 聚合器配置
- TrueFalseQuestionPaths 9 种预设评分问题
- Blocked Content 策略配置（score_blocked_content / raise_if_scorer_blocks）
- role_filter / skip_on_error_result 评分过滤
- ConversationScorer 对话级评分
- ScorerEvaluator 评估框架（ObjectiveScorerMetrics / HarmScorerMetrics）
- eval_hash 身份追踪 + RegistryUpdateBehavior 缓存策略
- Registry 命名空间修复（类名而非 snake_case）
"""

from src.scorers.scorer_registry import (
    # Scorer 类映射
    SCORER_CLASS_MAP,
    SCORER_METADATA,
    # Scorer 实例创建
    create_scorer_instance,
    create_scorers_for_scenario,
    create_scorers_by_type,
    # AttackScoringConfig 创建
    create_attack_scoring_config,
    create_attack_scoring_config_for_scenario,
    # Scorer 元数据查询
    get_scorer_metadata,
    list_scorers_by_category,
    list_scorers_for_attack_type,
    requires_chat_target,
    # 常用 Scorer 创建（快捷方法）
    create_general_scorer,
    create_leakage_scorer,
    create_injection_scorer,
    create_composite_scorer,
    create_refusal_scorer,
    create_tap_scoring_config,
    create_llama_guard_scorer,
    # ScorerPromptValidator 预设配置（PyRIT 1.0.0）
    SCORER_VALIDATOR_PRESETS,
    get_validator_preset,
    create_validator,
    create_scorer_with_validator,
    # ResponseHandler 响应契约工厂（PyRIT 1.0.0）
    create_json_response_handler,
    create_callable_response_handler,
    create_scorer_with_response_handler,
    # TrueFalseCompositeScorer 组合评分器工厂（PyRIT 1.0.0）
    create_composite_scorer_with_aggregator,
    create_and_composite_scorer,
    create_or_composite_scorer,
    create_majority_composite_scorer,
    # TrueFalseInverterScorer 逻辑取反工厂（PyRIT 1.0.0）
    create_inverter_scorer,
    # FloatScaleThresholdScorer + Aggregator 配置工厂（PyRIT 1.0.0）
    create_float_scale_threshold_scorer,
    # TrueFalseQuestionPaths 预设问题工厂（PyRIT 1.0.0）
    create_scorer_from_preset_question,
    list_preset_questions,
    # Blocked Content 策略配置（PyRIT 1.0.0）
    configure_blocked_content_strategy,
    configure_for_red_teaming,
    configure_for_strict,
    # score_response 包装器（role_filter / skip_on_error 支持）
    score_response_with_scorers,
    score_text_with_scorer,
    score_batch_with_scorer,
    # ConversationScorer 对话级评分工厂（PyRIT 1.0.0）
    create_conversation_level_scorer,
    # Scorer Metrics 查询与比较（PyRIT 1.0.0）
    get_scorer_evaluation_metrics,
    get_scorer_eval_hash,
    list_all_scorer_evaluation_metrics,
    find_scorer_metrics_by_hash,
    compare_scorer_metrics,
    # PyRIT Registry 集成（修复命名空间）
    register_scorers_to_pyrit_registry,
    get_scorer_from_pyrit_registry,
    list_registered_scorers,
)
from src.scorers.evaluator import (
    ScorerAccuracyEvaluator,
    create_scorer_evaluator,
    evaluate_scorer_quick,
    format_metrics_report,
)

__all__ = [
    # Scorer 类映射
    "SCORER_CLASS_MAP",
    "SCORER_METADATA",
    # Scorer 实例创建
    "create_scorer_instance",
    "create_scorers_for_scenario",
    "create_scorers_by_type",
    # AttackScoringConfig 创建
    "create_attack_scoring_config",
    "create_attack_scoring_config_for_scenario",
    # Scorer 元数据查询
    "get_scorer_metadata",
    "list_scorers_by_category",
    "list_scorers_for_attack_type",
    "requires_chat_target",
    # 常用 Scorer 创建（快捷方法）
    "create_general_scorer",
    "create_leakage_scorer",
    "create_injection_scorer",
    "create_composite_scorer",
    "create_refusal_scorer",
    "create_tap_scoring_config",
    "create_llama_guard_scorer",
    # ScorerPromptValidator 预设配置
    "SCORER_VALIDATOR_PRESETS",
    "get_validator_preset",
    "create_validator",
    "create_scorer_with_validator",
    # ResponseHandler 响应契约工厂
    "create_json_response_handler",
    "create_callable_response_handler",
    "create_scorer_with_response_handler",
    # TrueFalseCompositeScorer 组合评分器工厂
    "create_composite_scorer_with_aggregator",
    "create_and_composite_scorer",
    "create_or_composite_scorer",
    "create_majority_composite_scorer",
    # TrueFalseInverterScorer 逻辑取反工厂
    "create_inverter_scorer",
    # FloatScaleThresholdScorer + Aggregator 配置工厂
    "create_float_scale_threshold_scorer",
    # TrueFalseQuestionPaths 预设问题工厂
    "create_scorer_from_preset_question",
    "list_preset_questions",
    # Blocked Content 策略配置
    "configure_blocked_content_strategy",
    "configure_for_red_teaming",
    "configure_for_strict",
    # score_response 包装器
    "score_response_with_scorers",
    "score_text_with_scorer",
    "score_batch_with_scorer",
    # ConversationScorer 对话级评分工厂
    "create_conversation_level_scorer",
    # Scorer Metrics 查询与比较
    "get_scorer_evaluation_metrics",
    "get_scorer_eval_hash",
    "list_all_scorer_evaluation_metrics",
    "find_scorer_metrics_by_hash",
    "compare_scorer_metrics",
    # PyRIT Registry 集成
    "register_scorers_to_pyrit_registry",
    "get_scorer_from_pyrit_registry",
    "list_registered_scorers",
    # 评估器
    "ScorerAccuracyEvaluator",
    "create_scorer_evaluator",
    "evaluate_scorer_quick",
    "format_metrics_report",
]
