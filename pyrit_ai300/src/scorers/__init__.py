"""
Scorers Module
==============

本模块负责 Scorer 的配置和注册。
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
    # PyRIT Registry 集成
    register_scorers_to_pyrit_registry,
    get_scorer_from_pyrit_registry,
    list_registered_scorers,
)

__all__ = [
    "SCORER_CLASS_MAP",
    "SCORER_METADATA",
    "create_scorer_instance",
    "create_scorers_for_scenario",
    "create_scorers_by_type",
    "create_attack_scoring_config",
    "create_attack_scoring_config_for_scenario",
    "get_scorer_metadata",
    "list_scorers_by_category",
    "list_scorers_for_attack_type",
    "requires_chat_target",
    "create_general_scorer",
    "create_leakage_scorer",
    "create_injection_scorer",
    "create_composite_scorer",
    "register_scorers_to_pyrit_registry",
    "get_scorer_from_pyrit_registry",
    "list_registered_scorers",
]