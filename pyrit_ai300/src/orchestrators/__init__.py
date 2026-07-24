"""
Orchestrators Module
====================

本模块负责攻击编排，包括单 Attack 创建和批量攻击执行。
"""

from src.orchestrators.attack_builder import (
    # Attack 类映射
    ATTACK_CLASS_MAP,
    ATTACK_METADATA,
    # Attack 实例创建
    create_attack_instance,
    create_attacks_for_scenario,
    create_attacks_for_ai_type,
    # Attack 元数据查询
    get_attack_metadata,
    is_multi_turn_attack,
    list_attacks_by_multi_turn,
    # 常用 Attack 创建（快捷方法）
    create_simple_attack,
    create_red_team_attack,
    create_jailbreak_attack,
    create_leakage_attack,
    create_xpia_attack,
)

from src.orchestrators.batch_orchestrator import (
    BatchAttackOrchestrator,
    execute_batch_attacks,
)

__all__ = [
    "ATTACK_CLASS_MAP",
    "ATTACK_METADATA",
    "create_attack_instance",
    "create_attacks_for_scenario",
    "create_attacks_for_ai_type",
    "get_attack_metadata",
    "is_multi_turn_attack",
    "list_attacks_by_multi_turn",
    "create_simple_attack",
    "create_red_team_attack",
    "create_jailbreak_attack",
    "create_leakage_attack",
    "create_xpia_attack",
    "BatchAttackOrchestrator",
    "execute_batch_attacks",
]
