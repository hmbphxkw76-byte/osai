"""
Attack Executor Module
======================

对齐 pyrit.executor.attack

Layer 2: Attack 执行层
"1 个 objective → 1 个 AttackResult"

子模块：
- core/         核心引擎 + 横切配置
- single_turn/  单轮攻击执行器（直发型）
- multi_turn/   多轮攻击执行器（军师迭代型）
- compound/     Layer 3: 策略编排（SequentialAttack）
- streaming/    流式攻击（BargeIn, deprecated）
- component/    横切组件（SeedGroupBuilder）
"""

from src.executor.attack.core.attack_builder import (
    ATTACK_CLASS_MAP,
    ATTACK_METADATA,
    create_attack_instance,
    create_attack_adversarial_config,
    create_prepended_conversation_config,
    create_attack_result_attribution,
    create_attacks_for_scenario,
    create_attacks_for_ai_type,
    get_attack_metadata,
    is_multi_turn_attack,
    list_attacks_by_multi_turn,
    create_simple_attack,
    create_red_team_attack,
    create_jailbreak_attack,
    create_leakage_attack,
    create_xpia_attack,
)
from src.executor.attack.core.native_executor import (
    NativeAttackExecutor,
    DirectAttackExecutor,
    execute_single_attack,
    validate_attack_plan,
    get_attack_execution_summary,
)
from src.executor.attack.core.constants import (
    SINGLE_TURN_ATTACKS,
    TAP_FAMILY_ATTACKS,
    TREE_DEPTH_ATTACKS,
    MAX_TURNS_ATTACKS,
    MULTI_TURN_TECHNIQUES,
    NO_REFUSAL_SCORER_ATTACKS,
    NO_SCORING_ATTACKS,
)

__all__ = [
    # Attack Builder
    "ATTACK_CLASS_MAP",
    "ATTACK_METADATA",
    "create_attack_instance",
    "create_attack_adversarial_config",
    "create_prepended_conversation_config",
    "create_attack_result_attribution",
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
    # Native Attack Executor
    "NativeAttackExecutor",
    "DirectAttackExecutor",
    "execute_single_attack",
    "validate_attack_plan",
    "get_attack_execution_summary",
    # Constants
    "SINGLE_TURN_ATTACKS",
    "TAP_FAMILY_ATTACKS",
    "TREE_DEPTH_ATTACKS",
    "MAX_TURNS_ATTACKS",
    "MULTI_TURN_TECHNIQUES",
    "NO_REFUSAL_SCORER_ATTACKS",
    "NO_SCORING_ATTACKS",
]
