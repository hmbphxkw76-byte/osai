"""
Attack Technique Constants
==========================

PyRIT 1.0.0 攻击技术分类常量集合。

从 direct_executor.py 提取，供所有执行器子模块共享。

这些常量定义了不同攻击技术在 PyRIT 1.0.0 API 中的行为差异：
- 哪些技术是单轮 vs 多轮
- 哪些技术使用 tree_depth vs max_turns
- 哪些技术不接受 refusal_scorer
- 哪些技术需要 TAPAttackScoringConfig
"""

# PyRIT 1.0.0: 单轮 Attack 不接受 attack_adversarial_config
SINGLE_TURN_ATTACKS = frozenset({
    "prompt_sending", "multi_prompt_sending", "many_shot", "skeleton",
    "barge_in", "chunked_request",
})

# PyRIT 1.0.0: TAP/PAIR 需要专用的 TAPAttackScoringConfig
TAP_FAMILY_ATTACKS = frozenset({"tap", "pair", "tree_of_attacks_pruned"})

# PyRIT 1.0.0: 使用 tree_depth 而非 max_turns 的攻击技术
TREE_DEPTH_ATTACKS = frozenset({"tap", "pair", "tree_of_attacks_pruned"})

# PyRIT 1.0.0: 使用 max_turns 的多轮攻击技术
MAX_TURNS_ATTACKS = frozenset({"red_teaming", "crescendo", "crescendo_simulated"})

# PyRIT 1.0.0: 多轮攻击技术集合（用于 SequentialChildAttack adversarial_chat 传递）
MULTI_TURN_TECHNIQUES = frozenset({
    "red_teaming", "crescendo", "crescendo_simulated",
    "tap", "pair", "tree_of_attacks_pruned",
})

# PyRIT 1.0.0: 不接受 refusal_scorer 的攻击技术（warn_if_set 会发出警告）
# PromptSendingAttack 及其子类 (ManyShotJailbreakAttack, SkeletonKeyAttack) + RedTeamingAttack
NO_REFUSAL_SCORER_ATTACKS = frozenset({
    "prompt_sending", "many_shot", "skeleton",
    "multi_prompt_sending", "chunked_request",
    "red_teaming",
})

# PyRIT 1.0.0: 不接受 attack_scoring_config 的 Attack
NO_SCORING_ATTACKS = frozenset({"barge_in"})
