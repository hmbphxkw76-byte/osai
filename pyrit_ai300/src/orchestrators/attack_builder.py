"""
Attack Builder
===============

本模块负责从配置创建 PyRIT Attack 实例（遵循开发规则 1.4.1）。
"""

from typing import Any, Dict, List, Optional

from pyrit.executor.attack import (
    PromptSendingAttack,
    RedTeamingAttack,
    CrescendoAttack,
    PAIRAttack,
    TAPAttack,
    TreeOfAttacksWithPruningAttack,
    ManyShotJailbreakAttack,
    SkeletonKeyAttack,
    RolePlayAttack,
    FlipAttack,
    BargeInAttack,
    ChunkedRequestAttack,
    ContextComplianceAttack,
    SequentialAttack,
    MultiPromptSendingAttack,
    AttackScoringConfig,
    AttackConverterConfig,
)

from src.core.config_loader import get_config_loader


# ============================================================
# Attack 类映射
# ============================================================

ATTACK_CLASS_MAP: Dict[str, Any] = {
    "prompt_sending": PromptSendingAttack,
    "multi_prompt_sending": MultiPromptSendingAttack,
    "many_shot": ManyShotJailbreakAttack,
    "skeleton": SkeletonKeyAttack,
    "role_play": RolePlayAttack,
    "flip": FlipAttack,
    "barge_in": BargeInAttack,
    "chunked_request": ChunkedRequestAttack,
    "context_compliance": ContextComplianceAttack,
    "red_teaming": RedTeamingAttack,
    "crescendo": CrescendoAttack,
    "crescendo_simulated": CrescendoAttack,
    "tap": TAPAttack,
    "pair": PAIRAttack,
    "tree_of_attacks_pruned": TreeOfAttacksWithPruningAttack,
    "sequential": SequentialAttack,
}


# ============================================================
# Attack 类元数据
# ============================================================

ATTACK_METADATA: Dict[str, Dict[str, Any]] = {
    "prompt_sending": {
        "description": "单轮批量提示发送",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
    "multi_prompt_sending": {
        "description": "批量多提示发送",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
    "many_shot": {
        "description": "多示例越狱",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "skeleton": {
        "description": "骨架密钥攻击",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "role_play": {
        "description": "角色扮演攻击",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "flip": {
        "description": "翻转攻击",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
    "barge_in": {
        "description": "打断式攻击",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
    "chunked_request": {
        "description": "分块请求攻击",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
    "context_compliance": {
        "description": "上下文合规攻击",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
    "red_teaming": {
        "description": "多轮红队攻击",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "crescendo": {
        "description": "渐进式攻击",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "crescendo_simulated": {
        "description": "渐进式攻击（模拟）",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "tap": {
        "description": "树状攻击",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "pair": {
        "description": "PAIR 攻击",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "tree_of_attacks_pruned": {
        "description": "剪枝攻击树",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
    },
    "sequential": {
        "description": "顺序组合攻击",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
}


# ============================================================
# Attack 创建函数
# ============================================================


def create_attack_instance(
    technique_name: str,
    objective_target: Any,
    attack_scoring_config: Optional[AttackScoringConfig] = None,
    attack_converter_config: Optional[AttackConverterConfig] = None,
    **kwargs: Any,
) -> Any:
    """
    创建 Attack 实例

    Args:
        technique_name: 攻击技术名称
        objective_target: 目标 PromptTarget
        attack_scoring_config: AttackScoringConfig
        attack_converter_config: AttackConverterConfig
        **kwargs: 其他参数

    Returns:
        Attack 实例

    Raises:
        ValueError: 如果技术名称不存在
    """
    attack_class = ATTACK_CLASS_MAP.get(technique_name)
    if attack_class is None:
        raise ValueError(f"未知的攻击技术名称: {technique_name}")

    # 构造参数
    params = {
        "objective_target": objective_target,
        **kwargs,
    }

    if attack_scoring_config is not None:
        params["attack_scoring_config"] = attack_scoring_config

    if attack_converter_config is not None:
        params["attack_converter_config"] = attack_converter_config

    return attack_class(**params)


def create_attacks_for_scenario(
    scenario_name: str,
    objective_target: Any,
    chat_target: Any,
    use_preset_converters: bool = True,
) -> List[Any]:
    """
    为特定 Scenario 创建所有 Attack 实例

    Args:
        scenario_name: Scenario 名称
        objective_target: 目标 PromptTarget
        chat_target: 评审用 LLM Target
        use_preset_converters: 是否使用预设 Converter 链

    Returns:
        Attack 实例列表
    """
    config_loader = get_config_loader()
    scenario_config = config_loader.get_scenario_config(scenario_name)

    if scenario_config is None:
        return []

    technique_names = scenario_config.get("attack_techniques", [])
    attacks = []

    for technique_name in technique_names:
        try:
            # 创建 AttackScoringConfig
            from src.scorers import create_attack_scoring_config_for_scenario
            scoring_config = create_attack_scoring_config_for_scenario(
                scenario_name, chat_target
            )

            # 创建 AttackConverterConfig
            converter_config = None
            if use_preset_converters:
                from src.converters import load_preset_converter_chain
                chain_names = scenario_config.get("converter_chains", [])
                if chain_names:
                    converter_config = load_preset_converter_chain(chain_names[0])

            attack = create_attack_instance(
                technique_name=technique_name,
                objective_target=objective_target,
                attack_scoring_config=scoring_config,
                attack_converter_config=converter_config,
            )
            attacks.append(attack)
        except ValueError as e:
            # 忽略无法创建的 Attack
            pass

    return attacks


def create_attacks_for_ai_type(
    ai_system_type: str,
    objective_target: Any,
    chat_target: Any,
    use_preset_converters: bool = True,
) -> List[Any]:
    """
    为特定 AI 系统类型创建推荐的 Attack 实例

    Args:
        ai_system_type: AI 系统类型
        objective_target: 目标 PromptTarget
        chat_target: 评审用 LLM Target
        use_preset_converters: 是否使用预设 Converter 链

    Returns:
        Attack 实例列表
    """
    config_loader = get_config_loader()
    scenario_names = config_loader.get_ai_type_to_scenario_mapping().get(ai_system_type, [])

    attacks = []
    for scenario_name in scenario_names:
        attacks.extend(
            create_attacks_for_scenario(
                scenario_name, objective_target, chat_target, use_preset_converters
            )
        )

    return attacks


# ============================================================
# Attack 元数据查询
# ============================================================


def get_attack_metadata(technique_name: str) -> Optional[Dict[str, Any]]:
    """
    获取 Attack 技术元数据

    Args:
        technique_name: 技术名称

    Returns:
        技术元数据字典，如果不存在则返回 None
    """
    metadata = ATTACK_METADATA.get(technique_name)
    if metadata is None:
        # 尝试从配置文件加载
        config_loader = get_config_loader()
        metadata = config_loader.get_attack_technique_config(technique_name)
    return metadata


def is_multi_turn_attack(technique_name: str) -> bool:
    """
    判断攻击是否为多轮攻击

    Args:
        technique_name: 技术名称

    Returns:
        是否为多轮攻击
    """
    metadata = get_attack_metadata(technique_name)
    if metadata is None:
        return False
    return metadata.get("multi_turn", False)


def list_attacks_by_multi_turn(multi_turn: bool = True) -> List[str]:
    """
    列出指定类型（单轮/多轮）的所有 Attack

    Args:
        multi_turn: 是否为多轮攻击

    Returns:
        Attack 技术名称列表
    """
    return [
        name
        for name, metadata in ATTACK_METADATA.items()
        if metadata.get("multi_turn", False) == multi_turn
    ]


# ============================================================
# 常用 Attack 创建（快捷方法）
# ============================================================


def create_simple_attack(
    objective_target: Any,
    chat_target: Any,
) -> Any:
    """
    创建简单 Attack（PromptSendingAttack + SelfAskTrueFalseScorer）

    Args:
        objective_target: 目标 PromptTarget
        chat_target: 评审用 LLM Target

    Returns:
        Attack 实例
    """
    from src.scorers import create_general_scorer
    scoring_config = create_general_scorer(chat_target)

    return create_attack_instance(
        technique_name="prompt_sending",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
    )


def create_red_team_attack(
    objective_target: Any,
    chat_target: Any,
) -> Any:
    """
    创建红队攻击（RedTeamingAttack + SelfAskTrueFalseScorer）

    Args:
        objective_target: 目标 PromptTarget
        chat_target: 评审用 LLM Target

    Returns:
        Attack 实例
    """
    from src.scorers import create_general_scorer
    scoring_config = create_general_scorer(chat_target)

    return create_attack_instance(
        technique_name="red_teaming",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
    )


def create_jailbreak_attack(
    objective_target: Any,
    chat_target: Any,
    converter_chain_name: str = "stealth_evasion",
) -> Any:
    """
    创建越狱攻击（ManyShotJailbreakAttack + Converter 链）

    Args:
        objective_target: 目标 PromptTarget
        chat_target: 评审用 LLM Target
        converter_chain_name: Converter 链名称

    Returns:
        Attack 实例
    """
    from src.scorers import create_general_scorer
    from src.converters import load_preset_converter_chain

    scoring_config = create_general_scorer(chat_target)
    converter_config = load_preset_converter_chain(converter_chain_name)

    return create_attack_instance(
        technique_name="many_shot",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
        attack_converter_config=converter_config,
    )


def create_leakage_attack(
    objective_target: Any,
    chat_target: Any,
) -> Any:
    """
    创建数据泄露攻击（RedTeamingAttack + CredentialLeakScorer）

    Args:
        objective_target: 目标 PromptTarget
        chat_target: 评审用 LLM Target

    Returns:
        Attack 实例
    """
    from src.scorers import create_leakage_scorer
    scoring_config = create_leakage_scorer(chat_target)

    return create_attack_instance(
        technique_name="red_teaming",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
    )


def create_xpia_attack(
    objective_target: Any,
    chat_target: Any,
) -> Any:
    """
    创建 XPIA 攻击（PromptSendingAttack + SelfAskTrueFalseScorer）

    注意：XPIA 实际上使用 XPIATestWorkflow，这里返回的是基础 Attack

    Args:
        objective_target: 目标 PromptTarget
        chat_target: 评审用 LLM Target

    Returns:
        Attack 实例
    """
    from src.scorers import create_general_scorer
    scoring_config = create_general_scorer(chat_target)

    return create_attack_instance(
        technique_name="prompt_sending",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
    )