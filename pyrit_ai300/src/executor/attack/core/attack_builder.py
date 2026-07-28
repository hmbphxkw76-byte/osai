"""
Attack Builder
===============

本模块负责从配置创建 PyRIT Attack 实例（遵循开发规则 1.4.1）。

PyRIT 1.0.0 原生 API 对齐：
- AttackExecutor: 原生并行批量执行器（替代手动 execute_async 调度）
- AttackParameters: 原生参数管线（from_seed_group_async 自动提取三要素）
- AttackResultAttribution: 原生父级编排器关联
- PrependedConversationConfig: 原生前置对话 Converter 应用控制
- AttackAdversarialConfig: 完整的 system_prompt / first_message / adversarial_prompt_template 配置

对齐 pyrit.executor.attack.core.attack_config
"""

from typing import Any, Dict, List, Optional

from pyrit.executor.attack import (
    AttackAdversarialConfig,
    AttackConverterConfig,
    AttackParameters,
    AttackScoringConfig,
    AttackStrategy,
    ChunkedRequestAttack,
    CrescendoAttack,
    ManyShotJailbreakAttack,
    MultiPromptSendingAttack,
    PAIRAttack,
    PrependedConversationConfig,
    PromptSendingAttack,
    RedTeamingAttack,
    SequentialAttack,
    SkeletonKeyAttack,
    TAPAttack,
    TreeOfAttacksWithPruningAttack,
)
from pyrit.executor.attack.core.attack_result_attribution import AttackResultAttribution

# PyRIT 1.0.0 迁移说明：
# 以下 Attack 类在 1.0.0 中已被移除：
#   - RolePlayAttack       → 使用 PersuasionConverter 或 PolicyPuppetryConverter 替代
#   - FlipAttack           → 使用 FlipConverter 替代
#   - ContextComplianceAttack → 使用 PromptSendingAttack + PrependedConversationConfig 替代
# BargeInAttack 需要 audio_chunks 参数（AsyncIterator[bytes]），在纯文本场景下无法使用，
# 标记为 deprecated 并回退到 prompt_sending。

from src.core.config_loader import get_config_loader
from src.executor.attack.core.constants import NO_SCORING_ATTACKS, SINGLE_TURN_ATTACKS
from src.executor.attack.core.scenario_event_handler import ScenarioEventHandler


# ============================================================
# Attack 类映射
# ============================================================

ATTACK_CLASS_MAP: Dict[str, Any] = {
    "prompt_sending": PromptSendingAttack,
    "multi_prompt_sending": MultiPromptSendingAttack,
    "many_shot": ManyShotJailbreakAttack,
    "skeleton": SkeletonKeyAttack,
    # PyRIT 1.0.0: role_play / flip / context_compliance 已移除
    "chunked_request": ChunkedRequestAttack,
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
        "description": "角色扮演攻击（1.0.0已移除，回退到 prompt_sending + persuasion converter）",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
        "deprecated": True,
        "fallback": "prompt_sending",
    },
    "flip": {
        "description": "翻转攻击（1.0.0已移除 Attack 类，使用 FlipConverter 替代）",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
        "deprecated": True,
        "fallback": "prompt_sending",
    },
    "barge_in": {
        "description": "打断式攻击（需要 audio_chunks，纯文本场景回退到 prompt_sending）",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
        "deprecated": True,
        "fallback": "prompt_sending",
    },
    "chunked_request": {
        "description": "分块请求攻击",
        "multi_turn": False,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
    },
    "context_compliance": {
        "description": "上下文合规攻击（1.0.0已移除，使用 PromptSendingAttack + PrependedConversationConfig 替代）",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "prompt_injection",
        "deprecated": True,
        "fallback": "prompt_sending",
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
        "supports_max_backtracks": True,
    },
    "crescendo_simulated": {
        "description": "渐进式攻击（模拟）",
        "multi_turn": True,
        "requires_converter_config": False,
        "requires_scoring_config": False,
        "category": "jailbreak",
        "supports_max_backtracks": True,
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
    event_handler: Optional[ScenarioEventHandler] = None,
    **kwargs: Any,
) -> AttackStrategy:
    """
    创建 Attack 实例

    PyRIT 1.0.0 迁移说明：
    - 已移除的 Attack 类（role_play/flip/context_compliance/barge_in）自动回退到 prompt_sending
    - PromptSendingAttack 不再接受 attack_adversarial_config 参数
    - 多轮攻击（RedTeamingAttack/CrescendoAttack/PAIRAttack/TAPAttack/
      TreeOfAttacksWithPruningAttack）要求 attack_adversarial_config 为必填参数
    - CrescendoAttack 支持 max_backtracks 参数
    - PrependedConversationConfig 可通过 kwargs 传递给支持的 Attack

    L5 对齐优化：
    - 单轮攻击使用 AttackParameters.excluding() 显式约束参数集，
      防止 prepended_conversation 等多轮字段误传
    - 可选注入 ScenarioEventHandler 实现事件可观测性

    Args:
        technique_name: 攻击技术名称
        objective_target: 目标 PromptTarget
        attack_scoring_config: AttackScoringConfig
        attack_converter_config: AttackConverterConfig
        event_handler: 可选的 ScenarioEventHandler（注册到 Attack 实例）
        **kwargs: 其他参数（如 attack_adversarial_config, max_turns, max_backtracks,
                  prepended_conversation_config 等）

    Returns:
        AttackStrategy 实例

    Raises:
        ValueError: 如果技术名称不存在
    """
    # 检查是否为已弃用的技术，自动回退
    metadata = ATTACK_METADATA.get(technique_name, {})
    if metadata.get("deprecated", False):
        fallback_technique = metadata.get("fallback", "prompt_sending")
        technique_name = fallback_technique

    attack_class = ATTACK_CLASS_MAP.get(technique_name)
    if attack_class is None:
        raise ValueError(f"未知的攻击技术名称: {technique_name}")

    # 构造参数
    params = {
        "objective_target": objective_target,
        **kwargs,
    }

    if attack_scoring_config is not None and technique_name not in NO_SCORING_ATTACKS:
        params["attack_scoring_config"] = attack_scoring_config

    if attack_converter_config is not None:
        params["attack_converter_config"] = attack_converter_config

    # L5 对齐：单轮攻击使用 AttackParameters.excluding() 显式排除多轮字段
    # 防止 from_seed_group_async() 误传 prepended_conversation 给单轮攻击
    # 注意：部分 Attack 子类（如 SkeletonKeyAttack）不接受 params_type 参数，
    # 它们在 __init__ 内部自行设置 params_type，需用 inspect 检测
    if technique_name in SINGLE_TURN_ATTACKS:
        import inspect
        init_sig = inspect.signature(attack_class.__init__)
        if "params_type" in init_sig.parameters:
            single_turn_params = AttackParameters.excluding("prepended_conversation")
            params["params_type"] = single_turn_params

    attack = attack_class(**params)

    # L5 对齐：注册 ScenarioEventHandler 实现事件可观测性
    if event_handler is not None:
        attack._register_event_handler(event_handler)

    return attack


def create_attack_adversarial_config(
    judge_target: Any,
    metadata: Optional[Dict[str, Any]] = None,
) -> AttackAdversarialConfig:
    """
    创建 AttackAdversarialConfig（完整配置）

    PyRIT 1.0.0 的 AttackAdversarialConfig 支持：
    - target: 对抗 LLM target（必填）
    - system_prompt: 内联 Jinja 模板字符串或 SeedPrompt（可选）
    - first_message: 发送给对抗 chat 的首条消息（支持 {{ objective }} 模板变量）
    - adversarial_prompt_template: 每轮模板，包装 feedback_text

    当 YAML 数据集 metadata 中声明了 adversarial 配置时，使用自定义配置；
    否则使用 PyRIT 默认值（DEFAULT_ADVERSARIAL_FIRST_MESSAGE / DEFAULT_ADVERSARIAL_PROMPT_TEMPLATE）。

    Args:
        judge_target: 评审用 LLM Target（作为 adversarial chat）
        metadata: 来自 YAML 数据集的 metadata，可包含：
            - adversarial_system_prompt: 自定义系统提示
            - adversarial_system_prompt_path: YAML 文件路径加载系统提示
            - adversarial_first_message: 自定义首条消息
            - adversarial_prompt_template: 自定义每轮模板

    Returns:
        AttackAdversarialConfig 实例
    """
    metadata = metadata or {}

    config_kwargs: Dict[str, Any] = {"target": judge_target}

    # 从 YAML metadata 提取自定义对抗配置
    system_prompt = metadata.get("adversarial_system_prompt")
    system_prompt_path = metadata.get("adversarial_system_prompt_path")
    first_message = metadata.get("adversarial_first_message")
    adversarial_prompt_template = metadata.get("adversarial_prompt_template")

    # 支持通过 YAML 文件路径加载系统提示（优先级：内联 > 路径）
    if system_prompt:
        config_kwargs["system_prompt"] = system_prompt
    elif system_prompt_path:
        from pyrit.models.seeds.yaml_seed_loader import load_seed_from_yaml
        from pyrit.models import SeedPrompt
        from pathlib import Path
        prompt_path = Path(system_prompt_path)
        if not prompt_path.is_absolute():
            # 相对路径基于项目根目录解析
            from src.core.config_loader import get_config_loader
            project_root = Path(get_config_loader().config_path).parent
            prompt_path = project_root / prompt_path
        if prompt_path.exists():
            config_kwargs["system_prompt"] = load_seed_from_yaml(str(prompt_path), cls=SeedPrompt)
        else:
            import logging
            logging.getLogger(__name__).warning(
                f"adversarial_system_prompt_path '{prompt_path}' does not exist, using PyRIT default"
            )

    if first_message:
        config_kwargs["first_message"] = first_message
    if adversarial_prompt_template:
        config_kwargs["adversarial_prompt_template"] = adversarial_prompt_template

    return AttackAdversarialConfig(**config_kwargs)


def create_prepended_conversation_config(
    apply_converters_to_roles: Optional[List[str]] = None,
) -> PrependedConversationConfig:
    """
    创建 PrependedConversationConfig

    PyRIT 1.0.0 的 PrependedConversationConfig 控制：
    - apply_converters_to_roles: 哪些角色的消息应用 request converters
      默认对所有角色应用。设为 ["user"] 则仅对 user 消息应用。
    - message_normalizer: 非聊天目标的对话历史标准化器

    Args:
        apply_converters_to_roles: 应用 Converter 的角色列表，
            如 ["user"] 或 ["user", "assistant"]，None 表示全部角色

    Returns:
        PrependedConversationConfig 实例
    """
    from pyrit.models import ChatMessageRole

    if apply_converters_to_roles is not None:
        roles = [ChatMessageRole(role) for role in apply_converters_to_roles]
        return PrependedConversationConfig(apply_converters_to_roles=roles)

    return PrependedConversationConfig()


def create_attack_result_attribution(
    parent_id: str,
    parent_collection: str,
    parent_eval_hash: Optional[str] = None,
) -> AttackResultAttribution:
    """
    创建 AttackResultAttribution（原生父级编排器关联）

    PyRIT 1.0.0 的 AttackResultAttribution 用于：
    - 将 AttackResult 关联到父级编排器（如 Scenario）
    - parent_id: 父级实体 ID（如 Scenario result UUID）
    - parent_collection: 父级集合名称（如 atomic_attack_name）
    - parent_eval_hash: 可选的内容哈希，区分同名的不同配置

    Args:
        parent_id: 父级实体 ID
        parent_collection: 父级集合名称
        parent_eval_hash: 可选的内容哈希

    Returns:
        AttackResultAttribution 实例
    """
    return AttackResultAttribution(
        parent_id=parent_id,
        parent_collection=parent_collection,
        parent_eval_hash=parent_eval_hash,
    )


def create_attacks_for_scenario(
    scenario_name: str,
    objective_target: Any,
    chat_target: Any,
    use_preset_converters: bool = True,
) -> List[AttackStrategy]:
    """为特定 Scenario 创建所有 Attack 实例"""
    config_loader = get_config_loader()
    scenario_config = config_loader.get_scenario_config(scenario_name)

    if scenario_config is None:
        return []

    technique_names = scenario_config.get("attack_techniques", [])
    attacks = []

    for technique_name in technique_names:
        try:
            from src.scorers import create_attack_scoring_config_for_scenario
            scoring_config = create_attack_scoring_config_for_scenario(
                scenario_name, chat_target
            )

            converter_config = None
            if use_preset_converters:
                from src.converters import load_preset_converter_chain
                chain_names = scenario_config.get("converter_chains", [])
                if chain_names:
                    converter_config = load_preset_converter_chain(chain_names[0])

            attack_kwargs: Dict[str, Any] = {}
            metadata = ATTACK_METADATA.get(technique_name, {})
            if metadata.get("multi_turn", False) and technique_name not in NO_SCORING_ATTACKS:
                attack_kwargs["attack_adversarial_config"] = AttackAdversarialConfig(target=chat_target)

            attack = create_attack_instance(
                technique_name=technique_name,
                objective_target=objective_target,
                attack_scoring_config=scoring_config,
                attack_converter_config=converter_config,
                **attack_kwargs,
            )
            attacks.append(attack)
        except ValueError:
            pass

    return attacks


def create_attacks_for_ai_type(
    ai_system_type: str,
    objective_target: Any,
    chat_target: Any,
    use_preset_converters: bool = True,
) -> List[AttackStrategy]:
    """为特定 AI 系统类型创建推荐的 Attack 实例"""
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
    """获取 Attack 技术元数据"""
    metadata = ATTACK_METADATA.get(technique_name)
    if metadata is None:
        config_loader = get_config_loader()
        metadata = config_loader.get_attack_technique_config(technique_name)
    return metadata


def is_multi_turn_attack(technique_name: str) -> bool:
    """判断攻击是否为多轮攻击"""
    metadata = get_attack_metadata(technique_name)
    if metadata is None:
        return False
    return metadata.get("multi_turn", False)


def list_attacks_by_multi_turn(multi_turn: bool = True) -> List[str]:
    """列出指定类型（单轮/多轮）的所有 Attack"""
    return [
        name
        for name, metadata in ATTACK_METADATA.items()
        if metadata.get("multi_turn", False) == multi_turn
    ]


# ============================================================
# 常用 Attack 创建（快捷方法）
# ============================================================


def create_simple_attack(objective_target: Any, chat_target: Any) -> AttackStrategy:
    """创建简单 Attack（PromptSendingAttack + SelfAskTrueFalseScorer）"""
    from src.scorers import create_general_scorer
    scoring_config = create_general_scorer(chat_target)
    return create_attack_instance(
        technique_name="prompt_sending",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
    )


def create_red_team_attack(objective_target: Any, chat_target: Any) -> AttackStrategy:
    """创建红队攻击（RedTeamingAttack + SelfAskTrueFalseScorer）"""
    from src.scorers import create_general_scorer
    scoring_config = create_general_scorer(chat_target)
    return create_attack_instance(
        technique_name="red_teaming",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
        attack_adversarial_config=AttackAdversarialConfig(target=chat_target),
    )


def create_jailbreak_attack(
    objective_target: Any, chat_target: Any, converter_chain_name: str = "stealth_evasion"
) -> AttackStrategy:
    """创建越狱攻击（ManyShotJailbreakAttack + Converter 链）"""
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


def create_leakage_attack(objective_target: Any, chat_target: Any) -> AttackStrategy:
    """创建数据泄露攻击（RedTeamingAttack + CredentialLeakScorer）"""
    from src.scorers import create_leakage_scorer
    scoring_config = create_leakage_scorer(chat_target)
    return create_attack_instance(
        technique_name="red_teaming",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
        attack_adversarial_config=AttackAdversarialConfig(target=chat_target),
    )


def create_xpia_attack(objective_target: Any, chat_target: Any) -> AttackStrategy:
    """创建 XPIA 攻击（PromptSendingAttack + SelfAskTrueFalseScorer）"""
    from src.scorers import create_general_scorer
    scoring_config = create_general_scorer(chat_target)
    return create_attack_instance(
        technique_name="prompt_sending",
        objective_target=objective_target,
        attack_scoring_config=scoring_config,
    )
