"""
AI-300 Technique Factories — 对齐 pyrit.setup.initializers.techniques
=====================================================================

P1: Technique 注册与发现 — AttackTechniqueFactory + AttackTechniqueRegistry

从项目的 ATTACK_CLASS_MAP 构建 AttackTechniqueFactory 实例，
注册到 PyRIT 原生 AttackTechniqueRegistry。

分组模块（对齐 PyRIT 原生 core.py / extra.py）：
  - core: 通用技术（prompt_sending, role_play, many_shot, crescendo, red_teaming, tap）
  - extra: 可选技术（pair, skeleton_key, encoding converters）
  - encoding: 编码攻击技术（rot13, base64, caesar 等）

P0 (Converter-Aware): 为每个基础攻击技术注册多个 Converter 变体作为
独立的 AttackTechniqueFactory，将 AttackConverterConfig 烘焙到 attack_kwargs 中。
原生 AdaptiveTechniqueDispatcher 的 FIRST_SUCCESS 自动在首个成功变体处停止。

注册是按名称幂等的，所以可组合：运行多次只添加尚未注册的技术。
"""

import logging
from typing import Any, Dict, List

from pyrit.executor.attack import (
    AttackStrategy,
    ChunkedRequestAttack,
    CrescendoAttack,
    ManyShotJailbreakAttack,
    MultiPromptSendingAttack,
    PAIRAttack,
    PromptSendingAttack,
    RedTeamingAttack,
    SkeletonKeyAttack,
    TAPAttack,
    TreeOfAttacksWithPruningAttack,
)
from pyrit.executor.attack.core.attack_config import AttackConverterConfig
from pyrit.registry import AttackTechniqueRegistry
from pyrit.scenario.core.attack_technique_factory import AttackTechniqueFactory

logger = logging.getLogger(__name__)


# ============================================================
# P0: Converter 变体配置
# ============================================================

# Converter 变体链 — 从 payload_strategy_matrix.yaml 的 converter_chains 段加载
# 非 LLM 链可在无 converter_target 时创建；LLM 链需 converter_target
CONVERTER_VARIANT_CHAINS: Dict[str, Dict[str, Any]] = {
    "stealth_evasion": {
        "requires_llm": False,
        "priority": 1,
        "description": "Unicode 混淆 + Base64 + 后缀追加",
    },
    "encoding_bypass": {
        "requires_llm": False,
        "priority": 2,
        "description": "Base64 + ROT13 + Caesar 编码绕过",
    },
    "multi_encoding_v2": {
        "requires_llm": False,
        "priority": 1,
        "description": "四层编码: Base64 + ROT13 + Caesar(5) + Atbash",
    },
    "agent_injection_chain": {
        "requires_llm": False,
        "priority": 3,
        "description": "Agent 注入: Unicode 混淆 + 后缀追加 + 任务伪装",
    },
    "llm_assisted": {
        "requires_llm": True,
        "priority": 3,
        "description": "说服 + 语气 + 翻译 (LLM 辅助)",
    },
    "persuasion_authority": {
        "requires_llm": True,
        "priority": 4,
        "description": "权威说服: authority_endorsement + formal + en",
    },
    "persuasion_chain": {
        "requires_llm": True,
        "priority": 5,
        "description": "说服攻击链 (LLM 辅助)",
    },
}

# 基础技术 → 适用的 Converter 变体链名列表
# 只有单轮技术适合追加 Converter（多轮技术内部已有 adversarial chat 迭代）
BASE_TECHNIQUES_FOR_VARIANTS: Dict[str, List[str]] = {
    "prompt_sending": [
        "multi_encoding_v2", "stealth_evasion", "encoding_bypass",
        "agent_injection_chain", "llm_assisted", "persuasion_authority",
    ],
    "many_shot": [
        "multi_encoding_v2", "stealth_evasion", "encoding_bypass",
    ],
    "skeleton_key": [
        "stealth_evasion", "encoding_bypass",
    ],
    "chunked_request": [
        "encoding_bypass", "agent_injection_chain",
    ],
    "multi_prompt_sending": [
        "encoding_bypass",
    ],
}


# ============================================================
# 核心技术元数据
# ============================================================

AI300_TECHNIQUE_METADATA: Dict[str, Dict[str, Any]] = {
    # ── 基线技术 ──
    "prompt_sending": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "default", "light", "core"],
        "description": "基线提示发送（无转换器）",
        "uses_adversarial": False,
        "category": "baseline",
    },
    # ── 编码攻击 ──
    "rot13": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "ROT13 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "rot13",
    },
    "base64": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "Base64 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "base64",
    },
    "caesar": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "Caesar 密码编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "caesar",
    },
    "binary": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "二进制编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "binary",
    },
    "morse": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "摩尔斯电码编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "morse",
    },
    "leetspeak": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "LeetSpeak 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "leetspeak",
    },
    "flip": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "light", "core"],
        "description": "翻转编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "flip",
    },
    "char_swap": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "字符交换编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "char_swap",
    },
    "diacritic": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "变音符号编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "diacritic",
    },
    "character_space": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "字符间空格编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "character_space",
    },
    "string_join": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "字符串连接编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "string_join",
    },
    "suffix_append": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "后缀追加编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "suffix_append",
    },
    "atbash": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "Atbash 密码编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "atbash",
    },
    "url": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "encoding", "core"],
        "description": "URL 编码攻击",
        "uses_adversarial": False,
        "category": "encoding",
        "converter": "url",
    },
    # ── 角色扮演 ──
    "role_play_movie_script": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：电影剧本",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_persuasion": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：说服",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_persuasion_written": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：书面说服",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_trivia_game": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：问答游戏",
        "uses_adversarial": True,
        "category": "role_play",
    },
    "role_play_video_game": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "角色扮演：视频游戏",
        "uses_adversarial": True,
        "category": "role_play",
    },
    # ── Crescendo 变体 ──
    "crescendo_simulated": {
        "attack_class": CrescendoAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击（模拟对话）",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo_movie_director": {
        "attack_class": CrescendoAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击：电影导演",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo_history_lecture": {
        "attack_class": CrescendoAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击：历史讲座",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo_journalist_interview": {
        "attack_class": CrescendoAttack,
        "tags": ["single_turn", "core"],
        "description": "渐进式攻击：记者采访",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    "crescendo": {
        "attack_class": CrescendoAttack,
        "tags": ["multi_turn", "core"],
        "description": "渐进式攻击",
        "uses_adversarial": True,
        "category": "crescendo",
    },
    # ── 上下文合规 ──
    "context_compliance": {
        "attack_class": PromptSendingAttack,
        "tags": ["single_turn", "light", "core"],
        "description": "上下文合规攻击",
        "uses_adversarial": True,
        "category": "context_compliance",
    },
    # ── 多轮攻击 ──
    "many_shot": {
        "attack_class": ManyShotJailbreakAttack,
        "tags": ["multi_turn", "light", "core"],
        "description": "多示例越狱攻击",
        "uses_adversarial": False,
        "category": "jailbreak",
    },
    "red_teaming": {
        "attack_class": RedTeamingAttack,
        "tags": ["multi_turn", "light", "core"],
        "description": "多轮红队攻击",
        "uses_adversarial": True,
        "category": "jailbreak",
    },
    "tap": {
        "attack_class": TAPAttack,
        "tags": ["multi_turn", "core"],
        "description": "树状攻击（剪枝）",
        "uses_adversarial": True,
        "category": "jailbreak",
    },
    "pair": {
        "attack_class": PAIRAttack,
        "tags": ["multi_turn", "extra"],
        "description": "PAIR 攻击",
        "uses_adversarial": True,
        "category": "jailbreak",
    },
    "tree_of_attacks_pruned": {
        "attack_class": TreeOfAttacksWithPruningAttack,
        "tags": ["multi_turn", "core"],
        "description": "剪枝攻击树",
        "uses_adversarial": True,
        "category": "jailbreak",
    },
    # ── 额外技术 ──
    "skeleton_key": {
        "attack_class": SkeletonKeyAttack,
        "tags": ["single_turn", "extra"],
        "description": "骨架密钥攻击",
        "uses_adversarial": False,
        "category": "jailbreak",
    },
    "multi_prompt_sending": {
        "attack_class": MultiPromptSendingAttack,
        "tags": ["single_turn", "core"],
        "description": "批量多提示发送",
        "uses_adversarial": False,
        "category": "baseline",
    },
    "chunked_request": {
        "attack_class": ChunkedRequestAttack,
        "tags": ["single_turn", "core"],
        "description": "分块请求攻击",
        "uses_adversarial": False,
        "category": "prompt_injection",
    },
}


# ============================================================
# Factory 构建函数
# ============================================================

def _build_factory(name: str, metadata: Dict[str, Any]) -> AttackTechniqueFactory:
    """从元数据构建单个 AttackTechniqueFactory"""
    return AttackTechniqueFactory(
        name=name,
        attack_class=metadata["attack_class"],
        description=metadata.get("description"),
        technique_tags=metadata.get("tags", []),
        uses_adversarial=metadata.get("uses_adversarial"),
    )


def get_core_technique_factories() -> List[AttackTechniqueFactory]:
    """
    获取核心技术工厂列表（对齐 pyrit core.py）

    包含通用技术：prompt_sending、编码攻击、角色扮演、crescendo、
    context_compliance、many_shot、red_teaming、tap
    """
    core_names = [
        # 基线
        "prompt_sending",
        # 编码攻击
        "rot13", "base64", "caesar", "binary", "morse",
        "leetspeak", "flip", "char_swap", "diacritic",
        "character_space", "string_join", "suffix_append",
        "atbash", "url",
        # 角色扮演
        "role_play_movie_script", "role_play_persuasion",
        "role_play_persuasion_written", "role_play_trivia_game",
        "role_play_video_game",
        # Crescendo
        "crescendo_simulated", "crescendo_movie_director",
        "crescendo_history_lecture", "crescendo_journalist_interview",
        "crescendo",
        # 上下文合规
        "context_compliance",
        # 多轮
        "many_shot", "red_teaming", "tap", "tree_of_attacks_pruned",
        # 其他
        "multi_prompt_sending", "chunked_request",
    ]
    factories = []
    for name in core_names:
        meta = AI300_TECHNIQUE_METADATA.get(name)
        if meta:
            factories.append(_build_factory(name, meta))
    return factories


def get_extra_technique_factories() -> List[AttackTechniqueFactory]:
    """
    获取可选技术工厂列表（对齐 pyrit extra.py）

    包含：pair、skeleton_key
    """
    extra_names = ["pair", "skeleton_key"]
    factories = []
    for name in extra_names:
        meta = AI300_TECHNIQUE_METADATA.get(name)
        if meta:
            factories.append(_build_factory(name, meta))
    return factories


def get_all_technique_factories() -> List[AttackTechniqueFactory]:
    """获取全部技术工厂列表（core + extra）"""
    return get_core_technique_factories() + get_extra_technique_factories()


def get_encoding_technique_factories() -> List[AttackTechniqueFactory]:
    """获取编码攻击技术工厂列表"""
    encoding_names = [
        "rot13", "base64", "caesar", "binary", "morse",
        "leetspeak", "flip", "char_swap", "diacritic",
        "character_space", "string_join", "suffix_append",
        "atbash", "url",
    ]
    factories = []
    for name in encoding_names:
        meta = AI300_TECHNIQUE_METADATA.get(name)
        if meta:
            factories.append(_build_factory(name, meta))
    return factories


# ============================================================
# 注册函数
# ============================================================

# ============================================================
# P0: Converter 变体工厂构建
# ============================================================

def build_converter_variant_factories(
    converter_target: Any = None,
) -> List[AttackTechniqueFactory]:
    """
    P0: 构建 Converter 变体工厂列表

    为每个基础技术（BASE_TECHNIQUES_FOR_VARIANTS）注册多个 Converter 变体。
    每个变体将 AttackConverterConfig 烘焙到 attack_kwargs 中，
    使原生 AdaptiveTechniqueDispatcher 的 FIRST_SUCCESS 自动在首个成功变体处停止。

    非 LLM 链（stealth_evasion, encoding_bypass）可在无 converter_target 时创建。
    LLM 链（llm_assisted, persuasion_chain）需要 converter_target，
    若未提供则跳过并记录警告。

    Args:
        converter_target: LLM 辅助 Converter 所需的目标 PromptTarget（通常为 judge_target）

    Returns:
        Converter 变体的 AttackTechniqueFactory 列表
    """
    from src.converters.converter_registry import load_preset_converter_chain

    variant_factories: List[AttackTechniqueFactory] = []

    for base_tech, chain_names in BASE_TECHNIQUES_FOR_VARIANTS.items():
        meta = AI300_TECHNIQUE_METADATA.get(base_tech)
        if meta is None:
            logger.warning(f"Unknown base technique for converter variant: {base_tech}")
            continue

        for chain_name in chain_names:
            chain_info = CONVERTER_VARIANT_CHAINS.get(chain_name)
            if chain_info is None:
                logger.warning(f"Unknown converter chain variant: {chain_name}")
                continue

            # LLM 链需要 converter_target
            if chain_info["requires_llm"] and converter_target is None:
                logger.debug(
                    f"Skipping LLM converter variant '{base_tech}+{chain_name}': "
                    f"no converter_target provided"
                )
                continue

            try:
                converter_config = load_preset_converter_chain(
                    chain_name=chain_name,
                    converter_target=converter_target,
                )
            except Exception as e:
                logger.warning(
                    f"Failed to load converter chain '{chain_name}' for "
                    f"variant '{base_tech}+{chain_name}': {e}"
                )
                continue

            if converter_config is None:
                continue

            variant_name = f"{base_tech}+{chain_name}"
            variant_tags = list(meta.get("tags", []))
            if "converter_enhanced" not in variant_tags:
                variant_tags.append("converter_enhanced")

            factory = AttackTechniqueFactory(
                name=variant_name,
                attack_class=meta["attack_class"],
                description=f"{meta.get('description', '')} + {chain_info['description']}",
                technique_tags=variant_tags,
                attack_kwargs={"attack_converter_config": converter_config},
                uses_adversarial=meta.get("uses_adversarial"),
            )
            variant_factories.append(factory)

    logger.info(
        f"Built {len(variant_factories)} converter variant factories "
        f"(converter_target={'provided' if converter_target else 'None'})"
    )
    return variant_factories


def get_converter_variant_names() -> List[str]:
    """
    获取所有 Converter 变体技术名称列表

    Returns:
        变体名称列表（如 "prompt_sending+stealth_evasion"）
    """
    names = []
    for base_tech, chain_names in BASE_TECHNIQUES_FOR_VARIANTS.items():
        for chain_name in chain_names:
            names.append(f"{base_tech}+{chain_name}")
    return names


def is_converter_variant(technique_name: str) -> bool:
    """
    判断技术名称是否为 Converter 变体

    Args:
        technique_name: 技术名称

    Returns:
        True 如果是 Converter 变体（含 "+" 分隔符）
    """
    return "+" in technique_name


def get_base_technique_from_variant(technique_name: str) -> str:
    """
    从变体名称提取基础技术名

    Args:
        technique_name: 变体名称（如 "prompt_sending+stealth_evasion"）

    Returns:
        基础技术名（如 "prompt_sending"），若无 "+" 返回原名称
    """
    return technique_name.split("+")[0] if "+" in technique_name else technique_name


def get_converter_chain_from_variant(technique_name: str) -> str | None:
    """
    从变体名称提取 Converter 链名

    Args:
        technique_name: 变体名称（如 "prompt_sending+stealth_evasion"）

    Returns:
        Converter 链名（如 "stealth_evasion"），若非变体返回 None
    """
    parts = technique_name.split("+", 1)
    return parts[1] if len(parts) == 2 else None


# ============================================================
# 注册函数
# ============================================================

def register_ai300_techniques(
    tags: list[str] | None = None,
    reset: bool = False,
    converter_target: Any = None,
    include_variants: bool = True,
) -> int:
    """
    注册 AI-300 技术到 PyRIT AttackTechniqueRegistry

    Args:
        tags: 注册的组别，默认为 ["core"]
              ["core"] - 仅注册核心技术
              ["core", "extra"] - 注册核心 + 可选技术
              ["all"] - core + extra 简写
        reset: 是否重置注册表（主要用于测试）
        converter_target: LLM 辅助 Converter 所需的目标 PromptTarget
        include_variants: 是否注册 Converter 变体（P0 新增）

    Returns:
        新注册的技术数量
    """
    if reset:
        AttackTechniqueRegistry.reset_registry_singleton()

    registry = AttackTechniqueRegistry.get_registry_singleton()
    existing = set(registry.get_factories().keys())

    if tags is None:
        tags = ["core"]

    if "all" in tags:
        factories = get_all_technique_factories()
    else:
        factories = []
        if "core" in tags:
            factories.extend(get_core_technique_factories())
        if "extra" in tags:
            factories.extend(get_extra_technique_factories())
        if "encoding" in tags:
            factories.extend(get_encoding_technique_factories())

    # P0: 追加 Converter 变体工厂
    if include_variants:
        variant_factories = build_converter_variant_factories(
            converter_target=converter_target,
        )
        factories.extend(variant_factories)

    # 过滤已注册的（幂等）
    new_factories = [f for f in factories if f.name not in existing]
    if new_factories:
        registry.register_from_factories(new_factories)
        logger.info(
            f"AI-300 techniques registered: {len(new_factories)} new, "
            f"{len(existing)} already present"
        )
    else:
        logger.debug(f"AI-300 techniques: all {len(factories)} already registered")

    return len(new_factories)
