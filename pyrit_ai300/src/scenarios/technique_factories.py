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
from pyrit.registry import AttackTechniqueRegistry
from pyrit.scenario.core.attack_technique_factory import AttackTechniqueFactory

logger = logging.getLogger(__name__)


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

def register_ai300_techniques(
    tags: list[str] | None = None,
    reset: bool = False,
) -> int:
    """
    注册 AI-300 技术到 PyRIT AttackTechniqueRegistry

    Args:
        tags: 注册的组别，默认为 ["core"]
              ["core"] - 仅注册核心技术
              ["core", "extra"] - 注册核心 + 可选技术
              ["all"] - core + extra 简写
        reset: 是否重置注册表（主要用于测试）

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
