"""攻击技术选择 — 纯黑盒 Burp 场景。

单轮技术 (HTTPTarget 直接发送):
    - prompt_sending: 基线 (直接发送种子)
    - many_shot: 多示例引导 (无需 adversarial)
    - skeleton_key: 骨架密钥 (无需 adversarial)
    - role_play: 角色扮演越狱 (无需 adversarial)
    - context_compliance: 上下文合规攻击

多轮技术 (需要 adversarial_target):
    - crescendo: 渐进升级 (max_turns=8)
    - tap: 树搜索 (tree_width=4, depth=3)
    - pair: 迭代越狱
    - red_teaming: 红队对抗

注意: HTTPTarget 不维护对话状态, 多轮攻击通过 adversarial LLM
      生成每轮 prompt 后通过 HTTPTarget 发送给目标。
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# 单轮技术 (HTTPTarget 直接发送, 不需要 adversarial)
SINGLE_TURN_TECHNIQUES = [
    "prompt_sending",
    "many_shot",
    "skeleton_key",
    "role_play_movie_script",
    "role_play_persuasion",
    "context_compliance",
    "flip",
]

# 多轮技术 (需要 adversarial_target 生成迭代 prompt)
MULTI_TURN_TECHNIQUES = [
    "crescendo_simulated",
    "tap",
    "pair",
    "red_teaming",
    "best_of_n_jailbreak",
]

# PyRIT 原生技术目录中的可用技术名
# L5 v38: "adaptive_text" 是 TextAdaptive 场景的占位技术名
_AVAILABLE_TECHNIQUES = {
    "prompt_sending",
    "many_shot",
    "skeleton_key",
    "tap",
    "red_teaming",
    "crescendo_simulated",
    "crescendo_movie_director",
    "crescendo_history_lecture",
    "crescendo_journalist_interview",
    "role_play_movie_script",
    "role_play_video_game",
    "role_play_trivia_game",
    "role_play_persuasion",
    "role_play_persuasion_written",
    "context_compliance",
    "flip",
    "best_of_n_jailbreak",
    "adaptive_text",
}


def select_techniques(
    mode: str = "auto",
    has_adversarial: bool = True,
) -> list[str]:
    """选择攻击技术。

    Args:
        mode: 技术选择模式。
            - "auto": 单轮技术 + 多轮技术 (当有 adversarial 时)
            - "single": 仅单轮技术
            - "multi": 仅多轮技术
            - "adaptive": PyRIT 原生 TextAdaptive 场景 (ε-greedy 自适应)
            - "tap,crescendo": 逗号分隔的指定技术
        has_adversarial: 是否有 adversarial target (多轮攻击需要)。

    Returns:
        技术名称列表。
    """
    # L5 v38: "adaptive" 模式 — PyRIT 原生 TextAdaptive 场景
    # 不走常规技术选择, 返回 ["adaptive_text"] 占位,
    # main.py 中检测 techniques=="adaptive" 后路由到 text_adaptive_executor.py
    if mode == "adaptive":
        logger.info("Technique mode: adaptive (PyRIT native TextAdaptive scenario)")
        return ["adaptive_text"]

    if mode == "auto":
        techniques = list(SINGLE_TURN_TECHNIQUES)
        if has_adversarial:
            techniques.extend(MULTI_TURN_TECHNIQUES)
        _validate_techniques(techniques)
        return techniques

    if mode == "single":
        _validate_techniques(SINGLE_TURN_TECHNIQUES)
        return list(SINGLE_TURN_TECHNIQUES)

    if mode == "multi":
        _validate_techniques(MULTI_TURN_TECHNIQUES)
        return list(MULTI_TURN_TECHNIQUES)

    # 指定技术 (逗号分隔)
    techniques = [t.strip() for t in mode.split(",") if t.strip()]
    _validate_techniques(techniques)
    return techniques


def _validate_techniques(techniques: list[str]) -> None:
    """验证技术名是否在 PyRIT 原生技术目录中可用。"""
    invalid = [t for t in techniques if t not in _AVAILABLE_TECHNIQUES]
    if invalid:
        logger.warning(
            "Techniques not in PyRIT native catalog (will be attempted): %s. "
            "Available: %s",
            invalid,
            sorted(_AVAILABLE_TECHNIQUES),
        )


def is_multi_turn_technique(technique_name: str) -> bool:
    """判断是否为多轮技术。

    Args:
        technique_name: 技术名称。

    Returns:
        True 如果是多轮技术。
    """
    # L5 v38: "adaptive_text" 不是多轮技术, 是 TextAdaptive 场景占位
    if technique_name == "adaptive_text":
        return False
    return technique_name in MULTI_TURN_TECHNIQUES


def filter_by_adversarial(
    techniques: list[str],
    has_adversarial: bool,
) -> list[str]:
    """根据是否有 adversarial target 过滤技术。

    无 adversarial 时移除多轮技术。
    """
    if has_adversarial:
        return techniques
    filtered = [t for t in techniques if not is_multi_turn_technique(t)]
    if len(filtered) < len(techniques):
        removed = [t for t in techniques if is_multi_turn_technique(t)]
        logger.warning(
            "Removed multi-turn techniques (no adversarial target): %s",
            removed,
        )
    return filtered


# ── 断点 #2 修复: 能力→技术映射 ──

# 能力指纹 → 定向追加技术映射
# 当深度探测检测到特定能力时, 自动追加对应攻击技术
_CAPABILITY_TECHNIQUE_MAP: dict[str, list[str]] = {
    "mcp": ["context_compliance"],
    "rag": ["context_compliance"],
    "function_calling": ["context_compliance"],
    "tool_hijack": ["context_compliance"],
    "multi_agent": ["context_compliance"],
    "workflow": ["context_compliance"],
    "session_auth": ["context_compliance"],
    "memory": ["context_compliance"],
    "a2a": ["context_compliance"],
}


def augment_techniques_by_capability(
    techniques: list[str],
    capabilities: str | None,
) -> list[str]:
    """基于能力指纹自动追加定向攻击技术 (断点 #2 修复).

    学术依据: Greshake et al. (arXiv:2302.12173) — 目标能力指纹
    应指导攻击策略选择。探测到 MCP/RAG/Agent 能力时, 自动追加
    context_compliance 等针对 Agent 架构的攻击技术。

    Args:
        techniques: 当前技术列表。
        capabilities: 目标能力指纹 (逗号分隔, 如 "mcp,rag,function_calling")。
            None 或空字符串时直接返回原列表。

    Returns:
        追加定向技术后的列表 (去重)。
    """
    if not capabilities:
        return techniques

    cap_list = [c.strip().lower() for c in capabilities.split(",") if c.strip()]
    augmented = list(techniques)
    added: list[str] = []

    for cap in cap_list:
        mapped_techs = _CAPABILITY_TECHNIQUE_MAP.get(cap, [])
        for tech in mapped_techs:
            if tech not in augmented:
                augmented.append(tech)
                added.append(tech)

    if added:
        logger.info(
            "Capability-adaptive technique augmentation: %s (from capabilities=%s)",
            added,
            cap_list,
        )

    return augmented
