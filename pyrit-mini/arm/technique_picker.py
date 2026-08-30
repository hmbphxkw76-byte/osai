# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2402.19181 — Zeng et al., Persuasion
# arXiv:2402.01135 — Chao et al., Best-of-N
# arXiv:2312.02191 — Mehrotra et al., TAP
# arXiv:2310.08419 — Chao et al., PAIR
"""鏀诲嚮鎶€鏈€夋嫨 鈥?绾粦鐩?Burp 鍦烘櫙銆?

鍗曡疆鎶€鏈?(HTTPTarget 鐩存帴鍙戦€?:
    - prompt_sending: 鍩虹嚎 (鐩存帴鍙戦€佺瀛?
    - many_shot: 澶氱ず渚嬪紩瀵?(鏃犻渶 adversarial)
    - skeleton_key: 楠ㄦ灦瀵嗛挜 (鏃犻渶 adversarial)
    - role_play: 瑙掕壊鎵紨瓒婄嫳 (鏃犻渶 adversarial)
    - context_compliance: 涓婁笅鏂囧悎瑙勬敾鍑?

澶氳疆鎶€鏈?(闇€瑕?adversarial_target):
    - crescendo: 娓愯繘鍗囩骇 (max_turns=8)
    - tap: 鏍戞悳绱?(tree_width=4, depth=3)
    - pair: 杩唬瓒婄嫳
    - red_teaming: 绾㈤槦瀵规姉

娉ㄦ剰: HTTPTarget 涓嶇淮鎶ゅ璇濈姸鎬? 澶氳疆鏀诲嚮閫氳繃 adversarial LLM
      鐢熸垚姣忚疆 prompt 鍚庨€氳繃 HTTPTarget 鍙戦€佺粰鐩爣銆?
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# 鍗曡疆鎶€鏈?(HTTPTarget 鐩存帴鍙戦€? 涓嶉渶瑕?adversarial)
SINGLE_TURN_TECHNIQUES = [
    "prompt_sending",
    "many_shot",
    "skeleton_key",
    "role_play_movie_script",
    "role_play_persuasion",
    "context_compliance",
    "flip",
]

# 澶氳疆鎶€鏈?(闇€瑕?adversarial_target 鐢熸垚杩唬 prompt)
MULTI_TURN_TECHNIQUES = [
    "crescendo_simulated",
    "tap",
    "pair",
    "red_teaming",
    "best_of_n_jailbreak",
]

# PyRIT 鍘熺敓鎶€鏈洰褰曚腑鐨勫彲鐢ㄦ妧鏈悕
# L5 v38: "adaptive_text" 鏄?TextAdaptive 鍦烘櫙鐨勫崰浣嶆妧鏈悕
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
    """閫夋嫨鏀诲嚮鎶€鏈€?

    Args:
        mode: 鎶€鏈€夋嫨妯″紡銆?
            - "auto": 鍗曡疆鎶€鏈?+ 澶氳疆鎶€鏈?(褰撴湁 adversarial 鏃?
            - "single": 浠呭崟杞妧鏈?
            - "multi": 浠呭杞妧鏈?
            - "adaptive": PyRIT 鍘熺敓 TextAdaptive 鍦烘櫙 (蔚-greedy 鑷€傚簲)
            - "tap,crescendo": 閫楀彿鍒嗛殧鐨勬寚瀹氭妧鏈?
        has_adversarial: 鏄惁鏈?adversarial target (澶氳疆鏀诲嚮闇€瑕?銆?

    Returns:
        鎶€鏈悕绉板垪琛ㄣ€?
    """
    # L5 v38: "adaptive" 妯″紡 鈥?PyRIT 鍘熺敓 TextAdaptive 鍦烘櫙
    # 涓嶈蛋甯歌鎶€鏈€夋嫨, 杩斿洖 ["adaptive_text"] 鍗犱綅,
    # main.py 涓娴?techniques=="adaptive" 鍚庤矾鐢卞埌 text_adaptive_executor.py
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

    # 鎸囧畾鎶€鏈?(閫楀彿鍒嗛殧)
    techniques = [t.strip() for t in mode.split(",") if t.strip()]
    _validate_techniques(techniques)
    return techniques


def _validate_techniques(techniques: list[str]) -> None:
    """楠岃瘉鎶€鏈悕鏄惁鍦?PyRIT 鍘熺敓鎶€鏈洰褰曚腑鍙敤銆?"""
    invalid = [t for t in techniques if t not in _AVAILABLE_TECHNIQUES]
    if invalid:
        logger.warning(
            "Techniques not in PyRIT native catalog (will be attempted): %s. "
            "Available: %s",
            invalid,
            sorted(_AVAILABLE_TECHNIQUES),
        )


def is_multi_turn_technique(technique_name: str) -> bool:
    """鍒ゆ柇鏄惁涓哄杞妧鏈€?

    Args:
        technique_name: 鎶€鏈悕绉般€?

    Returns:
        True 濡傛灉鏄杞妧鏈€?
    """
    # L5 v38: "adaptive_text" 涓嶆槸澶氳疆鎶€鏈? 鏄?TextAdaptive 鍦烘櫙鍗犱綅
    if technique_name == "adaptive_text":
        return False
    return technique_name in MULTI_TURN_TECHNIQUES


def filter_by_adversarial(
    techniques: list[str],
    has_adversarial: bool,
) -> list[str]:
    """鏍规嵁鏄惁鏈?adversarial target 杩囨护鎶€鏈€?

    鏃?adversarial 鏃剁Щ闄ゅ杞妧鏈€?
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


# 鈹€鈹€ 鏂偣 #2 淇: 鑳藉姏鈫掓妧鏈槧灏?鈹€鈹€

# 鑳藉姏鎸囩汗 鈫?瀹氬悜杩藉姞鎶€鏈槧灏?
# 褰撴繁搴︽帰娴嬫娴嬪埌鐗瑰畾鑳藉姏鏃? 鑷姩杩藉姞瀵瑰簲鏀诲嚮鎶€鏈?
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
    # P1-2: OpenAPI 发现的端点 → 参数注入攻击技术
    "openapi": ["context_compliance"],
    "openapi_auth": ["context_compliance"],
}


def augment_techniques_by_capability(
    techniques: list[str],
    capabilities: str | None,
) -> list[str]:
    """鍩轰簬鑳藉姏鎸囩汗鑷姩杩藉姞瀹氬悜鏀诲嚮鎶€鏈?(鏂偣 #2 淇).

    瀛︽湳渚濇嵁: Greshake et al. (arXiv:2302.12173) 鈥?鐩爣鑳藉姏鎸囩汗
    搴旀寚瀵兼敾鍑荤瓥鐣ラ€夋嫨銆傛帰娴嬪埌 MCP/RAG/Agent 鑳藉姏鏃? 鑷姩杩藉姞
    context_compliance 绛夐拡瀵?Agent 鏋舵瀯鐨勬敾鍑绘妧鏈€?

    Args:
        techniques: 褰撳墠鎶€鏈垪琛ㄣ€?
        capabilities: 鐩爣鑳藉姏鎸囩汗 (閫楀彿鍒嗛殧, 濡?"mcp,rag,function_calling")銆?
            None 鎴栫┖瀛楃涓叉椂鐩存帴杩斿洖鍘熷垪琛ㄣ€?

    Returns:
        杩藉姞瀹氬悜鎶€鏈悗鐨勫垪琛?(鍘婚噸)銆?
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

