# arXiv:2402.12109 - Russinovich et al., Crescendo
# arXiv:2402.19181 - Zeng et al., Persuasion
# arXiv:2402.01135 - Chao et al., Best-of-N
# arXiv:2312.02191 - Mehrotra et al., TAP
# arXiv:2310.08419 - Chao et al., PAIR
"""EUREUR ??Burp ?

EUR?(HTTPTarget EUR?:
    - prompt_sending:  (EUR?
    - many_shot: zu?( adversarial)
    - skeleton_key: er ( adversarial)
    - role_play:  ( adversarial)
    - context_compliance: ?

EUR?(EUR?adversarial_target):
    - crescendo:  (max_turns from defaults.yaml)
    - tap: ?(tree_width from defaults.yaml, depth from defaults.yaml)
    - pair:
        - red_teaming:
            pass

er: HTTPTarget yu?  adversarial LLM
       prompt EUR HTTPTarget EUR?
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# EUR?(HTTPTarget EUR? ?adversarial)
SINGLE_TURN_TECHNIQUES = [
    "prompt_sending",
    "many_shot",
    "skeleton_key",
    "role_play_movie_script",
    "role_play_persuasion",
    "context_compliance",
    "flip",
]

# EUR?(EUR?adversarial_target prompt)
MULTI_TURN_TECHNIQUES = [
    "crescendo_simulated",
    "tap",
    "pair",
    "red_teaming",
    "best_of_n_jailbreak",
]

# PyRIT EURer
# L5 v38: "adaptive_text" ?TextAdaptive
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
    """EUREUR?

    Args:
        mode: EUREUR"?
            - "auto": EUR?+ EUR?( adversarial ?
            - "single": ?
            - "multi": ?
            - "adaptive": PyRIT  TextAdaptive  (-greedy EUR)
            - "tap,crescendo": ?
        has_adversarial: ?adversarial target (EUR??

    Returns:
        EURuEUR?
    """
 # L5 v38: "adaptive" " ?PyRIT TextAdaptive
 # EUREUR, ["adaptive_text"] ,
 # main.py ?techniques=="adaptive" text_adaptive_executor.py
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

 # EUR?()
    techniques = [t.strip() for t in mode.split(",") if t.strip()]
    _validate_techniques(techniques)
    return techniques

def _validate_techniques(techniques: list[str]) -> None:
    """EUR?PyRIT EUR?"""
    invalid = [t for t in techniques if t not in _AVAILABLE_TECHNIQUES]
    if invalid:
     # INFO : pipeline.log, ()
        logger.info(
            "Techniques not in PyRIT native catalog (will be attempted): %s. "
            "Available: %s",
            invalid,
            sorted(_AVAILABLE_TECHNIQUES),
        )

def is_multi_turn_technique(technique_name: str) -> bool:
    """yuEUR?

    Args:
        technique_name: EUREUR?

    Returns:
        True EUR?
    """
 # L5 v38: "adaptive_text" EUR? ?TextAdaptive
    if technique_name == "adaptive_text":
        return False
    return technique_name in MULTI_TURN_TECHNIQUES

# EUREUR #2 : ?EUREUR

# ?EUR?
# [? EUR?
_CAPABILITY_TECHNIQUE_MAP: dict[str, list[str]] = {
    "mcp": ["context_compliance"],
    "mcp_protocol": ["context_compliance"],  # - mcp
    "rag": ["context_compliance"],
    "function_calling": ["context_compliance"],
    "tool_hijack": ["context_compliance"],
    "multi_agent": ["context_compliance"],
    "workflow": ["context_compliance"],
    "session_auth": ["context_compliance"],
    "memory": ["context_compliance"],
    "multi_tenant": ["context_compliance"],  # -
    # - recon_report.py _CAPABILITY_STRATEGY
    "a2a_protocol": ["context_compliance"],
    "embedding_rag": ["context_compliance"],
    #
    "a2a": ["context_compliance"],
    # P1-2: OpenAPI ->
    "openapi": ["context_compliance"],
    "openapi_auth": ["context_compliance"],
}

def augment_techniques_by_capability(
    techniques: list[str],
    capabilities: str | None,
) -> list[str]:
    """EUR?( #2 ).

    [: Greshake et al. (arXiv:2302.12173) ?
    raEUR MCP/RAG/Agent ?
    context_compliance ?Agent EUR?

    Args:
        techniques: EURuEUR?
        capabilities:  (, ?"mcp,rag,function_calling")?
            None +uEUR?

    Returns:
        EUR?()?
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
