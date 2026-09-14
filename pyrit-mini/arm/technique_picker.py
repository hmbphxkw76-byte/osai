# arXiv:2402.12109 - Russinovich et al., Crescendo
# arXiv:2402.19181 - Zeng et al., Persuasion
# arXiv:2402.01135 - Chao et al., Best-of-N
# arXiv:2312.02191 - Mehrotra et al., TAP
# arXiv:2310.08419 - Chao et al., PAIR
"""Attack technique selection for Burp HTTP targets.

Single-turn techniques (HTTPTarget only, no adversarial_target):
    - prompt_sending: baseline single-prompt attack
    - many_shot: multi-prompt adversarial context
    - skeleton_key: multi-stage jailbreak (adversarial)
    - role_play: persona-based jailbreak (adversarial)
    - context_compliance: context-following exploitation

Multi-turn techniques (require adversarial_target prompt):
    - crescendo: progressive escalation (max_turns from defaults.yaml)
    - tree-of-attacks (TAP): branching attack tree (tree_width/depth from defaults.yaml)
    - pair: iterative prompt refinement
        - red_teaming: automated adversarial prompt generation

Note: HTTPTarget requires adversarial LLM for multi-turn techniques.
      Single-turn attacks send prompt directly via HTTPTarget.
"""

from __future__ import annotations

import logging
from typing import Any

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
    "pair",
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
            "Techniques not in PyRIT native catalog (will be attempted): %s. Available: %s",
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


# Capability-specific technique augmentation
# Maps capability tags to recommended techniques for targeted attack scenarios
_CAPABILITY_TECHNIQUE_MAP: dict[str, list[str]] = {
    # MCP/Agent attacks benefit from context compliance (tool manipulation)
    "mcp": ["context_compliance", "skeleton_key"],
    "mcp_protocol": ["context_compliance"],
    "multi_agent": ["context_compliance", "skeleton_key"],
    "a2a_protocol": ["context_compliance"],
    "a2a": ["context_compliance"],
    # RAG systems are vulnerable to context compliance (retrieval manipulation)
    "rag": ["context_compliance"],
    "embedding_rag": ["context_compliance"],
    # Function calling / tool hijack use context compliance for injection
    "function_calling": ["context_compliance"],
    "tool_hijack": ["context_compliance"],
}


def augment_techniques_by_capability(
    techniques: list[str],
    capabilities: str | None,
) -> list[str]:
    """Augment technique list based on detected capabilities.

    When deep probing detects specific capabilities (MCP, RAG, etc.),
    this function adds targeted techniques that exploit those capabilities.

    Academic basis:
        - Greshake et al. (arXiv:2302.12173): Indirect injection via RAG/MCP
        - Zeng et al. (arXiv:2402.19181): Context compliance for agent systems

    Args:
        techniques: Base technique list.
        capabilities: Comma-separated capability tags (e.g., "mcp,rag").
            None returns techniques unchanged.

    Returns:
        Augmented technique list (deduplicated).
    """
    if not capabilities:
        return techniques

    cap_list = [c.strip().lower() for c in capabilities.split(",") if c.strip()]
    augmented = list(techniques)

    for cap in cap_list:
        for tech in _CAPABILITY_TECHNIQUE_MAP.get(cap, []):
            if tech not in augmented:
                augmented.append(tech)

    if len(augmented) > len(techniques):
        added = [t for t in augmented if t not in techniques]
        logger.info("Capability-adaptive technique augmentation: %s", added)

    return augmented


# ---------------------------------------------------------------------------
# S9 运行期接线（最小可见性 / REQ-151 范畴）
# ---------------------------------------------------------------------------
# 背景：S9 的 24 项组件 technique 已完成「覆盖 100% + 单测通过」，但真实攻击路径上
# Executor/PlaybookEngine 并不按 ctx.techniques 路由调用它们（CP-010 延后项）。本切片只做
# 「可见性」：把 RECON 识别组件的 required_techniques 并入 ctx.techniques，使 reporting/
# coverage 显式可见「这些组件 technique 已被识别但未在真实路径执行」（反静默 C9：把『未接线』
# 显式为『可见未执行』）。不新增真实执行——实跑属 B/C 切片（逐 technique 路由 + S3 根治）。
#
# SSOT：tools._purity_baselines._STRIKE_COMPONENT_BASELINES（S9 24 项来源）。
# 映射：component_graph 节点 component_key → registry spec.id（短名，如 mcp）→ baselines[id].required_techniques。
# 已知债务（option C 解决）：required_techniques 现仍由 tools 数据表提供，未来应提升进
# config/components/*.yaml + ComponentSpec，消除 arm→tools 方向；本切片用 try/except 保证
# 导入缺失时静默降级为 []，零回归、不阻断主链路。


def collect_component_techniques(ctx: Any) -> list[str]:
    """从 ctx.component_graph 收集已识别组件的 required_techniques（去重）。

    复用 core.component_techniques（S9 technique↔component 索引 SSOT），消除本模块直接
    依赖 tools 的临时方向。任意环节（无图 / 索引不可用）失败 → 返回 []（C9 诚实、不静默阻断）。
    """
    graph = getattr(ctx, "component_graph", None)
    if graph is None or not getattr(graph, "nodes", None):
        return []
    try:
        from core.component_techniques import required_techniques_for
    except Exception:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for node in graph.nodes:
        key = str(getattr(node, "component_key", "") or "")
        if not key:
            continue
        for tech in required_techniques_for(key):
            if tech and tech not in seen:
                seen.add(tech)
                out.append(tech)
    return out


def merge_component_techniques(ctx: Any) -> list[str]:
    """把识别组件的 required_techniques 并入 ctx.techniques（最小可见性接线）。

    不新增真实执行：仅提升 reporting/coverage 可见性（B/C 切片才接入 chain_executor 实跑）。
    门禁：ctx.args.wire_component_techniques（默认 True）；关闭或无可合并项 → 静默返回 []。
    """
    if not getattr(getattr(ctx, "args", None), "wire_component_techniques", True):
        return []
    added = collect_component_techniques(ctx)
    if not added:
        return []
    # 防御性去重（collect 实现/桩可能返回重复项）
    _seen: set[str] = set()
    added = [t for t in added if t not in _seen and not _seen.add(t)]
    base = list(getattr(ctx, "techniques", []) or [])
    existing = set(base)
    merged = base + [t for t in added if t not in existing]
    ctx.techniques = merged
    ctx.component_techniques = added
    if hasattr(ctx, "orchestration_log"):
        ctx.orchestration_log.append(
            {
                "phase": "arm",
                "decision": "component_technique_wiring",
                "input": {"component_graph_nodes": len(getattr(ctx.component_graph, "nodes", []))},
                "output": {"merged_component_techniques": added, "total_techniques": len(merged)},
                "reasoning": "S9 运行期接线（可见性）：组件 technique 并入 ctx.techniques，未触发真实执行",
            }
        )
    logger.info("[ARM] S9 组件 technique 接线（可见性）：并入 %d 项（合计 %d）", len(added), len(merged))
    return added
