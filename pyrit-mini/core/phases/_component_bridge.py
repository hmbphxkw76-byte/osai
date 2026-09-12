"""core/phases/_component_bridge.py - Component-Aware Phase Bridge.

This module acts as a bridge between the strike phase and the scoring/report
phases by stamping component_type metadata on AttackResult objects.

Purpose:
    Complete the component-aware pipeline by ensuring that attack results
    flow downstream with proper component classification, enabling:
        - assess/component_router.py to route to component-specific scorers
        - report/component_reports.py to generate component-specific reports
        - report/component_poc.py to generate component-specific PoCs

Design principles:
    - Non-intrusive: Only adds metadata, does not modify response data
    - Backward compatible: Works with existing strike implementations
    - SSOT: Uses metadata from seeds/strikes as single source of truth

Data flow:
    strike/executor.py -> _component_bridge.stamp_results()
                     -> results with component_type metadata
                     -> assess/component_router.py (T0 heuristic routing)
                     -> report/component_reports.py (report sections)
                     -> report/component_poc.py (PoC generation)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def stamp_component_metadata(
    attack_results: dict[str, list[Any]],
    seed_metadata_map: dict[str, dict[str, Any]] | None = None,
    *,
    component_graph: Any = None,
) -> dict[str, list[Any]]:
    """Stamp component_type metadata on attack results.

    This function enriches attack results with component classification
    based on either:
        1. Seed metadata passed via seed_metadata_map
        2. Objective/technique name heuristic matching
        3. Existing metadata (category, attack_vector)
        4. RECON 已识别的 ComponentGraph（plan Wave 6：最优来源，优先于纯文本推断）

    Args:
        attack_results: Dict mapping technique names to lists of AttackResult
        seed_metadata_map: Optional mapping from seed/prompt value to metadata dict
        component_graph: Optional ComponentGraph（core.contracts.component_graph）

    Returns:
        The same attack_results dict (modified in-place for efficiency)
    """
    if not attack_results:
        return attack_results

    total_stamped = 0

    for technique_name, results in attack_results.items():
        if not results:
            continue

        for result in results:
            # Check if already has component_type
            meta = getattr(result, "metadata", None)
            if not isinstance(meta, dict):
                meta = {}
                try:
                    result.metadata = meta
                except AttributeError:
                    continue  # Can't set metadata on this result type

            if meta.get("component_type"):
                continue  # Already stamped

            # Try to stamp from various sources
            stamped = False

            # Source 1: Match by seed/prompt value
            if seed_metadata_map:
                prompt_val = _extract_prompt_from_result(result)
                if prompt_val and prompt_val in seed_metadata_map:
                    seed_meta = seed_metadata_map[prompt_val]
                    comp = seed_meta.get("component_type")
                    if comp:
                        meta["component_type"] = comp
                        stamped = True

            # Source 2: Infer from objective + technique_name
            if not stamped:
                objective = getattr(result, "objective", "") or ""
                comp = _infer_component_from_text(f"{technique_name} {objective}")
                if comp:
                    meta["component_type"] = comp
                    stamped = True

            # Source 3: Infer from category
            if not stamped:
                category = meta.get("category", "")
                comp = _infer_component_from_category(category)
                if comp:
                    meta["component_type"] = comp
                    stamped = True

            # Source 4: RECON 已识别的组件图（plan Wave 6 —— 优先于纯文本启发式，
            # 保证"识别出来的组件"与"报告里的组件"是同一个，避免下游 CB-2 恒空）
            if not stamped and component_graph is not None:
                comp = _component_from_graph(technique_name, component_graph)
                if comp:
                    meta["component_type"] = comp
                    stamped = True

            if stamped:
                total_stamped += 1

    if total_stamped > 0:
        logger.info(
            "Component bridge: stamped %d/%d attack results with component_type",
            total_stamped,
            sum(len(r) for r in attack_results.values()),
        )

    return attack_results


def _extract_prompt_from_result(result: Any) -> str | None:
    """Extract the original prompt value from an attack result.

    Args:
        result: AttackResult object

    Returns:
        Prompt value string or None
    """
    # Try various attributes where prompt might be stored
    for attr in ("prompt", "seed_prompt", "seed_value", "original_prompt"):
        val = getattr(result, attr, None)
        if val:
            if isinstance(val, str):
                return val
            # Handle SeedPrompt objects
            inner_val = getattr(val, "value", None)
            if inner_val and isinstance(inner_val, str):
                return inner_val
    return None


def _infer_component_from_text(text: str) -> str | None:
    """Infer component type from technique/objective text.

    Args:
        text: Combined technique_name + objective text

    Returns:
        Component type key or None
    """
    text_lower = text.lower()

    # MCP indicators
    mcp_indicators = ["mcp", "tool", "schema", "server"]
    if any(ind in text_lower for ind in mcp_indicators):
        return "mcp_tool_poisoning"

    # A2A indicators
    a2a_indicators = ["a2a", "agent", "agent_card", "workflow", "trust", "registration"]
    if any(ind in text_lower for ind in a2a_indicators):
        return "a2a_agent_integrity"

    # Model indicators
    model_indicators = ["backdoor", "filter", "persona", "jailbreak"]
    if any(ind in text_lower for ind in model_indicators):
        return "model_behavior_shift"

    # RAG indicators
    rag_indicators = ["rag", "retrieval", "vector", "knowledge_base", "embedding"]
    if any(ind in text_lower for ind in rag_indicators):
        return "rag_pipeline"

    # Session/Memory indicators
    session_indicators = ["session", "memory", "context_leak", "context_persist"]
    if any(ind in text_lower for ind in session_indicators):
        return "session_memory"

    # Web/API indicators
    web_indicators = ["web", "auth", "jwt", "rate_limit", "smuggling", "gateway", "api_scope"]
    if any(ind in text_lower for ind in web_indicators):
        return "web_api"

    return None


def _component_from_graph(technique_name: str, graph: Any) -> str | None:
    """从 RECON 识别出的 ComponentGraph 中挑出与该技术最匹配的组件。

    匹配顺序：技术名直接命中组件键 → 技术名命中组件短名/标签 → 图的 dominant 组件。
    全程只读（IA-6：图缺失或异常返回 None，不抛异常）。
    """
    try:
        nodes = getattr(graph, "nodes", None)
        if not nodes:
            return None
        tech = (technique_name or "").lower()

        # 1) 技术名直接命中组件键
        for node in nodes:
            key = str(getattr(node, "component_key", "") or "")
            if key and (key in tech or key.replace("_", "") in tech.replace("_", "")):
                return key

        # 2) 取置信度最高的**已确认**节点（跳过组合体推断出的弱节点）
        confirmed = [n for n in nodes if not (getattr(n, "attributes", None) or {}).get("inferred")]
        pool = confirmed or list(nodes)
        if not pool:
            return None
        best = max(pool, key=lambda n: float(getattr(n, "confidence", 0.0) or 0.0))
        return str(getattr(best, "component_key", "") or "") or None
    except Exception as e:
        logger.debug("[ComponentBridge] 从组件图推断失败（忽略）: %s", e)
        return None


def _infer_component_from_category(category: str) -> str | None:
    """Infer component type from metadata category.

    Args:
        category: Metadata category string

    Returns:
        Component type key or None
    """
    if not category or not isinstance(category, str):
        return None

    cat_lower = category.lower()

    if cat_lower.startswith("mcp_"):
        return "mcp_tool_poisoning"
    if cat_lower.startswith("a2a_") or cat_lower.startswith("agent_"):
        return "a2a_agent_integrity"
    if cat_lower.startswith("model_") or "backdoor" in cat_lower or "filter_bypass" in cat_lower:
        return "model_behavior_shift"
    if cat_lower.startswith("rag_") or "retrieval" in cat_lower or "vector" in cat_lower:
        return "rag_pipeline"
    if cat_lower.startswith("session_") or "memory" in cat_lower or "context_leak" in cat_lower:
        return "session_memory"
    if cat_lower.startswith("web_") or cat_lower.startswith("auth_") or "jwt" in cat_lower:
        return "web_api"

    return None


def get_component_stats(
    attack_results: dict[str, list[Any]],
) -> dict[str, int]:
    """Get component type distribution statistics from stamped results.

    Args:
        attack_results: Dict mapping technique names to lists of AttackResult

    Returns:
        Dict mapping component type to count (includes "unclassified" key)
    """
    stats: dict[str, int] = {}
    unclassified = 0

    for results in attack_results.values():
        for result in results:
            meta = getattr(result, "metadata", None)
            if isinstance(meta, dict):
                comp = meta.get("component_type")
                if comp:
                    stats[comp] = stats.get(comp, 0) + 1
                else:
                    unclassified += 1
            else:
                unclassified += 1

    if unclassified:
        stats["unclassified"] = unclassified

    return stats
