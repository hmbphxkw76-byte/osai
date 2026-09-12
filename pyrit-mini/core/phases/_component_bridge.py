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

from ._component_inference import (
    _component_from_graph,
    _derive_single_from_labels,
    _extract_prompt_from_result,
    _infer_component_from_category,
    _infer_component_from_text,
    _stamp_multi_labels,
)

# 重新导出内部助手：保持 `tests/*` 与下游对 `_component_bridge.*` 的直接引用零回归。
__all__ = [
    "stamp_component_metadata",
    "get_component_stats",
    "_stamp_multi_labels",
    "_derive_single_from_labels",
    "_extract_prompt_from_result",
    "_infer_component_from_text",
    "_component_from_graph",
    "_infer_component_from_category",
]

logger = logging.getLogger(__name__)


def stamp_component_metadata(
    attack_results: dict[str, list[Any]],
    seed_metadata_map: dict[str, dict[str, Any]] | None = None,
    *,
    component_graph: Any = None,
    surface_graph: Any = None,
) -> dict[str, list[Any]]:
    """Stamp component_type metadata on attack results.

    This function enriches attack results with component classification
    based on either:
        1. Seed metadata passed via seed_metadata_map
        2. Objective/technique name heuristic matching
        3. Existing metadata (category, attack_vector)
        4. RECON 已识别的 ComponentGraph（plan Wave 6：最优来源，优先于纯文本推断）

    IC-1 / IC-3（REQ-150）：除单值 `component_type`（兼容派生视图，W5 删除）外，
    同时写入**多标签**归属：
        - `component_labels`   : list[str]           —— 该结果归属的全部组件（IC-3）
        - `label_confidence`   : dict[str, float]    —— 每个标签的置信度
        - `graph_ref`          : dict                —— 回指 SurfaceGraph 节点，供取证
    单值仍由多标签**派生**（置信度最高者），保证下游零回归。

    Args:
        attack_results: Dict mapping technique names to lists of AttackResult
        seed_metadata_map: Optional mapping from seed/prompt value to metadata dict
        component_graph: Optional ComponentGraph（core.contracts.component_graph）
        surface_graph: Optional SurfaceGraph（recon.surface.graph，REQ-150）

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

            # IC-1：无论单值是否已盖章，多标签归属都要补齐（幂等）
            _stamp_multi_labels(meta, technique_name, surface_graph)

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

            # IC-1：单值缺失时，从多标签派生（保证下游 CB-2 永不恒空）
            if not stamped and meta.get("component_labels"):
                derived = _derive_single_from_labels(meta)
                if derived:
                    meta["component_type"] = derived
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
