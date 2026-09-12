"""recon/surface/legacy.py — 旧 `target_fingerprint` 兼容视图（REQ-150 ⑤）。

迁移期（W1 → W5）内，下游仍按旧 `target_fingerprint` 字典消费侦察结果。
本模块从 `SurfaceGraph` 派生出**字段不丢失**的旧视图，保证 W5 删除前下游零回归。

设计要点：
    - **派生而非复制**：旧视图由图谱 + 原始 fingerprint 合并产出，不存在第二份事实源（C3）。
    - **字段不丢失**：所有旧键原样保留；图谱新增的信息以 `component_labels` /
      `label_confidence` / `surface_ref` 三个**附加键**追加，不覆盖任何旧键。
    - **过期即删**：W5 随兼容层一并删除（蓝图 13.6「只减不增」）。
"""

from __future__ import annotations

import logging
from typing import Any

from recon.surface.graph import SurfaceGraph

logger = logging.getLogger(__name__)

# 旧视图中由图谱追加的键（不与任何旧 fingerprint 字段冲突）
APPEND_KEYS = ("component_labels", "label_confidence", "surface_ref", "taxonomy_labels")


def legacy_fingerprint_view(
    fingerprint: Any = None,
    *,
    graph: SurfaceGraph | None = None,
    taxonomy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """从原始 fingerprint + SurfaceGraph 派生旧 `target_fingerprint` 视图。

    Args:
        fingerprint: 原始 `TargetFingerprint`（dataclass 或 dict）。
        graph: `SurfaceGraph`；为 None 时仅返回原始 fingerprint（零回归）。
        taxonomy: 四维本体产物，用于回填 `taxonomy_labels`。

    Returns:
        旧视图 dict：原始 fingerprint 的**全部**字段 + 图谱追加键。
    """
    view: dict[str, Any] = {}

    # 1) 原始 fingerprint 全量保留（daclass → asdict；dict → 浅拷贝）
    if fingerprint is not None:
        if isinstance(fingerprint, dict):
            view = dict(fingerprint)
        else:
            to_dict = getattr(fingerprint, "to_dict", None)
            if callable(to_dict):
                try:
                    candidate = to_dict()
                    if isinstance(candidate, dict):
                        view = dict(candidate)
                except Exception as e:
                    logger.debug("[SurfaceLegacy] fingerprint.to_dict() 失败: %s", e)
            if not view:
                try:
                    from dataclasses import asdict, is_dataclass

                    if is_dataclass(fingerprint):
                        view = asdict(fingerprint)
                    else:
                        view = dict(vars(fingerprint))
                except Exception as e:
                    logger.debug("[SurfaceLegacy] fingerprint 序列化失败: %s", e)
                    view = {}

    if graph is None:
        return view

    # 2) 图谱追加键（IC-1：多标签 + 分组件置信度）
    entry = graph.node(graph.entry_node_id)
    if entry is not None:
        view["component_labels"] = list(entry.sorted_labels())
        view["label_confidence"] = dict(entry.label_confidence)

    all_labels: list[str] = []
    seen: set[str] = set()
    for node in graph.nodes:
        for label in node.sorted_labels():
            if label not in seen:
                seen.add(label)
                all_labels.append(label)
    view.setdefault("component_labels", all_labels)

    if "label_confidence" not in view:
        merged: dict[str, float] = {}
        for node in graph.nodes:
            for label, conf in node.label_confidence.items():
                merged[label] = max(merged.get(label, 0.0), conf)
        view["label_confidence"] = merged

    # 3) 反向引用（下游可据此回到图谱，IC-3 多归属取证）
    view["surface_ref"] = {
        "schema_version": graph.schema_version,
        "entry_node_id": graph.entry_node_id,
        "node_ids": [n.node_id for n in graph.nodes],
        "edge_count": len(graph.edges),
        "unknown": graph.unknown,
        "fallback_labels": list(graph.fallback_labels),
    }

    if isinstance(taxonomy, dict) and taxonomy:
        view["taxonomy_labels"] = {
            dimension: taxonomy.get(dimension)
            for dimension in ("architecture_mode", "protocol", "input_modality", "auth_method")
            if taxonomy.get(dimension)
        }

    return view


def component_type_view(
    graph: SurfaceGraph | None,
    *,
    node_id: str | None = None,
) -> str | None:
    """IC-1 兼容派生：从多标签派生**单值** `component_type`。

    迁移期下游（assess/component_router、report/component_reports）仍按单值消费；
    W5 删除本函数与单值语义。取置信度最高的标签作为单值。

    Args:
        graph: 图谱；为 None 返回 None。
        node_id: 指定节点；为 None 时用入口节点。

    Returns:
        单值组件标签；无法确定时返回 None（IA-6：不崩溃）。
    """
    if graph is None:
        return None
    target = graph.node(node_id) if node_id else graph.node(graph.entry_node_id)
    if target is None:
        return graph.dominant_label()
    return target.top_label() or graph.dominant_label()
