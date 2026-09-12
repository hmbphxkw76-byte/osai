"""recon/surface — 攻击面图谱（REQ-150）。

对外最小面（按 80-COMPONENT 的 `__all__` 纪律声明）：
    - `SurfaceGraph` / `SurfaceNode` / `SurfaceEdge`：数据结构
    - `build_surface_graph`：从既有侦察产物构图
    - `legacy_fingerprint_view` / `component_type_view`：迁移期兼容视图（W5 删除）
"""

from __future__ import annotations

from recon.surface.builder import build_surface_graph
from recon.surface.graph import (
    DEFAULT_FALLBACK_LABELS,
    SCHEMA_VERSION,
    SurfaceEdge,
    SurfaceGraph,
    SurfaceNode,
)
from recon.surface.legacy import component_type_view, legacy_fingerprint_view

__all__ = [
    "DEFAULT_FALLBACK_LABELS",
    "SCHEMA_VERSION",
    "SurfaceEdge",
    "SurfaceGraph",
    "SurfaceNode",
    "build_surface_graph",
    "component_type_view",
    "legacy_fingerprint_view",
]
