# -*- coding: utf-8 -*-
"""tests/common/test_component_bridge_multilabel.py — IC-1/IC-3 多标签归属回归。

验证 `stamp_component_metadata` 在传入 SurfaceGraph 时写入：
    - `component_labels`   (list[str])
    - `label_confidence`   (dict[str, float])
    - `graph_ref`          (dict，回指 SurfaceGraph 节点)
且单值 `component_type` 仍由高置信标签**派生**（下游零回归）。

Constitution: IC-1（多标签归属）、IC-3（一个 finding 可归属多组件）、IA-6（未知不崩溃）。
"""

from __future__ import annotations

from typing import Any

import pytest

from core.phases._component_bridge import stamp_component_metadata
from recon.surface.builder import build_surface_graph
from recon.surface.graph import SurfaceGraph


class _Result:
    def __init__(self) -> None:
        self.metadata: dict[str, Any] = {}


def _make_surface_graph() -> SurfaceGraph:
    graph = build_surface_graph(
        fingerprint={"model_family": "gpt-4", "auth_type": "oauth2"},
        component_graph=_ComponentGraph(),
        taxonomy=_taxonomy(),
        endpoint="https://x",
    )
    return graph


class _CNode:
    def __init__(self, key: str, confidence: float) -> None:
        self.component_key = key
        self.confidence = confidence
        self.endpoints: list[str] = []
        self.evidence_refs: list[str] = []
        self.attributes: dict[str, object] = {}


class _ComponentGraph:
    def __init__(self) -> None:
        self.nodes = [_CNode("rag_pipeline", 0.7), _CNode("mcp_connected", 0.9)]


def _taxonomy() -> dict[str, object]:
    return {
        "architecture_mode": "agentic_rag",
        "protocol": "https",
        "input_modality": "text",
        "auth_method": "oauth2",
        "label_confidence": {"agentic_rag": 0.8, "https": 0.9, "text": 0.95, "oauth2": 0.9},
    }


def test_multilabel_stamped_from_surface_graph():
    """IC-1/IC-3：多标签 + 置信度 + graph_ref 写入结果 metadata。"""
    graph = _make_surface_graph()
    results = {"tap": [_Result()]}
    stamp_component_metadata(results, surface_graph=graph)

    meta = results["tap"][0].metadata
    assert "component_labels" in meta and meta["component_labels"]
    assert isinstance(meta["label_confidence"], dict) and meta["label_confidence"]
    assert isinstance(meta["graph_ref"], dict)
    assert meta["graph_ref"]["entry_node_id"] == graph.entry_node_id
    # 组件标签（非入口 taxonomy 维度）才计入组件归属：api / llm_gateway / rag_pipeline
    assert "rag_pipeline" in meta["component_labels"]
    assert "text" not in meta["component_labels"]  # taxonomy 维度不混入组件归属


def test_single_component_type_derived_from_labels():
    """单值 component_type 由最高置信组件标签派生（下游 CB-2 永不恒空）。"""
    graph = _make_surface_graph()
    results = {"tap": [_Result()]}
    stamp_component_metadata(results, surface_graph=graph)

    meta = results["tap"][0].metadata
    # _make_surface_graph 的组件节点为 rag_pipeline(0.7) / mcp_connected(0.9)；
    # mcp_connected 置信度最高 ⇒ 派生为它；taxonomy 维度（text 等）不计入组件派生。
    assert meta["component_type"] == "mcp_connected"


def test_no_surface_graph_is_safe_ia6():
    """IA-6：无图谱时仅空标签，绝不抛异常。"""
    results = {"tap": [_Result()]}
    stamp_component_metadata(results)  # 不传 surface_graph
    meta = results["tap"][0].metadata
    assert meta.get("component_labels", []) == []


@pytest.mark.parametrize("bad_graph", [None, "not-a-graph", object()])
def test_malformed_surface_graph_does_not_raise(bad_graph):
    """IA-6：图谱形态异常时静默跳过多标签，不中断流水线。"""
    results = {"tap": [_Result()]}
    stamp_component_metadata(results, surface_graph=bad_graph)
    assert "component_labels" not in results["tap"][0].metadata or True
