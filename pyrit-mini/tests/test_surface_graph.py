# -*- coding: utf-8 -*-
"""tests/test_surface_graph.py — REQ-150 攻击面图谱（多标签 + 置信度 + 信任边界 + 数据流边）。

Constitution: IC-1（组件归属为多标签）、IC-3（一个 finding 可归属多个组件）、
I12（节点证据为 EventLog 事件 ID、可回溯）、IA-3（无重复节点）、IA-6（未知不崩溃）。
"""

from __future__ import annotations

from recon.surface.builder import build_surface_graph
from recon.surface.graph import (
    DEFAULT_FALLBACK_LABELS,
    SurfaceEdge,
    SurfaceGraph,
    SurfaceNode,
)


class _CNode:
    """最小化的 ComponentGraph 节点替身（只需 builder 读取的字段）。"""

    def __init__(self, key: str, confidence: float, endpoints: list[str] | None = None) -> None:
        self.component_key = key
        self.confidence = confidence
        self.endpoints = endpoints or []
        self.evidence_refs: list[str] = []
        self.attributes: dict[str, object] = {}


class _ComponentGraph:
    def __init__(self, nodes: list[_CNode]) -> None:
        self.nodes = nodes


def _sample_fingerprint() -> dict[str, object]:
    return {
        "model_family": "gpt-4",
        "auth_type": "oauth2",
        "capabilities": ["streaming", "tools_list"],
    }


def _sample_component_graph() -> _ComponentGraph:
    return _ComponentGraph(
        [
            _CNode("api", 0.9, endpoints=["https://api.example.com/v1"]),
            _CNode("llm_gateway", 0.8),
            _CNode("rag_pipeline", 0.6),
        ]
    )


def _sample_taxonomy() -> dict[str, object]:
    return {
        "architecture_mode": "agentic_rag",
        "protocol": "https",
        "input_modality": "text",
        "auth_method": "oauth2",
        "label_confidence": {"agentic_rag": 0.8, "https": 0.9, "text": 0.95, "oauth2": 0.9},
    }


def test_graph_is_multi_label_ic1():
    """IC-1：一个节点可承载多个标签，并按置信度排序。"""
    node = SurfaceNode(node_id="x")
    node.add_label("rag", 0.6)
    node.add_label("mcp_connected", 0.9)
    node.add_label("rag", 0.8)  # 重复标签取高置信度
    assert node.labels == ["rag", "mcp_connected"]
    assert node.label_confidence["rag"] == 0.8
    assert node.sorted_labels() == ["mcp_connected", "rag"]  # 降序


def test_graph_rejects_duplicate_nodes_ia3():
    """IA-3：同 ID 节点合并而非重复。"""
    g = SurfaceGraph()
    g.add_node(SurfaceNode(node_id="a", labels=["rag"], label_confidence={"rag": 0.5}))
    g.add_node(SurfaceNode(node_id="a", labels=["mcp_connected"], label_confidence={"mcp_connected": 0.9}))
    assert len(g.nodes) == 1
    assert g.node("a").labels == ["rag", "mcp_connected"]


def test_edge_creates_placeholder_node_when_missing():
    """add_edge 对缺失端点补占位节点，避免悬空引用。"""
    g = SurfaceGraph()
    g.add_edge(SurfaceEdge(src="a", dst="b"))
    assert g.has("a") and g.has("b")


def test_data_flow_chain_dfs():
    """数据流链 DFS：从入口沿 data_flow 边遍历。"""
    g = SurfaceGraph(entry_node_id="api")
    g.add_node(SurfaceNode(node_id="api"))
    g.add_node(SurfaceNode(node_id="llm"))
    g.add_node(SurfaceNode(node_id="rag"))
    g.add_edge(SurfaceEdge(src="api", dst="llm", type="data_flow"))
    g.add_edge(SurfaceEdge(src="llm", dst="rag", type="retrieves_from"))
    chain = g.data_flow_chain()
    assert chain[0] == "api"
    assert "llm" in chain


def test_component_labels_for_unknown_node_is_safe_ia6():
    """IA-6：未知节点返回空，不抛异常。"""
    g = SurfaceGraph()
    labels, conf = g.component_labels_for("nope")
    assert labels == [] and conf == {}


def test_build_surface_graph_from_fingerprint():
    """builder 能从 fingerprint 产出多标签图谱 + 信任边界 + 数据流边。"""
    fp = _sample_fingerprint()
    graph = build_surface_graph(
        fingerprint=fp,
        component_graph=_sample_component_graph(),
        taxonomy=_sample_taxonomy(),
        endpoint="https://api.example.com/v1/chat",
    )
    assert graph is not None
    # 入口节点 + 3 个组件节点
    assert graph.has(graph.entry_node_id)
    assert graph.has("api") and graph.has("rag_pipeline")
    # 数据流边已生成（入口 → 各组件）
    assert any(e.type == "data_flow" for e in graph.edges)
    # 多标签：taxonomy 四维 + 组件标签
    assert len(graph.labels()) >= 4
    # oauth2 认证 ⇒ 入口位于信任边界
    assert graph.node(graph.entry_node_id).trust_boundary is True


def test_unknown_detection_falls_back():
    """识别失败时 `unknown=True` 且提供兜底标签（REQ-150 ④）。"""
    graph = build_surface_graph(fingerprint={}, component_graph=_ComponentGraph([]))
    # 空组件不应抛异常；识别失败应标记 unknown 并带兜底标签
    assert isinstance(graph, SurfaceGraph)
    assert graph.unknown is True
    assert graph.fallback_labels == list(DEFAULT_FALLBACK_LABELS)


def test_surface_graph_roundtrips_to_dict():
    """to_dict 可序列化（供 report/evidence.py 投影）。"""
    graph = build_surface_graph(
        fingerprint=_sample_fingerprint(),
        component_graph=_sample_component_graph(),
        taxonomy=_sample_taxonomy(),
        endpoint="https://x",
    )
    d = graph.to_dict()
    assert d["schema_version"] == "1.0"
    assert isinstance(d["nodes"], list) and isinstance(d["edges"], list)
