"""core/contracts/component_graph.py — 多组件组合体拓扑（ComponentGraph）。

真实企业 LLM 应用几乎从不是单一组件：一次 Burp 拦截背后通常是
`web_api → llm_gateway → {rag_pipeline, embedding, mcp_tool_poisoning, ...}` 的组合体。
单一 `component_type` 标签无法表达这种结构，因此引入组件拓扑图。

复用既有资产（接线而非重写）：
    recon/a2a/topology.py:105  TopologyGraph        → 泛化为 ComponentGraph
    recon/a2a/discoverer.py:106 AgentTopologyNode   → 复用为 ComponentNode 来源
    recon/a2a/topology_mapper.py:89 A2ATopologyMapper → 接线为图构建器

Academic basis:
    - Greshake et al. (arXiv:2302.12173): 组合式攻击面
    - OWASP ASI06 / ASI07: 多智能体与跨组件信任链
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

Relation = Literal[
    "calls",
    "retrieves_from",
    "delegates_to",
    "persists_to",
    "gated_by",
    "observes",
]


class ComponentNode(BaseModel):
    """组合体中的一个组件实例。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    component_key: str
    confidence: float = 0.0
    evidence_refs: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    def add_evidence(self, ref: str) -> None:
        if ref and ref not in self.evidence_refs:
            self.evidence_refs.append(ref)

    def merge(self, other: "ComponentNode") -> None:
        """合并同键重复节点：置信度取高，证据/端点/属性取并集。"""
        if other.component_key != self.component_key:
            raise ValueError("cannot merge nodes with different component_key")
        self.confidence = max(self.confidence, other.confidence)
        for ref in other.evidence_refs:
            self.add_evidence(ref)
        for ep in other.endpoints:
            if ep not in self.endpoints:
                self.endpoints.append(ep)
        for k, v in other.attributes.items():
            self.attributes.setdefault(k, v)


class ComponentEdge(BaseModel):
    """组件间的一条有向关系边。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    src: str
    dst: str
    relation: Relation = "calls"
    confidence: float = 0.0
    evidence_refs: list[str] = Field(default_factory=list)


class ComponentGraph(BaseModel):
    """多组件组合体拓扑图（有向图）。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    nodes: list[ComponentNode] = Field(default_factory=list)
    edges: list[ComponentEdge] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # 图查询
    # ------------------------------------------------------------------
    def node(self, key: str) -> ComponentNode | None:
        for n in self.nodes:
            if n.component_key == key:
                return n
        return None

    def keys(self) -> list[str]:
        return [n.component_key for n in self.nodes]

    def has(self, key: str) -> bool:
        return self.node(key) is not None

    def add_node(self, node: ComponentNode) -> None:
        """加入节点；同键已存在时合并（不产生重复节点，IA-3）。"""
        existing = self.node(node.component_key)
        if existing is not None:
            existing.merge(node)
            return
        self.nodes.append(node)

    def add_edge(self, edge: ComponentEdge) -> None:
        """加入边；端点缺失时自动补占位节点，避免悬空引用。"""
        for key in (edge.src, edge.dst):
            if not self.has(key):
                self.nodes.append(ComponentNode(component_key=key, confidence=0.0))
        if not any(e.src == edge.src and e.dst == edge.dst and e.relation == edge.relation for e in self.edges):
            self.edges.append(edge)

    def neighbors(self, key: str, *, relation: str | None = None) -> list[str]:
        """返回 key 的下游邻居；relation 非空时按关系过滤。"""
        out: list[str] = []
        for e in self.edges:
            if e.src == key and (relation is None or e.relation == relation):
                if e.dst not in out:
                    out.append(e.dst)
        return out

    def upstream(self, key: str, *, relation: str | None = None) -> list[str]:
        """返回 key 的上游邻居。"""
        out: list[str] = []
        for e in self.edges:
            if e.dst == key and (relation is None or e.relation == relation):
                if e.src not in out:
                    out.append(e.src)
        return out

    def reachable(self, src: str) -> set[str]:
        """从 src 出发可达的全部节点（含自身）。"""
        seen: set[str] = {src}
        stack = [src]
        while stack:
            cur = stack.pop()
            for nxt in self.neighbors(cur):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    def shortest_path(self, src: str, dst: str) -> list[str] | None:
        """BFS 最短路径；不可达返回 None（IA-6：不崩溃）。"""
        if src == dst:
            return [src]
        if not self.has(src) or not self.has(dst):
            return None
        from collections import deque

        queue: deque[str] = deque([src])
        parents: dict[str, str | None] = {src: None}
        while queue:
            cur = queue.popleft()
            for nxt in self.neighbors(cur):
                if nxt in parents:
                    continue
                parents[nxt] = cur
                if nxt == dst:
                    path = [dst]
                    while parents[path[-1]] is not None:
                        path.append(parents[path[-1]])  # type: ignore[arg-type]
                    return list(reversed(path))
                queue.append(nxt)
        return None

    def all_chains(self, src: str, dst: str, *, max_depth: int = 6) -> list[list[str]]:
        """枚举 src→dst 的全部简单路径（DFS），供影响链 DFS 搜索复用。

        复用自 recon/a2a/trust_analyzer.py:200 `_dfs_chains` 的算法语义。
        """
        results: list[list[str]] = []

        def _dfs(cur: str, path: list[str]) -> None:
            if len(path) > max_depth:
                return
            if cur == dst:
                results.append(list(path))
                return
            for nxt in self.neighbors(cur):
                if nxt in path:
                    continue  # 简单路径，避免环路
                path.append(nxt)
                _dfs(nxt, path)
                path.pop()

        if not self.has(src):
            return results
        _dfs(src, [src])
        return results

    def topological_order(self) -> list[str]:
        """Kahn 拓扑排序；存在环时把剩余节点按置信度降序追加（不抛异常）。"""
        indeg: dict[str, int] = {n.component_key: 0 for n in self.nodes}
        for e in self.edges:
            if e.dst in indeg:
                indeg[e.dst] += 1
        ready = [k for k, v in indeg.items() if v == 0]
        order: list[str] = []
        while ready:
            cur = ready.pop(0)
            order.append(cur)
            for nxt in self.neighbors(cur):
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    ready.append(nxt)
        remaining = [k for k in indeg if k not in order]
        remaining.sort(key=lambda k: -(self.node(k).confidence if self.node(k) else 0.0))
        return order + remaining

    def dominant(self) -> str | None:
        """置信度最高的组件键；空图返回 None（IA-6 兼容 _determine_dominant_component）。"""
        if not self.nodes:
            return None
        return max(self.nodes, key=lambda n: n.confidence).component_key

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
