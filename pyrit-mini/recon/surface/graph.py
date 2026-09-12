"""recon/surface/graph.py — 攻击面图谱数据结构（REQ-150）。

为什么不是单标签：
    企业目标是**组合体**。一次 Burp 拦截背后常见
    `web_api → llm_gateway → {rag_pipeline, mcp_tool_poisoning, ...}`，
    单值 `component_type` 无法表达，也无法表达"跨组件链"
    （间接注入 → 工具调用 → 数据外传）。本模块把侦察输出升级为
    **多标签 + 分组件置信度 + 信任边界 + 数据流边**的图谱。

三条主线约束落点：
    - IC-1：组件归属为 `labels: list[str]` + `label_confidence: dict[str, float]`，
      单值 `component_type` 仅为**兼容派生视图**（W5 删除）。
    - IC-3：一个 finding 允许归属多个组件（见 `report/evidence.py` 的 `graph_ref`
      与 `core/phases/_component_bridge.stamp_component_metadata`）。
    - 蓝图 I12：节点证据一律为 EventLog 事件 ID（可回溯），禁止另立旁路。

Academic basis:
    - Greshake et al. (arXiv:2302.12173): 组合式间接注入攻击面
    - OWASP ASI06 / ASI07: 多智能体与跨组件信任链

Note:
    本模块为**纯数据结构 + 图查询**，不含任何 I/O（不发起请求、不读文件）。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

EdgeType = Literal[
    "data_flow",
    "trust_boundary",
    "calls",
    "delegates_to",
    "retrieves_from",
    "persists_to",
    "gated_by",
]

# 识别失败时的兜底标签（REQ-150 ④）
DEFAULT_FALLBACK_LABELS: tuple[str, ...] = ("model",)


class SurfaceNode(BaseModel):
    """攻击面图谱中的一个节点。

    Attributes:
        node_id: 稳定节点标识（通常与 `component_key` 一致；入口节点为 `entry`）。
        labels: **多标签**（IC-1）。如 `["rag", "mcp_connected"]`。
        label_confidence: 每个标签的置信度（0.0–1.0）。
        capabilities: 该节点观测到的能力（tools_list / streaming / file_upload ...）。
        endpoints: 该节点对应的 URL/端点。
        evidence: EventLog 事件 ID 列表（蓝图 I12：可回溯，禁止旁路）。
        trust_boundary: 该节点是否位于信任边界上（认证/网关/租户隔离点）。
        attributes: 其他观测属性（模型族、认证方式、租户键等）。
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    node_id: str
    labels: list[str] = Field(default_factory=list)
    label_confidence: dict[str, float] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    trust_boundary: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # 标签查询
    # ------------------------------------------------------------------
    def add_label(self, label: str, confidence: float) -> None:
        """追加/升级一个标签（同标签取高置信度，IA-3：不产生重复）。"""
        if not label:
            return
        if label not in self.labels:
            self.labels.append(label)
        if confidence >= self.label_confidence.get(label, 0.0):
            self.label_confidence[label] = round(float(confidence), 3)

    def confidence_for(self, label: str) -> float:
        """返回指定标签的置信度；未命中返回 0.0（IA-6：不抛异常）。"""
        return float(self.label_confidence.get(label, 0.0))

    def top_label(self) -> str | None:
        """置信度最高的标签；无标签返回 None。"""
        if not self.label_confidence:
            return None
        return max(self.label_confidence, key=lambda k: self.label_confidence[k])

    def sorted_labels(self) -> list[str]:
        """按置信度降序返回标签列表（报告与决策消费的稳定顺序）。"""
        return sorted(self.labels, key=lambda k: -self.label_confidence.get(k, 0.0))

    def add_evidence(self, event_id: str) -> None:
        if event_id and event_id not in self.evidence:
            self.evidence.append(event_id)

    def merge(self, other: "SurfaceNode") -> None:
        """合并同 `node_id` 的重复节点（置信度取高，其余取并集）。"""
        if other.node_id != self.node_id:
            raise ValueError("cannot merge nodes with different node_id")
        for label, conf in other.label_confidence.items():
            self.add_label(label, conf)
        for item in other.capabilities:
            if item not in self.capabilities:
                self.capabilities.append(item)
        for item in other.endpoints:
            if item not in self.endpoints:
                self.endpoints.append(item)
        for ref in other.evidence:
            self.add_evidence(ref)
        self.trust_boundary = self.trust_boundary or other.trust_boundary
        for k, v in other.attributes.items():
            self.attributes.setdefault(k, v)


class SurfaceEdge(BaseModel):
    """图谱中的一条有向边。

    Attributes:
        src / dst: 节点 ID。
        type: 边类型。`data_flow` = 数据实际流经；`trust_boundary` = 跨越信任边界
            （认证/网关/租户隔离）；其余为 `ComponentGraph.Relation` 的语义延续。
        confidence: 该关系的置信度。
        evidence: EventLog 事件 ID 列表。
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    src: str
    dst: str
    type: EdgeType = "data_flow"
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class SurfaceGraph(BaseModel):
    """攻击面图谱（REQ-150）。

    Attributes:
        nodes: 节点集合。
        edges: 边集合。
        fallback_labels: 识别失败时使用的兜底标签（REQ-150 ④）。
        entry_node_id: 入口节点（Burp 拦截到的那个端点）。
        unknown: 是否识别失败（True 时下游应走兜底路径而非相信标签）。
    """

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    nodes: list[SurfaceNode] = Field(default_factory=list)
    edges: list[SurfaceEdge] = Field(default_factory=list)
    fallback_labels: list[str] = Field(default_factory=lambda: list(DEFAULT_FALLBACK_LABELS))
    entry_node_id: str = "entry"
    unknown: bool = False

    # ------------------------------------------------------------------
    # 结构操作
    # ------------------------------------------------------------------
    def node(self, node_id: str) -> SurfaceNode | None:
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        return None

    def has(self, node_id: str) -> bool:
        return self.node(node_id) is not None

    def add_node(self, node: SurfaceNode) -> None:
        """加入节点；同 ID 已存在时合并（IA-3：无重复节点）。"""
        existing = self.node(node.node_id)
        if existing is not None:
            existing.merge(node)
            return
        self.nodes.append(node)

    def add_edge(self, edge: SurfaceEdge) -> None:
        """加入边；端点缺失时补占位节点，避免悬空引用。"""
        for node_id in (edge.src, edge.dst):
            if not self.has(node_id):
                self.nodes.append(SurfaceNode(node_id=node_id))
        if not any(e.src == edge.src and e.dst == edge.dst and e.type == edge.type for e in self.edges):
            self.edges.append(edge)

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def labels(self) -> list[str]:
        """图中出现的全部标签（去重，按最高置信度降序）。"""
        best: dict[str, float] = {}
        for node in self.nodes:
            for label, conf in node.label_confidence.items():
                best[label] = max(best.get(label, 0.0), conf)
        return sorted(best, key=lambda k: -best[k])

    def by_label(self, label: str) -> list[SurfaceNode]:
        """返回带指定标签的全部节点（IC-3：一个标签可命中多个节点）。"""
        return [n for n in self.nodes if label in n.labels]

    def dominant_label(self) -> str | None:
        """全图置信度最高的标签；空图/识别失败返回兜底标签之首。"""
        ranked = self.labels()
        if ranked:
            return ranked[0]
        return self.fallback_labels[0] if self.fallback_labels else None

    def component_labels_for(self, node_id: str) -> tuple[list[str], dict[str, float]]:
        """IC-1 兼容读取口：返回 `(labels, label_confidence)`。

        未知节点返回 `([], {})` —— 由调用方决定是否落到 `fallback_labels`
        （IA-6：未知不崩溃）。
        """
        node = self.node(node_id)
        if node is None:
            return [], {}
        return list(node.sorted_labels()), dict(node.label_confidence)

    def neighbors(self, node_id: str, *, edge_type: EdgeType | None = None) -> list[str]:
        out: list[str] = []
        for e in self.edges:
            if e.src == node_id and (edge_type is None or e.type == edge_type):
                if e.dst not in out:
                    out.append(e.dst)
        return out

    def data_flow_chain(self) -> list[str]:
        """从入口沿 `data_flow` 边做 DFS，返回数据流路径（攻击链编排的消费入口）。"""
        seen: list[str] = []

        def _dfs(cur: str) -> None:
            if cur in seen:
                return
            seen.append(cur)
            for nxt in self.neighbors(cur, edge_type="data_flow"):
                _dfs(nxt)

        _dfs(self.entry_node_id)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
