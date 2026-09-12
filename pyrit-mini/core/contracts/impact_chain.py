"""core/contracts/impact_chain.py — 影响链举证（ImpactChain）。

红队报告的价值不在「某个 prompt 生效了」，而在证明一条从入口组件到最终业务影响的
**因果链**。`validate_causality()` 是「举证而非断言」的硬约束：每个中间节点必须有
≥1 条入边、且能追溯到 EVD-* 证据，否则返回 `CausalityGap`。

复用既有资产（接线而非重写）：
    recon/a2a/trust_analyzer.py:53  TrustChainSegment
    recon/a2a/trust_analyzer.py:182 _discover_chains
    recon/a2a/trust_analyzer.py:200 _dfs_chains        → 影响链 DFS 搜索引擎
    recon/a2a/attack_planner.py:115 AttackPathPlanner
    recon/trust_chain_probe.py:60   TrustChainResult
    recon/trust_level_enum.py:225   TrustEscalationPath → 边语义

Academic basis:
    - OWASP ASI Top 10: 影响映射到 ASI01-ASI10
    - CVSS v3.1: cvss_vector 字段
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

Severity = Literal["critical", "high", "medium", "low"]


class ImpactLink(BaseModel):
    """因果边：从上一步骤到下一步骤的机制说明 + 证据引用。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    from_step: str
    to_step: str
    mechanism: str
    evidence_ids: list[str] = Field(default_factory=list)


class ImpactNode(BaseModel):
    """影响链中的一个节点：技术结果 + 业务影响 + 严重级 + 合规映射。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    step_id: str
    component_key: str
    outcome: str
    business_impact: str = ""
    severity: Severity = "medium"
    owasp: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)

    def is_traceable(self) -> bool:
        """是否可追溯到至少一条证据（举证要求）。"""
        return bool(self.evidence_ids)


class CausalityGap(BaseModel):
    """因果链缺口：举证不完整的节点/边。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    kind: Literal["orphan_node", "missing_evidence", "dangling_link"]
    target: str
    detail: str


class ImpactChain(BaseModel):
    """完整影响链。"""

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    nodes: list[ImpactNode] = Field(default_factory=list)
    links: list[ImpactLink] = Field(default_factory=list)
    terminal_impact: str = ""
    entry_step: str | None = None

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def node(self, step_id: str) -> ImpactNode | None:
        for n in self.nodes:
            if n.step_id == step_id:
                return n
        return None

    def entry_nodes(self) -> list[ImpactNode]:
        """没有任何入边的节点（链起点）。"""
        targets = {link.to_step for link in self.links}
        return [n for n in self.nodes if n.step_id not in targets]

    def terminal_nodes(self) -> list[ImpactNode]:
        """没有任何出边的节点（链终点）。"""
        sources = {link.from_step for link in self.links}
        return [n for n in self.nodes if n.step_id not in sources]

    def evidence_ids(self) -> list[str]:
        out: list[str] = []
        for n in self.nodes:
            for e in n.evidence_ids:
                if e not in out:
                    out.append(e)
        for link in self.links:
            for e in link.evidence_ids:
                if e not in out:
                    out.append(e)
        return out

    def max_severity(self) -> Severity:
        order = ["low", "medium", "high", "critical"]
        idx = 0
        for n in self.nodes:
            idx = max(idx, order.index(n.severity))
        return order[idx]  # type: ignore[return-value]

    def owasp_ids(self) -> list[str]:
        out: list[str] = []
        for n in self.nodes:
            for o in n.owasp:
                if o not in out:
                    out.append(o)
        return out

    # ------------------------------------------------------------------
    # 因果性校验（举证而非断言）
    # ------------------------------------------------------------------
    def validate_causality(self) -> list[CausalityGap]:
        """校验因果链完整性，返回全部缺口（空列表 = 举证成立）。

        约束：
            1. 每个非入口节点必须有 ≥1 条入边（orphan_node）
            2. 每个节点必须能追溯到 ≥1 个 EVD-* 证据（missing_evidence）
            3. 每条 link 的两端节点必须存在（dangling_link）
        """
        gaps: list[CausalityGap] = []
        known = {n.step_id for n in self.nodes}
        targets = {link.to_step for link in self.links}

        for n in self.nodes:
            if n.step_id not in targets and len(self.nodes) > 1 and self.entry_step != n.step_id:
                gaps.append(
                    CausalityGap(
                        kind="orphan_node",
                        target=n.step_id,
                        detail=f"节点 {n.step_id} 无入边且非声明入口，因果链断裂",
                    )
                )
            if not n.is_traceable():
                gaps.append(
                    CausalityGap(
                        kind="missing_evidence",
                        target=n.step_id,
                        detail=f"节点 {n.step_id} 无 EVD-* 证据支撑，属断言而非举证",
                    )
                )

        for link in self.links:
            if link.from_step not in known or link.to_step not in known:
                gaps.append(
                    CausalityGap(
                        kind="dangling_link",
                        target=f"{link.from_step}->{link.to_step}",
                        detail="link 端点不存在于 nodes",
                    )
                )
        return gaps

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
