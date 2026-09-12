"""tests/test_impact_chain.py — 影响链举证（plan Wave 3）。

覆盖 DoD：
    - ImpactChain.validate_causality() 对合规链返回 0 个 CausalityGap
    - 每个 ImpactNode 可追溯到 >= 1 个 EVD-* 证据
    - 缺证据时**必须**报缺口（举证而非断言）
"""

from __future__ import annotations

from typing import Any

from core.contracts.attack_chain import AttackStep, StatefulAttackChain
from core.contracts.component_graph import ComponentEdge, ComponentGraph, ComponentNode
from core.contracts.impact_chain import ImpactChain, ImpactNode
from report.impact_chain import (
    ImpactChainBuilder,
    build_impact_chains_from_components,
    validate_all,
)


def _chain(*steps: AttackStep) -> StatefulAttackChain:
    chain = StatefulAttackChain(name="t")
    chain.steps = list(steps)
    for s in chain.steps:
        chain.state.status[s.id] = "succeeded"
    return chain


def _step(sid: str, component: str, **kw: Any) -> AttackStep:
    return AttackStep(id=sid, component_key=component, action="a", **kw)


class TestBuildImpactChain:
    def test_builds_nodes_and_links_from_successful_steps(self) -> None:
        chain = _chain(
            _step("1:web_api", "web_api", produces=["reachable_endpoint"]),
            _step("2:mcp", "mcp_tool_poisoning", consumes=["reachable_endpoint"], produces=["tool_schema"]),
        )
        ic = ImpactChainBuilder().build(
            attack_chain=chain,
            evidence_by_step={"1:web_api": ["EVD-0001"], "2:mcp": ["EVD-0002"]},
        )
        assert len(ic.nodes) == 2
        assert len(ic.links) == 1
        assert ic.nodes[0].component_key == "web_api"

    def test_no_gaps_when_evidence_present(self) -> None:
        """合规链：每个节点有证据 → 0 缺口。"""
        chain = _chain(_step("1:web_api", "web_api"))
        ic = ImpactChainBuilder().build(attack_chain=chain, evidence_by_step={"1:web_api": ["EVD-0001"]})
        assert ic.validate_causality() == []

    def test_missing_evidence_reports_gap(self) -> None:
        """举证而非断言：缺证据必须报 missing_evidence 缺口。"""
        chain = _chain(_step("1:web_api", "web_api"))
        ic = ImpactChainBuilder().build(attack_chain=chain, evidence_by_step={})
        gaps = ic.validate_causality()
        assert any(g.kind == "missing_evidence" for g in gaps)

    def test_terminal_impact_and_severity(self) -> None:
        chain = _chain(
            _step("1:web_api", "web_api"),
            _step("2:mcp", "mcp_tool_poisoning"),
        )
        ic = ImpactChainBuilder().build(
            attack_chain=chain, evidence_by_step={"1:web_api": ["EVD-1"], "2:mcp": ["EVD-2"]}
        )
        assert ic.max_severity() == "critical"
        assert ic.terminal_impact, "最终业务影响禁止为空"
        assert "ASI02" in ic.owasp_ids()

    def test_empty_chain_returns_empty_impact(self) -> None:
        ic = ImpactChainBuilder().build(attack_chain=_chain())
        assert ic.nodes == []
        assert ic.validate_causality() == []

    def test_unknown_component_uses_fallback_template(self) -> None:
        ic = ImpactChainBuilder().build(
            attack_chain=_chain(_step("1:x", "totally_unknown_component")),
            evidence_by_step={"1:x": ["EVD-0001"]},
        )
        assert len(ic.nodes) == 1
        assert ic.nodes[0].severity == "low"


class TestImpactChainContract:
    def test_orphan_node_detected(self) -> None:
        ic = ImpactChain(
            nodes=[
                ImpactNode(step_id="a", component_key="web_api", outcome="x", evidence_ids=["EVD-1"]),
                ImpactNode(step_id="b", component_key="mcp_tool_poisoning", outcome="y", evidence_ids=["EVD-2"]),
            ],
            links=[],
            entry_step="a",
        )
        gaps = ic.validate_causality()
        assert any(g.kind == "orphan_node" and g.target == "b" for g in gaps)

    def test_dangling_link_detected(self) -> None:
        ic = ImpactChain(
            nodes=[ImpactNode(step_id="a", component_key="web_api", outcome="x", evidence_ids=["EVD-1"])],
            links=[],
            entry_step="a",
        )
        from core.contracts.impact_chain import ImpactLink

        ic.links = [ImpactLink(from_step="a", to_step="ghost", mechanism="m", evidence_ids=[])]
        assert any(g.kind == "dangling_link" for g in ic.validate_causality())

    def test_evidence_ids_aggregated(self) -> None:
        ic = ImpactChain(
            nodes=[
                ImpactNode(step_id="a", component_key="web_api", outcome="x", evidence_ids=["EVD-1"]),
                ImpactNode(step_id="b", component_key="rag_pipeline", outcome="y", evidence_ids=["EVD-2", "EVD-1"]),
            ],
            links=[],
        )
        assert ic.evidence_ids() == ["EVD-1", "EVD-2"]


class TestEnumerateChainsFromGraph:
    def _graph(self) -> ComponentGraph:
        g = ComponentGraph()
        g.add_node(ComponentNode(component_key="web_api", confidence=0.9))
        g.add_node(ComponentNode(component_key="llm_gateway", confidence=0.8))
        g.add_node(ComponentNode(component_key="mcp_tool_poisoning", confidence=0.7))
        g.add_edge(ComponentEdge(src="web_api", dst="llm_gateway", relation="gated_by", confidence=0.8))
        g.add_edge(ComponentEdge(src="llm_gateway", dst="mcp_tool_poisoning", relation="delegates_to", confidence=0.7))
        g.entry_points = ["web_api"]
        return g

    def test_enumerates_entry_to_leaf_chains(self) -> None:
        chains = build_impact_chains_from_components(self._graph())
        assert chains, "应枚举出至少一条影响链"
        assert all(c.nodes for c in chains)
        assert any(len(c.nodes) == 3 for c in chains), "应存在入口→网关→MCP 的完整链"

    def test_validate_all_returns_gaps_only_for_unbacked(self) -> None:
        chains = build_impact_chains_from_components(
            self._graph(),
            evidence_by_component={"web_api": ["EVD-1"], "llm_gateway": ["EVD-2"], "mcp_tool_poisoning": ["EVD-3"]},
        )
        assert validate_all(chains) == []

    def test_empty_graph_returns_no_chains(self) -> None:
        assert build_impact_chains_from_components(ComponentGraph()) == []

    def test_none_graph_returns_no_chains(self) -> None:
        assert build_impact_chains_from_components(None) == []
