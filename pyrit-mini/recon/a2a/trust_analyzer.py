# -*- coding: utf-8 -*-
"""recon/a2a/trust_analyzer.py - A2A Trust Chain Analysis.

Analyzes trust relationships in multi-agent systems:
    1. Trust path identification between agents
    2. Trust level classification (full, partial, untrusted)
    3. Trust chain vulnerability detection
    4. Cascading trust exploitation mapping
    5. Boundary agent detection (trust transition points)

Academic basis:
    - Eidam et al. (arXiv:2407.16924) - A2A trust chain exploits
    - OWASP ASI Top 10 2025 - Agent trust boundary violations

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - trust analysis only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TrustEdge:
    """Trust relationship between two agents."""

    from_agent: str = ""
    to_agent: str = ""
    trust_level: str = "unknown"  # full, partial, none, verified
    bidirectional: bool = False
    authentication: str = "none"  # none, token, certificate, signature
    is_boundary: bool = False  # Trust level change boundary

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "trust_level": self.trust_level,
            "bidirectional": self.bidirectional,
            "authentication": self.authentication,
            "is_boundary": self.is_boundary,
        }


@dataclass
class TrustChainSegment:
    """A segment of the trust chain."""

    chain: list[str] = field(default_factory=list)
    weakest_link: str = ""
    exploitability: float = 0.0  # 0.0-1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain,
            "weakest_link": self.weakest_link,
            "exploitability": self.exploitability,
        }


@dataclass
class TrustAnalysisResult:
    """Complete trust analysis result."""

    target_url: str = ""
    trust_edges: list[TrustEdge] = field(default_factory=list)
    trust_chains: list[TrustChainSegment] = field(default_factory=list)
    boundary_agents: list[str] = field(default_factory=list)
    weakest_trust_links: list[tuple[str, str]] = field(default_factory=list)
    cascading_trust_risk: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "trust_edges": [e.to_dict() for e in self.trust_edges],
            "trust_chains": [c.to_dict() for c in self.trust_chains],
            "boundary_agents": self.boundary_agents,
            "weakest_trust_links": self.weakest_trust_links,
            "cascading_trust_risk": self.cascading_trust_risk,
        }


class A2ATrustAnalyzer:
    """Analyze trust relationships in A2A multi-agent systems.

    Usage:
        analyzer = A2ATrustAnalyzer()
        result = await analyzer.analyze(
            target_url="http://multi-agent:8000",
            agent_cards=discovered_cards,
        )
    """

    def __init__(self):
        self._trust_map: dict[str, dict[str, TrustEdge]] = {}

    async def analyze(
        self,
        target_url: str,
        agent_cards: list[dict[str, Any]],
    ) -> TrustAnalysisResult:
        """Analyze trust relationships between agents.

        Args:
            target_url: Target A2A system URL
            agent_cards: Discovered agent cards with trust info

        Returns:
            TrustAnalysisResult with complete trust analysis
        """
        result = TrustAnalysisResult(target_url=target_url)

        # Build trust edges from agent cards
        result.trust_edges = await self._build_trust_edges(agent_cards)

        # Discover trust chains
        result.trust_chains = self._discover_chains(result.trust_edges)

        # Identify boundary agents
        result.boundary_agents = self._find_boundaries(result.trust_edges)

        # Find weakest links
        result.weakest_trust_links = self._find_weakest_links(result.trust_edges)

        # Calculate cascading trust risk
        result.cascading_trust_risk = self._calc_cascading_risk(result)

        return result

    async def _build_trust_edges(
        self,
        agent_cards: list[dict[str, Any]],
    ) -> list[TrustEdge]:
        """Build trust edges from agent cards."""
        edges = []

        for card in agent_cards:
            agent_id = card.get("id", card.get("name", ""))
            connections = card.get("connections", card.get("trustedAgents", []))

            for conn in connections:
                if isinstance(conn, str):
                    target_id = conn
                    trust_info = {}
                elif isinstance(conn, dict):
                    target_id = conn.get("agentId", conn.get("id", ""))
                    trust_info = conn
                else:
                    continue

                edge = TrustEdge(
                    from_agent=agent_id,
                    to_agent=target_id,
                    trust_level=trust_info.get("trustLevel", "unknown"),
                    bidirectional=trust_info.get("bidirectional", False),
                    authentication=self._detect_auth(card),
                )
                edges.append(edge)

        return edges

    def _detect_auth(self, card: dict[str, Any]) -> str:
        """Detect authentication type from agent card."""
        security_schemes = card.get("securitySchemes", {})
        if not security_schemes:
            return "none"
        if "bearer" in str(security_schemes).lower():
            return "token"
        if "certificate" in str(security_schemes).lower():
            return "certificate"
        if "signature" in str(security_schemes).lower():
            return "signature"
        return "other"

    def _discover_chains(
        self,
        edges: list[TrustEdge],
    ) -> list[TrustChainSegment]:
        """Discover trust chains from edges."""
        chains = []
        adj: dict[str, list[str]] = {}

        for edge in edges:
            adj.setdefault(edge.from_agent, []).append(edge.to_agent)

        # Simple chain detection: depth-first walks
        for start in adj:
            visited = set()
            self._dfs_chains(start, [start], visited, adj, chains)

        return chains[:10]  # Limit to top 10 chains

    def _dfs_chains(
        self,
        current: str,
        path: list[str],
        visited: set[str],
        adj: dict[str, list[str]],
        chains: list[TrustChainSegment],
    ) -> None:
        """DFS to find trust chains."""
        if current in visited:
            return
        visited.add(current)

        neighbors = adj.get(current, [])
        if not neighbors and len(path) > 1:
            # End of chain
            segment = TrustChainSegment(
                chain=list(path),
                weakest_link=path[-1],
                exploitability=1.0 / len(path),  # Shorter chains = more exploitable
            )
            chains.append(segment)
            return

        for neighbor in neighbors:
            self._dfs_chains(neighbor, path + [neighbor], visited, adj, chains)

        visited.remove(current)

    def _find_boundaries(self, edges: list[TrustEdge]) -> list[str]:
        """Find agents at trust level boundaries."""
        boundaries = []

        for agent_id in {e.from_agent for e in edges}:
            outgoing_trust = {e.trust_level for e in edges if e.from_agent == agent_id}
            if len(outgoing_trust) > 1:
                # Agent trusts others at different levels
                boundaries.append(agent_id)

        return boundaries

    def _find_weakest_links(
        self,
        edges: list[TrustEdge],
    ) -> list[tuple[str, str]]:
        """Find weakest trust links (none or partial trust)."""
        weak = []
        for edge in edges:
            if edge.trust_level in ("none", "unknown"):
                weak.append((edge.from_agent, edge.to_agent))
        return weak

    def _calc_cascading_risk(self, result: TrustAnalysisResult) -> float:
        """Calculate cascading trust exploitation risk."""
        if not result.trust_edges:
            return 0.0

        # More chains + weaker links = higher cascading risk
        chain_factor = min(len(result.trust_chains) / 5, 1.0)
        weak_factor = min(len(result.weakest_trust_links) / 3, 1.0)
        boundary_factor = min(len(result.boundary_agents) / 2, 1.0)

        return (chain_factor * 0.4 + weak_factor * 0.35 + boundary_factor * 0.25,)


async def analyze_a2a_trust(
    target_url: str,
    agent_cards: list[dict[str, Any]],
) -> TrustAnalysisResult:
    """Convenience function for A2A trust analysis."""
    analyzer = A2ATrustAnalyzer()
    return await analyzer.analyze(target_url, agent_cards)
