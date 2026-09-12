# -*- coding: utf-8 -*-
"""recon/a2a/topology_mapper.py - A2A Multi-Agent Topology Mapping.

Maps the communication topology of multi-agent systems:
    1. Agent-to-agent communication patterns
    2. Hub/spoke vs mesh topology detection
    3. Critical path identification for attack targeting
    4. Trust relationship mapping
    5. Bottleneck agent detection (high-value targets)

Academic basis:
    - Eidam et al. (arXiv:2407.16924) - A2A trust chain analysis
    - OWASP ASI Top 10 2025 - Multi-agent reconnaissance

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - topology mapping only
    - R-S1: No hardcoded target identifiers
    - R-S4: Tests all mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AgentNode:
    """Represents an agent in the multi-agent topology."""

    agent_id: str = ""
    agent_name: str = ""
    agent_url: str = ""
    capabilities: list[str] = field(default_factory=list)
    connections: list[str] = field(default_factory=list)  # agent_ids this agent communicates with
    trust_level: str = "unknown"  # trusted, untrusted, boundary
    is_hub: bool = False  # High connectivity = hub
    is_critical: bool = False  # Critical path agent

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "agent_url": self.agent_url,
            "capabilities": self.capabilities,
            "connections": self.connections,
            "trust_level": self.trust_level,
            "is_hub": self.is_hub,
            "is_critical": self.is_critical,
        }


@dataclass
class TopologyMapResult:
    """Complete topology mapping result."""

    target_url: str = ""
    agents: list[AgentNode] = field(default_factory=list)
    topology_type: str = "unknown"  # hub_spoke, mesh, chain, star
    hub_agents: list[str] = field(default_factory=list)
    critical_paths: list[list[str]] = field(default_factory=list)
    trust_boundaries: list[tuple[str, str]] = field(default_factory=list)
    attack_surface_score: float = 0.0  # 0.0-1.0

    @property
    def agent_count(self) -> int:
        return len(self.agents)

    @property
    def has_hub_agents(self) -> bool:
        return len(self.hub_agents) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "agents": [a.to_dict() for a in self.agents],
            "topology_type": self.topology_type,
            "hub_agents": self.hub_agents,
            "critical_paths": self.critical_paths,
            "trust_boundaries": self.trust_boundaries,
            "attack_surface_score": self.attack_surface_score,
        }


class A2ATopologyMapper:
    """Maps multi-agent system communication topology.

    Usage:
        mapper = A2ATopologyMapper()
        result = await mapper.map_topology(
            target_url="http://multi-agent:8000",
            agent_cards=discovered_cards,
        )
        for hub in result.hub_agents:
            print(f"Hub agent: {hub}")
    """

    def __init__(self):
        self._hub_threshold = 3  # Connections needed to be a hub

    async def map_topology(
        self,
        target_url: str,
        agent_cards: list[dict[str, Any]],
    ) -> TopologyMapResult:
        """Map the multi-agent topology from agent cards.

        Args:
            target_url: Target multi-agent system URL
            agent_cards: List of discovered agent cards

        Returns:
            TopologyMapResult with complete topology map
        """
        result = TopologyMapResult(target_url=target_url)

        # Build agent nodes from cards
        for card in agent_cards:
            node = self._build_agent_node(card)
            result.agents.append(node)

        # Detect connections between agents
        self._detect_connections(result)

        # Classify topology type
        result.topology_type = self._classify_topology(result)

        # Identify hub agents
        result.hub_agents = self._identify_hubs(result)

        # Find critical paths
        result.critical_paths = self._find_critical_paths(result)

        # Calculate attack surface score
        result.attack_surface_score = self._calculate_attack_surface(result)

        return result

    def _build_agent_node(self, card: dict[str, Any]) -> AgentNode:
        """Build an AgentNode from an agent card."""
        return AgentNode(
            agent_id=card.get("id", card.get("name", "")),
            agent_name=card.get("name", ""),
            agent_url=card.get("url", ""),
            capabilities=card.get("skills", card.get("capabilities", [])),
        )

    def _detect_connections(self, result: TopologyMapResult) -> None:
        """Detect inter-agent connections from agent capabilities."""
        for agent in result.agents:
            # Agents with matching capabilities likely communicate
            for other in result.agents:
                if agent.agent_id == other.agent_id:
                    continue
                # Check for capability overlap (potential communication)
                shared_caps = set(agent.capabilities) & set(other.capabilities)
                if shared_caps:
                    other.agent_id in agent.connections or agent.connections.append(other.agent_id)

    def _classify_topology(self, result: TopologyMapResult) -> str:
        """Classify the topology type."""
        if not result.agents:
            return "empty"

        connection_counts = [len(a.connections) for a in result.agents]
        max_connections = max(connection_counts) if connection_counts else 0
        avg_connections = sum(connection_counts) / max(len(connection_counts), 1)

        if max_connections >= len(result.agents) - 1:
            return "star"  # One agent connected to all others
        elif avg_connections >= len(result.agents) / 2:
            return "mesh"  # Most agents connected to many others
        elif max_connections <= 2:
            return "chain"  # Linear chain topology
        else:
            return "hub_spoke"  # Hub agents with spoke connections

    def _identify_hubs(self, result: TopologyMapResult) -> list[str]:
        """Identify hub agents with high connectivity."""
        hubs = []
        for agent in result.agents:
            if len(agent.connections) >= self._hub_threshold:
                agent.is_hub = True
                hubs.append(agent.agent_id)
        return hubs

    def _find_critical_paths(self, result: TopologyMapResult) -> list[list[str]]:
        """Find critical communication paths for attack targeting."""
        if not result.agents:
            return []

        # Simple critical path: paths through hub agents
        paths = []
        for hub in result.hub_agents:
            hub_agent = next((a for a in result.agents if a.agent_id == hub), None)
            if hub_agent:
                for conn in hub_agent.connections:
                    paths.append([hub, conn])

        return paths

    def _calculate_attack_surface(self, result: TopologyMapResult) -> float:
        """Calculate overall attack surface score."""
        if not result.agents:
            return 0.0

        # More agents + more connections = larger attack surface
        agent_factor = min(len(result.agents) / 5, 1.0)  # Cap at 5 agents
        connection_factor = min(
            sum(len(a.connections) for a in result.agents) / (len(result.agents) * 3),
            1.0,
        )

        return (agent_factor + connection_factor) / 2


async def map_a2a_topology(
    target_url: str,
    agent_cards: list[dict[str, Any]],
) -> TopologyMapResult:
    """Convenience function for A2A topology mapping.

    Args:
        target_url: Target URL
        agent_cards: List of discovered agent cards

    Returns:
        TopologyMapResult
    """
    mapper = A2ATopologyMapper()
    return await mapper.map_topology(target_url, agent_cards)
