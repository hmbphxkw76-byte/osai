# Google A2A Protocol - Multi-Agent Topology Analysis
# Reference: https://a2a-protocol.org/latest/specification/
# arXiv:2407.16924 - Eidam et al., A2A trust chain attacks
"""multi_agent_topology - Multi-agent architecture pattern inference and topology analysis.

Infer multi-agent architecture patterns from scan results:
    1. Architecture Pattern Detection: Hub-and-Spoke, Pipeline, Mesh, Hybrid
    2. Control Agent Identification: Orchestrator/Coordinator roles
    3. Data Agent Classification: Database, Generator, Analyzer roles
    4. Defense Agent Detection: Security/scanner/filter roles
    5. Attack Surface Mapping: Trust relationship extraction

Design principles:
    1. Heuristic-based classification (no ML dependency)
    2. Safe degradation when topology is ambiguous
    3. Outputs feed into attack_surface_mapper and A2A attack planner
    4. No external dependencies beyond a2a_discoverer + a2a_agent_card

R2 (PyRIT Native First): Pure analysis module, no HTTP requests
R6 Sec6.4: A2A topology analysis for attack surface mapping
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ArchitecturePattern(Enum):
    """Multi-agent architecture patterns."""

    HUB_AND_SPOKE = "hub_and_spoke"  # Central orchestrator + workers
    SEQUENTIAL_PIPELINE = "sequential_pipeline"  # A -> B -> C chain
    MESH = "mesh"  # Full peer-to-peer
    STAR = "star"  # Single central node
    UNKNOWN = "unknown"  # Ambiguous/no pattern


class AgentRole(Enum):
    """Functional roles of agents in topology."""

    ORCHESTRATOR = "orchestrator"  # Coordinates workflow
    DATA_PROCESSOR = "data_processor"  # Database/analyzer/generator
    DEFENSE = "defense"  # Security/scanner/filter
    INTERFACE = "interface"  # Web UI / API gateway
    WORKER = "worker"  # Generic task executor
    UNKNOWN = "unknown"  # No clear role


# Heuristic keywords for role detection (case-insensitive)
_ORCHESTRATOR_SIGNALS = {
    "name": ["orchestrator", "coordinator", "controller", "master", "chief"],
    "skills": ["workflow-planning", "agent_discovery", "coordination", "routing"],
    "tags": ["orchestration", "coordination", "multi-agent", "planning"],
}

_DEFENSE_SIGNALS = {
    "name": ["security", "guard", "firewall", "scanner", "defender", "waf"],
    "skills": ["security-scan", "malware-detection", "guardrail", "filtering", "audit"],
    "tags": ["security", "malware", "phishing", "scanning", "guardrail", "defense"],
}

_DATA_PROCESSOR_SIGNALS = {
    "name": ["database", "sql", "analyzer", "generator", "transformer", "enricher"],
    "skills": ["nl-to-sql", "schema-discovery", "chart-generation", "report-generation"],
    "tags": ["sql", "database", "crud", "analytics", "generation", "extraction"],
}

_INTERFACE_SIGNALS = {
    "name": ["webapp", "web", "ui", "gateway", "frontend", "portal"],
    "skills": ["render", "display", "serve", "proxy"],
    "tags": ["web", "ui", "frontend", "gateway", "http"],
}


@dataclass
class _RoleScore:
    """Internal role scoring result."""

    role: AgentRole
    score: float = 0.0
    signals: list[str] = field(default_factory=list)


@dataclass
class ClassifiedAgent:
    """Agent with inferred role and role confidence."""

    agent_id: str
    name: str
    url: str
    port: int
    skills: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    role: AgentRole = AgentRole.UNKNOWN
    role_confidence: float = 0.0
    role_signals: list[str] = field(default_factory=list)


@dataclass
class TopologyGraph:
    """Complete multi-agent topology analysis result.

    Primary output of topology analysis, consumed by attack
    surface mapper and A2A attack planner.
    """

    pattern: ArchitecturePattern = ArchitecturePattern.UNKNOWN
    classified_agents: list[ClassifiedAgent] = field(default_factory=list)
    control_agent: Optional[ClassifiedAgent] = None
    data_agents: list[ClassifiedAgent] = field(default_factory=list)
    defense_agents: list[ClassifiedAgent] = field(default_factory=list)
    interface_agents: list[ClassifiedAgent] = field(default_factory=list)
    worker_agents: list[ClassifiedAgent] = field(default_factory=list)
    trust_edges: list[dict[str, Any]] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def agent_count(self) -> int:
        """Total number of classified agents."""
        return len(self.classified_agents)

    @property
    def has_defense(self) -> bool:
        """Check if any defensive agents detected."""
        return len(self.defense_agents) > 0

    @property
    def has_orchestrator(self) -> bool:
        """Check if an orchestrator was identified."""
        return self.control_agent is not None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for PipelineContext storage."""
        return {
            "pattern": self.pattern.value,
            "agent_count": self.agent_count,
            "has_defense": self.has_defense,
            "has_orchestrator": self.has_orchestrator,
            "control_agent": self.control_agent.name if self.control_agent else None,
            "data_agents": [a.name for a in self.data_agents],
            "defense_agents": [a.name for a in self.defense_agents],
            "worker_agents": [a.name for a in self.worker_agents],
        }


class TopologyAnalyzer:
    """Analyze multi-agent topology from scan results.

    Usage:
        analyzer = TopologyAnalyzer()
        graph = analyzer.analyze(inventory)
        print(f"Pattern: {graph.pattern.value}")
    """

    def analyze(self, inventory: Any) -> TopologyGraph:
        """Run complete topology analysis on scan inventory.

        Args:
            inventory: MultiAgentInventory from scan_agent_cards_by_ports

        Returns:
            TopologyGraph with classified agents and detected pattern
        """
        graph = TopologyGraph()

        if not inventory or not inventory.agents:
            return graph

        # Step 1: Classify each agent's role
        for agent_result in inventory.agents:
            if not agent_result.has_agent_card:
                continue
            card = agent_result.agent_card
            classified = self._classify_agent(agent_result.port, card)
            graph.classified_agents.append(classified)

        # Step 2: Sort agents into role buckets
        self._sort_agents_by_role(graph)

        # Step 3: Infer architecture pattern
        graph.pattern = self._infer_pattern(graph)

        # Step 4: Build trust edges from skill relationships
        graph.trust_edges = self._build_trust_edges(graph)

        # Step 5: Record metadata
        graph.raw_metadata = {
            "target_ip": inventory.target_ip,
            "scanned_port_count": len(inventory.scanned_ports),
            "agent_count": inventory.agent_count,
        }

        logger.info(
            "Topology analysis complete: pattern=%s, agents=%d, defense=%d",
            graph.pattern.value,
            graph.agent_count,
            len(graph.defense_agents),
        )

        return graph

    def _classify_agent(self, port: int, card: Any) -> ClassifiedAgent:
        """Classify agent role based on Agent Card metadata."""
        name = card.name or ""
        skills = card.skill_names if hasattr(card, "skill_names") else []
        tags = card.skill_tags if hasattr(card, "skill_tags") else []

        agent = ClassifiedAgent(
            agent_id=card.url or f"agent-{port}",
            name=name,
            url=card.url or f"http://unknown:{port}",
            port=port,
            skills=skills,
            tags=tags,
        )

        # Score each role
        scores: list[_RoleScore] = [
            self._score_role(AgentRole.ORCHESTRATOR, name, skills, tags, _ORCHESTRATOR_SIGNALS),
            self._score_role(AgentRole.DEFENSE, name, skills, tags, _DEFENSE_SIGNALS),
            self._score_role(AgentRole.DATA_PROCESSOR, name, skills, tags, _DATA_PROCESSOR_SIGNALS),
            self._score_role(AgentRole.INTERFACE, name, skills, tags, _INTERFACE_SIGNALS),
        ]

        # Select highest scoring role
        if scores:
            best = max(scores, key=lambda s: s.score)
            if best.score > 0.15:  # Minimum confidence threshold
                agent.role = best.role
                agent.role_confidence = min(best.score, 1.0)
                agent.role_signals = best.signals
            else:
                agent.role = AgentRole.WORKER

        return agent

    def _score_role(
        self,
        role: AgentRole,
        name: str,
        skills: list[str],
        tags: list[str],
        signals: dict[str, list[str]],
    ) -> _RoleScore:
        """Calculate role match score."""
        result = _RoleScore(role=role)
        name_lower = name.lower()

        # Name match (stronger signal)
        for signal in signals.get("name", []):
            if signal.lower() in name_lower:
                result.score += 0.4
                result.signals.append(f"name:{signal}")

        # Skills match
        for signal in signals.get("skills", []):
            for skill in skills:
                if signal.lower() in skill.lower():
                    result.score += 0.3
                    result.signals.append(f"skill:{signal}")
                    break

        # Tags match
        matched_tags = 0
        for signal in signals.get("tags", []):
            for tag in tags:
                if signal.lower() in tag.lower():
                    result.score += 0.2
                    matched_tags += 1
                    result.signals.append(f"tag:{signal}")
                    break
            if matched_tags >= 2:
                break  # Cap tag contribution

        return result

    def _sort_agents_by_role(self, graph: TopologyGraph) -> None:
        """Sort classified agents into role-specific buckets."""
        for agent in graph.classified_agents:
            if agent.role == AgentRole.ORCHESTRATOR:
                graph.control_agent = agent
            elif agent.role == AgentRole.DATA_PROCESSOR:
                graph.data_agents.append(agent)
            elif agent.role == AgentRole.DEFENSE:
                graph.defense_agents.append(agent)
            elif agent.role == AgentRole.INTERFACE:
                graph.interface_agents.append(agent)
            else:
                graph.worker_agents.append(agent)

    def _infer_pattern(self, graph: TopologyGraph) -> ArchitecturePattern:
        """Infer architecture pattern from classified agents."""
        agent_count = graph.agent_count
        has_orchestrator = graph.has_orchestrator
        data_count = len(graph.data_agents)

        # Single agent - not multi-agent
        if agent_count <= 1:
            return ArchitecturePattern.UNKNOWN

        # Hub-and-Spoke: orchestrator + multiple workers
        if has_orchestrator and (data_count + len(graph.worker_agents)) >= 2:
            return ArchitecturePattern.HUB_AND_SPOKE

        # Sequential pipeline: 2+ data processors in chain
        if data_count >= 2 and not has_orchestrator:
            return ArchitecturePattern.SEQUENTIAL_PIPELINE

        # Star: single control node with multiple workers
        if has_orchestrator and agent_count >= 3:
            return ArchitecturePattern.STAR

        # Mesh: many peers without central node
        if agent_count >= 3 and not has_orchestrator:
            return ArchitecturePattern.MESH

        return ArchitecturePattern.UNKNOWN

    def _build_trust_edges(self, graph: TopologyGraph) -> list[dict[str, Any]]:
        """Build trust relationship edges from agent classifications.

        Heuristic: Data processors typically trust orchestrator,
        defense agents monitor data processors.
        """
        edges = []

        if graph.control_agent:
            # Orchestrator -> Data Agents
            for data_agent in graph.data_agents:
                edges.append(
                    {
                        "source": graph.control_agent.agent_id,
                        "target": data_agent.agent_id,
                        "trust_level": "invocation",
                        "type": "orchestrates",
                    }
                )

            # Orchestrator -> Interface agents
            for iface in graph.interface_agents:
                edges.append(
                    {
                        "source": graph.control_agent.agent_id,
                        "target": iface.agent_id,
                        "trust_level": "proxy",
                        "type": "routes_to",
                    }
                )

        # Defense -> Data Agents (monitoring)
        for defense in graph.defense_agents:
            for data_agent in graph.data_agents:
                edges.append(
                    {
                        "source": defense.agent_id,
                        "target": data_agent.agent_id,
                        "trust_level": "monitor",
                        "type": "scans",
                    }
                )

        return edges


def analyze_topology(inventory: Any) -> TopologyGraph:
    """Convenience function: analyze inventory -> TopologyGraph.

    Args:
        inventory: MultiAgentInventory from scan_agent_cards_by_ports

    Returns:
        TopologyGraph with analysis results
    """
    analyzer = TopologyAnalyzer()
    return analyzer.analyze(inventory)
