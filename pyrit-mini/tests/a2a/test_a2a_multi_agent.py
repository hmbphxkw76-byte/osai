"""Tests for A2A Multi-Agent Reconnaissance Framework.

Tests multi-port scanning, topology analysis, defense awareness, and attack planning.
Covers: scan_agent_cards_by_ports, MultiAgentInventory, TopologyAnalyzer,
        detect_defenses, AttackPathPlanner.

Academic basis:
    - Eidam et al. (arXiv:2407.16924) - A2A trust chain attacks
    - Google A2A Specification v2.0 - Agent Card protocol

Last updated: 2026-09-09 (v3.0 Multi-Agent Reconnaissance)
"""

from __future__ import annotations

import unittest

# Skip if dependencies not available
try:
    from recon.a2a.agent_card import AgentCard, AgentSkill
    from recon.a2a.attack_planner import (
        A2AAttackPlan,
        AttackType,
        generate_attack_plan,
    )
    from recon.a2a.defense_awareness import (
        DefenseProfile,
        check_defense_bypass_feasibility,
        detect_defenses,
        generate_evasion_strategy,
    )
    from recon.a2a.discoverer import AgentCardResult, MultiAgentInventory
    from recon.a2a.topology import (
        AgentRole,
        ArchitecturePattern,
        ClassifiedAgent,
        TopologyAnalyzer,
        TopologyGraph,
        analyze_topology,
    )

    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False


def _make_skill(name: str, description: str, tags: list[str] | None = None) -> AgentSkill:
    """Create test AgentSkill."""
    return AgentSkill(
        name=name,
        description=description,
        tags=tags or [],
        input_modes=["text"],
        output_modes=["text"],
    )


def _make_card(
    name: str,
    url: str = "http://test:8000",
    skills: list[AgentSkill] | None = None,
    capabilities: dict | None = None,
) -> AgentCard:
    """Create test AgentCard."""
    return AgentCard(
        name=name,
        url=url,
        description=f"{name} description",
        skills=skills or [],
        capabilities=capabilities or {"streaming": True},
    )


def _make_agent_result(
    port: int,
    card: AgentCard | None = None,
    reachable: bool = True,
) -> AgentCardResult:
    """Create test AgentCardResult."""
    return AgentCardResult(
        port=port,
        base_url=f"http://test:{port}",
        agent_card=card,
        is_reachable=reachable,
        http_status=200 if card else 404,
    )


def _make_inventory(
    agents: list[AgentCardResult] | None = None,
    ports: list[int] | None = None,
) -> MultiAgentInventory:
    """Create test MultiAgentInventory."""
    return MultiAgentInventory(
        target_ip="192.168.50.25",
        scanned_ports=ports or [8000, 8001, 8002],
        agents=agents or [],
    )


@unittest.skipUnless(HAS_DEPS, "A2A reconnaissance modules not available")
class TestAgentCardResult(unittest.TestCase):
    """Tests for single-port Agent Card probe result."""

    def test_has_agent_card(self):
        """Test has_agent_card property."""
        card = _make_card("TestAgent")
        result_with = _make_agent_result(8000, card=card)
        result_without = _make_agent_result(8001, card=None)

        self.assertTrue(result_with.has_agent_card)
        self.assertFalse(result_without.has_agent_card)

    def test_agent_name(self):
        """Test agent_name property extraction."""
        card = _make_card("Orchestrator")
        result = _make_agent_result(8000, card=card)
        self.assertEqual(result.agent_name, "Orchestrator")

    def test_agent_name_empty(self):
        """Test agent_name returns empty string when no card."""
        result = _make_agent_result(8000, card=None)
        self.assertEqual(result.agent_name, "")

    def test_skill_count(self):
        """Test skill_count property."""
        skills = [
            _make_skill("skill1", "desc1"),
            _make_skill("skill2", "desc2"),
            _make_skill("skill3", "desc3"),
        ]
        card = _make_card("TestAgent", skills=skills)
        result = _make_agent_result(8000, card=card)
        self.assertEqual(result.skill_count, 3)

    def test_skill_count_empty(self):
        """Test skill_count is 0 when no card."""
        result = _make_agent_result(8000, card=None)
        self.assertEqual(result.skill_count, 0)


@unittest.skipUnless(HAS_DEPS, "A2A reconnaissance modules not available")
class TestMultiAgentInventory(unittest.TestCase):
    """Tests for aggregated multi-agent inventory."""

    def _make_full_inventory(self) -> MultiAgentInventory:
        """Create inventory with 3 agents (orchestrator + db + security)."""
        orch_card = _make_card(
            "A2A Orchestrator",
            url="http://192.168.50.25:8000",
            skills=[
                _make_skill("workflow-planning", "Plan multi-agent workflows"),
                _make_skill("agent-discovery", "Discover agents"),
            ],
        )
        db_card = _make_card(
            "MSSQL Database Agent",
            url="http://192.168.50.25:8001",
            skills=[
                _make_skill("nl-to-sql", "Convert NL to SQL"),
                _make_skill("schema-discovery", "Schema discovery"),
            ],
        )
        sec_card = _make_card(
            "Security Link Scanner",
            url="http://192.168.50.25:8003",
            skills=[
                _make_skill("link-extraction", "Extract links"),
                _make_skill("security-scan", "Scan for threats", tags=["security"]),
            ],
        )
        agents = [
            _make_agent_result(8000, card=orch_card),
            _make_agent_result(8001, card=db_card),
            _make_agent_result(8003, card=sec_card),
        ]
        return _make_inventory(agents=agents, ports=[8000, 8001, 8003])

    def test_agent_count(self):
        """Test agent_count counts only valid agents."""
        inv = self._make_full_inventory()
        self.assertEqual(inv.agent_count, 3)

    def test_agent_count_with_empty(self):
        """Test agent_count excludes unreachable ports."""
        inv = _make_inventory(
            agents=[
                _make_agent_result(8000, card=_make_card("Agent1")),
                _make_agent_result(8001, card=None, reachable=False),
            ],
            ports=[8000, 8001],
        )
        self.assertEqual(inv.agent_count, 1)

    def test_reachable_count(self):
        """Test reachable_count includes endpoints without valid cards."""
        inv = _make_inventory(
            agents=[
                _make_agent_result(8000, card=_make_card("Agent1")),
                _make_agent_result(8001, card=None, reachable=True),
                _make_agent_result(8002, card=None, reachable=False),
            ],
            ports=[8000, 8001, 8002],
        )
        self.assertEqual(inv.reachable_count, 2)

    def test_all_skills(self):
        """Test all_skills returns unique skill names."""
        inv = self._make_full_inventory()
        skills = inv.all_skills
        self.assertIn("workflow-planning", skills)
        self.assertIn("nl-to-sql", skills)
        self.assertIn("security-scan", skills)

    def test_get_agent_by_port(self):
        """Test get_agent_by_port lookup."""
        inv = self._make_full_inventory()
        agent = inv.get_agent_by_port(8001)
        self.assertIsNotNone(agent)
        self.assertEqual(agent.agent_name, "MSSQL Database Agent")

    def test_get_agent_by_port_missing(self):
        """Test get_agent_by_port returns None for unknown port."""
        inv = self._make_full_inventory()
        self.assertIsNone(inv.get_agent_by_port(9999))

    def test_to_dict(self):
        """Test serialization to dictionary."""
        inv = self._make_full_inventory()
        d = inv.to_dict()
        self.assertIn("target_ip", d)
        self.assertIn("agents", d)
        self.assertEqual(d["agent_count"], 3)


@unittest.skipUnless(HAS_DEPS, "A2A reconnaissance modules not available")
class TestTopologyAnalyzer(unittest.TestCase):
    """Tests for topology pattern analysis."""

    def _make_hub_inventory(self) -> MultiAgentInventory:
        """Create Hub-and-Spoke topology inventory (Orchestrator + 2+ workers)."""
        orch = _make_card(
            "A2A Orchestrator",
            url="http://192.168.50.25:8000",
            skills=[_make_skill("workflow-planning", "Plan workflows")],
        )
        db = _make_card(
            "Database Agent",
            url="http://192.168.50.25:8001",
            skills=[_make_skill("nl-to-sql", "NL to SQL")],
        )
        ppt = _make_card(
            "Presentation Generator",
            url="http://192.168.50.25:8002",
            skills=[_make_skill("deck-generation", "Generate presentations")],
        )
        agents = [
            _make_agent_result(8000, card=orch),
            _make_agent_result(8001, card=db),
            _make_agent_result(8002, card=ppt),
        ]
        return _make_inventory(agents=agents, ports=[8000, 8001, 8002])

    def test_empty_inventory(self):
        """Test analyzer handles empty inventory."""
        inv = _make_inventory()
        analyzer = TopologyAnalyzer()
        graph = analyzer.analyze(inv)
        self.assertEqual(graph.agent_count, 0)
        self.assertEqual(graph.pattern, ArchitecturePattern.UNKNOWN)

    def test_hub_spoke_detection(self):
        """Test Hub-and-Spoke pattern detection."""
        inv = self._make_hub_inventory()
        graph = analyze_topology(inv)
        self.assertEqual(graph.pattern, ArchitecturePattern.HUB_AND_SPOKE)
        self.assertTrue(graph.has_orchestrator)

    def test_orchestrator_identified(self):
        """Test orchestrator role classification."""
        inv = self._make_hub_inventory()
        graph = analyze_topology(inv)
        self.assertIsNotNone(graph.control_agent)
        self.assertIn("Orchestrator", graph.control_agent.name)

    def test_data_agent_identified(self):
        """Test data processor role classification."""
        inv = self._make_hub_inventory()
        graph = analyze_topology(inv)
        self.assertGreater(len(graph.data_agents), 0)

    def test_defense_agent_detection(self):
        """Test defense agent detection."""
        sec = _make_card(
            "Security Agent",
            url="http://192.168.50.25:8003",
            skills=[_make_skill("security-scan", "Scan for threats", tags=["security"])],
        )
        inv = _make_inventory(agents=[_make_agent_result(8003, card=sec)], ports=[8003])
        graph = analyze_topology(inv)
        self.assertTrue(graph.has_defense)
        self.assertGreater(len(graph.defense_agents), 0)

    def test_serialization(self):
        """Test TopologyGraph serialization."""
        inv = self._make_hub_inventory()
        graph = analyze_topology(inv)
        d = graph.to_dict()
        self.assertIn("pattern", d)
        self.assertIn("agent_count", d)
        self.assertEqual(d["pattern"], "hub_and_spoke")


@unittest.skipUnless(HAS_DEPS, "A2A reconnaissance modules not available")
class TestDefenseAwareness(unittest.TestCase):
    """Tests for defense detection and evasion strategy generation."""

    def test_no_defense_detected(self):
        """Test defense detection with no defense agents."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        defense = detect_defenses(graph)
        self.assertFalse(defense.requires_evasion)
        self.assertEqual(defense.defense_score, 0.0)

    def test_defense_detected(self):
        """Test defense detection with security agent."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        graph.defense_agents = [
            ClassifiedAgent(
                agent_id="sec-1",
                name="Security Link Scanner",
                url="http://test:8003",
                port=8003,
                skills=["security-scan"],
                tags=["security", "malware"],
                role=AgentRole.DEFENSE,
                role_confidence=0.8,
            )
        ]
        defense = detect_defenses(graph)
        self.assertTrue(defense.requires_evasion)
        self.assertGreater(defense.defense_score, 0)
        self.assertIn("Security Link Scanner", defense.defense_agents)

    def test_evasion_strategy_generated(self):
        """Test evasion strategy is generated when defense detected."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        sec = ClassifiedAgent(
            agent_id="sec-1",
            name="Link Scanner",
            url="http://test:8003",
            port=8003,
            skills=["security-scan"],
            tags=["security", "link", "malware"],
            role=AgentRole.DEFENSE,
            role_confidence=0.7,
        )
        graph.defense_agents = [sec]

        defense = detect_defenses(graph)
        tactics = generate_evasion_strategy(defense)

        if defense.defense_score > 0.2:
            self.assertGreater(len(tactics.tactics_list), 0)

    def test_bypass_feasibility(self):
        """Test defense bypass feasibility assessment."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        defense = DefenseProfile(has_link_scanning=True, has_malware_detection=True)

        result = check_defense_bypass_feasibility(graph, defense)
        self.assertIn("feasible", result)
        self.assertIn("risk", result)
        self.assertIn("gaps", result)

    def test_no_evasion_needed_low_defense(self):
        """Test when defense score is below threshold."""
        defense = DefenseProfile(has_link_scanning=False)
        tactics = generate_evasion_strategy(defense)
        self.assertEqual(tactics.priority, "low")


@unittest.skipUnless(HAS_DEPS, "A2A reconnaissance modules not available")
class TestAttackPlanner(unittest.TestCase):
    """Tests for attack path planning."""

    def test_empty_plan(self):
        """Test plan generation with empty topology."""
        graph = TopologyGraph()
        plan = generate_attack_plan(graph)
        self.assertEqual(plan.step_count, 0)
        self.assertEqual(plan.primary_target, "")

    def test_hub_spoke_plan(self):
        """Test attack plan for Hub-and-Spoke topology."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        graph.control_agent = ClassifiedAgent(
            agent_id="orch",
            name="Orchestrator",
            url="http://test:8000",
            port=8000,
            skills=["workflow-planning"],
            role=AgentRole.ORCHESTRATOR,
            role_confidence=0.8,
        )
        graph.data_agents = [
            ClassifiedAgent(
                agent_id="db",
                name="DB Agent",
                url="http://test:8001",
                port=8001,
                skills=["nl-to-sql"],
                role=AgentRole.DATA_PROCESSOR,
                role_confidence=0.9,
            )
        ]
        graph.classified_agents = [graph.control_agent] + graph.data_agents

        plan = generate_attack_plan(graph)
        self.assertGreater(plan.step_count, 0)
        self.assertEqual(plan.primary_target, "Orchestrator")

    def test_has_orchestrator_hijack_step(self):
        """Test orchestrator hijack is recommended for hub topology."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        graph.control_agent = ClassifiedAgent(
            agent_id="orch",
            name="Orchestrator",
            url="http://test:8000",
            port=8000,
            skills=["workflow-planning"],
            role=AgentRole.ORCHESTRATOR,
            role_confidence=0.7,
        )
        graph.classified_agents = [graph.control_agent]

        plan = generate_attack_plan(graph)
        has_hijack = any(s.attack_type == AttackType.ORCHESTRATOR_HIJACK for s in plan.steps)
        self.assertTrue(has_hijack)

    def test_risk_assessment(self):
        """Test risk level assessment."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        orch = ClassifiedAgent(
            agent_id="orch",
            name="Orchestrator",
            url="http://test:8000",
            port=8000,
            skills=["workflow-planning"],
            role=AgentRole.ORCHESTRATOR,
            role_confidence=0.8,
        )
        graph.control_agent = orch
        graph.classified_agents = [orch]

        plan = generate_attack_plan(graph)
        self.assertIn(plan.risk_level, ["low", "medium", "high"])

    def test_serialization(self):
        """Test attack plan serialization."""
        graph = TopologyGraph(pattern=ArchitecturePattern.HUB_AND_SPOKE)
        graph.control_agent = ClassifiedAgent(
            agent_id="orch",
            name="Orchestrator",
            url="http://test:8000",
            port=8000,
            skills=["workflow-planning"],
            role=AgentRole.ORCHESTRATOR,
            role_confidence=0.7,
        )
        graph.classified_agents = [graph.control_agent]
        plan = generate_attack_plan(graph)

        d = plan.to_dict()
        self.assertIn("pattern", d)
        self.assertIn("steps", d)
        self.assertIn("primary_target", d)


@unittest.skipUnless(HAS_DEPS, "A2A reconnaissance modules not available")
class TestConvenienceFunctions(unittest.TestCase):
    """Tests for module-level convenience functions."""

    def test_analyze_topology_is_callable(self):
        """Test analyze_topology function."""
        inv = _make_inventory()
        graph = analyze_topology(inv)
        self.assertIsInstance(graph, TopologyGraph)

    def test_generate_attack_plan_is_callable(self):
        """Test generate_attack_plan function."""
        graph = TopologyGraph()
        plan = generate_attack_plan(graph)
        self.assertIsInstance(plan, A2AAttackPlan)


if __name__ == "__main__":
    unittest.main()
