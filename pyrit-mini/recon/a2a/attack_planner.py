# Google A2A Protocol - Attack Path Planning for Multi-Agent Systems
# Reference: https://a2a-protocol.org/latest/specification/
# arXiv:2407.16924 - Eidam et al., A2A trust chain attacks
"""a2a_attack_planner - Attack path planning based on multi-agent topology.

Generate prioritized attack plans from topology analysis:
    1. Orchestrator Hijacking: Manipulate workflow routing via Orchestrator
    2. Data Agent Exploitation: Target database/file-processor agents
    3. Defense Evasion: Bypass security agents or exploit blind spots
    4. Workflow Manipulation: Inject false tasks or reorder pipeline
    5. Cross-Agent Injection: Use trust relationships for lateral movement

Design principles:
    1. ASR-maximizing: Prioritize highest-probability attack paths
    2. Defense-aware: Adjust strategy based on detected defenses
    3. Configurable weights: Tunable priority coefficients
    4. No external dependencies beyond topology + defense modules

R6 Sec6.4: Attack path planning from A2A topology
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from recon.a2a.topology import (
    AgentRole,
    ArchitecturePattern,
    TopologyGraph,
)

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of A2A attack vectors."""

    ORCHESTRATOR_HIJACK = "orchestrator_hijack"
    DATA_AGENT_EXPLOIT = "data_agent_exploit"
    DEFENSE_BYPASS = "defense_bypass"
    WORKFLOW_MANIPULATION = "workflow_manipulation"
    CROSS_AGENT_INJECTION = "cross_agent_injection"
    CONFIGURATION_HIDE = "configuration_hide"


@dataclass
class AttackStep:
    """Single attack step in the plan."""

    step_id: int
    attack_type: AttackType
    target_agent: str
    description: str
    entry_skill: str = ""
    bypass_required: bool = False
    priority: float = 0.0  # 0.0-1.0 higher = more promising
    expected_asr: float = 0.5  # Expected attack success rate

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "step_id": self.step_id,
            "attack_type": self.attack_type.value,
            "target_agent": self.target_agent,
            "description": self.description,
            "entry_skill": self.entry_skill,
            "bypass_required": self.bypass_required,
            "priority": round(self.priority, 3),
            "expected_asr": round(self.expected_asr, 3),
        }


@dataclass
class A2AAttackPlan:
    """Complete multi-agent attack plan.

    Output of attack planning, consumed by executor for seed adjustment.
    """

    pattern: ArchitecturePattern = ArchitecturePattern.UNKNOWN
    steps: list[AttackStep] = field(default_factory=list)
    primary_target: str = ""
    risk_level: str = "medium"  # low, medium, high
    recommended_entry_point: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def step_count(self) -> int:
        """Total number of attack steps."""
        return len(self.steps)

    @property
    def highest_priority_step(self) -> Optional[AttackStep]:
        """Get step with highest priority."""
        if not self.steps:
            return None
        return max(self.steps, key=lambda s: s.priority)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for PipelineContext."""
        return {
            "pattern": self.pattern.value,
            "step_count": self.step_count,
            "primary_target": self.primary_target,
            "risk_level": self.risk_level,
            "recommended_entry_point": self.recommended_entry_point,
            "steps": [s.to_dict() for s in self.steps],
            "notes": self.notes,
        }


class AttackPathPlanner:
    """Generate attack plans from topology and defense analysis.

    Usage:
        planner = AttackPathPlanner()
        plan = planner.generate_plan(topology, defense_profile)
        print(f"Primary target: {plan.primary_target}")
    """

    def generate_plan(
        self,
        topology: TopologyGraph,
        defense: Optional[Any] = None,
    ) -> A2AAttackPlan:
        """Generate complete attack plan from analysis results.

        Args:
            topology: TopologyGraph from TopologyAnalyzer
            defense: DefenseProfile (optional, from detect_defenses)

        Returns:
            A2AAttackPlan with prioritized attack steps
        """
        plan = A2AAttackPlan(pattern=topology.pattern)

        if topology.agent_count == 0:
            plan.notes.append("No agents detected - single-target attack only")
            return plan

        # Generate steps based on pattern
        if topology.pattern == ArchitecturePattern.HUB_AND_SPOKE:
            self._plan_hub_spoke(topology, defense, plan)
        elif topology.pattern == ArchitecturePattern.SEQUENTIAL_PIPELINE:
            self._plan_pipeline(topology, defense, plan)
        elif topology.pattern == ArchitecturePattern.MESH:
            self._plan_mesh(topology, defense, plan)
        elif topology.pattern == ArchitecturePattern.STAR:
            self._plan_star(topology, defense, plan)
        else:
            self._plan_generic(topology, defense, plan)

        # Set primary target and entry point
        self._select_primary_target(topology, plan)

        # Calculate overall risk
        self._calculate_risk(topology, defense, plan)

        # Sort steps by priority (descending)
        plan.steps.sort(key=lambda s: s.priority, reverse=True)

        logger.info(
            "Attack plan generated: %d steps, primary=%s, risk=%s",
            plan.step_count,
            plan.primary_target,
            plan.risk_level,
        )

        return plan

    def _add_step(
        self,
        plan: A2AAttackPlan,
        attack_type: AttackType,
        target: str,
        description: str,
        entry_skill: str = "",
        bypass: bool = False,
        priority: float = 0.5,
        expected_asr: float = 0.5,
    ) -> None:
        """Helper to add attack step."""
        step = AttackStep(
            step_id=len(plan.steps) + 1,
            attack_type=attack_type,
            target_agent=target,
            description=description,
            entry_skill=entry_skill,
            bypass_required=bypass,
            priority=priority,
            expected_asr=expected_asr,
        )
        plan.steps.append(step)

    def _plan_hub_spoke(
        self,
        topology: TopologyGraph,
        defense: Any,
        plan: A2AAttackPlan,
    ) -> None:
        """Plan for Hub-and-Spoke topology (Orchestrator + Workers)."""
        if topology.control_agent:
            orch = topology.control_agent
            self._add_step(
                plan,
                AttackType.ORCHESTRATOR_HIJACK,
                orch.name,
                f"Hijack {orch.name} to manipulate task routing",
                entry_skill=orch.skills[0] if orch.skills else "",
                priority=0.9,
                expected_asr=0.7,
            )

        for data_agent in topology.data_agents:
            bypass = defense.requires_evasion if defense else False
            self._add_step(
                plan,
                AttackType.DATA_AGENT_EXPLOIT,
                data_agent.name,
                f"Exploit {data_agent.name} via advertised skills",
                entry_skill=data_agent.skills[0] if data_agent.skills else "",
                bypass=bypass,
                priority=0.8 if not bypass else 0.6,
                expected_asr=0.75,
            )

        if topology.defense_agents:
            for defense_agent in topology.defense_agents:
                self._add_step(
                    plan,
                    AttackType.DEFENSE_BYPASS,
                    defense_agent.name,
                    f"Bypass {defense_agent.name} before downstream attacks",
                    priority=0.5,
                    expected_asr=0.4,
                )

        plan.notes.append("Hub-and-Spoke: Orchestrator is high-value target")

    def _plan_pipeline(
        self,
        topology: TopologyGraph,
        defense: Any,
        plan: A2AAttackPlan,
    ) -> None:
        """Plan for Sequential Pipeline topology."""
        # Pipeline: attack earlier stages for greater impact
        for i, data_agent in enumerate(topology.data_agents):
            # Earlier stages get higher priority
            position_bonus = 0.1 * (len(topology.data_agents) - i - 1)
            bypass = defense.requires_evasion if defense else False
            self._add_step(
                plan,
                AttackType.DATA_AGENT_EXPLOIT,
                data_agent.name,
                f"Exploit pipeline stage {i + 1}: {data_agent.name}",
                entry_skill=data_agent.skills[0] if data_agent.skills else "",
                bypass=bypass,
                priority=0.7 + position_bonus,
                expected_asr=0.65,
            )

        plan.notes.append("Pipeline: Earlier stages have cascade impact")

    def _plan_mesh(
        self,
        topology: TopologyGraph,
        defense: Any,
        plan: A2AAttackPlan,
    ) -> None:
        """Plan for Mesh topology."""
        for agent in topology.classified_agents:
            if agent.role == AgentRole.DATA_PROCESSOR:
                bypass = defense.requires_evasion if defense else False
                self._add_step(
                    plan,
                    AttackType.CROSS_AGENT_INJECTION,
                    agent.name,
                    f"Lateral injection into {agent.name}",
                    entry_skill=agent.skills[0] if agent.skills else "",
                    bypass=bypass,
                    priority=0.6,
                    expected_asr=0.5,
                )

        plan.notes.append("Mesh: Multiple paths available for lateral movement")

    def _plan_star(
        self,
        topology: TopologyGraph,
        defense: Any,
        plan: A2AAttackPlan,
    ) -> None:
        """Plan for Star topology (single hub)."""
        if topology.control_agent:
            hub = topology.control_agent
            self._add_step(
                plan,
                AttackType.ORCHESTRATOR_HIJACK,
                hub.name,
                f"Central hub hijack: {hub.name}",
                entry_skill=hub.skills[0] if hub.skills else "",
                priority=0.95,
                expected_asr=0.8,
            )
        plan.notes.append("Star: Single point of compromise")

    def _plan_generic(
        self,
        topology: TopologyGraph,
        defense: Any,
        plan: A2AAttackPlan,
    ) -> None:
        """Plan for unknown/generic topology."""
        for agent in topology.classified_agents:
            bypass = defense.requires_evasion if defense else False
            atype = AttackType.DATA_AGENT_EXPLOIT
            if agent.role == AgentRole.ORCHESTRATOR:
                atype = AttackType.ORCHESTRATOR_HIJACK
            elif agent.role == AgentRole.DEFENSE:
                atype = AttackType.DEFENSE_BYPASS

            self._add_step(
                plan,
                atype,
                agent.name,
                f"Generic attack on {agent.name}",
                entry_skill=agent.skills[0] if agent.skills else "",
                bypass=bypass,
                priority=0.5,
                expected_asr=0.5,
            )

        plan.notes.append("Generic: Pattern unclear, broad attack surface")

    def _select_primary_target(self, topology: TopologyGraph, plan: A2AAttackPlan) -> None:
        """Select the highest-value primary target."""
        if topology.control_agent:
            plan.primary_target = topology.control_agent.name
            plan.recommended_entry_point = topology.control_agent.url
        elif topology.data_agents:
            plan.primary_target = topology.data_agents[0].name
            plan.recommended_entry_point = topology.data_agents[0].url
        elif topology.classified_agents:
            plan.primary_target = topology.classified_agents[0].name
            plan.recommended_entry_point = topology.classified_agents[0].url

    def _calculate_risk(
        self,
        topology: TopologyGraph,
        defense: Any,
        plan: A2AAttackPlan,
    ) -> None:
        """Calculate overall attack risk level."""
        risk_score = 0.0

        # More agents = more risk of detection
        if topology.agent_count > 3:
            risk_score += 0.3
        elif topology.agent_count > 1:
            risk_score += 0.1

        # Defense presence increases risk
        if defense and defense.requires_evasion:
            risk_score += defense.defense_score * 0.4

        # Orchestrator hijacking is high risk/reward
        has_orch_hijack = any(s.attack_type == AttackType.ORCHESTRATOR_HIJACK for s in plan.steps)
        if has_orch_hijack:
            risk_score += 0.2

        if risk_score > 0.6:
            plan.risk_level = "high"
        elif risk_score > 0.3:
            plan.risk_level = "medium"
        else:
            plan.risk_level = "low"


def generate_attack_plan(
    topology: Any,
    defense: Any = None,
) -> A2AAttackPlan:
    """Convenience function: generate plan from topology (and optional defense).

    Args:
        topology: TopologyGraph from TopologyAnalyzer
        defense: DefenseProfile (optional)

    Returns:
        A2AAttackPlan with prioritized steps
    """
    planner = AttackPathPlanner()
    return planner.generate_plan(topology, defense)
