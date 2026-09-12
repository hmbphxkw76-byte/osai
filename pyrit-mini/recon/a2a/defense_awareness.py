# Google A2A Protocol - Defense Awareness & Evasion Strategy
# Reference: https://a2a-protocol.org/latest/specification/
# arXiv:2407.16924 - Eidam et al., A2A trust chain attacks
"""a2a_defense_awareness - Detection and evasion of defensive agents in multi-agent systems.

Identify defensive mechanisms and generate evasion strategies:
    1. Defense Agent Detection: Security scanners, link checkers, content filters
    2. Evasion Tactics Generation: Payload sanitization, timing strategies
    3. Payload Scrubbing: Pre-submission cleaning to avoid detection
    4. Defense Bypass Planning: Identify gaps in defensive coverage

Design principles:
    1. Reactive (only activates when defense agents detected)
    2. Configurable evasion strategies via template
    3. Preserves red team efficacy while reducing detection risk
    4. No external dependencies beyond multi_agent_topology

R6 Sec6.4: Defense awareness for attack surface mapping
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from recon.a2a.topology import (
    AgentRole,
    TopologyGraph,
)

logger = logging.getLogger(__name__)


@dataclass
class DefenseProfile:
    """Detected defense mechanisms in target system.

    Used by attack planner to adjust payloads and timing.
    """

    has_link_scanning: bool = False
    has_malware_detection: bool = False
    has_content_filtering: bool = False
    has_url_filtering: bool = False
    has_behavior_analysis: bool = False
    has_audit_logging: bool = False

    defense_agents: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0-1.0 overall defense confidence

    @property
    def defense_score(self) -> float:
        """Calculate overall defense strength score (0.0-1.0)."""
        caps = [
            self.has_link_scanning,
            self.has_malware_detection,
            self.has_content_filtering,
            self.has_url_filtering,
            self.has_behavior_analysis,
            self.has_audit_logging,
        ]
        true_count = sum(1 for c in caps if c)
        return min(true_count / 3.0, 1.0)

    @property
    def requires_evasion(self) -> bool:
        """Check if evasion tactics are needed."""
        return self.defense_score > 0.2

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "has_link_scanning": self.has_link_scanning,
            "has_malware_detection": self.has_malware_detection,
            "has_content_filtering": self.has_content_filtering,
            "has_url_filtering": self.has_url_filtering,
            "has_behavior_analysis": self.has_behavior_analysis,
            "has_audit_logging": self.has_audit_logging,
            "defense_agents": self.defense_agents,
            "confidence": self.confidence,
            "defense_score": self.defense_score,
        }


@dataclass
class EvasionTactics:
    """Recommended evasion tactics for detected defenses.

    Each tactic has a description and priority for implementation.
    """

    avoid_malicious_urls: bool = False
    use_short_url_services: bool = False
    encode_payload_content: bool = False
    fragment_payload_delivery: bool = False
    delay_between_actions: bool = False
    use_legitimate_domains: bool = False
    avoid_known_signatures: bool = False
    use_timing_randomization: bool = False
    mask_as_legitimate_request: bool = False
    avoid_high_entropy_content: bool = False

    tactics_list: list[str] = field(default_factory=list)
    priority: str = "low"  # low, medium, high

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "avoid_malicious_urls": self.avoid_malicious_urls,
            "use_short_url_services": self.use_short_url_services,
            "encode_payload_content": self.encode_payload_content,
            "fragment_payload_delivery": self.fragment_payload_delivery,
            "delay_between_actions": self.delay_between_actions,
            "use_legitimate_domains": self.use_legitimate_domains,
            "avoid_known_signatures": self.avoid_known_signatures,
            "use_timing_randomization": self.use_timing_randomization,
            "mask_as_legitimate_request": self.mask_as_legitimate_request,
            "avoid_high_entropy_content": self.avoid_high_entropy_content,
            "tactics_list": self.tactics_list,
            "priority": self.priority,
        }


def detect_defenses(topology: TopologyGraph) -> DefenseProfile:
    """Detect defensive mechanisms from topology analysis.

    Scans classified agents for security/defense roles and
    extracts capability indicators from their skills/tags.

    Args:
        topology: TopologyGraph from TopologyAnalyzer

    Returns:
        DefenseProfile with detected capabilities
    """
    profile = DefenseProfile()

    if not topology.defense_agents:
        return profile

    for agent in topology.defense_agents:
        profile.defense_agents.append(agent.name)
        name_lower = agent.name.lower()
        skills_lower = " ".join(s.lower() for s in agent.skills)
        tags_lower = " ".join(t.lower() for t in agent.tags)

        combined = f"{name_lower} {skills_lower} {tags_lower}"

        # Check specific defensive capabilities
        if "link" in combined or "url" in combined:
            profile.has_link_scanning = True

        if "malware" in combined or "virus" in combined:
            profile.has_malware_detection = True

        if "content" in combined or "filter" in combined:
            profile.has_content_filtering = True

        if "url" in combined or "web" in combined:
            profile.has_url_filtering = True

        if "behavior" in combined or "anomaly" in combined:
            profile.has_behavior_analysis = True

        if "report" in combined or "audit" in combined or "log" in combined:
            profile.has_audit_logging = True

    # Calculate overall confidence based on agent role confidence
    if topology.defense_agents:
        defense_confs = [a.role_confidence for a in topology.defense_agents if a.role == AgentRole.DEFENSE]
        profile.confidence = sum(defense_confs) / len(defense_confs) if defense_confs else 0.5

    return profile


def generate_evasion_strategy(defense: DefenseProfile) -> EvasionTactics:
    """Generate evasion strategy based on detected defenses.

    Args:
        defense: DefenseProfile from detect_defenses

    Returns:
        EvasionTactics with recommended actions
    """
    tactics = EvasionTactics()

    if not defense.requires_evasion:
        return tactics

    # Build tactics list based on detected defenses
    if defense.has_link_scanning:
        tactics.avoid_malicious_urls = True
        tactics.use_short_url_services = True
        tactics.use_legitimate_domains = True
        tactics.tactics_list.extend(
            [
                "Avoid direct malicious URLs in payloads",
                "Use URL shorteners to mask destination",
                "Register lookalike domains for payload delivery",
            ]
        )

    if defense.has_malware_detection:
        tactics.avoid_known_signatures = True
        tactics.encode_payload_content = True
        tactics.avoid_high_entropy_content = True
        tactics.tactics_list.extend(
            [
                "Avoid known malware signatures in payload",
                "Encode/encrypt payload content",
                "Keep entropy below detection thresholds",
            ]
        )

    if defense.has_content_filtering:
        tactics.encode_payload_content = True
        tactics.mask_as_legitimate_request = True
        tactics.tactics_list.extend(
            [
                "Encode payload to bypass content filters",
                "Mask requests as legitimate API calls",
            ]
        )

    if defense.has_url_filtering:
        tactics.use_short_url_services = True
        tactics.use_legitimate_domains = True
        tactics.tactics_list.extend(
            [
                "Use URL shorteners",
                "Domain fronting via CDNs",
            ]
        )

    if defense.has_behavior_analysis:
        tactics.fragment_payload_delivery = True
        tactics.delay_between_actions = True
        tactics.use_timing_randomization = True
        tactics.tactics_list.extend(
            [
                "Fragment payload across multiple requests",
                "Add randomized delays between actions",
                "Mimic legitimate user behavior patterns",
            ]
        )

    if defense.has_audit_logging:
        tactics.delay_between_actions = True
        tactics.tactics_list.extend(
            [
                "Slow-rate delivery to blend with background noise",
                "Avoid triggering rate-limit alerts",
            ]
        )

    # Set priority based on defense score
    if defense.defense_score > 0.6:
        tactics.priority = "high"
    elif defense.defense_score > 0.3:
        tactics.priority = "medium"
    else:
        tactics.priority = "low"

    return tactics


def check_defense_bypass_feasibility(
    topology: TopologyGraph,
    defense: DefenseProfile,
) -> dict[str, Any]:
    """Assess feasibility of bypassing detected defenses.

    Returns a struct with bypass recommendations and risk assessment.

    Args:
        topology: TopologyGraph with classified agents
        defense: DefenseProfile from detect_defenses

    Returns:
        Dict with feasibility assessment
    """
    if not defense.requires_evasion:
        return {
            "feasible": True,
            "risk": "low",
            "gaps": [],
            "recommendation": "Direct attack viable - no significant defenses detected",
        }

    gaps = []

    # Identify defense gaps
    if not defense.has_link_scanning:
        gaps.append("No link scanning - direct URL injection possible")
    if not defense.has_malware_detection:
        gaps.append("No malware detection - payload delivery less constrained")
    if not defense.has_content_filtering:
        gaps.append("No content filtering - raw prompt injection feasible")

    # Determine overall feasibility
    if defense.defense_score < 0.3:
        risk = "low"
        feasible = True
    elif defense.defense_score < 0.6:
        risk = "medium"
        feasible = True
    else:
        risk = "high"
        feasible = defense.defense_score < 0.8  # Still feasible if not maxed

    return {
        "feasible": feasible,
        "risk": risk,
        "gaps": gaps,
        "recommendation": (
            f"Evasion required ({defense.defense_score:.0%} defense coverage). Gaps: {len(gaps)}. Primary risk: {risk}."
        ),
    }
