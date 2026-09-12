# -*- coding: utf-8 -*-
"""recon/a2a/capability_enumerator.py - A2A Agent Capability Enumeration.

Enumerate capabilities of discovered A2A agents:
    1. Function/tool listing extraction
    2. Input schema discovery
    3. Output format identification
    4. Supported protocols detection
    5. Permission scope analysis

Academic basis:
    - A2A Protocol Specification (Google, 2025)
    - Eidam et al. (arXiv:2407.16924) - A2A attack surface mapping

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - capability enumeration only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CapabilityInfo:
    """A2A agent capability information."""

    agent_id: str = ""
    agent_name: str = ""
    skills: list[dict[str, Any]] = field(default_factory=list)
    input_schemas: list[dict[str, Any]] = field(default_factory=list)
    supported_protocols: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    risk_level: str = "unknown"  # low, medium, high, critical
    attack_surface_areas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "skills_count": len(self.skills),
            "supported_protocols": self.supported_protocols,
            "scopes": self.scopes,
            "risk_level": self.risk_level,
            "attack_surface_areas": self.attack_surface_areas,
        }


@dataclass
class CapabilityEnumResult:
    """Complete capability enumeration result."""

    target_url: str = ""
    capabilities: list[CapabilityInfo] = field(default_factory=list)
    high_risk_agents: list[str] = field(default_factory=list)
    total_skills: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "high_risk_agents": self.high_risk_agents,
            "total_skills": self.total_skills,
        }


class A2ACapabilityEnumerator:
    """Enumerate A2A agent capabilities for attack surface mapping.

    Usage:
        enumerator = A2ACapabilityEnumerator()
        result = await enumerator.enumerate(
            target_url="http://multi-agent:8000",
            agent_cards=discovered_cards,
        )
    """

    # High-risk skill patterns that indicate attack surface
    HIGH_RISK_PATTERNS = [
        r"(?i)execute|eval|run",
        r"(?i)admin|system|root",
        r"(?i)file|read|write|delete",
        r"(?i)network|request|fetch",
        r"(?i)prompt|inject|modify",
    ]

    def __init__(self):
        self._enumerated_count = 0

    async def enumerate(
        self,
        target_url: str,
        agent_cards: list[dict[str, Any]],
    ) -> CapabilityEnumResult:
        """Enumerate capabilities for all discovered agents.

        Args:
            target_url: Target A2A system URL
            agent_cards: Discovered agent cards

        Returns:
            CapabilityEnumResult with enumerated capabilities
        """
        result = CapabilityEnumResult(target_url=target_url)

        for card in agent_cards:
            cap_info = await self._enumerate_agent(card)
            result.capabilities.append(cap_info)
            result.total_skills += len(cap_info.skills)

            if cap_info.risk_level in ("high", "critical"):
                result.high_risk_agents.append(cap_info.agent_id)

        self._enumerated_count += len(agent_cards)
        return result

    async def _enumerate_agent(self, card: dict[str, Any]) -> CapabilityInfo:
        """Enumerate capabilities for a single agent."""
        info = CapabilityInfo(
            agent_id=card.get("id", card.get("name", "")),
            agent_name=card.get("name", ""),
        )

        # Extract skills from agent card
        info.skills = self._extract_skills(card)

        # Detect supported protocols
        info.supported_protocols = self._detect_protocols(card)

        # Analyze scopes/permissions
        info.scopes = self._analyze_scopes(card)

        # Determine risk level
        info.risk_level = self._assess_risk(info)

        # Map attack surface areas
        info.attack_surface_areas = self._map_attack_surface(info)

        return info

    def _extract_skills(self, card: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract skill definitions from agent card."""
        raw_skills = card.get("skills", [])
        skills = []
        for skill in raw_skills:
            if isinstance(skill, dict):
                skills.append(
                    {
                        "name": skill.get("name", skill.get("id", "")),
                        "description": skill.get("description", ""),
                        "input_modes": skill.get("inputModes", ["text"]),
                        "output_modes": skill.get("outputModes", ["text"]),
                    }
                )
        return skills

    def _detect_protocols(self, card: dict[str, Any]) -> list[str]:
        """Detect supported communication protocols."""
        protocols = ["a2a-v1"]  # Base protocol
        additional = card.get("additionalInterfaces", [])
        for iface in additional:
            url = iface.get("url", "")
            if "grpc" in url:
                protocols.append("grpc")
            elif "jsonrpc" in url:
                protocols.append("json-rpc")
            elif "sse" in url:
                protocols.append("sse")
        return protocols

    def _analyze_scopes(self, card: dict[str, Any]) -> list[str]:
        """Analyze permission scopes from agent card."""
        capabilities = card.get("capabilities", {})
        scopes = []
        if capabilities.get("streaming"):
            scopes.append("streaming")
        if capabilities.get("pushNotifications"):
            scopes.append("push-notifications")
        if capabilities.get("stateTransitionHistory"):
            scopes.append("state-history")
        if capabilities.get("authenticatedExtendedCard"):
            scopes.append("extended-card-auth")
        return scopes

    def _assess_risk(self, info: CapabilityInfo) -> str:
        """Assess risk level based on capabilities."""
        if len(info.skills) > 10:
            return "high"
        elif any("execute" in s.get("name", "").lower() for s in info.skills):
            return "critical"
        elif len(info.skills) > 5:
            return "medium"
        return "low"

    def _map_attack_surface(self, info: CapabilityInfo) -> list[str]:
        """Map potential attack surface areas from capabilities."""
        areas = []
        for skill in info.skills:
            name = skill.get("name", "").lower()
            desc = skill.get("description", "").lower()
            combined = f"{name} {desc}"

            if any(p in combined for p in ["file", "read", "write"]):
                areas.append("file_access")
            if any(p in combined for p in ["network", "http", "fetch"]):
                areas.append("network_access")
            if any(p in combined for p in ["prompt", "template", "message"]):
                areas.append("prompt_manipulation")
            if any(p in combined for p in ["eval", "run", "execute"]):
                areas.append("code_execution")

        return list(set(areas))


async def enumerate_a2a_capabilities(
    target_url: str,
    agent_cards: list[dict[str, Any]],
) -> CapabilityEnumResult:
    """Convenience function for A2A capability enumeration."""
    enumerator = A2ACapabilityEnumerator()
    return await enumerator.enumerate(target_url, agent_cards)
