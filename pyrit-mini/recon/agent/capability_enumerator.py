# -*- coding: utf-8 -*-
"""recon/agent/capability_enumerator — enumerate agent capabilities.

Enumerates an agent's capabilities from its declared tools and skills. Real
extraction, no fabricated capability claims.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AgentCapability:
    """A single enumerated agent capability."""

    name: str
    kind: str  # "tool" | "skill"
    description: str = ""


@dataclass
class CapabilityEnumResult:
    """Aggregate capability enumeration result."""

    capabilities: list[AgentCapability] = field(default_factory=list)
    tool_count: int = 0
    skill_count: int = 0


def enumerate_agent_capabilities(
    tools: list[dict] | None = None,
    skills: list[dict] | None = None,
) -> CapabilityEnumResult:
    """Enumerate an agent's capabilities from its tool and skill declarations."""
    out = CapabilityEnumResult()
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        name = t.get("name") or t.get("function", {}).get("name", "unknown")
        desc = t.get("description") or t.get("function", {}).get("description", "")
        out.capabilities.append(AgentCapability(name=name, kind="tool", description=desc or ""))
        out.tool_count += 1
    for s in skills or []:
        if not isinstance(s, dict):
            continue
        out.capabilities.append(
            AgentCapability(name=str(s.get("id", "unknown")), kind="skill", description=str(s.get("name", "")))
        )
        out.skill_count += 1
    return out
