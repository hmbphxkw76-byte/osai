# -*- coding: utf-8 -*-
"""recon/agent - ReAct / Tool-use Agent reconnaissance (Agent Surface Recon).

Discovers whether a target exposes a function-calling / tool-use agent loop and
enumerates its tool/function surface for injection-prone parameters.

Academic basis:
    - Greshake et al. (arXiv:2302.12173) — Indirect prompt injection
    - Zhan et al. (arXiv:2307.00929) — Schema-guided injection (InjecAgent)
    - OWASP ASI04 — Tool / Function Misuse

Constitution compliance:
    - R-SIZE: 每模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
"""

from recon.agent.capability_enumerator import (
    AgentCapability,
    CapabilityEnumResult,
    enumerate_agent_capabilities,
)
from recon.agent.discoverer import (
    AgentSurface,
    DiscoveryResult,
    discover_agent_surface,
)
from recon.agent.tool_analyzer import (
    ToolAnalysisResult,
    analyze_tool_definitions,
)

__all__ = [
    # discoverer
    "AgentSurface",
    "DiscoveryResult",
    "discover_agent_surface",
    # tool_analyzer
    "ToolAnalysisResult",
    "analyze_tool_definitions",
    # capability_enumerator
    "AgentCapability",
    "CapabilityEnumResult",
    "enumerate_agent_capabilities",
]
