# -*- coding: utf-8 -*-
"""recon/agent/discoverer — ReAct / Tool-use Agent surface discovery.

Detects whether a target exposes a function-calling / tool-use agent loop
(tool_calls, function_call, OpenAI-style ``tools`` schema, ReAct action loop)
by inspecting an observed response or a captured API specification.

Real logic: marker detection + schema parsing. No fabricated telemetry.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Structural markers that indicate a tool-use / function-calling agent loop.
_TOOL_USE_MARKERS = (
    "tool_calls",
    "function_call",
    "tool_call",
    "functions",
    "tools",
    "action",
    "action_input",
    "intermediate_steps",
    "agent_scratchpad",
)


@dataclass
class AgentSurface:
    """Discovered tool-use surface of a target agent."""

    tool_use_detected: bool = False
    frameworks: list[str] = field(default_factory=list)
    declared_tools: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


@dataclass
class DiscoveryResult:
    """Result wrapper for agent surface discovery."""

    surface: AgentSurface
    raw_markers: list[str] = field(default_factory=list)


def _detect_framework(text: str) -> list[str]:
    """Identify the agent framework from response/spec markers."""
    frameworks: list[str] = []
    lowered = text.lower()
    if "tool_calls" in lowered or "function_call" in lowered:
        frameworks.append("openai_function_calling")
    if "intermediate_steps" in lowered or "agent_scratchpad" in lowered:
        frameworks.append("langchain_react")
    if "action" in lowered and "action_input" in lowered:
        frameworks.append("react_agent")
    if "tools" in lowered and ("json_schema" in lowered or "parameters" in lowered):
        frameworks.append("tool_schema_agent")
    return frameworks


def discover_agent_surface(
    response_text: str = "",
    api_spec: str | None = None,
) -> DiscoveryResult:
    """Discover a target's tool-use / agent surface.

    Args:
        response_text: An observed model/agent response (may contain tool_calls JSON).
        api_spec: Optional captured OpenAPI/JSON spec text to parse for a ``tools`` schema.

    Returns:
        DiscoveryResult with markers, declared tools, and a confidence score.
    """
    text = (response_text or "").strip()
    markers: list[str] = [m for m in _TOOL_USE_MARKERS if m in text.lower()]

    declared_tools: list[str] = []
    if api_spec:
        try:
            spec = json.loads(api_spec) if api_spec.strip().startswith("{") else {}
            tools = spec.get("tools") or spec.get("functions") or []
            for t in tools:
                if isinstance(t, dict):
                    name = t.get("name") or t.get("function", {}).get("name")
                    if name:
                        declared_tools.append(name)
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug("agent discoverer: api_spec parse failed: %s", e)

    frameworks = _detect_framework(text)
    tool_use_detected = bool(markers) or bool(declared_tools) or bool(frameworks)

    confidence = 0.0
    if markers:
        confidence += min(0.5, 0.1 * len(markers))
    if declared_tools:
        confidence += 0.3
    if frameworks:
        confidence += 0.2
    confidence = min(confidence, 1.0)

    surface = AgentSurface(
        tool_use_detected=tool_use_detected,
        frameworks=frameworks,
        declared_tools=declared_tools,
        confidence=round(confidence, 2),
        evidence=markers,
    )
    return DiscoveryResult(surface=surface, raw_markers=markers)
