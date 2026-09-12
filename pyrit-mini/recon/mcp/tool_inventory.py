# -*- coding: utf-8 -*-
"""recon/mcp/tool_inventory.py - MCP Tool Inventory Scanner.

Scans and catalogs all tools exposed by an MCP server for attack surface analysis:
    1. Tool name and description extraction
    2. Input schema analysis (parameter injection points)
    3. Output schema mapping (data exfiltration paths)
    4. Tool relationship graph (chain attack opportunities)
    5. Risk scoring per tool (based on schema complexity)

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Tool description injection surface
    - Zhan et al. (arXiv:2307.00929) - InjecAgent tool schema attacks
    - OWASP ASI Top 10 2025 - MCP Tool Poisoning Surface

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - tool inventory only
    - R-S1: No hardcoded target identifiers
    - R-S4: Tests all mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MCPToolRisk:
    """Risk assessment result for a single MCP tool."""

    tool_name: str = ""
    risk_score: float = 0.0  # 0.0-1.0
    injection_points: list[str] = field(default_factory=list)
    exfiltration_paths: list[str] = field(default_factory=list)
    chain_opportunities: list[str] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "risk_score": self.risk_score,
            "injection_points": self.injection_points,
            "exfiltration_paths": self.exfiltration_paths,
            "chain_opportunities": self.chain_opportunities,
            "risk_factors": self.risk_factors,
        }


@dataclass
class ToolInventoryResult:
    """Complete tool inventory scan result."""

    target_url: str = ""
    tools_scanned: int = 0
    tools: list[dict[str, Any]] = field(default_factory=list)
    risk_assessments: list[MCPToolRisk] = field(default_factory=list)
    high_risk_tools: list[str] = field(default_factory=list)
    injection_surface_count: int = 0
    scan_timestamp: str = ""

    @property
    def has_high_risk_tools(self) -> bool:
        """Check if any tools have high risk scores."""
        return any(t.risk_score >= 0.7 for t in self.risk_assessments)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "tools_scanned": self.tools_scanned,
            "tools_count": len(self.tools),
            "risk_assessments": [r.to_dict() for r in self.risk_assessments],
            "high_risk_tools": self.high_risk_tools,
            "injection_surface_count": self.injection_surface_count,
        }


# Risk factor patterns for MCP tools
_HIGH_RISK_PATTERNS = [
    "file",
    "path",
    "directory",  # File system access
    "exec",
    "command",
    "shell",
    "system",  # Command execution
    "url",
    "http",
    "fetch",
    "request",  # Network access
    "env",
    "secret",
    "credential",
    "key",  # Credential access
    "database",
    "query",
    "sql",  # Database access
    "email",
    "send",
    "notify",  # External communication
]

_INJECTION_POINT_PATTERNS = [
    "description",
    "prompt",
    "template",  # Description injection
    "query",
    "search",
    "filter",  # Query injection
    "content",
    "text",
    "body",  # Content injection
]


class MCPToolInventoryScanner:
    """MCP tool inventory and risk assessment scanner.

    Usage:
        scanner = MCPToolInventoryScanner()
        result = await scanner.scan_tool_inventory(
            target_url="http://mcp-server:8080",
            tool_definitions=tools_list,
        )
        for risk in result.risk_assessments:
            if risk.risk_score >= 0.7:
                print(f"High risk: {risk.tool_name}")
    """

    def __init__(self):
        self._high_risk_patterns = _HIGH_RISK_PATTERNS
        self._injection_patterns = _INJECTION_POINT_PATTERNS

    async def scan_tool_inventory(
        self,
        target_url: str,
        tool_definitions: list[dict[str, Any]],
    ) -> ToolInventoryResult:
        """Scan and assess all tools in inventory.

        Args:
            target_url: MCP server URL
            tool_definitions: List of tool definitions from /tools/list

        Returns:
            ToolInventoryResult with risk assessments
        """
        import datetime

        result = ToolInventoryResult(
            target_url=target_url,
            scan_timestamp=datetime.datetime.now().isoformat(),
        )

        for tool_def in tool_definitions:
            result.tools.append(tool_def)
            result.tools_scanned += 1

            # Assess risk for each tool
            risk = self._assess_tool_risk(tool_def)
            result.risk_assessments.append(risk)
            result.injection_surface_count += len(risk.injection_points)

            if risk.risk_score >= 0.7:
                result.high_risk_tools.append(risk.tool_name)

        return result

    def _assess_tool_risk(self, tool_def: dict[str, Any]) -> MCPToolRisk:
        """Assess risk level of a single tool.

        Args:
            tool_def: Tool definition from MCP server

        Returns:
            MCPToolRisk assessment
        """
        risk = MCPToolRisk(tool_name=tool_def.get("name", "unknown"))

        tool_name = tool_def.get("name", "").lower()
        description = tool_def.get("description", "").lower()
        input_schema = tool_def.get("inputSchema", {})

        # Check name against high-risk patterns
        for pattern in self._high_risk_patterns:
            if pattern in tool_name or pattern in description:
                risk.risk_factors.append(f"high_risk_keyword:{pattern}")
                risk.risk_score += 0.15

        # Analyze input schema for injection points
        properties = input_schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            prop_str = f"{prop_name} {prop_schema.get('description', '')}".lower()
            for inj_pattern in self._injection_patterns:
                if inj_pattern in prop_str:
                    risk.injection_points.append(prop_name)
                    risk.risk_score += 0.1
                    break

        # Check for chain opportunities (output of one tool feeds into another)
        if self._has_chain_potential(tool_def):
            risk.chain_opportunities.append("output_to_input_chain")
            risk.risk_score += 0.05

        # Check for exfiltration paths
        if any(kw in description for kw in ["send", "forward", "notify", "email"]):
            risk.exfiltration_paths.append("description_exfil")
            risk.risk_score += 0.1

        risk.risk_score = min(1.0, risk.risk_score)
        return risk

    def _has_chain_potential(self, tool_def: dict[str, Any]) -> bool:
        """Check if tool output can be chained to another tool input."""
        description = tool_def.get("description", "").lower()
        chain_indicators = ["result", "output", "return", "data", "content"]
        return any(ind in description for ind in chain_indicators)

    def get_high_risk_patterns(self) -> list[str]:
        """Get list of high-risk keyword patterns."""
        return list(self._high_risk_patterns)

    def get_injection_patterns(self) -> list[str]:
        """Get list of injection point patterns."""
        return list(self._injection_point_patterns)


async def scan_mcp_tool_inventory(
    target_url: str,
    tool_definitions: list[dict[str, Any]],
) -> ToolInventoryResult:
    """Convenience function for MCP tool inventory scanning.

    Args:
        target_url: MCP server URL
        tool_definitions: List of tool definitions

    Returns:
        ToolInventoryResult
    """
    scanner = MCPToolInventoryScanner()
    return await scanner.scan_tool_inventory(target_url, tool_definitions)
