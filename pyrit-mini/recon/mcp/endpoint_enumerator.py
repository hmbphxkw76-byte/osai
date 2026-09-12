# -*- coding: utf-8 -*-
"""recon/mcp/endpoint_enumerator.py - MCP Endpoint Enumeration Module.

Enumerates MCP server endpoints to discover all available attack surfaces:
    1. /tools/list — Tool enumeration for poisoning targets
    2. /resources/list — Resource enumeration for traversal attacks
    3. /prompts/list — Prompt enumeration for injection targets
    4. /health — Server health/status endpoint
    5. /sse — Server-Sent Events for streaming attacks

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Indirect Prompt Injection via endpoints
    - Zhan et al. (arXiv:2307.00929) - Tool schema attack surface mapping
    - OWASP ASI Top 10 2025 - MCP Security Surface

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - endpoint enumeration only
    - R-S1: No hardcoded target identifiers
    - R-S4: Tests all mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MCPEndpointInfo:
    """Discovered MCP endpoint information."""

    endpoint_path: str = ""
    endpoint_type: str = ""  # tools, resources, prompts, health, sse
    is_accessible: bool = False
    response_schema: dict[str, Any] = field(default_factory=dict)
    tool_count: int = 0
    resource_count: int = 0
    prompt_count: int = 0
    requires_auth: bool = False
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_path": self.endpoint_path,
            "endpoint_type": self.endpoint_type,
            "is_accessible": self.is_accessible,
            "tool_count": self.tool_count,
            "resource_count": self.resource_count,
            "prompt_count": self.prompt_count,
            "requires_auth": self.requires_auth,
        }


@dataclass
class EndpointEnumerationResult:
    """Complete endpoint enumeration result."""

    target_url: str = ""
    endpoints: list[MCPEndpointInfo] = field(default_factory=list)
    total_tools: int = 0
    total_resources: int = 0
    total_prompts: int = 0
    enumeration_time_ms: float = 0.0
    scan_timestamp: str = ""

    @property
    def is_fully_enumerated(self) -> bool:
        """Check if all standard MCP endpoints were discovered."""
        required_types = {"tools", "resources", "prompts"}
        found_types = {ep.endpoint_type for ep in self.endpoints if ep.is_accessible}
        return required_types.issubset(found_types)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "total_tools": self.total_tools,
            "total_resources": self.total_resources,
            "total_prompts": self.total_prompts,
            "is_fully_enumerated": self.is_fully_enumerated,
        }


# Standard MCP protocol endpoints
_MCP_STANDARD_ENDPOINTS = [
    {"path": "/tools/list", "type": "tools", "method": "POST"},
    {"path": "/resources/list", "type": "resources", "method": "POST"},
    {"path": "/prompts/list", "type": "prompts", "method": "POST"},
    {"path": "/tools/call", "type": "tools_call", "method": "POST"},
    {"path": "/resources/read", "type": "resources_read", "method": "POST"},
    {"path": "/prompts/get", "type": "prompts_get", "method": "POST"},
    {"path": "/sse", "type": "sse", "method": "GET"},
    {"path": "/health", "type": "health", "method": "GET"},
]

# MCP JSON-RPC method names for tool discovery
_MCP_DISCOVERY_METHODS = {
    "tools/list": "List available tools",
    "resources/list": "List available resources",
    "prompts/list": "List available prompts",
    "tools/call": "Execute a tool",
    "resources/read": "Read a resource",
    "prompts/get": "Get a prompt template",
}


class MCPEndpointEnumerator:
    """MCP server endpoint enumeration.

    Discovers all MCP server endpoints for attack surface mapping.

    Usage:
        enumerator = MCPEndpointEnumerator()
        result = await enumerator.enumerate_endpoints(
            target_url="http://mcp-server:8080",
            max_probes=10,
        )
        if result.is_fully_enumerated:
            print(f"Discovered {result.total_tools} tools")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        stealth_mode: bool = True,
    ):
        self.timeout = timeout
        self.stealth_mode = stealth_mode

    async def enumerate_endpoints(
        self,
        target_url: str,
        max_probes: int = 10,
    ) -> EndpointEnumerationResult:
        """Enumerate all MCP endpoints on target.

        Args:
            target_url: Base URL of MCP server
            max_probes: Maximum number of enumeration probes

        Returns:
            EndpointEnumerationResult with discovered endpoints
        """
        import time

        result = EndpointEnumerationResult(target_url=target_url)
        start_time = time.time()

        probe_count = 0
        for endpoint_def in _MCP_STANDARD_ENDPOINTS:
            if probe_count >= max_probes:
                break

            endpoint_info = await self._probe_endpoint(
                target_url=target_url,
                path=endpoint_def["path"],
                method=endpoint_def["method"],
                endpoint_type=endpoint_def["type"],
            )
            result.endpoints.append(endpoint_info)
            probe_count += 1

        # Aggregate counts
        for ep in result.endpoints:
            result.total_tools += ep.tool_count
            result.total_resources += ep.resource_count
            result.total_prompts += ep.prompt_count

        result.enumeration_time_ms = (time.time() - start_time) * 1000
        return result

    async def _probe_endpoint(
        self,
        target_url: str,
        path: str,
        method: str,
        endpoint_type: str,
    ) -> MCPEndpointInfo:
        """Probe a single MCP endpoint.

        Args:
            target_url: Base URL of MCP server
            path: Endpoint path
            method: HTTP method
            endpoint_type: Type classification

        Returns:
            MCPEndpointInfo with probe result
        """
        import aiohttp

        info = MCPEndpointInfo(
            endpoint_path=path,
            endpoint_type=endpoint_type,
        )

        url = f"{target_url.rstrip('/')}{path}"

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                if method == "POST":
                    # MCP JSON-RPC request format
                    json_rpc_body = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": path.strip("/"),
                        "params": {},
                    }
                    async with session.post(url, json=json_rpc_body) as response:
                        info.is_accessible = response.status in (200, 201, 204)
                        info.requires_auth = response.status == 401
                        if info.is_accessible:
                            data = await response.json()
                            info.response_schema = data
                            self._extract_counts(info, data)
                else:  # GET
                    async with session.get(url) as response:
                        info.is_accessible = response.status == 200
                        info.requires_auth = response.status == 401
        except Exception as e:
            info.error_message = str(e)
            logger.debug("MCP endpoint probe failed [%s]: %s", path, e)

        return info

    def _extract_counts(self, info: MCPEndpointInfo, data: dict[str, Any]) -> None:
        """Extract tool/resource/prompt counts from response."""
        result = data.get("result", {})

        if info.endpoint_type == "tools":
            tools = result.get("tools", [])
            info.tool_count = len(tools)
        elif info.endpoint_type == "resources":
            resources = result.get("resources", [])
            info.resource_count = len(resources)
        elif info.endpoint_type == "prompts":
            prompts = result.get("prompts", [])
            info.prompt_count = len(prompts)

    def get_standard_endpoint_paths(self) -> list[str]:
        """Get list of standard MCP endpoint paths."""
        return [ep["path"] for ep in _MCP_STANDARD_ENDPOINTS]

    def get_discovery_methods(self) -> dict[str, str]:
        """Get MCP discovery method names."""
        return dict(_MCP_DISCOVERY_METHODS)


async def enumerate_mcp_endpoints(
    target_url: str,
    max_probes: int = 10,
    timeout: float = 10.0,
) -> EndpointEnumerationResult:
    """Convenience function for MCP endpoint enumeration.

    Args:
        target_url: Base URL of MCP server
        max_probes: Maximum probes to send
        timeout: Request timeout in seconds

    Returns:
        EndpointEnumerationResult
    """
    enumerator = MCPEndpointEnumerator(timeout=timeout)
    return await enumerator.enumerate_endpoints(target_url, max_probes)
