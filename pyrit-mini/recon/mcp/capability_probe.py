# -*- coding: utf-8 -*-
"""recon/mcp/capability_probe.py - MCP Capability Probe Module.

Probes MCP server capabilities for attack surface mapping:
    1. Protocol version detection
    2. Supported transport types (stdio, SSE, HTTP)
    3. Batch request support detection
    4. Notification capability detection
    5. Tool/resource/prompt capability bits

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Capability-based attack surface
    - OWASP ASI Top 10 2025 - MCP capability enumeration

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - capability probing only
    - R-S1: No hardcoded target identifiers
    - R-S4: Tests all mock
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MCPCapabilityInfo:
    """MCP server capability information."""

    protocol_version: str = ""
    supported_transports: list[str] = field(default_factory=list)
    supports_batch: bool = False
    supports_notifications: bool = False
    server_name: str = ""
    server_version: str = ""
    server_info: dict[str, Any] = field(default_factory=dict)
    capability_bits: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "supported_transports": self.supported_transports,
            "supports_batch": self.supports_batch,
            "supports_notifications": self.supports_notifications,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "capability_bits": self.capability_bits,
        }


# MCP capability probe methods
_CAPABILITIES_PROBE_METHODS = [
    "initialize",
    "tools/list",
    "resources/list",
    "prompts/list",
    "logging/setLevel",
]

# Transport type indicators
_TRANSPORT_INDICATORS = {
    "stdio": ["/stdio", "stdio"],
    "sse": ["/sse", "/events", "server-sent-events"],
    "http": ["/http", "/mcp", "/api/mcp"],
}


class MCPCapabilityProbe:
    """Probe MCP server capabilities.

    Usage:
        probe = MCPCapabilityProbe()
        info = await probe.probe_capabilities(
            target_url="http://mcp-server:8080",
        )
        print(f"Server: {info.server_name} v{info.server_version}")
    """

    def __init__(
        self,
        timeout: float = 10.0,
    ):
        self.timeout = timeout

    async def probe_capabilities(
        self,
        target_url: str,
    ) -> MCPCapabilityInfo:
        """Probe all MCP server capabilities.

        Args:
            target_url: MCP server URL

        Returns:
            MCPCapabilityInfo with discovered capabilities
        """
        info = MCPCapabilityInfo()

        # Initialize probe to get server info and capabilities
        init_result = await self._send_initialize(target_url)
        if init_result:
            info.server_name = init_result.get("serverInfo", {}).get("name", "")
            info.server_version = init_result.get("serverInfo", {}).get("version", "")
            info.protocol_version = init_result.get("protocolVersion", "")
            info.server_info = init_result.get("serverInfo", {})
            info.capability_bits = init_result.get("capabilities", {})

        # Detect transport support
        info.supported_transports = self._detect_transports(target_url)

        # Check batch support
        info.supports_batch = await self._check_batch_support(target_url)

        # Check notification support
        info.supports_notifications = "notifications" in str(info.capability_bits).lower()

        return info

    async def _send_initialize(self, target_url: str) -> dict[str, Any] | None:
        """Send MCP initialize request."""
        import aiohttp

        url = f"{target_url.rstrip('/')}"
        init_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-recon",
                    "version": "1.0.0",
                },
            },
        }

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.post(url, json=init_body) as response:
                    if response.status == 200:
                        return await response.json()
        except Exception as e:
            logger.debug("Initialize probe failed: %s", e)

        return None

    def _detect_transports(self, target_url: str) -> list[str]:
        """Detect supported transport types from URL."""
        transports = []
        url_lower = target_url.lower()

        for transport, indicators in _TRANSPORT_INDICATORS.items():
            if any(ind in url_lower for ind in indicators):
                transports.append(transport)

        # Default: HTTP transport assumed if URL is HTTP-based
        if not transports and url_lower.startswith("http"):
            transports.append("http")

        return transports

    async def _check_batch_support(self, target_url: str) -> bool:
        """Check if server supports batch JSON-RPC requests."""
        import aiohttp

        url = f"{target_url.rstrip('/')}"
        batch_body = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}},
        ]

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.post(url, json=batch_body) as response:
                    if response.status == 200:
                        data = await response.json()
                        # If we got an array response, batch is supported
                        return isinstance(data, list)
        except Exception as e:
            logger.debug("Batch support check failed: %s", e)

        return False

    def get_probe_methods(self) -> list[str]:
        """Get list of MCP probe method names."""
        return list(_CAPABILITIES_PROBE_METHODS)


async def probe_mcp_capabilities(
    target_url: str,
    timeout: float = 10.0,
) -> MCPCapabilityInfo:
    """Convenience function for MCP capability probing.

    Args:
        target_url: MCP server URL
        timeout: Request timeout

    Returns:
        MCPCapabilityInfo
    """
    probe = MCPCapabilityProbe(timeout=timeout)
    return await probe.probe_capabilities(target_url)
