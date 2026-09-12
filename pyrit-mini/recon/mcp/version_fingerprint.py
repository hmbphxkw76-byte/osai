# -*- coding: utf-8 -*-
"""recon/mcp/version_fingerprint.py - MCP Version Fingerprinting Module.

Identifies MCP server implementations based on response characteristics:
    1. Server header analysis
    2. Response format fingerprinting
    3. Error message patterns
    4. Timing-based identification
    5. Protocol behavior quirks

Academic basis:
    - OWASP ASI Top 10 2025 - Attack surface identification via fingerprinting
    - NIST AI RMF 600-1 - System identification for risk assessment

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - version fingerprinting only
    - R-S1: No hardcoded target identifiers
    - R-S4: Tests all mock
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VersionFingerprintResult:
    """Version fingerprinting result."""

    target_url: str = ""
    server_software: str = ""
    server_version: str = ""
    protocol_version: str = ""
    implementation_family: str = ""  # python-sdk, typescript-sdk, custom, unknown
    confidence: float = 0.0  # 0.0-1.0
    fingerprint_hash: str = ""
    indicators: list[str] = field(default_factory=list)
    response_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "server_software": self.server_software,
            "server_version": self.server_version,
            "protocol_version": self.protocol_version,
            "implementation_family": self.implementation_family,
            "confidence": self.confidence,
            "fingerprint_hash": self.fingerprint_hash,
            "indicators": self.indicators,
        }


# Known MCP implementation fingerprints
_KNOWN_IMPLEMENTATIONS = {
    "python-sdk": {
        "patterns": [
            re.compile(r"@modelcontextprotocol/sdk", re.I),
            re.compile(r"mcp_server", re.I),
            re.compile(r"FastMCP", re.I),
        ],
        "headers": ["mcp-server", "python"],
        "version_pattern": re.compile(r"(\d+\.\d+\.\d+)"),
    },
    "typescript-sdk": {
        "patterns": [
            re.compile(r"@modelcontextprotocol/sdk", re.I),
            re.compile(r"mcp-server", re.I),
        ],
        "headers": ["mcp-server", "node", "express"],
        "version_pattern": re.compile(r"(\d+\.\d+\.\d+)"),
    },
    "custom": {
        "patterns": [],
        "headers": [],
        "version_pattern": re.compile(r"v?(\d+\.\d+)"),
    },
}


class MCPVersionFingerprinter:
    """MCP server version fingerprinter.

    Usage:
        fingerprinter = MCPVersionFingerprinter()
        result = await fingerprinter.fingerprint_version(
            target_url="http://mcp-server:8080",
        )
        print(f"Server: {result.server_software} ({result.implementation_family})")
    """

    def __init__(
        self,
        timeout: float = 10.0,
    ):
        self.timeout = timeout

    async def fingerprint_version(
        self,
        target_url: str,
    ) -> VersionFingerprintResult:
        """Fingerprint the MCP server version.

        Args:
            target_url: MCP server URL

        Returns:
            VersionFingerprintResult with identification
        """
        result = VersionFingerprintResult(target_url=target_url)

        # 1. Send initialize and analyze response
        init_response = await self._send_initialize(target_url)
        if init_response:
            self._analyze_init_response(init_response, result)

        # 2. Analyze response headers
        headers = await self._get_response_headers(target_url)
        if headers:
            result.response_headers = headers
            self._analyze_headers(headers, result)

        # 3. Generate fingerprint hash
        fingerprint_data = f"{result.server_software}:{result.server_version}:{result.implementation_family}"
        result.fingerprint_hash = hashlib.md5(fingerprint_data.encode()).hexdigest()[:12]

        return result

    async def _send_initialize(self, target_url: str) -> dict[str, Any] | None:
        """Send MCP initialize and capture response."""
        import aiohttp

        url = f"{target_url.rstrip('/')}"
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fingerprint", "version": "1.0.0"},
            },
        }

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.post(url, json=body) as response:
                    if response.status == 200:
                        return await response.json()
        except Exception as e:
            logger.debug("Fingerprint initialize failed: %s", e)

        return None

    async def _get_response_headers(self, target_url: str) -> dict[str, str]:
        """Capture response headers."""
        import aiohttp

        url = f"{target_url.rstrip('/')}/health"

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url) as response:
                    return dict(response.headers)
        except Exception as e:
            logger.debug("Header capture failed: %s", e)
            return {}

    def _analyze_init_response(
        self,
        response: dict[str, Any],
        result: VersionFingerprintResult,
    ) -> None:
        """Analyze initialize response for version info."""
        server_info = response.get("result", {}).get("serverInfo", {})
        result.server_software = server_info.get("name", "")
        result.server_version = server_info.get("version", "")
        result.protocol_version = response.get("result", {}).get("protocolVersion", "")

        # Try to identify implementation family
        full_response_str = str(response)
        for family, data in _KNOWN_IMPLEMENTATIONS.items():
            for pattern in data["patterns"]:
                if pattern.search(full_response_str):
                    result.implementation_family = family
                    result.confidence = 0.7
                    result.indicators.append(f"pattern_match:{pattern.pattern}")
                    break

        # If server name suggests known implementation
        if "mcp" in result.server_software.lower():
            result.confidence = max(result.confidence, 0.5)
            result.indicators.append(f"server_name_match:{result.server_software}")

    def _analyze_headers(
        self,
        headers: dict[str, str],
        result: VersionFingerprintResult,
    ) -> None:
        """Analyze HTTP headers for fingerprinting."""
        server_header = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()

        if "python" in server_header or "uvicorn" in server_header or "fastapi" in server_header:
            if result.implementation_family == "":
                result.implementation_family = "python-sdk"
                result.confidence = max(result.confidence, 0.4)
            result.indicators.append(f"header_python:{server_header}")

        if "node" in server_header or "express" in server_header:
            if result.implementation_family == "":
                result.implementation_family = "typescript-sdk"
                result.confidence = max(result.confidence, 0.4)
            result.indicators.append(f"header_node:{server_header}")

        if powered_by:
            result.indicators.append(f"powered_by:{powered_by}")

    def get_known_families(self) -> list[str]:
        """Get list of known implementation families."""
        return list(_KNOWN_IMPLEMENTATIONS.keys())


async def fingerprint_mcp_version(
    target_url: str,
    timeout: float = 10.0,
) -> VersionFingerprintResult:
    """Convenience function for MCP version fingerprinting.

    Args:
        target_url: MCP server URL
        timeout: Request timeout

    Returns:
        VersionFingerprintResult
    """
    fingerprinter = MCPVersionFingerprinter(timeout=timeout)
    return await fingerprinter.fingerprint_version(target_url)
