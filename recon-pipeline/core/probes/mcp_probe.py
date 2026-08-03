# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""MCPProbe: MCP Server reconnaissance probe.

Responsibilities:
  1. Filter MCP_SERVER endpoints from NetworkInterceptor results
  2. Active MCP handshake (initialize JSON-RPC) to get serverInfo/capabilities
  3. Active tool enumeration (tools/list, resources/list, prompts/list)
  4. Tool annotation contradiction detection (readOnlyHint vs name implying mutation)
  5. Tool shadowing detection (same tool name from multiple servers)
  6. YARA-style scanning of tool descriptions for threat patterns
  7. InputSchema injection surface extraction

Architecture alignment (DESIGN.md six-probe architecture):
  - Input: auth_state (HTTP headers)
  - Output: endpoints (MCP_SERVER) + mcp_tools + server_info
  - Browser: False (JSON-RPC over HTTP, interception needs browser)

Academic basis:
  - MCP Protocol Spec (2024-11): tools/list, resources/list, prompts/list JSON-RPC
  - OWASP LLM06: Excessive Agency — MCP tools may expose excessive permissions
  - OWASP LLM07: System Prompt Leakage — MCP configuration info leakage
  - Hou et al. (arXiv:2503.23278): MCP four-phase attack surface
  - VulnerableMCP: 50 CVEs / 13 Critical — tool poisoning/RCE/SSRF/shadowing
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from core.models.recon_report import (
    DiscoveredEndpoint,
    EndpointType,
    MCPToolInfo,
)
from core.probes.ai_signal_catalog import AI_MCP_PROBE_PATHS
from core.probes.base import ReconProbe
from core.probes.mcp_yara import scan_mcp_detail

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# Risk assessment keyword groups (used only for risk_level tie-breaking)
_CRITICAL_KEYWORDS = ("execute", "shell", "system", "delete", "drop", "sudo", "root", "admin", "rm -rf", "format")
_HIGH_KEYWORDS = ("write", "upload", "send", "post", "fetch", "download", "modify", "update", "create", "deploy", "install")
_MEDIUM_KEYWORDS = ("read", "get", "list", "search", "query", "find", "lookup", "describe", "show")

# Mutation-indicating tool name patterns (for annotation contradiction detection)
_MUTATION_NAME_PATTERNS = ("exec", "delete", "drop", "write", "modify", "update", "create", "remove", "kill", "stop", "restart")


class MCPProbe(ReconProbe):
    """MCP Server reconnaissance probe.

    Discovers MCP Server endpoints, performs active handshake and
    tool enumeration, detects tool shadowing and annotation contradictions.

    Usage::
        probe = MCPProbe()
        result = await probe.probe(session)
        # result["endpoints"] -> MCP Server endpoint list
        # result["mcp_tools"] -> MCPToolInfo list
        # result["mcp_server_info"] -> server capabilities
    """

    def __init__(self, active_timeout: float = 15.0) -> None:
        self._active_timeout = active_timeout

    @property
    def name(self) -> str:
        return "MCPProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute MCP probe.

        Args:
            session: Recon session.

        Returns:
            Dict with mcp_endpoints, mcp_tools, and server_info.
        """
        mcp_endpoints = [
            e for e in session.report.endpoints
            if e.endpoint_type == EndpointType.MCP_SERVER
        ]

        # Passive parsing from intercepted responses
        tools: list[MCPToolInfo] = []
        for ep in mcp_endpoints:
            parsed_tools = self._parse_mcp_response(ep)
            tools.extend(parsed_tools)

        # Active probing: handshake + enumerate
        server_info: list[dict[str, Any]] = []
        if mcp_endpoints:
            headers = session.auth_headers if session.auth_state else {}
            active_tools, active_info = await self._active_mcp_probe(mcp_endpoints, headers)
            tools.extend(active_tools)
            server_info.extend(active_info)

        # Tool shadowing detection
        self._check_tool_shadowing(tools)

        # Annotation contradiction detection
        self._check_annotation_contradictions(tools)

        # Threat pattern scanning
        for tool in tools:
            tool.threat_tags = self._scan_threats(tool)

        # Deduplicate tools by name+server
        tools = self._deduplicate_tools(tools)

        logger.info(
            "MCPProbe: %d MCP servers, %d tools discovered, "
            "%d servers with info",
            len(mcp_endpoints), len(tools), len(server_info),
        )

        return {
            "endpoints": mcp_endpoints,
            "mcp_tools": tools,
            "mcp_server_info": server_info,
        }

    # ── Passive parsing ──

    def _parse_mcp_response(self, endpoint: DiscoveredEndpoint) -> list[MCPToolInfo]:
        """Parse MCP tool list from endpoint response body.

        Supports formats:
          1. tools/list response: {"jsonrpc":"2.0","result":{"tools":[...]}}
          2. Initialize response: {"jsonrpc":"2.0","result":{"capabilities":{"tools":{}}}}
        """
        body = endpoint.response_body_preview or ""
        if not body or '"jsonrpc"' not in body:
            return []

        tools: list[MCPToolInfo] = []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            for candidate in self._extract_json_fragments(body):
                try:
                    data = json.loads(candidate)
                    break
                except json.JSONDecodeError:
                    continue
            else:
                return tools

        result = data.get("result", {})
        tool_list = result.get("tools", [])

        for tool_data in tool_list:
            tool_name = tool_data.get("name", "unknown")
            description = tool_data.get("description", "")
            input_schema = tool_data.get("inputSchema", {})

            risk_level = self._assess_risk(tool_name, description)
            injection_surfaces = self._extract_injection_surfaces(tool_data)

            tools.append(MCPToolInfo(
                tool_name=tool_name,
                description=description,
                input_schema=input_schema,
                risk_level=risk_level,
                shadowing_detected=False,
                server_url=endpoint.url,
                annotation_contradiction=False,
                tool_hash=self._hash_tool(tool_data),
                injection_surfaces=injection_surfaces,
            ))

        return tools

    # ── Active probing ──

    async def _active_mcp_probe(
        self,
        mcp_endpoints: list[DiscoveredEndpoint],
        headers: dict[str, str],
    ) -> tuple[list[MCPToolInfo], list[dict[str, Any]]]:
        """Perform active MCP handshake and tool enumeration."""
        all_tools: list[MCPToolInfo] = []
        server_info: list[dict[str, Any]] = []

        # Build base URLs from discovered endpoints
        seen_bases: set[str] = set()
        base_urls: list[str] = []
        for ep in mcp_endpoints:
            from urllib.parse import urlparse
            parsed = urlparse(ep.url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in seen_bases:
                seen_bases.add(base)
                base_urls.append(base)

        async with httpx.AsyncClient(timeout=self._active_timeout, verify=False, follow_redirects=False) as client:
            for base_url in base_urls:
                # 1. MCP handshake (initialize)
                info = await self._mcp_handshake(client, base_url, headers)
                instructions = info.get("instructions", "") if info else ""
                if info:
                    server_info.append(info)

                # 2. Tool enumeration
                for path in AI_MCP_PROBE_PATHS:
                    endpoint_url = f"{base_url.rstrip('/')}{path}"
                    tools = await self._mcp_enumerate(client, endpoint_url, headers, instructions)
                    if tools:
                        all_tools.extend(tools)
                        break  # One successful path per base URL

                # 3. Also try the original endpoint URLs
                for ep in mcp_endpoints:
                    if ep.url.startswith(base_url):
                        tools = await self._mcp_enumerate(client, ep.url, headers, instructions)
                        if tools:
                            for t in tools:
                                if not any(ex.tool_name == t.tool_name and ex.server_url == t.server_url for ex in all_tools):
                                    all_tools.append(t)

        return all_tools, server_info

    async def _mcp_handshake(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        """Perform MCP initialize handshake.

        POST {"jsonrpc":"2.0","method":"initialize","params":{...}} to candidate paths.
        Returns server info dict or None.
        """
        initialize_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "recon-pipeline-mcp-probe",
                    "version": "0.1.0",
                },
            },
        }

        for path in AI_MCP_PROBE_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.post(url, json=initialize_payload, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        result = data.get("result", {})
                        return {
                            "url": url,
                            "protocolVersion": result.get("protocolVersion", "unknown"),
                            "serverInfo": result.get("serverInfo", {}),
                            "instructions": result.get("instructions", ""),
                            "capabilities": result.get("capabilities", {}),
                            "auth_required": False,
                        }
                    except json.JSONDecodeError:
                        pass
                elif resp.status_code == 401:
                    return {
                        "url": url,
                        "protocolVersion": "unknown",
                        "serverInfo": {},
                        "capabilities": {},
                        "auth_required": True,
                    }
                elif resp.status_code == 400:
                    # Check if it's a version mismatch error
                    try:
                        data = resp.json()
                        error = data.get("error", {})
                        if "supported" in str(error.get("data", {})):
                            return {
                                "url": url,
                                "protocolVersion": "mismatch",
                                "serverInfo": {},
                                "capabilities": {},
                                "auth_required": False,
                                "version_error": str(error.get("data", {}).get("supported", "")),
                            }
                    except json.JSONDecodeError:
                        pass
            except (httpx.RequestError, asyncio.TimeoutError):
                pass

        return None

    async def _mcp_enumerate(
        self,
        client: httpx.AsyncClient,
        endpoint_url: str,
        headers: dict[str, str],
        instructions: str = "",
    ) -> list[MCPToolInfo]:
        """Enumerate MCP tools, resources, and prompts from an endpoint."""
        tools: list[MCPToolInfo] = []

        # tools/list
        tools_list_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        try:
            resp = await client.post(endpoint_url, json=tools_list_payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                tool_list = data.get("result", {}).get("tools", [])
                for tool_data in tool_list:
                    tool_name = tool_data.get("name", "unknown")
                    description = tool_data.get("description", "")
                    input_schema = tool_data.get("inputSchema", {})
                    annotations = tool_data.get("annotations", {})

                    risk_level = self._assess_risk(tool_name, description)
                    injection_surfaces = self._extract_injection_surfaces(tool_data)

                    tools.append(MCPToolInfo(
                        tool_name=tool_name,
                        description=description,
                        input_schema=input_schema,
                        risk_level=risk_level,
                        shadowing_detected=False,
                        server_url=endpoint_url,
                        annotation_contradiction=False,
                        tool_hash=self._hash_tool(tool_data),
                        instructions_hash=self._hash_instructions(instructions),
                        injection_surfaces=injection_surfaces,
                        annotations=annotations,
                    ))
        except (httpx.RequestError, asyncio.TimeoutError, json.JSONDecodeError):
            pass

        # resources/list
        resources_payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/list",
            "params": {},
        }
        try:
            resp = await client.post(endpoint_url, json=resources_payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                resource_list = data.get("result", {}).get("resources", [])
                for resource in resource_list:
                    tools.append(MCPToolInfo(
                        tool_name=f"resource:{resource.get('name', 'unknown')}",
                        description=resource.get("description", ""),
                        input_schema={"uri": resource.get("uri", ""), "mimeType": resource.get("mimeType", "")},
                        risk_level="low",
                        server_url=endpoint_url,
                        tool_hash="",
                        injection_surfaces=["uri"],
                    ))
        except (httpx.RequestError, asyncio.TimeoutError, json.JSONDecodeError):
            pass

        # prompts/list
        prompts_payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "prompts/list",
            "params": {},
        }
        try:
            resp = await client.post(endpoint_url, json=prompts_payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                prompt_list = data.get("result", {}).get("prompts", [])
                for prompt in prompt_list:
                    tools.append(MCPToolInfo(
                        tool_name=f"prompt:{prompt.get('name', 'unknown')}",
                        description=prompt.get("description", ""),
                        input_schema=prompt.get("arguments", {}),
                        risk_level="low",
                        server_url=endpoint_url,
                        tool_hash="",
                        injection_surfaces=["arguments"],
                    ))
        except (httpx.RequestError, asyncio.TimeoutError, json.JSONDecodeError):
            pass

        return tools

    # ── Analysis methods ──

    @staticmethod
    def _extract_json_fragments(body: str) -> list[str]:
        """Extract possible JSON objects from partial text."""
        fragments: list[str] = []
        depth = 0
        start = -1
        for i, ch in enumerate(body):
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start >= 0:
                    fragments.append(body[start:i + 1])
                    start = -1
        return fragments

    @staticmethod
    def _assess_risk(tool_name: str, description: str) -> str:
        """Assess risk level based on tool name and description."""
        text = f"{tool_name} {description}".lower()

        for kw in _CRITICAL_KEYWORDS:
            if kw in text:
                return "critical"
        for kw in _HIGH_KEYWORDS:
            if kw in text:
                return "high"
        for kw in _MEDIUM_KEYWORDS:
            if kw in text:
                return "medium"
        return "low"

    def _check_tool_shadowing(self, tools: list[MCPToolInfo]) -> None:
        """Detect tool shadowing: same tool name from different MCP servers."""
        seen: dict[str, list[int]] = {}
        for i, tool in enumerate(tools):
            seen.setdefault(tool.tool_name, []).append(i)

        for name, indices in seen.items():
            if len(indices) > 1:
                servers = {tools[idx].server_url for idx in indices}
                logger.warning(
                    "MCPProbe: tool shadowing detected — '%s' "
                    "provided by %d servers: %s",
                    name, len(indices), servers,
                )
                for idx in indices:
                    tools[idx].shadowing_detected = True

    def _check_annotation_contradictions(self, tools: list[MCPToolInfo]) -> None:
        """Detect annotation contradictions (readOnlyHint but name implies mutation)."""
        for tool in tools:
            annotations = getattr(tool, 'annotations', {})
            if not annotations:
                continue
            if annotations.get("readOnlyHint") is True:
                # Check if tool name implies mutation
                if any(pattern in tool.tool_name.lower() for pattern in _MUTATION_NAME_PATTERNS):
                    tool.annotation_contradiction = True
                    logger.warning(
                        "MCPProbe: annotation contradiction — '%s' has readOnlyHint "
                        "but name implies mutation",
                        tool.tool_name,
                    )

    @staticmethod
    def _hash_tool(tool_data: dict[str, Any]) -> str:
        """Generate SHA256 hash of tool (name+description+inputSchema)."""
        canonical = json.dumps({
            "name": tool_data.get("name", ""),
            "description": tool_data.get("description", ""),
            "inputSchema": tool_data.get("inputSchema", {}),
        }, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    @staticmethod
    def _hash_instructions(instructions: str) -> str:
        """P0-3-C: SHA256 pin of server instructions (rug-pull detection)."""
        if not instructions:
            return ""
        return hashlib.sha256(instructions.encode()).hexdigest()[:16]

    @staticmethod
    def _extract_injection_surfaces(tool_data: dict[str, Any]) -> list[str]:
        """Extract user-controllable parameters as potential injection surfaces."""
        surfaces: list[str] = []
        input_schema = tool_data.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        required = input_schema.get("required", [])

        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "")
            if prop_type == "string":
                # String parameters are the most likely injection surfaces
                surfaces.append(prop_name)
                if prop_name in required:
                    surfaces[-1] = f"{prop_name} (required)"

        return surfaces

    @staticmethod
    def _scan_threats(tool: MCPToolInfo) -> list[str]:
        """Scan tool for threat patterns using the YARA-style engine (P0-3-B/F)."""
        return scan_mcp_detail(tool.tool_name, tool.description, tool.input_schema)

    @staticmethod
    def _deduplicate_tools(tools: list[MCPToolInfo]) -> list[MCPToolInfo]:
        """Remove duplicate tools (same name + server_url)."""
        seen: set[tuple[str, str]] = set()
        unique: list[MCPToolInfo] = []
        for tool in tools:
            key = (tool.tool_name, tool.server_url)
            if key not in seen:
                seen.add(key)
                unique.append(tool)
        return unique
