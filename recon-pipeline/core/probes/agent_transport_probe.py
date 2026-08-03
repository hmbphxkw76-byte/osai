# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Agent Transport Probe — SSE / WebSocket / stdio protocol discovery.

Discovers agent communication transports beyond HTTP:
  1. SSE (Server-Sent Events): Accept: text/event-stream probe
  2. WebSocket: 101 upgrade handshake detection
  3. stdio: subprocess spawn patterns (detected via tool descriptions)

Academic basis:
  - OWASP LLM01: indirect injection via event-stream
  - MCP Protocol Spec (2024-11): transport layer agnostic (stdio + SSE + streamable HTTP)
  - Hou et al. (arXiv:2503.23278): MCP four-phase attack surface across transports

Non-LLM guarantee: HTTP protocol detection only; zero ML dependencies.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# ── SSE probe paths ──
_SSE_PROBE_PATHS: list[str] = [
    "/events",
    "/api/events",
    "/stream",
    "/sse",
    "/api/sse",
    "/v1/stream",
    "/agent/events",
    "/agent/stream",
]

# ── WebSocket probe paths ──
_WS_PROBE_PATHS: list[str] = [
    "/ws",
    "/api/ws",
    "/websocket",
    "/realtime",
    "/socket",
    "/chat/ws",
    "/agent/ws",
]

# ── stdio indicator patterns (from tool descriptions / response bodies) ──
_STDIO_INDICATORS: list[re.Pattern[str]] = [
    re.compile(r"\b(subprocess|spawn|child_process|exec_file)\b", re.I),
    re.compile(r"\b(stdin|stdout|stderr|pipe|stdio)\b", re.I),
    re.compile(r"\b(process\.exec|shell\.exec|os\.exec|sys\.exec)\b", re.I),
]


@dataclass
class TransportDiscovery:
    """Detected agent transport protocol."""

    transport_type: str = ""  # "sse" | "websocket" | "stdio" | "http"
    url: str = ""
    status_code: int | None = None
    evidence: list[str] = field(default_factory=list)
    duration_ms: int = 0
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "transport_type": self.transport_type,
            "url": self.url,
            "status_code": self.status_code,
            "evidence": self.evidence,
            "duration_ms": self.duration_ms,
        }


@dataclass
class TransportDiscoveryResult:
    """Aggregate transport discovery across all candidate endpoints."""

    discoveries: list[TransportDiscovery] = field(default_factory=list)
    sse_count: int = 0
    websocket_count: int = 0
    stdio_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "discoveries": [d.to_dict() for d in self.discoveries],
            "sse_count": self.sse_count,
            "websocket_count": self.websocket_count,
            "stdio_count": self.stdio_count,
            "total": len(self.discoveries),
        }


class AgentTransportProbe(ReconProbe):
    """Agent transport layer discovery probe.

    Discovers SSE, WebSocket, and stdio transports from discovered
    agent endpoints. Complements AgentProbe's HTTP-only probing.

    Usage::
        probe = AgentTransportProbe(timeout=8.0)
        result = await probe.probe(session)
        # result["transports"] → TransportDiscoveryResult
    """

    def __init__(self, timeout: float = 8.0) -> None:
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "AgentTransportProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute transport discovery.

        Args:
            session: Recon session.

        Returns:
            Dict with transports (TransportDiscoveryResult) and summary.
        """
        result = TransportDiscoveryResult()

        # Build base URLs from session endpoints
        from urllib.parse import urlparse

        bases: set[str] = set()
        for ep in session.report.endpoints:
            parsed = urlparse(ep.url)
            if parsed.scheme and parsed.netloc:
                bases.add(f"{parsed.scheme}://{parsed.netloc}")
        if session.target_url:
            bases.add(session.target_url.rstrip("/"))

        headers = session.auth_headers if session.auth_state else {}

        async with httpx.AsyncClient(
            timeout=self._timeout,
            verify=False,
            follow_redirects=False,
        ) as client:
            discoveries = await self._probe_transports(list(bases), headers, client)
            result.discoveries = discoveries

        # Count by type
        for d in result.discoveries:
            if d.transport_type == "sse":
                result.sse_count += 1
            elif d.transport_type == "websocket":
                result.websocket_count += 1
            elif d.transport_type == "stdio":
                result.stdio_count += 1

        # Also scan tool descriptions for stdio indicators
        stdio_from_tools = await self._detect_stdio_from_tools(session)
        result.discoveries.extend(stdio_from_tools)

        # Update counts
        result.sse_count = sum(1 for d in result.discoveries if d.transport_type == "sse")
        result.websocket_count = sum(1 for d in result.discoveries if d.transport_type == "websocket")
        result.stdio_count = sum(1 for d in result.discoveries if d.transport_type == "stdio")

        logger.info(
            "AgentTransportProbe: %d SSE, %d WebSocket, %d stdio",
            result.sse_count, result.websocket_count, result.stdio_count,
        )

        return {
            "transports": result.to_dict(),
            "summary": {
                "sse_count": result.sse_count,
                "websocket_count": result.websocket_count,
                "stdio_count": result.stdio_count,
                "total": len(result.discoveries),
            },
        }

    async def _probe_transports(
        self,
        bases: list[str],
        headers: dict[str, str],
        client: httpx.AsyncClient,
    ) -> list[TransportDiscovery]:
        """Probe SSE and WebSocket endpoints on all base URLs."""
        discoveries: list[TransportDiscovery] = []

        for base in bases:
            # Probes are executed sequentially per base, bases in parallel
            sse_tasks = [self._probe_sse(client, base, path, headers) for path in _SSE_PROBE_PATHS]
            ws_tasks = [self._probe_websocket(client, base, path, headers) for path in _WS_PROBE_PATHS]

            # Run SSE + WS probes in parallel per base
            results: list[TransportDiscovery | None] = list(await asyncio.gather(
                *sse_tasks, *ws_tasks, return_exceptions=True,
            ))

            for r in results:
                if isinstance(r, TransportDiscovery):
                    discoveries.append(r)
                elif isinstance(r, Exception):
                    logger.debug("Transport probe error: %s", r)

        return discoveries

    async def _probe_sse(
        self,
        client: httpx.AsyncClient,
        base: str,
        path: str,
        headers: dict[str, str],
    ) -> TransportDiscovery | None:
        """Probe a single SSE endpoint."""
        url = f"{base.rstrip('/')}{path}"
        t0 = time.monotonic()
        sse_headers = {**headers, "Accept": "text/event-stream"}

        try:
            resp = await client.get(url, headers=sse_headers)
            duration_ms = int((time.monotonic() - t0) * 1000)

            content_type = resp.headers.get("content-type", "")
            is_sse = (
                "text/event-stream" in content_type
                or "data: " in resp.text[:500]
                or "event: " in resp.text[:500]
            )

            if is_sse or resp.status_code == 200:
                return TransportDiscovery(
                    transport_type="sse",
                    url=url,
                    status_code=resp.status_code,
                    evidence=[
                        f"Content-Type: {content_type}",
                        f"status: {resp.status_code}",
                    ],
                    duration_ms=duration_ms,
                )
        except (httpx.RequestError, asyncio.TimeoutError):
            pass

        return None

    async def _probe_websocket(
        self,
        client: httpx.AsyncClient,
        base: str,
        path: str,
        headers: dict[str, str],
    ) -> TransportDiscovery | None:
        """Probe a single WebSocket endpoint."""
        url = f"{base.rstrip('/')}{path}"
        t0 = time.monotonic()
        ws_headers = {
            **headers,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",  # static test key
        }

        try:
            resp = await client.get(url, headers=ws_headers)
            duration_ms = int((time.monotonic() - t0) * 1000)

            is_ws = (
                resp.status_code == 101
                or resp.headers.get("upgrade", "").lower() == "websocket"
                or "sec-websocket-accept" in {k.lower() for k in resp.headers.keys()}
            )

            if is_ws:
                return TransportDiscovery(
                    transport_type="websocket",
                    url=url,
                    status_code=resp.status_code,
                    evidence=[
                        f"status: {resp.status_code}",
                        f"Upgrade: {resp.headers.get('upgrade', '')}",
                    ],
                    duration_ms=duration_ms,
                )
        except (httpx.RequestError, asyncio.TimeoutError):
            pass

        return None

    async def _detect_stdio_from_tools(
        self, session: ReconSession,
    ) -> list[TransportDiscovery]:
        """Detect stdio transport indicators from tool descriptions."""
        discoveries: list[TransportDiscovery] = []

        for tool in session.report.mcp_tools:
            text = f"{tool.tool_name} {tool.description}"
            for pattern in _STDIO_INDICATORS:
                if pattern.search(text):
                    discoveries.append(TransportDiscovery(
                        transport_type="stdio",
                        url=tool.server_url,
                        evidence=[f"Pattern matched: {pattern.pattern} in tool '{tool.tool_name}'"],
                    ))
                    break  # One match per tool is sufficient

        return discoveries
