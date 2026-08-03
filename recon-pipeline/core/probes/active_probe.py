# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Active probe helper for recon-pipeline.

This module provides a small set of proactive reconnaissance steps that can be
used by the pipeline before or after the passive probes run. The goal is to
simulate an orchestrator-style active scan loop without requiring a full browser
automation framework.
"""

from __future__ import annotations

import logging
from typing import Any

from core.probes.ai_signal_catalog import AI_CHAT_PROBE_PATHS, AI_MCP_PROBE_PATHS, AI_OPENAPI_DISCOVERY_PATHS
from core.probes.recon_result import DiscoveredEndpoint, EndpointType

logger = logging.getLogger(__name__)


class ActiveProbeHarness:
    """Generate lightweight active probing candidates from discovered endpoints."""

    def build_candidates(self, endpoints: list[DiscoveredEndpoint]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for endpoint in endpoints:
            base_url = endpoint.url.rstrip("/")
            if endpoint.endpoint_type == EndpointType.MODEL_API:
                for path in AI_CHAT_PROBE_PATHS:
                    candidates.append({"source": endpoint.url, "type": "llm-chat", "url": f"{base_url}{path}"})
                for path in AI_OPENAPI_DISCOVERY_PATHS:
                    candidates.append({"source": endpoint.url, "type": "openapi", "url": f"{base_url}{path}"})
            if endpoint.endpoint_type == EndpointType.MCP_SERVER:
                for path in AI_MCP_PROBE_PATHS:
                    candidates.append({"source": endpoint.url, "type": "mcp", "url": f"{base_url}{path}"})
            if endpoint.endpoint_type == EndpointType.RAG_API:
                candidates.append({"source": endpoint.url, "type": "rag", "url": f"{base_url}/search"})
        return candidates

    def score_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scored: list[dict[str, Any]] = []
        for candidate in candidates:
            weight = 1
            if candidate["type"] == "llm-chat":
                weight = 3
            elif candidate["type"] == "mcp":
                weight = 3
            elif candidate["type"] == "openapi":
                weight = 2
            elif candidate["type"] == "rag":
                weight = 2
            scored.append({**candidate, "priority": weight})
        return sorted(scored, key=lambda item: item["priority"], reverse=True)
