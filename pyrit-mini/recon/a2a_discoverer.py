# Google A2A Protocol - Deep Discovery & Topology Probing
# Reference: https://a2a-protocol.org/latest/specification/
# arXiv:2407.16924 - Eidam et al., A2A trust chain attacks
"""a2a_discoverer - A2A protocol deep discovery and topology probing.

Implements A2A protocol discovery beyond Agent Card parsing:
    1. Endpoint Discovery: Find A2A endpoints from HTTP headers, Agent Card, OpenAPI specs
    2. Method Enumeration: Probe JSON-RPC methods (tasks/send, tasks/get, etc.)
    3. Multi-Agent Topology: Discover connected agents and trust relationships
    4. Transport Detection: Identify supported transports (JSON-RPC, gRPC, HTTP+JSON)

Design principles:
    1. Black-box probing via HTTP (no agent installation required)
    2. Safe degradation when A2A not detected
    3. Reusable results for capability_probe and endpoint_sorter
    4. No external dependencies beyond aiohttp + a2a_agent_card

R2 (PyRIT Native First): Uses aiohttp for HTTP requests
R6 Sec6.4: A2A protocol discovery for attack surface mapping
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from recon.a2a_agent_card import AgentCard, fetch_agent_card

logger = logging.getLogger(__name__)

# A2A JSON-RPC method names (Google A2A spec v2.0)
_A2A_JSONRPC_METHODS = [
    "tasks/send",
    "tasks/get",
    "tasks/cancel",
    "tasks/sendSubscribe",
    "tasks/sendUnsubscribe",
    "tasks/resubscribe",
    "message/send",
    "message/stream",
]

# HTTP headers that indicate A2A support
_A2A_INDICATOR_HEADERS = [
    "x-a2a-version",
    "x-a2a-protocol",
    "x-agent-protocol",
    "x-jsonrpc-version",
]

# Response body patterns that indicate A2A support
_A2A_INDICATOR_PATTERNS = [
    '"jsonrpc"',
    '"taskId"',
    '"agentId"',
    '"messageId"',
    '"parts"',
    '"kind":"task"',
    '"status":"completed"',
]


@dataclass
class A2AEndpoint:
    """Discovered A2A endpoint information."""
    url: str
    transport: str = "JSON-RPC"
    methods: list[str] = field(default_factory=list)
    supports_streaming: bool = False
    agent_card_url: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0  # 0.0-1.0 discovery confidence


@dataclass
class AgentTopologyNode:
    """Node in multi-agent topology graph."""
    agent_id: str
    url: str
    name: str = ""
    skills: list[str] = field(default_factory=list)
    trusted_peers: list[str] = field(default_factory=list)
    trust_level: str = "unknown"  # unauthenticated, basic, full_access


@dataclass
class DiscoveryResult:
    """Complete A2A discovery result."""
    base_url: str
    a2a_detected: bool = False
    endpoints: list[A2AEndpoint] = field(default_factory=list)
    agent_card: Optional[AgentCard] = None
    topology_nodes: list[AgentTopologyNode] = field(default_factory=list)
    trust_relationships: list[dict[str, Any]] = field(default_factory=list)
    raw_findings: dict[str, Any] = field(default_factory=dict)

    @property
    def primary_endpoint(self) -> Optional[A2AEndpoint]:
        """Get primary (highest confidence) endpoint."""
        if not self.endpoints:
            return None
        return max(self.endpoints, key=lambda e: e.confidence)

    @property
    def jsonrpc_methods(self) -> list[str]:
        """Get all discovered JSON-RPC methods."""
        methods = []
        for ep in self.endpoints:
            methods.extend(ep.methods)
        return list(set(methods))

    @property
    def is_multi_agent(self) -> bool:
        """Check if topology indicates multi-agent system."""
        return len(self.topology_nodes) > 1 or len(self.trust_relationships) > 0


async def discover_a2a_endpoints(
    base_url: str,
    timeout: float = 10.0,
) -> list[A2AEndpoint]:
    """Discover A2A endpoints from base URL.

    Probes common A2A endpoint paths and headers.

    Args:
        base_url: Base URL to probe
        timeout: Request timeout in seconds

    Returns:
        List of discovered A2AEndpoint objects
    """
    import aiohttp

    from recon.config_loader import get_tls_verify

    verify = get_tls_verify()
    endpoints: list[A2AEndpoint] = []

    # Common A2A endpoint paths
    a2a_paths = [
        "/",
        "/a2a",
        "/api/a2a",
        "/v1/a2a",
        "/jsonrpc",
        "/api/jsonrpc",
        "/rpc",
        "/api/rpc",
    ]

    base_url = base_url.rstrip("/")

    for path in a2a_paths:
        url = f"{base_url}{path}"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url, ssl=verify) as response:
                    headers = dict(response.headers)
                    body = await response.text()

                    # Check for A2A indicators
                    endpoint = _check_a2a_indicators(url, headers, body)
                    if endpoint:
                        endpoints.append(endpoint)

        except aiohttp.ClientError:
            pass
        except Exception as e:
            logger.debug("Error probing %s: %s", url, e)

    return endpoints


def _check_a2a_indicators(
    url: str,
    headers: dict[str, Any],
    body: str,
) -> Optional[A2AEndpoint]:
    """Check if response indicates A2A support."""
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check headers
    for header in _A2A_INDICATOR_HEADERS:
        if header in headers_lower:
            return A2AEndpoint(
                url=url,
                response_headers=dict(headers),
                confidence=0.7,
            )

    # Check body patterns
    body_lower = body.lower()
    for pattern in _A2A_INDICATOR_PATTERNS:
        if pattern.lower() in body_lower:
            return A2AEndpoint(
                url=url,
                response_headers=dict(headers),
                confidence=0.5,
            )

    return None


async def enumerate_jsonrpc_methods(
    endpoint_url: str,
    timeout: float = 10.0,
) -> list[str]:
    """Enumerate supported JSON-RPC methods via A2A protocol probing.

    Sends minimal JSON-RPC requests to discover supported methods.

    Args:
        endpoint_url: A2A endpoint URL
        timeout: Request timeout in seconds

    Returns:
        List of supported method names
    """
    import aiohttp

    from recon.config_loader import get_tls_verify

    verify = get_tls_verify()
    supported_methods: list[str] = []

    base_request = {
        "jsonrpc": "2.0",
        "id": "discovery-probe",
        "method": "",
        "params": {},
    }

    for method in _A2A_JSONRPC_METHODS:
        try:
            request_body = {**base_request, "method": method}
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.post(
                    endpoint_url,
                    json=request_body,
                    ssl=verify,
                    headers={"Content-Type": "application/json"},
                ) as response:
                    # Any response (including error) indicates method exists
                    if response.status < 500:
                        body = await response.text()
                        if body:
                            supported_methods.append(method)
        except aiohttp.ClientError:
            pass
        except Exception as e:
            logger.debug("JSON-RPC probe error for %s: %s", method, e)

    return supported_methods


async def discover_agent_topology(
    base_url: str,
    agent_card: Optional[AgentCard] = None,
    timeout: float = 10.0,
) -> list[AgentTopologyNode]:
    """Discover multi-agent topology from Agent Card and endpoint probing.

    Extracts connected agents, trusted peers, and trust relationships.

    Args:
        base_url: Base URL of the primary agent
        agent_card: Parsed AgentCard (if already fetched)
        timeout: Request timeout in seconds

    Returns:
        List of AgentTopologyNode objects
    """
    from recon.config_loader import get_tls_verify

    get_tls_verify()  # Ensure config loaded
    nodes: list[AgentTopologyNode] = []

    # If no agent card provided, try to fetch
    if agent_card is None:
        agent_card = await fetch_agent_card(base_url, timeout=timeout)

    if not agent_card:
        return nodes

    # Create primary node
    primary_node = AgentTopologyNode(
        agent_id=agent_card.url or base_url,
        url=agent_card.url or base_url,
        name=agent_card.name,
        skills=agent_card.skill_names,
        trust_level="unauthenticated",
    )

    # Infer trust from security schemes
    if agent_card.is_authenticated:
        primary_node.trust_level = "basic"

    nodes.append(primary_node)

    # Check skills for peer agent references
    for skill in agent_card.skills:
        # Look for peer agent indicators in skill tags
        for tag in skill.tags:
            if "agent" in tag.lower() or "peer" in tag.lower():
                peer_node = AgentTopologyNode(
                    agent_id=f"peer-{skill.name}",
                    url="",  # Unknown URL
                    name=skill.name,
                    skills=[skill.name],
                    trust_level="unknown",
                )
                nodes.append(peer_node)
                primary_node.trusted_peers.append(peer_node.agent_id)

    # Check provider URL for organization-level topology
    if agent_card.provider and agent_card.provider.url:
        provider_node = AgentTopologyNode(
            agent_id=f"provider-{agent_card.provider.organization}",
            url=agent_card.provider.url,
            name=agent_card.provider.organization,
            skills=["provider"],
            trust_level="organization",
        )
        nodes.append(provider_node)

    return nodes


async def run_a2a_discovery(
    base_url: str,
    timeout: float = 15.0,
) -> DiscoveryResult:
    """Run complete A2A discovery pipeline.

    Combines endpoint discovery, method enumeration, and topology discovery.

    Args:
        base_url: Target base URL
        timeout: Overall timeout in seconds

    Returns:
        DiscoveryResult with all findings
    """
    result = DiscoveryResult(base_url=base_url)

    # Step 1: Try to fetch Agent Card
    logger.info("Starting A2A discovery for %s", base_url)
    agent_card = await fetch_agent_card(base_url, timeout=timeout)
    if agent_card:
        result.agent_card = agent_card
        result.a2a_detected = True
        logger.info(
            "Agent Card found: %s (v%s) with %d skills",
            agent_card.name,
            agent_card.version,
            len(agent_card.skills),
        )

        # Add Agent Card URL as endpoint
        endpoint = A2AEndpoint(
            url=agent_card.url or base_url,
            transport=agent_card.preferred_transport,
            agent_card_url=base_url + "/.well-known/agent-card.json",
            confidence=0.9,
        )
        result.endpoints.append(endpoint)

    # Step 2: Discover additional endpoints
    additional_endpoints = await discover_a2a_endpoints(base_url, timeout=timeout)
    for ep in additional_endpoints:
        if not any(e.url == ep.url for e in result.endpoints):
            result.endpoints.append(ep)
            result.a2a_detected = True

    # Step 3: Enumerate JSON-RPC methods on primary endpoint
    primary = result.primary_endpoint
    if primary:
        methods = await enumerate_jsonrpc_methods(primary.url, timeout=timeout)
        primary.methods = methods
        if methods:
            logger.info("Found %d JSON-RPC methods at %s", len(methods), primary.url)

    # Step 4: Discover topology
    topology_nodes = await discover_agent_topology(
        base_url, agent_card=agent_card, timeout=timeout,
    )
    result.topology_nodes = topology_nodes
    if result.is_multi_agent:
        logger.info(
            "Multi-agent topology detected: %d nodes",
            len(topology_nodes),
        )

    # Extract trust relationships
    result.trust_relationships = _extract_trust_relationships(result)

    return result


def _extract_trust_relationships(result: DiscoveryResult) -> list[dict[str, Any]]:
    """Extract trust relationships from discovery results."""
    relationships = []

    for node in result.topology_nodes:
        for peer_id in node.trusted_peers:
            relationships.append({
                "source": node.agent_id,
                "target": peer_id,
                "trust_level": node.trust_level,
                "type": "peer_trust",
            })

    return relationships
