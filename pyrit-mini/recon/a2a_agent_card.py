# Google A2A Protocol - Agent Card Data Model
# Reference: https://a2a-protocol.org/latest/specification/
# arXiv:2407.16924 - Eidam et al., A2A trust chain attacks
"""a2a_agent_card - Agent Card data model and parser for A2A protocol discovery.

Implements Google A2A specification v2.0 Agent Card parsing:
    - Agent identity (name, description, version)
    - Capabilities (streaming, push notifications, state transition history)
    - Skills (name, description, tags, examples, input/output modes)
    - Security schemes (API key, OAuth2, OpenID Connect, mTLS)
    - Transport protocols (JSON-RPC, gRPC, HTTP+JSON/REST)

Design principles:
    1. Strict schema validation with safe degradation
    2. Async-friendly with aiohttp
    3. TLS verification via config_loader SSOT
    4. No external dependencies beyond aiohttp + stdlib

R2 (PyRIT Native First): Uses aiohttp for HTTP requests
R6 Sec6.4: A2A protocol discovery for attack surface mapping
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# A2A Agent Card default paths (Google A2A spec)
_A2A_DEFAULT_PATHS = [
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
    "/agent-card",
    "/agent.json",
    "/api/agent-card",
    "/v1/agent-card",
]

# A2A Transport protocols
_A2A_TRANSPORTS = {
    "JSON-RPC": "jsonrpc",
    "grpc": "grpc",
    "HTTP+JSON/REST": "http_json",
}


@dataclass
class AgentSkill:
    """A2A Agent Skill definition.

    Reference: https://a2a-protocol.org/latest/specification/#agent-card
    """
    name: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    input_modes: list[str] = field(default_factory=lambda: ["text"])
    output_modes: list[str] = field(default_factory=lambda: ["text"])
    security: list[dict[str, list[str]]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentSkill:
        """Parse AgentSkill from JSON dict with safe defaults."""
        return cls(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            tags=list(data.get("tags", [])),
            examples=list(data.get("examples", [])),
            input_modes=list(data.get("inputModes", data.get("input_modes", ["text"]))),
            output_modes=list(data.get("outputModes", data.get("output_modes", ["text"]))),
            security=list(data.get("security", [])),
        )


@dataclass
class AgentProvider:
    """A2A Agent Provider information."""
    organization: str = ""
    url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentProvider:
        return cls(
            organization=str(data.get("organization", "")),
            url=str(data.get("url", "")),
        )


@dataclass
class AgentCard:
    """A2A Agent Card - complete agent metadata.

    Reference: https://a2a-protocol.org/latest/specification/#agent-card

    Attributes:
        name: Agent name
        description: Agent description
        url: Agent endpoint URL
        version: Agent version
        provider: Provider information
        capabilities: Supported capabilities
        skills: List of agent skills
        default_input_modes: Default input modes
        default_output_modes: Default output modes
        security_schemes: Security scheme definitions
        security: Security requirements
        documentation_url: External documentation URL
        icon_url: Agent icon URL
        preferred_transport: Preferred transport protocol
        protocol_version: A2A protocol version
        raw_data: Original JSON data
    """
    name: str = ""
    description: str = ""
    url: str = ""
    version: str = "1.0.0"
    provider: Optional[AgentProvider] = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    skills: list[AgentSkill] = field(default_factory=list)
    default_input_modes: list[str] = field(default_factory=lambda: ["text"])
    default_output_modes: list[str] = field(default_factory=lambda: ["text"])
    security_schemes: dict[str, Any] = field(default_factory=dict)
    security: list[list[str]] = field(default_factory=list)
    documentation_url: str = ""
    icon_url: str = ""
    preferred_transport: str = "JSON-RPC"
    protocol_version: str = "2.0"
    raw_data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCard:
        """Parse AgentCard from JSON dict with safe degradation.

        Handles missing fields gracefully - all fields have safe defaults.
        """
        # Parse skills
        skills_data = data.get("skills", [])
        skills = [AgentSkill.from_dict(s) for s in skills_data] if skills_data else []

        # Parse provider
        provider_data = data.get("provider")
        provider = AgentProvider.from_dict(provider_data) if provider_data else None

        return cls(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            url=str(data.get("url", "")),
            version=str(data.get("version", "1.0.0")),
            provider=provider,
            capabilities=dict(data.get("capabilities", {})),
            skills=skills,
            default_input_modes=list(data.get("defaultInputModes", data.get("default_input_modes", ["text"]))),
            default_output_modes=list(data.get("defaultOutputModes", data.get("default_output_modes", ["text"]))),
            security_schemes=dict(data.get("securitySchemes", data.get("security_schemes", {}))),
            security=list(data.get("security", [])),
            documentation_url=str(data.get("documentationUrl", data.get("documentation_url", ""))),
            icon_url=str(data.get("iconUrl", data.get("icon_url", ""))),
            preferred_transport=str(data.get("preferredTransport", data.get("preferred_transport", "JSON-RPC"))),
            protocol_version=str(data.get("protocolVersion", data.get("protocol_version", "2.0"))),
            raw_data=data,
        )

    @property
    def has_streaming(self) -> bool:
        """Check if agent supports streaming capability."""
        return bool(self.capabilities.get("streaming", False))

    @property
    def has_push_notifications(self) -> bool:
        """Check if agent supports push notifications."""
        return bool(self.capabilities.get("pushNotifications", False))

    @property
    def has_state_history(self) -> bool:
        """Check if agent supports state transition history."""
        return bool(self.capabilities.get("stateTransitionHistory", False))

    @property
    def skill_names(self) -> list[str]:
        """Get list of skill names."""
        return [s.name for s in self.skills]

    @property
    def skill_tags(self) -> list[str]:
        """Get flattened list of all skill tags."""
        tags = []
        for skill in self.skills:
            tags.extend(skill.tags)
        return list(set(tags))

    @property
    def security_scheme_types(self) -> list[str]:
        """Get list of security scheme types."""
        return list(self.security_schemes.keys())

    @property
    def is_authenticated(self) -> bool:
        """Check if agent requires authentication."""
        return bool(self.security and self.security_schemes)

    def get_skill_by_name(self, name: str) -> Optional[AgentSkill]:
        """Find skill by name (case-insensitive)."""
        for skill in self.skills:
            if skill.name.lower() == name.lower():
                return skill
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "version": self.version,
            "provider": {"organization": self.provider.organization, "url": self.provider.url} if self.provider else None,
            "capabilities": self.capabilities,
            "skills": [
                {
                    "name": s.name,
                    "description": s.description,
                    "tags": s.tags,
                    "examples": s.examples,
                }
                for s in self.skills
            ],
            "default_input_modes": self.default_input_modes,
            "default_output_modes": self.default_output_modes,
            "security_schemes": self.security_schemes,
            "security": self.security,
            "preferred_transport": self.preferred_transport,
            "protocol_version": self.protocol_version,
        }


async def fetch_agent_card(
    base_url: str,
    timeout: float = 10.0,
    paths: Optional[list[str]] = None,
) -> Optional[AgentCard]:
    """Fetch Agent Card from A2A-compatible endpoint.

    Tries multiple default paths per Google A2A specification.

    Args:
        base_url: Base URL of the agent endpoint
        timeout: Request timeout in seconds
        paths: Custom paths to try (defaults to _A2A_DEFAULT_PATHS)

    Returns:
        AgentCard if found, None otherwise

    Example:
        card = await fetch_agent_card("https://agent.example.com")
        if card:
            print(f"Agent: {card.name}, Skills: {card.skill_names}")
    """
    import aiohttp

    from recon.config_loader import get_tls_verify

    verify = get_tls_verify()
    paths = paths or _A2A_DEFAULT_PATHS

    # Normalize base URL
    base_url = base_url.rstrip("/")

    for path in paths:
        url = f"{base_url}{path}"
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url, ssl=verify) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        if isinstance(data, dict):
                            card = AgentCard.from_dict(data)
                            card.url = base_url
                            logger.info(
                                "A2A Agent Card found at %s: %s (v%s)",
                                url, card.name, card.version,
                            )
                            return card
        except aiohttp.ClientError as e:
            logger.debug("A2A Agent Card fetch failed for %s: %s", url, e)
        except Exception as e:
            logger.debug("Unexpected error fetching Agent Card from %s: %s", url, e)

    logger.debug("No A2A Agent Card found at %s", base_url)
    return None


async def parse_agent_card_from_response(
    response_data: dict[str, Any],
    source_url: str = "",
) -> Optional[AgentCard]:
    """Parse Agent Card from HTTP response data.

    Args:
        response_data: JSON response data
        source_url: Source URL for reference

    Returns:
        AgentCard if valid, None otherwise
    """
    if not isinstance(response_data, dict):
        return None

    # Validate minimum required fields (name should be present)
    if "name" not in response_data:
        logger.debug("Response missing 'name' field, not a valid Agent Card")
        return None

    card = AgentCard.from_dict(response_data)
    if source_url:
        card.url = source_url
    return card


def get_a2a_default_paths() -> list[str]:
    """Get default A2A Agent Card discovery paths.

    Reference: https://a2a-protocol.org/latest/specification/#agent-card-discovery
    """
    return list(_A2A_DEFAULT_PATHS)
