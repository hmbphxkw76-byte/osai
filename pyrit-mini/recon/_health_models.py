"""recon/_health_models — Data models for AI-service health probing.

Extracted from `recon/health_probe.py` (SRP): the structured dataclasses
(`HealthEndpointInfo`, `DiscoveredEndpoint`, `OpenAIValidationResult`,
`ServiceProfile`) are the reconnaissance output contracts, shared by the probe
functions and the downstream phases, so they live in their own dependency-free
module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HealthEndpointInfo:
    """Discovered health/status endpoint information.

    Attributes:
        path: Endpoint path (e.g., "/api/health")
        status_code: HTTP status code
        content_type: Response content type
        body_parsed: Parsed JSON body (if applicable)
        body_raw: Raw response body preview
        service_metadata: Extracted service metadata fields
    """

    path: str
    status_code: int = 200
    content_type: str = ""
    body_parsed: dict[str, Any] = field(default_factory=dict)
    body_raw: str = ""
    service_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveredEndpoint:
    """API endpoint discovered via wordlist enumeration.

    Attack-focused: Existence confidence reflects red team value.
        - confirmed:    2xx response (direct access)
        - protected:    401/403 (endpoint exists, auth bypass viable)
        - probable:     405/500 (method error / verbose error = target exists)
        - nonexistent:  404 with server-specific body pattern

    Attributes:
        path: Endpoint path
        method: HTTP method that returned success
        status_code: HTTP status code
        content_type: Response content type
        is_api: Whether response appears to be API (JSON)
        existence: Existence confidence level (confirmed/protected/probable/nonexistent)
        auth_hint: Auth type detected from 401 WWW-Authenticate header
    """

    path: str
    method: str = "GET"
    status_code: int = 200
    content_type: str = ""
    is_api: bool = False
    existence: str = "confirmed"
    auth_hint: str = ""


@dataclass
class OpenAIValidationResult:
    """OpenAI-compatible API validation result.

    Attributes:
        is_compatible: Whether endpoint appears OpenAI-compatible
        endpoint_path: Path tested (e.g., "/v1/chat/completions")
        model_name: Model name extracted from response if any
        response_structure_valid: Whether response has expected structure
        usage_info: Token usage information if available
        sample_response: Preview of response structure
    """

    is_compatible: bool = False
    endpoint_path: str = "/v1/chat/completions"
    model_name: str = ""
    response_structure_valid: bool = False
    usage_info: dict[str, Any] = field(default_factory=dict)
    sample_response: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceProfile:
    """Complete service reconnaissance profile.

    All fields are dynamically populated from target responses.
    No hardcoded values - adapts to any target service.

    Attributes:
        host: Target host (any IP or FQDN)
        server: Server header value
        x_powered_by: X-Powered-By header value
        x_ai_backend: X-AI-Backend header value (custom AI backend identifier)
        x_rag_provider: X-RAG-Provider header value (RAG system identifier)
        custom_headers: All X-* custom headers detected
        health_endpoints: Discovered health/status endpoints
        discovered_endpoints: API endpoints found via enumeration
        openai_validation: OpenAI compatibility validation result
        service_fingerprint: Computed fingerprint string
        rag_pipeline: RAG pipeline configuration
        raw_headers: Raw HTTP headers from initial probe
        probe_count: Total number of probes executed
        probe_duration_seconds: Total probe duration
    """

    host: str = ""
    server: str = ""
    x_powered_by: str = ""
    x_ai_backend: str = ""
    x_rag_provider: str = ""
    custom_headers: dict[str, str] = field(default_factory=dict)
    health_endpoints: list[HealthEndpointInfo] = field(default_factory=list)
    discovered_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    openai_validation: OpenAIValidationResult = field(default_factory=OpenAIValidationResult)
    service_fingerprint: str = ""
    rag_pipeline: dict[str, Any] = field(default_factory=dict)
    raw_headers: dict[str, str] = field(default_factory=dict)
    probe_count: int = 0
    probe_duration_seconds: float = 0.0

    def compute_fingerprint(self) -> str:
        """Compute service fingerprint from collected attributes.

        Format: "vendor:version:backend_model:rag_provider"

        Returns:
            Computed fingerprint string
        """
        parts: list[str] = []

        # Extract vendor/version from x_powered_by (dynamic, not hardcoded)
        if self.x_powered_by:
            vendor = self.x_powered_by.lower().replace(" ", "_")
            parts.append(vendor)
        elif self.server:
            parts.append(self.server.lower().replace(" ", "_"))
        else:
            parts.append("unknown")

        # AI backend (from header or validation, whatever is available)
        backend = self.x_ai_backend or self.openai_validation.model_name
        if backend:
            parts.append(backend.lower().replace(" ", "_").replace("-", "_"))

        # RAG provider
        if self.x_rag_provider:
            parts.append(self.x_rag_provider.lower().replace(" ", "_"))

        self.service_fingerprint = ":".join(parts) if parts else "unknown"
        return self.service_fingerprint

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for ctx storage.

        Returns:
            Dict representation of service profile
        """
        return {
            "host": self.host,
            "server": self.server,
            "x_powered_by": self.x_powered_by,
            "x_ai_backend": self.x_ai_backend,
            "x_rag_provider": self.x_rag_provider,
            "custom_headers": self.custom_headers,
            "health_endpoints": [
                {"path": h.path, "status": h.status_code, "metadata": h.service_metadata}
                for h in self.health_endpoints
            ],
            "discovered_endpoints": [
                {
                    "path": d.path,
                    "method": d.method,
                    "status": d.status_code,
                    "existence": d.existence,
                    "auth_hint": d.auth_hint,
                }
                for d in self.discovered_endpoints
            ],
            "is_openai_compatible": self.openai_validation.is_compatible,
            "model_name": self.openai_validation.model_name,
            "service_fingerprint": self.service_fingerprint,
            "rag_pipeline": self.rag_pipeline,
            "probe_count": self.probe_count,
            "probe_duration_seconds": self.probe_duration_seconds,
        }
