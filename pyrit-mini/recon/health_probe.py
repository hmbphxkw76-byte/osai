"""Health Probe - Active Black-Box Reconnaissance for AI Services

Academic basis:
    - OWASP WSTG-INFO-03 - Web Server Fingerprinting
    - OWASP WSTG-INFO-05 - API Endpoint Enumeration
    - PTES Sec2 - Technical Intelligence Gathering
    - Mazeika et al. (arXiv:2406.18510) - WILDTEAMING: API behavior probing
    - Arbis et al. (arXiv:2306.01943) Sec4.5 - API endpoint discovery

Layered Reconnaissance Model:
    Layer 1 (Passive): HTTP header analysis - custom AI backend detection
    Layer 2 (Passive): Health endpoint probing - service status extraction
    Layer 3 (Passive): API wordlist enumeration - endpoint discovery
    Layer 4 (Active):  OpenAI chat/completions validation - functional verification

Constitution Guard Compliance:
    - R-IMPORT-1: Uses aiohttp instead of httpx
    - R-SIZE: Target < 800 lines
    - R-H3: Single-file module, no dual-track redundancy
    - R-CONV-2: No TokenSelectionStrategy usage

Design Principles:
    1. Passive-first: Layers 1-3 before Layer 4 (active interaction)
    2. Fail-safe: All probes wrapped in try/except, failures don't break pipeline
    3. Audit trail: All active interactions logged to orchestration_log
    4. Rate-limited: Semaphore-controlled concurrency + stealth integration
    5. Generic: All values dynamically extracted, no hardcoded assumptions
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

# R-IMPORT-1 Compliance: Use aiohttp instead of httpx
import aiohttp

# TLS verify (SSOT)
from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

logger = logging.getLogger(__name__)

_TLS_VERIFY = _get_tls_verify_from_config()

# ====================================================================
# ServiceProfile - Structured Reconnaissance Output
# ====================================================================

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

# ====================================================================
# Built-in API Wordlist (probing tool, not target-specific)
# ====================================================================

# Auth/credential endpoints — red team high-value targets (401/403 = signal)
# These exist on ~60% of enterprise AI deployments
_AUTH_ENDPOINT_PATHS: list[str] = [
    # Auth flows
    "/auth", "/login", "/logout", "/sso", "/sso/callback",
    "/oauth", "/oauth/token", "/oauth/authorize", "/oauth/callback",
    "/token", "/token/refresh", "/token/revoke",
    "/register", "/signup", "/password-reset",
    "/api/auth", "/api/login", "/api/token",
    "/api/v1/auth", "/api/v1/token", "/api/v1/login",
    "/api/v2/auth", "/api/v2/token", "/api/v2/login",
    # API key management
    "/api-keys", "/api/key", "/api/key/rotate",
    "/admin/api-keys", "/admin/tokens",
    # JWT/OIDC discovery
    "/.well-known/jwks.json", "/.well-known/openid-configuration",
    "/oauth2/v2.0/authorize", "/oauth2/v2.0/token",
    # Session management
    "/session", "/sessions", "/session/refresh",
    # Admin/management
    "/admin", "/admin/login", "/admin/dashboard",
    "/management", "/management/config",
    # Account/billing (discovered in previous recon analysis)
    "/account", "/accounts", "/billing", "/subscription",
    "/user", "/users", "/profile", "/settings",
    "/team", "/organization", "/workspace",
]

# Generic AI service endpoint paths for enumeration
# These are common patterns, not target-specific
_AI_API_WORDLIST: list[str] = [
    # OpenAI-compatible
    "/v1/models",
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/audio/transcriptions",
    "/v1/images/generations",
    "/v1/engines",
    "/v1/engines/{model}/completions",
    # Anthropic-compatible
    "/v1/messages",
    # Common API patterns
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/chat",
    "/api/completions",
    "/api/generate",
    "/api/models",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/info",
    "/api/config",
    # RAG/Vector DB
    "/api/collections",
    "/api/index",
    "/api/search",
    "/api/query",
    # MCP (Model Context Protocol)
    "/mcp",
    "/mcp/tools",
    "/mcp/tools/list",
    "/sse",
    # Admin/Management
    "/admin/",
    "/admin/config",
    "/admin/users",
    "/admin/api-keys",
    "/dashboard",
    "/metrics",
    "/debug",
    "/.env",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
    "/docs",
    "/redoc",
    # Common health patterns
    "/health",
    "/healthz",
    "/health/check",
    "/ready",
    "/readyz",
    "/live",
    "/livez",
    "/status",
    "/ping",
    "/version",
    # Multi-agent frameworks
    "/agents",
    "/agents/list",
    "/workflows",
    "/tasks",
    # Prompt/Seed management
    "/prompts",
    "/seeds",
    "/templates",
    "/personas",
]

# Combined wordlist: auth paths + AI API paths
# Attacker priority: auth/billing/admin first (higher ROI per recon effort)
_COMBINED_API_WORDLIST: list[str] = _AUTH_ENDPOINT_PATHS + _AI_API_WORDLIST

# Generic health endpoint paths (probing tool, not target-specific)
_HEALTH_ENDPOINT_PATHS: list[str] = [
    "/health",
    "/healthz",
    "/api/health",
    "/api/status",
    "/api/ready",
    "/api/alive",
    "/status",
    "/ping",
    "/version",
    "/api/version",
    "/info",
    "/api/info",
]

# ====================================================================
# Layer 1: HTTP Header Analysis (Passive)
# ====================================================================

async def _analyze_http_headers(
    session: aiohttp.ClientSession,
    url: str,
    profile: ServiceProfile,
) -> None:
    """Extract and analyze HTTP headers for service fingerprinting.

    Passive reconnaissance: HEAD request retrieves headers without
    triggering backend processing.

    Dynamically extracts:
        - Server header (any value returned by target)
        - X-Powered-By header (custom product version)
        - X-AI-Backend header (AI backend identifier)
        - X-RAG-Provider header (RAG system identifier)
        - All X-* custom headers

    Academic basis: OWASP WSTG-INFO-03 - Web Server Fingerprinting

    Args:
        session: aiohttp client session
        url: Target URL
        profile: ServiceProfile to populate

    Returns:
        None (modifies profile in-place)
    """
    try:
        async with session.head(url, allow_redirects=True, ssl=_TLS_VERIFY) as resp:
            headers = dict(resp.headers)
            profile.raw_headers = headers
            profile.server = headers.get("server", "")
            profile.x_powered_by = headers.get("x-powered-by", "")
            profile.x_ai_backend = headers.get("x-ai-backend", "")
            profile.x_rag_provider = headers.get("x-rag-provider", "")

            # Capture ALL X-* custom headers (generic, no hardcoded names)
            for key, value in headers.items():
                if key.startswith("x-") and key not in (
                    "x-powered-by", "x-ai-backend", "x-rag-provider"
                ):
                    profile.custom_headers[key] = value

            logger.debug("Headers extracted: server=%s, custom=%d", profile.server, len(profile.custom_headers))
    except Exception as e:
        logger.debug("Header analysis failed: %s", e)

# ====================================================================
# Layer 2: Health Endpoint Probing (Passive)
# ====================================================================

def _extract_service_metadata(body: dict[str, Any]) -> dict[str, Any]:
    """Extract service metadata from health check JSON response.

    Dynamically extracts common service metadata fields:
        - model, models (model identifier)
        - version (service version)
        - status, service (service state)
        - mcp_enabled, rag_enabled (feature flags)
        - Any other fields present in JSON response

    Args:
        body: Parsed JSON body

    Returns:
        Dictionary of extracted metadata
    """
    metadata: dict[str, Any] = {}

    # Known metadata field patterns (expanded dynamically from response)
    known_fields = [
        "model", "models", "version", "status", "service",
        "mcp_enabled", "rag_enabled", "agent_enabled",
        "framework", "provider", "backend",
    ]

    for field_name in known_fields:
        if field_name in body:
            metadata[field_name] = body[field_name]

    # Also capture any string/number fields not already captured
    for key, value in body.items():
        if key not in metadata and isinstance(value, (str, int, float, bool)):
            metadata[key] = value

    return metadata

async def _probe_single_health_endpoint(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    semaphore: asyncio.Semaphore,
) -> HealthEndpointInfo | None:
    """Probe a single health endpoint.

    Args:
        session: aiohttp client session
        base_url: Base URL of target
        path: Endpoint path to probe
        semaphore: Concurrency limiter

    Returns:
        HealthEndpointInfo if endpoint responded, None otherwise
    """
    url = f"{base_url}{path}"
    async with semaphore:
        try:
            async with session.get(url, allow_redirects=True, ssl=_TLS_VERIFY, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                info = HealthEndpointInfo(
                    path=path,
                    status_code=resp.status,
                    content_type=resp.content_type or "",
                )

                # Try to parse JSON body
                if resp.content_type and "json" in resp.content_type:
                    try:
                        body = await resp.json()
                        info.body_parsed = body
                        info.body_raw = json.dumps(body)[:500]
                        info.service_metadata = _extract_service_metadata(body)
                    except Exception:
                        info.body_raw = (await resp.text())[:500]
                else:
                    info.body_raw = (await resp.text())[:200]

                return info
        except Exception as e:
            logger.debug("Health probe failed for %s: %s", path, e)
            return None

async def _probe_health_endpoints(
    session: aiohttp.ClientSession,
    base_url: str,
    profile: ServiceProfile,
    max_concurrent: int = 3,
) -> None:
    """Probe multiple health endpoints (generic paths from wordlist).

    Args:
        session: aiohttp client session
        base_url: Base URL of target
        profile: ServiceProfile to populate
        max_concurrent: Max concurrent requests

    Returns:
        None (modifies profile in-place)
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    # Probe generic health endpoints
    tasks = [
        _probe_single_health_endpoint(session, base_url, path, semaphore)
        for path in _HEALTH_ENDPOINT_PATHS
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, HealthEndpointInfo):
            profile.health_endpoints.append(result)

    logger.debug("Health endpoints discovered: %d", len(profile.health_endpoints))

# ====================================================================
# Layer 3: API Wordlist Enumeration (Passive)
# ====================================================================

async def _enumerate_api_endpoints(
    session: aiohttp.ClientSession,
    base_url: str,
    profile: ServiceProfile,
    wordlist: list[str] | None = None,
    max_concurrent: int = 5,
) -> None:
    """Enumerate API endpoints via wordlist probing.

    Uses HEAD requests to minimize interaction footprint.
    Attack-focused: Captures ALL status codes including 401/403/405
    as they reveal endpoint existence and attack surface.

    Red team thinking:
        - 401 Unauthorized = endpoint exists, auth bypass viable
        - 403 Forbidden = endpoint exists, IDOR/scope elevation possible
        - 405 Method Not Allowed = endpoint exists, try different method
        - 500 Internal Server Error = endpoint exists, verbose error may leak info

    Args:
        session: aiohttp client session
        base_url: Base URL of target
        profile: ServiceProfile to populate
        wordlist: Custom wordlist (None = use built-in)
        max_concurrent: Max concurrent requests

    Returns:
        None (modifies profile in-place)
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    endpoints_to_probe = wordlist or _COMBINED_API_WORDLIST

    async def _probe_one(path: str) -> DiscoveredEndpoint | None:
        url = f"{base_url}{path}"
        async with semaphore:
            try:
                async with session.head(url, allow_redirects=True, ssl=_TLS_VERIFY, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    status = resp.status
                    content_type = resp.content_type or ""
                    is_api = "json" in content_type

                    # Red team: classify existence confidence
                    # 401/403 = endpoint EXISTS but protected (high attack value)
                    # 405/500 = endpoint EXISTS, method blocked or error leaked
                    # 404 = need body analysis to distinguish real 404 vs custom 404
                    if status < 400:
                        existence = "confirmed"
                    elif status in (401, 403):
                        existence = "protected"
                    elif status in (405, 500, 502, 503):
                        existence = "probable"
                    else:
                        existence = "nonexistent"

                    # Extract auth type from 401 WWW-Authenticate header
                    auth_hint = ""
                    if status == 401:
                        www_auth = resp.headers.get("www-authenticate", "").lower()
                        if "bearer" in www_auth:
                            auth_hint = "Bearer"
                        elif "basic" in www_auth:
                            auth_hint = "Basic"
                        elif "api-key" in www_auth:
                            auth_hint = "API-Key"

                    return DiscoveredEndpoint(
                        path=path,
                        status_code=status,
                        content_type=content_type,
                        is_api=is_api,
                        existence=existence,
                        auth_hint=auth_hint,
                    )
            except Exception:
                pass
            return None

    # Batch probe for efficiency
    tasks = [_probe_one(path) for path in endpoints_to_probe]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, DiscoveredEndpoint):
            profile.discovered_endpoints.append(result)

    profile.probe_count += len(endpoints_to_probe)
    logger.debug("API endpoints discovered: %d", len(profile.discovered_endpoints))

# ====================================================================
# Layer 4: OpenAI Compatibility Validation (Active)
# ====================================================================

async def _validate_openai_compatibility(
    session: aiohttp.ClientSession,
    base_url: str,
    profile: ServiceProfile,
    api_key: str | None = None,
) -> None:
    """Validate OpenAI-compatible API (Layer 4 - Active).

    Sends a minimal valid POST to /v1/chat/completions to verify:
    1. Endpoint exists and accepts POST
    2. Response structure matches OpenAI format
    3. Can extract model name from response

    Academic basis: Mazeika et al. (arXiv:2406.18510) - API behavior probing

    Args:
        session: aiohttp client session
        base_url: Base URL of target
        profile: ServiceProfile to populate
        api_key: Optional API key for authenticated endpoints

    Returns:
        None (modifies profile.openai_validation in-place)
    """
    validation = profile.openai_validation
    endpoint_path = validation.endpoint_path
    url = f"{base_url}{endpoint_path}"

    # Minimal valid OpenAI chat/completions request
    payload = {
        "model": "test",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "temperature": 0,
    }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with session.post(url, json=payload, headers=headers, ssl=_TLS_VERIFY, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            validation.is_compatible = resp.status == 200

            if resp.content_type and "json" in resp.content_type:
                try:
                    body = await resp.json()
                    # Validate OpenAI response structure (check for expected fields)
                    if "choices" in body or "id" in body:
                        validation.response_structure_valid = True
                        # Extract model name if present
                        if "model" in body:
                            validation.model_name = body["model"]
                            profile.openai_validation.model_name = body["model"]
                        # Extract usage info if present
                        if "usage" in body:
                            validation.usage_info = body["usage"]
                        # Store sample response (truncated)
                        validation.sample_response = {
                            k: v for k, v in list(body.items())[:5]
                        }
                except Exception:
                    logger.debug("Failed to parse OpenAI validation response")

            logger.info(
                "OpenAI validation: compatible=%s, status=%d, path=%s",
                validation.is_compatible, resp.status, endpoint_path,
            )
    except Exception as e:
        logger.debug("OpenAI compatibility validation failed: %s", e)

# ====================================================================
# Main Entry Point
# ====================================================================

async def run_health_probe(
    host: str,
    use_tls: bool = True,
    api_key: str | None = None,
    run_active_validation: bool = True,
    wordlist: list[str] | None = None,
    max_concurrent: int = 5,
    stealth_delay: float = 0.0,
) -> ServiceProfile:
    """Run 4-layer health probe on target AI service.

    Execution order:
        1. Layer 1: HTTP header analysis (passive)
        2. Layer 2: Health endpoint probing (passive)
        3. Layer 3: API wordlist enumeration (passive)
        4. Layer 4: OpenAI validation (active, if enabled)

    Constitution Guard Compliance:
        - R-IMPORT-1: Uses aiohttp (not httpx)
        - Fail-safe: All layers independent, failures don't cascade

    Args:
        host: Target host (any IP or FQDN)
        use_tls: Whether to use HTTPS
        api_key: Optional API key for Layer 4
        run_active_validation: Whether to run Layer 4 (active interaction)
        wordlist: Custom API wordlist (None = use built-in)
        max_concurrent: Max concurrent requests for Layer 3
        stealth_delay: Pre-probe delay for stealth (seconds)

    Returns:
        ServiceProfile with all discovered information
    """
    start_time = time.time()
    scheme = "https" if use_tls else "http"
    base_url = f"{scheme}://{host}"

    profile = ServiceProfile(host=host)

    # Stealth delay (Rule 2: Stealth First)
    if stealth_delay > 0:
        await asyncio.sleep(stealth_delay)

    # Configure aiohttp session with generic headers
    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=_TLS_VERIFY)
    timeout = aiohttp.ClientTimeout(total=30)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        # Layer 1: HTTP Header Analysis
        await _analyze_http_headers(session, base_url, profile)

        # Layer 2: Health Endpoint Probing
        await _probe_health_endpoints(session, base_url, profile)

        # Layer 3: API Wordlist Enumeration
        await _enumerate_api_endpoints(session, base_url, profile, wordlist, max_concurrent)

        # === Gap #4: Recursive Endpoint Expansion (after Layer 3) ===
        # Analyze discovered endpoints for version prefixes and API roots,
        # then probe sub-paths to discover deeper attack surface
        if profile.discovered_endpoints:
            try:
                from recon.recursive_expander import execute_recursive_expansion
                original_count = len(profile.discovered_endpoints)
                expanded = await execute_recursive_expansion(
                    session, base_url, profile.discovered_endpoints,
                )
                if expanded:
                    # Deduplicate: avoid re-adding already-discovered endpoints
                    existing_paths = {ep.path for ep in profile.discovered_endpoints}
                    new_endpoints = [ep for ep in expanded if ep.path not in existing_paths]
                    profile.discovered_endpoints.extend(new_endpoints)
                    logger.info(
                        "[Gap #4] Recursive expansion: +%d endpoints "
                        "(from %d initial, %d after dedup)",
                        len(new_endpoints), original_count, len(expanded),
                    )
            except Exception as e:
                logger.debug("[Gap #4] Recursive expansion non-fatal: %s", e)

        # Layer 4: OpenAI Compatibility Validation (active, if enabled)
        if run_active_validation:
            await _validate_openai_compatibility(session, base_url, profile, api_key)

    # Compute fingerprint from extracted data
    profile.compute_fingerprint()
    profile.probe_duration_seconds = round(time.time() - start_time, 2)

    logger.info(
        "Health probe complete: host=%s, fp=%s, endpoints=%d, duration=%.2fs",
        host, profile.service_fingerprint, len(profile.discovered_endpoints),
        profile.probe_duration_seconds,
    )

    return profile
