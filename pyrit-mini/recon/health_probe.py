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

# Dataclasses split out (SRP) into `recon/_health_models.py`; re-exported so
# `recon.health_probe` and all external importers keep working unchanged.
from recon._health_models import (
    DiscoveredEndpoint,
    HealthEndpointInfo,
    OpenAIValidationResult,
    ServiceProfile,
)

logger = logging.getLogger(__name__)

_TLS_VERIFY = _get_tls_verify_from_config()

# ====================================================================
# Built-in API Wordlist (probing tool, not target-specific)
# ====================================================================

# Auth/credential endpoints — red team high-value targets (401/403 = signal)
# These exist on ~60% of enterprise AI deployments
_AUTH_ENDPOINT_PATHS: list[str] = [
    # Auth flows
    "/auth",
    "/login",
    "/logout",
    "/sso",
    "/sso/callback",
    "/oauth",
    "/oauth/token",
    "/oauth/authorize",
    "/oauth/callback",
    "/token",
    "/token/refresh",
    "/token/revoke",
    "/register",
    "/signup",
    "/password-reset",
    "/api/auth",
    "/api/login",
    "/api/token",
    "/api/v1/auth",
    "/api/v1/token",
    "/api/v1/login",
    "/api/v2/auth",
    "/api/v2/token",
    "/api/v2/login",
    # API key management
    "/api-keys",
    "/api/key",
    "/api/key/rotate",
    "/admin/api-keys",
    "/admin/tokens",
    # JWT/OIDC discovery
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/oauth2/v2.0/authorize",
    "/oauth2/v2.0/token",
    # Session management
    "/session",
    "/sessions",
    "/session/refresh",
    # Admin/management
    "/admin",
    "/admin/login",
    "/admin/dashboard",
    "/management",
    "/management/config",
    # Account/billing (discovered in previous recon analysis)
    "/account",
    "/accounts",
    "/billing",
    "/subscription",
    "/user",
    "/users",
    "/profile",
    "/settings",
    "/team",
    "/organization",
    "/workspace",
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
    # Agent platform flat routes (modern AI agent frameworks)
    "/chat",
    "/upload",
    "/reset",
    "/summarize",
    "/browse",
    "/review",
    "/session/new",
    # Knowledge base routes
    "/kb/topics",
    "/kb/add",
    "/kb/search",
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
                if key.startswith("x-") and key not in ("x-powered-by", "x-ai-backend", "x-rag-provider"):
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
        "model",
        "models",
        "version",
        "status",
        "service",
        "mcp_enabled",
        "rag_enabled",
        "agent_enabled",
        "framework",
        "provider",
        "backend",
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
            async with session.get(
                url, allow_redirects=True, ssl=_TLS_VERIFY, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
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
    stealth_mode: bool = True,
) -> None:
    """Probe multiple health endpoints (generic paths from wordlist).

    Stealth enhancement: When stealth_mode=True, uses sequential probing
    with lognormal-distributed delays to avoid burst detection.

    Args:
        session: aiohttp client session
        base_url: Base URL of target
        profile: ServiceProfile to populate
        max_concurrent: Max concurrent requests (forced to 1 in stealth mode)
        stealth_mode: Enable inter-probe delays

    Returns:
        None (modifies profile in-place)
    """
    # Stealth: sequential probing with delays (avoids burst detection)
    if stealth_mode:
        from recon.stealth_timing import StealthTimer

        timer = StealthTimer(base_delay=3.0, enable_logging=False)

        for path in _HEALTH_ENDPOINT_PATHS:
            await timer.next_request()
            result = await _probe_single_health_endpoint(
                session,
                base_url,
                path,
                asyncio.Semaphore(1),
            )
            if result is not None:
                profile.health_endpoints.append(result)

        timer.log_session_summary()
    else:
        # Legacy burst mode (for CTF / low-security targets)
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = [_probe_single_health_endpoint(session, base_url, path, semaphore) for path in _HEALTH_ENDPOINT_PATHS]
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
    stealth_mode: bool = True,
) -> None:
    """Enumerate API endpoints via wordlist probing.

    Uses HEAD requests to minimize interaction footprint.
    Attack-focused: Captures ALL status codes including 401/403/405
    as they reveal endpoint existence and attack surface.

    Stealth enhancement: When stealth_mode=True, uses sequential probing
    with lognormal-distributed delays to avoid burst detection.

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
        max_concurrent: Max concurrent requests (forced to 1 in stealth mode)
        stealth_mode: Enable inter-probe delays

    Returns:
        None (modifies profile in-place)
    """
    endpoints_to_probe = wordlist or _COMBINED_API_WORDLIST

    async def _probe_one(path: str) -> DiscoveredEndpoint | None:
        url = f"{base_url}{path}"
        try:
            async with session.head(
                url, allow_redirects=True, ssl=_TLS_VERIFY, timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
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

    if stealth_mode:
        # Stealth: sequential probing with lognormal delays
        from recon.stealth_timing import StealthTimer

        timer = StealthTimer(base_delay=2.0, enable_logging=False)

        for path in endpoints_to_probe:
            await timer.next_request()
            result = await _probe_one(path)
            if result is not None:
                profile.discovered_endpoints.append(result)

        timer.log_session_summary()
    else:
        # Legacy burst mode (for CTF / low-security targets)
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _probe_with_sem(path: str) -> DiscoveredEndpoint | None:
            async with semaphore:
                return await _probe_one(path)

        tasks = [_probe_with_sem(path) for path in endpoints_to_probe]
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
        async with session.post(
            url, json=payload, headers=headers, ssl=_TLS_VERIFY, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
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
                        validation.sample_response = {k: v for k, v in list(body.items())[:5]}
                except Exception:
                    logger.debug("Failed to parse OpenAI validation response")

            logger.info(
                "OpenAI validation: compatible=%s, status=%d, path=%s",
                validation.is_compatible,
                resp.status,
                endpoint_path,
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
    stealth_mode: bool = True,
) -> ServiceProfile:
    """Run 4-layer health probe on target AI service with stealth integration.

    Execution order:
        1. Layer 1: HTTP header analysis (passive)
        2. Layer 2: Health endpoint probing (stealth-enhanced)
        3. Layer 3: API wordlist enumeration (stealth-enhanced)
        4. Layer 4: OpenAI validation (active, if enabled)

    Stealth enhancements (stealth_mode=True):
        - Sequential endpoint probing with lognormal-distributed delays
        - Avoids burst patterns that trigger detection systems
        - Maintains full functionality while blending with background traffic

    Constitution Guard Compliance:
        - R-IMPORT-1: Uses aiohttp (not httpx)
        - Fail-safe: All layers independent, failures don't cascade

    Args:
        host: Target host (any IP or FQDN)
        use_tls: Whether to use HTTPS
        api_key: Optional API key for Layer 4
        run_active_validation: Whether to run Layer 4 (active interaction)
        wordlist: Custom API wordlist (None = use built-in)
        max_concurrent: Max concurrent requests (forced to 1 in stealth mode)
        stealth_delay: Pre-probe delay for stealth (seconds)
        stealth_mode: Enable inter-probe stealth timing

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
    # Extended timeout for stealth mode (sequential delays add up)
    effective_timeout = 300 if stealth_mode else 30
    connector = aiohttp.TCPConnector(
        limit=1 if stealth_mode else max_concurrent,
        ssl=_TLS_VERIFY,
    )
    timeout = aiohttp.ClientTimeout(total=effective_timeout)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        # Layer 1: HTTP Header Analysis
        await _analyze_http_headers(session, base_url, profile)

        # Layer 2: Health Endpoint Probing (stealth-enhanced)
        await _probe_health_endpoints(
            session,
            base_url,
            profile,
            stealth_mode=stealth_mode,
        )

        # Layer 3: API Wordlist Enumeration (stealth-enhanced)
        await _enumerate_api_endpoints(
            session,
            base_url,
            profile,
            wordlist,
            max_concurrent=max_concurrent,
            stealth_mode=stealth_mode,
        )

        # === Gap #4: Recursive Endpoint Expansion (after Layer 3) ===
        # Analyze discovered endpoints for version prefixes and API roots,
        # then probe sub-paths to discover deeper attack surface
        if profile.discovered_endpoints:
            try:
                from recon.api.recursive_expander import execute_recursive_expansion

                original_count = len(profile.discovered_endpoints)
                expanded = await execute_recursive_expansion(
                    session,
                    base_url,
                    profile.discovered_endpoints,
                )
                if expanded:
                    # Deduplicate: avoid re-adding already-discovered endpoints
                    existing_paths = {ep.path for ep in profile.discovered_endpoints}
                    new_endpoints = [ep for ep in expanded if ep.path not in existing_paths]
                    profile.discovered_endpoints.extend(new_endpoints)
                    logger.info(
                        "[Gap #4] Recursive expansion: +%d endpoints (from %d initial, %d after dedup)",
                        len(new_endpoints),
                        original_count,
                        len(expanded),
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
        host,
        profile.service_fingerprint,
        len(profile.discovered_endpoints),
        profile.probe_duration_seconds,
    )

    return profile


# ====================================================================
# Backwards Compatibility Aliases
# HealthProbeResult was renamed to ServiceProfile in v2.0 refactoring.
# ====================================================================
HealthProbeResult = ServiceProfile
