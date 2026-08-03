# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""OpenAI-compatible API surface mapping probe.

Systematically probes all OpenAI-compatible API endpoints to determine
the full API surface available on the target platform.

Covers:
  1. Chat Completions (/v1/chat/completions)
  2. Completions (legacy) (/v1/completions)
  3. Embeddings (/v1/embeddings)
  4. Models list (/v1/models)
  5. Moderations (/v1/moderations)
  6. Audio transcriptions (/v1/audio/transcriptions)
  7. Audio translations (/v1/audio/translations)
  8. Images generations (/v1/images/generations)
  9. Files API (/v1/files)
  10. Fine-tuning jobs (/v1/fine_tuning/jobs)
  11. Assistants (/v1/assistants)
  12. Threads (/v1/threads)
  13. Batches (/v1/batches)

Returns a compatibility score (% of endpoints responding with valid
OpenAI-shaped responses vs 404), plus per-endpoint details.

Architecture:
  - Input: auth_state (HTTP headers) + model API base URL
  - Output: openai_compat (score, endpoints, missing, errors)
  - Browser: False (pure HTTP)
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


@dataclass
class OpenAICompatResult:
    """Result of OpenAI API compatibility probe."""

    base_url: str = ""
    compat_score: float = 0.0
    total_endpoints: int = 0
    found: int = 0
    missing: int = 0
    auth_required: int = 0
    error_responses: int = 0
    found_endpoints: list[dict[str, Any]] = field(default_factory=list)
    missing_endpoints: list[str] = field(default_factory=list)
    error_details: list[dict[str, Any]] = field(default_factory=list)
    api_version: str = ""
    openai_org_header: bool = False
    rate_limit_headers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "compat_score": round(self.compat_score, 2),
            "total_endpoints": self.total_endpoints,
            "found": self.found,
            "missing": self.missing,
            "auth_required": self.auth_required,
            "error_responses": self.error_responses,
            "found_endpoints": self.found_endpoints,
            "missing_endpoints": self.missing_endpoints,
            "api_version": self.api_version,
            "openai_org_header": self.openai_org_header,
            "rate_limit_headers": self.rate_limit_headers,
        }


# OpenAI API surface paths — ordered by importance
_OPENAI_API_ENDPOINTS: list[dict[str, Any]] = [
    # Chat — highest priority
    {"path": "/v1/chat/completions", "method": "POST", "body": {"model": "probe", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}, "category": "chat", "weight": 3},
    # Models
    {"path": "/v1/models", "method": "GET", "body": None, "category": "models", "weight": 3},
    # Embeddings
    {"path": "/v1/embeddings", "method": "POST", "body": {"model": "probe", "input": "test"}, "category": "embeddings", "weight": 2},
    # Legacy completions
    {"path": "/v1/completions", "method": "POST", "body": {"model": "probe", "prompt": "hi", "max_tokens": 1}, "category": "completions", "weight": 2},
    # Moderations
    {"path": "/v1/moderations", "method": "POST", "body": {"input": "test"}, "category": "moderations", "weight": 1},
    # Audio
    {"path": "/v1/audio/transcriptions", "method": "POST", "body": None, "category": "audio", "weight": 1},
    {"path": "/v1/audio/translations", "method": "POST", "body": None, "category": "audio", "weight": 1},
    # Images
    {"path": "/v1/images/generations", "method": "POST", "body": {"prompt": "test", "n": 1, "size": "256x256"}, "category": "images", "weight": 1},
    # Files
    {"path": "/v1/files", "method": "GET", "body": None, "category": "files", "weight": 1},
    # Fine-tuning
    {"path": "/v1/fine_tuning/jobs", "method": "GET", "body": None, "category": "fine_tuning", "weight": 1},
    # Assistants (Beta)
    {"path": "/v1/assistants", "method": "GET", "body": None, "category": "assistants", "weight": 1},
    # Threads (Beta)
    {"path": "/v1/threads", "method": "GET", "body": None, "category": "threads", "weight": 1},
    # Batches
    {"path": "/v1/batches", "method": "GET", "body": None, "category": "batches", "weight": 1},
]

# Known error patterns that indicate the endpoint EXISTS but is misconfigured
_KNOWN_ERROR_PATTERNS: list[str] = [
    "invalid_api_key",
    "insufficient_quota",
    "invalid_request_error",
    "authentication_error",
    "rate_limit_exceeded",
    "model_not_found",
    "invalid_model",
    "context_length_exceeded",
    "content_filter",
    "missing_required_parameter",
    "invalid_parameter",
]

# API version headers to check
_VERSION_HEADERS: list[str] = [
    "openai-version",
    "x-api-version",
    "anthropic-version",
    "x-request-id",
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
    "retry-after",
    "x-should-retry",
]


class OpenAICompatProbe(ReconProbe):
    """OpenAI API compatibility surface mapper.

    Systematically probes all OpenAI-compatible endpoints to determine
    the full API surface and compatibility level of the target platform.

    Usage::
        probe = OpenAICompatProbe()
        result = await probe.probe(session)
        # result["openai_compat"] -> OpenAICompatResult
    """

    def __init__(self, timeout: float = 10.0, max_endpoints: int | None = None) -> None:
        self._timeout = timeout
        self._max_endpoints = max_endpoints

    @property
    def name(self) -> str:
        return "OpenAICompatProbe"

    @property
    def requires_browser(self) -> bool:
        return False

    @property
    def requires_auth(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """Execute OpenAI compatibility probe.

        Args:
            session: Recon session.

        Returns:
            Dict with openai_compat key containing OpenAICompatResult.
        """
        # Find base URLs from discovered MODEL_API endpoints
        base_urls = self._extract_base_urls(session)
        if not base_urls:
            logger.warning("OpenAICompatProbe: no model API endpoints found")
            return {"openai_compat": OpenAICompatResult(compat_score=0).to_dict()}

        headers = session.auth_headers if session.auth_state else {}

        # Probe the first base URL (primary target)
        base_url = base_urls[0]
        result = await self._probe_api_surface(base_url, headers)

        logger.info(
            "OpenAICompatProbe: %s compatibility score %.1f%% (%d/%d endpoints)",
            base_url, result.compat_score * 100, result.found, result.total_endpoints,
        )

        return {"openai_compat": result.to_dict()}

    def _extract_base_urls(self, session: ReconSession) -> list[str]:
        """Extract unique base URLs from MODEL_API endpoints."""
        from urllib.parse import urlparse

        from core.models.recon_report import EndpointType

        seen: set[str] = set()
        base_urls: list[str] = []
        for ep in session.report.endpoints:
            if ep.endpoint_type == EndpointType.MODEL_API:
                parsed = urlparse(ep.url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                if base not in seen:
                    seen.add(base)
                    base_urls.append(base)
        return base_urls

    async def _probe_api_surface(
        self, base_url: str, headers: dict[str, str]
    ) -> OpenAICompatResult:
        """Probe all OpenAI API endpoints against a base URL."""
        result = OpenAICompatResult(base_url=base_url)
        endpoints = _OPENAI_API_ENDPOINTS
        if self._max_endpoints:
            endpoints = endpoints[:self._max_endpoints]
        result.total_endpoints = len(endpoints)

        async with httpx.AsyncClient(timeout=self._timeout, verify=False, follow_redirects=False) as client:
            for ep in endpoints:
                path = ep["path"]
                method = ep["method"]
                body = ep["body"]
                category = ep["category"]

                url = f"{base_url.rstrip('/')}{path}"
                endpoint_info = await self._check_endpoint(client, url, method, body, headers, category)

                if endpoint_info["status"] == "found":
                    result.found += 1
                    result.found_endpoints.append(endpoint_info)
                elif endpoint_info["status"] == "auth_required":
                    result.auth_required += 1
                    result.found_endpoints.append(endpoint_info)
                elif endpoint_info["status"] == "error":
                    result.error_responses += 1
                    result.error_details.append(endpoint_info)
                else:
                    result.missing += 1
                    result.missing_endpoints.append(path)

                # Extract version/rate-limit headers from first successful response
                if endpoint_info.get("version_headers"):
                    for h in endpoint_info["version_headers"]:
                        if h not in result.rate_limit_headers:
                            result.rate_limit_headers.append(h)

                if endpoint_info.get("api_version") and not result.api_version:
                    result.api_version = endpoint_info["api_version"]

                if endpoint_info.get("openai_org_header"):
                    result.openai_org_header = True

        # Calculate weighted compatibility score
        total_weight = sum(ep["weight"] for ep in endpoints)
        found_weight = sum(
            ep["weight"] for ep, fi in zip(endpoints, result.found_endpoints)
            if fi["status"] in ("found", "auth_required")
        ) + sum(
            ep["weight"] for ep in endpoints
            if any(d["path"] == ep["path"] and d["status"] in ("found", "auth_required") for d in result.error_details)
        )
        result.compat_score = found_weight / total_weight if total_weight > 0 else 0

        return result

    async def _check_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: dict[str, Any] | None,
        headers: dict[str, str],
        category: str,
    ) -> dict[str, Any]:
        """Check a single API endpoint and classify the response."""
        info: dict[str, Any] = {
            "path": url,
            "method": method,
            "category": category,
            "status": "missing",
            "http_status": None,
            "response_preview": "",
            "error_type": "",
            "api_version": "",
            "openai_org_header": False,
            "version_headers": [],
            "rate_limit_info": {},
        }

        try:
            if method == "POST":
                resp = await client.post(url, json=body, headers=headers)
            else:
                resp = await client.get(url, headers=headers)

            info["http_status"] = resp.status_code

            # Extract version headers
            for h_name in _VERSION_HEADERS:
                if h_name in resp.headers:
                    value = resp.headers[h_name]
                    info["version_headers"].append(f"{h_name}: {value}")
                    if h_name == "openai-version" and not info["api_version"]:
                        info["api_version"] = value
                    if "ratelimit" in h_name.lower():
                        info["rate_limit_info"][h_name] = value

            # Check for OpenAI-Organization header
            if "openai-organization" in resp.headers:
                info["openai_org_header"] = True

            # Classify response
            if resp.status_code == 404:
                info["status"] = "missing"
            elif resp.status_code in (401, 403):
                info["status"] = "auth_required"
                info["error_type"] = "authentication_required"
                info["response_preview"] = resp.text[:200]
            elif resp.status_code == 200:
                info["status"] = "found"
                try:
                    data = resp.json()
                    info["response_preview"] = json.dumps(data)[:200]
                except json.JSONDecodeError:
                    info["response_preview"] = resp.text[:200]
            elif resp.status_code == 400:
                # Check if it's an OpenAI-shaped error (endpoint exists)
                try:
                    data = resp.json()
                    error = data.get("error", {})
                    error_type = error.get("type", "")
                    error_message = error.get("message", "")
                    info["error_type"] = error_type
                    info["response_preview"] = error_message[:200]

                    if any(pattern in error_type.lower() or pattern in error_message.lower()
                           for pattern in _KNOWN_ERROR_PATTERNS):
                        info["status"] = "found"  # Endpoint exists but has an error
                    else:
                        info["status"] = "error"
                except json.JSONDecodeError:
                    info["status"] = "error"
                    info["response_preview"] = resp.text[:200]
            elif resp.status_code == 429:
                info["status"] = "found"  # Rate limited = endpoint exists
                info["error_type"] = "rate_limited"
                info["response_preview"] = resp.text[:200]
            else:
                info["status"] = "error"
                info["response_preview"] = resp.text[:200]

        except (httpx.RequestError, asyncio.TimeoutError) as e:
            info["status"] = "error"
            info["error_type"] = type(e).__name__
            info["response_preview"] = str(e)[:200]

        return info
