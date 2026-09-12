"""web_api_discoverer.py - API Endpoint Discovery & Cataloging.

Discovers, catalogs, and classifies web API endpoints from various
sources including OpenAPI specs, traffic analysis, and fuzzing.

Academic basis:
    - OWASP API Security Top 10 - Endpoint discovery
    - Gavrichenko et al. (2023) - REST API attack surface mapping
    - Molina et al. (2022) - Automated API documentation analysis

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — API discovery only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HttpMethod(Enum):
    """HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


@dataclass
class ApiEndpoint:
    """Discovered API endpoint."""

    path: str
    method: HttpMethod
    parameters: list[str] = field(default_factory=list)
    auth_required: bool = False
    content_type: str = ""
    risk_tags: list[str] = field(default_factory=list)
    source: str = ""  # openapi, traffic, fuzz, manual


class WebApiDiscoverer:
    """Discover and catalog web API endpoints."""

    # Sensitive operations that warrant extra scrutiny
    SENSITIVE_KEYWORDS: list[str] = [
        "admin",
        "delete",
        "create",
        "update",
        "exec",
        "upload",
        "download",
        "export",
        "import",
        "config",
        "password",
        "token",
        "secret",
        "key",
        "credential",
        "batch",
        "bulk",
        "destroy",
        "purge",
    ]

    # High-risk content types
    HIGH_RISK_CONTENT_TYPES: list[str] = [
        "multipart/form-data",
        "application/x-www-form-urlencoded",
    ]

    def __init__(self) -> None:
        self.endpoints: list[ApiEndpoint] = []

    def discover_from_openapi(self, spec: dict[str, Any]) -> list[ApiEndpoint]:
        """Discover endpoints from OpenAPI specification."""
        endpoints: list[ApiEndpoint] = []

        spec_paths = spec.get("paths", {})
        for path, path_item in spec_paths.items():
            if not isinstance(path_item, dict):
                continue

            for method in ["get", "post", "put", "patch", "delete"]:
                if method.upper() in [m.value for m in HttpMethod] and method in path_item:
                    operation = path_item[method]

                    # Extract parameters
                    params: list[str] = []
                    for param in operation.get("parameters", []):
                        params.append(param.get("name", "unknown"))

                    # Check auth requirements
                    auth_required = "security" in operation or "security" in spec

                    endpoint = ApiEndpoint(
                        path=path,
                        method=HttpMethod(method.upper()),
                        parameters=params,
                        auth_required=auth_required,
                        source="openapi",
                        risk_tags=self._classify_risk_tags(path, method),
                    )
                    endpoints.append(endpoint)

        self.endpoints.extend(endpoints)
        return endpoints

    def discover_from_traffic(self, traffic_log: list[dict[str, str]]) -> list[ApiEndpoint]:
        """Discover endpoints from traffic analysis."""
        endpoints: list[ApiEndpoint] = []

        for entry in traffic_log:
            method = entry.get("method", "GET").upper()
            path = entry.get("path", "/")

            if method in [m.value for m in HttpMethod]:
                endpoint = ApiEndpoint(
                    path=path,
                    method=HttpMethod(method),
                    source="traffic",
                    risk_tags=self._classify_risk_tags(path, method.lower()),
                )
                # Avoid duplicates
                if not any(e.path == path and e.method == endpoint.method for e in endpoints):
                    endpoints.append(endpoint)

        self.endpoints.extend(endpoints)
        return endpoints

    def enumerate_common_endpoints(self, base_url: str, wordlist: list[str] | None = None) -> list[str]:
        """Generate candidate endpoint paths from common patterns."""
        if wordlist is None:
            wordlist = [
                "api",
                "v1",
                "v2",
                "admin",
                "users",
                "auth",
                "login",
                "logout",
                "register",
                "config",
                "status",
                "health",
                "metrics",
                "debug",
                "swagger",
                "docs",
            ]

        candidates: list[str] = []
        for word in wordlist:
            candidates.append(f"{base_url}/{word}")
            candidates.append(f"{base_url}/api/{word}")
            candidates.append(f"{base_url}/v1/{word}")

        return candidates

    def get_high_risk_endpoints(self) -> list[ApiEndpoint]:
        """Get endpoints with high-risk tags."""
        return [e for e in self.endpoints if e.risk_tags]

    def get_discover_summary(self) -> dict[str, Any]:
        """Get discovery summary."""
        if not self.endpoints:
            return {"total": 0, "methods": {}, "high_risk": 0}

        methods: dict[str, int] = {}
        for ep in self.endpoints:
            methods[ep.method.value] = methods.get(ep.method.value, 0) + 1

        return {
            "total": len(self.endpoints),
            "unique_paths": len(set(e.path for e in self.endpoints)),
            "methods": methods,
            "high_risk": len(self.get_high_risk_endpoints()),
            "auth_protected": sum(1 for e in self.endpoints if e.auth_required),
        }

    def _classify_risk_tags(self, path: str, method: str) -> list[str]:
        """Classify endpoint risk tags."""
        tags: list[str] = []
        path_lower = path.lower()

        for keyword in self.SENSITIVE_KEYWORDS:
            if keyword in path_lower:
                tags.append(f"sensitive:{keyword}")

        if method in ("delete", "put", "patch"):
            tags.append("state_changing")

        if "batch" in path_lower or "bulk" in path_lower:
            tags.append("batch_operation")

        if re.search(r"\{.*(?:id|uuid).*\}", path_lower):
            tags.append("parameterized")

        return tags
