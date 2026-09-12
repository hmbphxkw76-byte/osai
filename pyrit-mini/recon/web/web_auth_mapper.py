"""web_auth_mapper.py - Authentication & Authorization Flow Mapper.

Maps authentication flows, token exchanges, and authorization scopes
to identify bypass opportunities and privilege escalation paths.

Academic basis:
    - OWASP Authorization Bypass
    - Sünnetçi et al. (USENIX 2023) - API authorization state machine bugs
    - Chelle et al. (2022) - OAuth 2.0 security analysis

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — auth flow mapping only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthFlowType(Enum):
    """Authentication flow types."""

    DIRECT_LOGIN = "direct_login"
    OAUTH2_CODE = "oauth2_authorization_code"
    OAUTH2_IMPLICIT = "oauth2_implicit"
    OAUTH2_CLIENT = "oauth2_client_credentials"
    API_KEY = "api_key"
    JWT_EXCHANGE = "jwt_exchange"
    SAML = "saml"
    UNKNOWN = "unknown"


@dataclass
class AuthFlowNode:
    """A node in the authentication flow."""

    name: str
    endpoint: str
    method: str
    requires_auth: bool = False
    produces_token: bool = False
    consumes_token: bool = False
    scopes: list[str] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)


@dataclass
class AuthFlowMap:
    """Complete authentication flow map."""

    flow_type: AuthFlowType
    nodes: list[AuthFlowNode] = field(default_factory=list)
    token_endpoint: str = ""
    scope_enforcement: float = 0.5  # 0.0 (none) to 1.0 (strict)
    bypass_opportunities: list[str] = field(default_factory=list)


class WebAuthMapper:
    """Map authentication and authorization flows."""

    # Indicators for flow classification
    OAUTH2_INDICATORS: list[re.Pattern] = [
        re.compile(r"(?i)/oauth/(?:authorize|token|callback)"),
        re.compile(r"(?i)/auth/(?:code|callback|redirect)"),
        re.compile(r"(?i)response_type=(?:code|token)"),
    ]

    SCOPE_ESCALATION_PATHS: list[str] = [
        "read -> write",
        "user -> admin",
        "readonly -> full",
        "scoped -> global",
    ]

    def __init__(self) -> None:
        self.flow_maps: list[AuthFlowMap] = []

    def map_auth_flow(
        self,
        endpoints: list[dict[str, Any]],
        token_endpoint: str = "",
    ) -> AuthFlowMap:
        """Map authentication flow from endpoint catalog."""
        flow_type = self._classify_flow(endpoints)

        nodes: list[AuthFlowNode] = []
        bypass_ops: list[str] = []

        for ep in endpoints:
            node = AuthFlowNode(
                name=ep.get("name", "unknown"),
                endpoint=ep.get("path", "/"),
                method=ep.get("method", "GET"),
                requires_auth=ep.get("auth_required", False),
                produces_token="token" in ep.get("path", "").lower(),
                consumes_token=ep.get("auth_required", False),
                scopes=ep.get("scopes", []),
            )
            nodes.append(node)

        # Detect bypass opportunities
        for node in nodes:
            if not node.requires_auth and self._is_sensitive_endpoint(node.endpoint):
                bypass_ops.append(f"Unauthenticated access to {node.endpoint}")

        # Check scope enforcement
        scope_enforcement = self._assess_scope_enforcement(nodes)

        flow_map = AuthFlowMap(
            flow_type=flow_type,
            nodes=nodes,
            token_endpoint=token_endpoint,
            scope_enforcement=scope_enforcement,
            bypass_opportunities=bypass_ops,
        )
        self.flow_maps.append(flow_map)
        return flow_map

    def analyze_scope_transitions(self, scopes_available: list[str], scopes_required: list[str]) -> dict[str, Any]:
        """Analyze scope transition opportunities."""
        result: dict[str, Any] = {
            "overprivileged": False,
            "scope_escalation_risk": 0.0,
            "accessible_scopes": scopes_available,
            "unauthorized_scopes": [],
        }

        # Check for scope overprivilege
        for required in scopes_required:
            matching_available = [s for s in scopes_available if required in s or s in required]
            if not matching_available:
                result["unauthorized_scopes"].append(required)

        # Admin scope without proper authorization
        admin_scopes = [s for s in scopes_available if "admin" in s]
        if admin_scopes:
            result["overprivileged"] = True
            result["scope_escalation_risk"] = 0.8

        return result

    def get_auth_summary(self) -> dict[str, Any]:
        """Get mapping summary."""
        if not self.flow_maps:
            return {"flows": 0, "bypass_count": 0}

        total_bypass = sum(len(m.bypass_opportunities) for m in self.flow_maps)
        flow_types = list(set(m.flow_type.value for m in self.flow_maps))

        return {
            "flows": len(self.flow_maps),
            "total_nodes": sum(len(m.nodes) for m in self.flow_maps),
            "bypass_count": total_bypass,
            "flow_types": flow_types,
            "avg_scope_enforcement": round(sum(m.scope_enforcement for m in self.flow_maps) / len(self.flow_maps), 3)
            if self.flow_maps
            else 0.0,
        }

    def _classify_flow(self, endpoints: list[dict[str, Any]]) -> AuthFlowType:
        """Classify the authentication flow type."""
        all_paths = " ".join(ep.get("path", "") for ep in endpoints)

        if any(pattern.search(all_paths) for pattern in self.OAUTH2_INDICATORS):
            if "client_credentials" in all_paths:
                return AuthFlowType.OAUTH2_CLIENT
            if "response_type=code" in all_paths:
                return AuthFlowType.OAUTH2_CODE
            return AuthFlowType.OAUTH2_IMPLICIT

        if "/login" in all_paths and "/token" in all_paths:
            return AuthFlowType.DIRECT_LOGIN

        if "api_key" in all_paths.lower():
            return AuthFlowType.API_KEY

        return AuthFlowType.UNKNOWN

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint is sensitive."""
        sensitive_paths = [
            "/admin",
            "/users",
            "/delete",
            "/update",
            "/config",
            "/export",
            "/import",
            "/secret",
            "/token",
        ]
        return any(sp in path.lower() for sp in sensitive_paths)

    def _assess_scope_enforcement(self, nodes: list[AuthFlowNode]) -> float:
        """Assess scope enforcement strength."""
        if not nodes:
            return 0.5

        unauthenticated = [n for n in nodes if not n.requires_auth]
        sensitive_unauth = [n for n in unauthenticated if self._is_sensitive_endpoint(n.endpoint)]

        if not sensitive_unauth:
            return 0.8  # Good: all sensitive endpoints require auth
        elif len(sensitive_unauth) <= len(nodes) * 0.2:
            return 0.6  # Acceptable: few exceptions
        else:
            return 0.3  # Poor: many unauthenticated sensitive endpoints
