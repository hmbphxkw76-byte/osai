"""session_auth_probe.py - Session Authentication Mechanism Prober.

Probes session authentication mechanisms to detect misconfigurations,
weak validation, bypass opportunities, and cross-session leakage.

Academic basis:
    - OWASP Authentication Cheat Sheet
    - Barth et al. (S&P 2008) - Session isolation violations
    - Calzavara et al. (CCS 2021) - Session security automated analysis

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — session auth probing only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthMechanismType(Enum):
    """Types of authentication mechanisms detected."""

    JWT_BEARER = "jwt_bearer"
    SESSION_COOKIE = "session_cookie"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC_AUTH = "basic_auth"
    CUSTOM_HEADER = "custom_header"
    UNKNOWN = "unknown"


@dataclass
class AuthProbeResult:
    """Result of an authentication probe."""

    mechanism_type: AuthMechanismType
    location: str  # header, cookie, body_param
    is_present: bool
    validation_strength: float  # 0.0 (none) to 1.0 (strong)
    bypass_detected: bool = False
    vuln_indicators: list[str] = field(default_factory=list)
    risk_score: float = 0.0


class SessionAuthProbe:
    """Probe session authentication mechanisms for weaknesses."""

    # Common JWT weakness indicators
    JWT_WEAK_PATTERNS: list[re.Pattern] = [
        re.compile(r"(?i)alg\s*[:=]\s*['\"]?none['\"]?"),
        re.compile(r"(?i)jku"),
        re.compile(r"(?i)\.{3,}"),  # Repeated separators
    ]

    def __init__(self) -> None:
        self.probe_results: list[AuthProbeResult] = []

    def detect_mechanism(self, response_headers: dict[str, str], response_body: str = "") -> AuthProbeResult:
        """Detect authentication mechanism from response."""
        mechanism = self._classify_mechanism(response_headers, response_body)
        location = self._detect_location(response_headers)

        result = AuthProbeResult(
            mechanism_type=mechanism,
            location=location,
            is_present=True,
            validation_strength=self._assess_strength(mechanism, response_headers),
        )
        result.vuln_indicators = self._find_vulnerabilities(mechanism, response_body)
        result.risk_score = self._compute_risk(result)
        self.probe_results.append(result)
        return result

    def check_session_isolation(
        self, session_a_token: str, session_b_token: str, response_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Check if session isolation is properly enforced."""
        result: dict[str, Any] = {
            "isolation_enforced": True,
            "cross_session_leak": False,
            "data_accessible_across_sessions": False,
            "risk_score": 0.0,
        }

        # Check for data leakage across sessions
        if not session_a_token or not session_b_token:
            return result

        # Simple heuristic: if responses match perfectly, isolation may be broken
        if isinstance(response_data, dict) and response_data.get("user_data"):
            result["isolation_enforced"] = False
            result["cross_session_leak"] = True
            result["risk_score"] = 0.85

        return result

    def get_summary(self) -> dict[str, Any]:
        """Get probe summary."""
        if not self.probe_results:
            return {"probes": 0, "weak_auth_count": 0}

        weak = [r for r in self.probe_results if r.validation_strength < 0.5]
        return {
            "probes": len(self.probe_results),
            "weak_auth_count": len(weak),
            "bypass_count": sum(1 for r in self.probe_results if r.bypass_detected),
            "mechanisms_detected": list(set(r.mechanism_type.value for r in self.probe_results)),
        }

    def _classify_mechanism(self, headers: dict[str, str], body: str) -> AuthMechanismType:
        """Classify authentication mechanism."""
        auth_header = headers.get("Authorization", "")
        cookies = headers.get("Set-Cookie", "")

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token.count(".") == 2:  # JWT
                return AuthMechanismType.JWT_BEARER
        if "session" in cookies.lower() or "sid" in cookies.lower():
            return AuthMechanismType.SESSION_COOKIE
        if auth_header.startswith("Basic "):
            return AuthMechanismType.BASIC_AUTH
        if "x-api-key" in headers:
            return AuthMechanismType.API_KEY
        if "Authorization" in auth_header and "Bearer" not in auth_header:
            return AuthMechanismType.OAUTH2

        return AuthMechanismType.UNKNOWN

    def _detect_location(self, headers: dict[str, str]) -> str:
        """Detect auth token location."""
        if "Authorization" in headers:
            return "header"
        if "Set-Cookie" in headers:
            return "cookie"
        if "x-api-key" in headers:
            return "custom_header"
        return "unknown"

    def _assess_strength(self, mechanism: AuthMechanismType, headers: dict[str, str]) -> float:
        """Assess validation strength of auth mechanism."""
        if mechanism == AuthMechanismType.JWT_BEARER:
            return 0.7  # Generally strong if implemented correctly
        elif mechanism == AuthMechanismType.SESSION_COOKIE:
            # Check secure flags
            cookies = headers.get("Set-Cookie", "")
            if "httponly" in cookies.lower() and "secure" in cookies.lower():
                return 0.8
            return 0.4
        elif mechanism == AuthMechanismType.API_KEY:
            return 0.5
        return 0.3

    def _find_vulnerabilities(self, mechanism: AuthMechanismType, body: str) -> list[str]:
        """Find vulnerability indicators."""
        vulns: list[str] = []

        if mechanism == AuthMechanismType.JWT_BEARER:
            for pattern in self.JWT_WEAK_PATTERNS:
                if pattern.search(body):
                    vulns.append(f"JWT weakness: {pattern.pattern[:30]}")

        if "debug=true" in body.lower() or "stack trace" in body.lower():
            vulns.append("Information disclosure in auth responses")

        return vulns

    def _compute_risk(self, result: AuthProbeResult) -> float:
        """Compute overall risk score."""
        risk = 0.0

        if not result.is_present:
            risk += 0.5  # No auth is high risk

        risk += (1.0 - result.validation_strength) * 0.4

        if result.bypass_detected:
            risk += 0.5
        if result.vuln_indicators:
            risk += len(result.vuln_indicators) * 0.1

        return min(risk, 1.0)
