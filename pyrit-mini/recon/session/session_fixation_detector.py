"""session_fixation_detector.py - Session Fixation Vulnerability Detector.

Detects session fixation vulnerabilities where an attacker can fixate
a session ID before authentication and gain access post-login.

Academic basis:
    - OWASP Session Fixation
    - Mitja Kolšek (2002) - Session Fixation Vulnerability in Web-based Applications
    - Robertson et al. (USENIX Security 2023) - Session fixation in LLM agent frameworks

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — session fixation detection only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FixationRiskLevel(Enum):
    """Risk levels for session fixation."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FixationDetectionResult:
    """Result of session fixation detection."""

    is_vulnerable: bool
    risk_level: FixationRiskLevel
    risk_score: float  # 0.0 to 1.0
    indicators: list[str] = field(default_factory=list)
    attack_vector: str = ""
    recommendations: list[str] = field(default_factory=list)


class SessionFixationDetector:
    """Detect session fixation vulnerabilities."""

    # Indicators that session ID does NOT change after auth
    FIXATION_INDICATORS: list[re.Pattern] = [
        re.compile(r"(?i)session[_-]?id[\s:=]+[^\s&]+"),
        re.compile(r"(?i)sid[\s:=]+[^\s&]+"),
        re.compile(r"(?i)jsessionid[\s:=]+[^\s&]+"),
        re.compile(r"(?i)phpsessid[\s:=]+[^\s&]+"),
        re.compile(r"(?i)connect\.sid[\s:=]+[^\s&]+"),
    ]

    def __init__(self) -> None:
        self.detections: list[FixationDetectionResult] = []

    def analyze_flow(
        self,
        pre_auth_token: str | None,
        post_auth_token: str | None,
        auth_response_headers: dict[str, str],
    ) -> FixationDetectionResult:
        """Analyze authentication flow for session fixation."""
        indicators: list[str] = []
        vulnerable = False
        risk_score = 0.0

        # Check if session token changes after authentication
        if pre_auth_token and post_auth_token:
            if pre_auth_token == post_auth_token:
                vulnerable = True
                indicators.append("Session ID unchanged after authentication")
                risk_score += 0.6

        # Check if Set-Cookie is present after login
        set_cookie = auth_response_headers.get("Set-Cookie", "")
        if not set_cookie and pre_auth_token:
            indicators.append("No new session ID issued post-authentication")
            risk_score += 0.3

        # Check for token in URL (fixation via URL)
        if "session_id=" in str(auth_response_headers):
            indicators.append("Session ID exposed in response/redirect URL")
            risk_score += 0.2

        # Determine risk level
        risk_level = self._classify_risk(risk_score)
        attack_vector = self._determine_attack_vector(indicators)
        recommendations = self._generate_recommendations(vulnerable, indicators)

        result = FixationDetectionResult(
            is_vulnerable=vulnerable,
            risk_level=risk_level,
            risk_score=min(risk_score, 1.0),
            indicators=indicators,
            attack_vector=attack_vector,
            recommendations=recommendations,
        )
        self.detections.append(result)
        return result

    def check_token_reuse_across_contexts(self, token: str, contexts: list[str]) -> FixationDetectionResult:
        """Check if a token is valid across different security contexts."""
        indicators: list[str] = []
        risk_score = 0.0

        if len(set(contexts)) > 1 and token:
            indicators.append("Same token accepted in multiple contexts")
            risk_score += 0.5
            if "admin" in contexts and "user" in contexts:
                indicators.append("Token works in both admin and user contexts")
                risk_score += 0.3

        return FixationDetectionResult(
            is_vulnerable=risk_score > 0.4,
            risk_level=self._classify_risk(risk_score),
            risk_score=min(risk_score, 1.0),
            indicators=indicators,
            recommendations=["Generate unique tokens per security context"],
        )

    def get_detection_summary(self) -> dict[str, Any]:
        """Get summary of all fixation detections."""
        if not self.detections:
            return {"detections": 0, "vulnerable_count": 0}

        vulnerable = [d for d in self.detections if d.is_vulnerable]
        critical = [d for d in self.detections if d.risk_level == FixationRiskLevel.CRITICAL]

        return {
            "detections": len(self.detections),
            "vulnerable_count": len(vulnerable),
            "critical_count": len(critical),
            "avg_risk_score": round(sum(d.risk_score for d in self.detections) / len(self.detections), 3),
        }

    def _classify_risk(self, score: float) -> FixationRiskLevel:
        """Classify risk level from score."""
        if score >= 0.8:
            return FixationRiskLevel.CRITICAL
        elif score >= 0.6:
            return FixationRiskLevel.HIGH
        elif score >= 0.4:
            return FixationRiskLevel.MEDIUM
        elif score >= 0.2:
            return FixationRiskLevel.LOW
        return FixationRiskLevel.NONE

    def _determine_attack_vector(self, indicators: list[str]) -> str:
        """Determine the most likely attack vector."""
        if any("unchanged" in i.lower() for i in indicators):
            return "Attacker fixes pre-auth session ID → victim authenticates → attacker hijacks session"
        if any("url" in i.lower() for i in indicators):
            return "Attacker crafts URL with fixated session ID → victim authenticates via link"
        return "Direct session ID predictability → attacker guesses valid session IDs"

    def _generate_recommendations(self, vulnerable: bool, indicators: list[str]) -> list[str]:
        """Generate fix recommendations."""
        recs: list[str] = []
        if vulnerable:
            recs.append("Issue a new session ID after successful authentication")
            recs.append("Regenerate session ID on privilege level change")
        if any("url" in i.lower() for i in indicators):
            recs.append("Never transmit session identifiers in URLs")
        recs.append("Implement session binding to client attributes (UA, IP)")
        return recs
