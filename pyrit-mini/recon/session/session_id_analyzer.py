"""session_id_analyzer.py - Session ID Entropy & Predictability Analyzer.

Analyzes session ID generation patterns to detect weak randomness,
predictable sequences, or insufficient entropy in session tokens.

Academic basis:
    - OWASP Session Management Cheat Session - Weak session ID detection
    - NIST SP 800-90A - Random bit generation requirements
    - Li et al. (CCS 2022) - Session token predictability attacks on web APIs

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — session ID analysis only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

# Minimum entropy threshold (bits) for secure session IDs
MIN_ENTROPY_BITS = 64.0

# Predictable patterns
PREDICTABLE_PATTERNS: list[re.Pattern] = [
    re.compile(r"^[\d]+$"),  # Sequential numeric IDs
    re.compile(r"^[a-f0-9]{32}$"),  # MD5 hash (often time-based)
    re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),  # Base64 encoded data
    re.compile(r"^192\.168\."),  # IP-embedded tokens
    re.compile(r"^[_-]\d+[_-]$"),  # Delimited counters
]


@dataclass
class SessionIdAnalysisResult:
    """Result of session ID analysis."""

    token: str
    entropy_bits: float
    length: int
    is_predictable: bool
    detected_pattern: str = ""
    risk_score: float = 0.0
    recommendations: list[str] = field(default_factory=list)


class SessionIdAnalyzer:
    """Analyze session ID tokens for entropy and predictability."""

    def __init__(self, min_entropy: float = MIN_ENTROPY_BITS) -> None:
        self.min_entropy = min_entropy
        self.analyses: list[SessionIdAnalysisResult] = []

    def analyze_token(self, token: str) -> SessionIdAnalysisResult:
        """Analyze a single session token."""
        entropy = self._calculate_entropy(token)
        is_predictable, pattern = self._detect_pattern(token)

        risk = self._compute_risk(token, entropy, is_predictable)
        recommendations = self._generate_recommendations(entropy, is_predictable)

        result = SessionIdAnalysisResult(
            token=token[:16] + "..." if len(token) > 16 else token,
            entropy_bits=entropy,
            length=len(token),
            is_predictable=is_predictable,
            detected_pattern=pattern,
            risk_score=risk,
            recommendations=recommendations,
        )
        self.analyses.append(result)
        return result

    def analyze_batch(self, tokens: list[str]) -> list[SessionIdAnalysisResult]:
        """Analyze multiple session tokens."""
        return [self.analyze_token(t) for t in tokens]

    def get_risk_summary(self) -> dict[str, Any]:
        """Get aggregate risk summary."""
        if not self.analyses:
            return {"total_analyzed": 0, "high_risk_count": 0, "avg_entropy": 0.0}

        high_risk = [a for a in self.analyses if a.risk_score >= 0.7]
        avg_entropy = sum(a.entropy_bits for a in self.analyses) / len(self.analyses)

        return {
            "total_analyzed": len(self.analyses),
            "high_risk_count": len(high_risk),
            "avg_entropy": round(avg_entropy, 2),
            "predictable_count": sum(1 for a in self.analyses if a.is_predictable),
        }

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of token in bits."""
        if not token:
            return 0.0

        freq: dict[str, int] = {}
        for char in token:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = len(token)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy * length  # Total entropy in bits

    def _detect_pattern(self, token: str) -> tuple[bool, str]:
        """Detect predictable patterns in token."""
        for pattern in PREDICTABLE_PATTERNS:
            if pattern.match(token):
                return True, pattern.pattern
        return False, ""

    def _compute_risk(self, token: str, entropy: float, predictable: bool) -> float:
        """Compute risk score (0.0 to 1.0)."""
        risk = 0.0

        # Entropy-based risk
        if entropy < 32:
            risk += 0.4
        elif entropy < self.min_entropy:
            risk += 0.2

        # Length-based risk
        if len(token) < 16:
            risk += 0.3
        elif len(token) < 32:
            risk += 0.1

        # Predictability risk
        if predictable:
            risk += 0.3

        return min(risk, 1.0)

    def _generate_recommendations(self, entropy: float, predictable: bool) -> list[str]:
        """Generate improvement recommendations."""
        recs: list[str] = []
        if entropy < self.min_entropy:
            recs.append("Insufficient entropy: expand token space or use CSPRNG")
        if predictable:
            recs.append("Replace predictable generation with cryptographic RNG (e.g., secrets.token_hex)")
        if entropy < 32:
            recs.append("CRITICAL: Session tokens forgeable with moderate resources")
        return recs
