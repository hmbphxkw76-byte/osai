# -*- coding: utf-8 -*-
"""recon/a2a/defense_mapper.py - A2A Defense Surface Mapping.

Maps implemented defenses in multi-agent systems:
    1. Input validation detection
    2. Output filtering detection
    3. Authentication mechanism identification
    4. Rate limiting detection
    5. Audit logging detection
    6. Trust verification mechanisms

Academic basis:
    - A2A Protocol Security (Google, 2025)
    - OWASP LLM Top 10 2025 - Defense bypass strategies

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - defense mapping only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DefenseIndicator:
    """Detection indicator for a defense mechanism."""

    defense_type: str  # input_validation, output_filter, auth, rate_limit, audit, trust_verify
    detected: bool = False
    confidence: float = 0.0  # 0.0-1.0
    evidence: list[str] = field(default_factory=list)
    bypass_potential: str = "unknown"  # low, medium, high

    def to_dict(self) -> dict[str, Any]:
        return {
            "defense_type": self.defense_type,
            "detected": self.detected,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence),
            "bypass_potential": self.bypass_potential,
        }


@dataclass
class DefenseMapResult:
    """Complete defense surface mapping result."""

    target_url: str = ""
    defenses: list[DefenseIndicator] = field(default_factory=list)
    defense_score: float = 0.0  # Overall defense strength 0.0-1.0
    weak_points: list[str] = field(default_factory=list)
    evasion_opportunities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "defenses": [d.to_dict() for d in self.defenses],
            "defense_score": self.defense_score,
            "weak_points": self.weak_points,
            "evasion_opportunities": self.evasion_opportunities,
        }


class A2ADefenseMapper:
    """Map A2A multi-agent defense mechanisms.

    Usage:
        mapper = A2ADefenseMapper()
        result = await mapper.map_defenses(
            target_url="http://multi-agent:8000",
            probe_responses=collected_responses,
        )
    """

    # Defense detection patterns
    DEFENSE_PATTERNS = {
        "input_validation": [
            r"(?i)input\s+(?:validation|sanitiz|check)",
            r"(?i)reject\s+(?:malicious|invalid|harmful)",
            r"(?i)content\s+(?:filter|check|validation)",
        ],
        "output_filter": [
            r"(?i)output\s+(?:filter|sanitiz|clean)",
            r"(?i)response\s+(?:check|validation|filter)",
            r"(?i)safe\s+(?:output|response)",
        ],
        "authentication": [
            r"(?i)auth(?:enticat)?",
            r"(?i)bearer\s+token",
            r"(?i)(?:jwt|api)\s+key",
            r"(?i)certificat",
        ],
        "rate_limit": [
            r"(?i)rate\s+limit",
            r"(?i)throttl",
            r"(?i)quota",
        ],
        "audit_log": [
            r"(?i)audit\s+log",
            r"(?i)log\s+(?:request|response|action)",
            r"(?i)trace",
        ],
        "trust_verification": [
            r"(?i)trust\s+(?:verif|check|validat)",
            r"(?i)agent\s+(?:verif|authenticat)",
        ],
    }

    def __init__(self):
        self._detected_defenses: dict[str, DefenseIndicator] = {}

    async def map_defenses(
        self,
        target_url: str,
        probe_responses: list[dict[str, Any]] | None = None,
        agent_cards: list[dict[str, Any]] | None = None,
    ) -> DefenseMapResult:
        """Map defense mechanisms from probe data.

        Args:
            target_url: Target A2A system URL
            probe_responses: Collected HTTP responses for analysis
            agent_cards: Agent cards with security info

        Returns:
            DefenseMapResult with complete defense analysis
        """
        result = DefenseMapResult(target_url=target_url)

        # Initialize all defense indicators
        all_defenses = {dtype: DefenseIndicator(defense_type=dtype) for dtype in self.DEFENSE_PATTERNS}

        # Analyze probe responses
        if probe_responses:
            for resp in probe_responses:
                self._analyze_response(resp, all_defenses)

        # Analyze agent cards for security info
        if agent_cards:
            for card in agent_cards:
                self._analyze_card_security(card, all_defenses)

        result.defenses = list(all_defenses.values())

        # Calculate overall defense score
        result.defense_score = self._calculate_defense_score(result.defenses)

        # Identify weak points (undetected defenses)
        result.weak_points = [d.defense_type for d in result.defenses if not d.detected or d.confidence < 0.5]

        # Map evasion opportunities
        result.evasion_opportunities = self._map_evasion(result.defenses)

        return result

    def _analyze_response(
        self,
        resp: dict[str, Any],
        defenses: dict[str, DefenseIndicator],
    ) -> None:
        """Analyze a single response for defense indicators."""
        # Check headers for defense indicators
        headers = resp.get("headers", {})
        header_str = str(headers).lower()

        body = resp.get("body", "")
        body_str = str(body).lower()

        combined = f"{header_str} {body_str}"

        for dtype, patterns in self.DEFENSE_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, combined)
                if matches:
                    defenses[dtype].detected = True
                    defenses[dtype].evidence.append(f"Pattern '{pattern}' in response")
                    defenses[dtype].confidence = min(
                        defenses[dtype].confidence + 0.3,
                        1.0,
                    )

    def _analyze_card_security(
        self,
        card: dict[str, Any],
        defenses: dict[str, DefenseIndicator],
    ) -> None:
        """Analyze agent card for security features."""
        card_str = str(card).lower()

        if "securityschemes" in card_str:
            defenses["authentication"].detected = True
            defenses["authentication"].confidence = 0.8
            defenses["authentication"].evidence.append("securitySchemes in agent card")

        capabilities = card.get("capabilities", {})
        if "authenticatedExtendedCard" in capabilities:
            defenses["trust_verification"].detected = True
            defenses["trust_verification"].confidence = 0.6

    def _calculate_defense_score(self, defenses: list[DefenseIndicator]) -> float:
        """Calculate overall defense strength score."""
        if not defenses:
            return 0.0

        detected_count = sum(1 for d in defenses if d.detected)
        confidence_sum = sum(d.confidence for d in defenses)

        detection_ratio = detected_count / len(defenses)
        avg_confidence = confidence_sum / len(defenses)

        return detection_ratio * 0.6 + avg_confidence * 0.4

    def _map_evasion(self, defenses: list[DefenseIndicator]) -> list[str]:
        """Map evasion opportunities based on defense gaps."""
        opportunities = []

        for defense in defenses:
            if not defense.detected:
                opportunities.append(f"no_{defense.defense_type}")
            elif defense.confidence < 0.5:
                opportunities.append(f"weak_{defense.defense_type}")

        return opportunities


async def map_a2a_defenses(
    target_url: str,
    probe_responses: list[dict[str, Any]] | None = None,
    agent_cards: list[dict[str, Any]] | None = None,
) -> DefenseMapResult:
    """Convenience function for A2A defense mapping."""
    mapper = A2ADefenseMapper()
    return await mapper.map_defenses(target_url, probe_responses, agent_cards)
