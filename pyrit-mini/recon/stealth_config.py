"""Stealth Level Configuration - Evasion policy management

Academic basis:
    - Huang et al. (arXiv:2306.05685) - "Gradient-based adversarial attacks"
    - Russinovich et al. (2024) - PyRIT framework
    - Mazeika et al. (arXiv:2406.18510) - WILDTEAMING: Multi-turn attacks

Stealth levels:
    paranoid:   High security targets (30-60s delays, minimal footprint)
    balanced:   Default - moderate evasion (5-15s delays)
    aggressive:  Low security / CTF (no delays, maximum probes)
    silent_recon-only:  Passive reconnaissance only (no active attacks)

Each policy controls:
    - Request delay_range (min, max seconds)
    - Max probe count
    - Allowed/disallowed converters
    - Jitter percentage
    - Concurrent request limit

Constitution compliance (Rule 2: Stealth First):
    Default "balanced" mode for all targets
    Escalate to "paranoid" only when guardrails detected
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ====================================================================
# Stealth Level Schema
# ====================================================================


@dataclass
class StealthPolicy:
    """Stealth policy configuration for attack evasion.

    Controls timing, concurrency, and converter selection to avoid detection.
    """

    name: str
    delay_range: tuple[float, float]  # (min, max) seconds
    max_probes: int
    allowed_converters: list[str] | None  # None = all allowed
    converter_blacklist: list[str]
    behavioral_verify: bool
    guardrail_detection_strength: str  # "full" / "light" / "none"
    aggressive_templates_allowed: bool
    multi_turn_enabled: bool
    jitter: float  # +/- percentage (0.5 = 50%)
    max_concurrent_requests: int
    notes: str = ""


# ====================================================================
# Predefined Stealth Policies
# ====================================================================

STEALTH_POLICIES: dict[str, StealthPolicy] = {
    "paranoid": StealthPolicy(
        name="paranoid",
        delay_range=(30.0, 60.0),
        max_probes=3,
        allowed_converters=[
            "base64",
            "humanizer",
            "unicode_smuggling",
            "homoglyph_chinese",
            "accent_obfuscation",
        ],
        converter_blacklist=[
            "rot13",
            "leet_speak",
        ],
        behavioral_verify=True,
        guardrail_detection_strength="full",
        aggressive_templates_allowed=False,
        multi_turn_enabled=True,
        jitter=0.5,
        max_concurrent_requests=1,
        notes="High security targets, maximum evasion",
    ),
    "balanced": StealthPolicy(
        name="balanced",
        delay_range=(5.0, 15.0),
        max_probes=8,
        allowed_converters=None,  # All allowed
        converter_blacklist=[],
        behavioral_verify=False,
        guardrail_detection_strength="light",
        aggressive_templates_allowed=False,
        multi_turn_enabled=True,
        jitter=0.3,
        max_concurrent_requests=3,
        notes="Default mode for standard targets",
    ),
    "aggressive": StealthPolicy(
        name="aggressive",
        delay_range=(0.5, 2.0),
        max_probes=20,
        allowed_converters=None,  # All allowed
        converter_blacklist=[],
        behavioral_verify=False,
        guardrail_detection_strength="none",
        aggressive_templates_allowed=True,
        multi_turn_enabled=True,
        jitter=0.1,
        max_concurrent_requests=10,
        notes="CTF / low security targets, maximum speed",
    ),
    "silent_recon-only": StealthPolicy(
        name="silent_recon-only",
        delay_range=(10.0, 30.0),
        max_probes=5,
        allowed_converters=[],  # No active attacks
        converter_blacklist=["rot13", "leet_speak", "base64", "humanizer"],
        behavioral_verify=False,
        guardrail_detection_strength="full",
        aggressive_templates_allowed=False,
        multi_turn_enabled=False,
        jitter=0.4,
        max_concurrent_requests=2,
        notes="Passive reconnaissance only, no active attacks",
    ),
}


# ====================================================================
# Stealth Level Manager
# ====================================================================


class StealthLevelManager:
    """Manages stealth policy selection based on guardrail detection.

    Maps guardrail severity to appropriate stealth level:
        - strict      -> paranoid
        - moderate    -> balanced
        - permissive  -> balanced
        - none        -> aggressive
    """

    def __init__(self, default_policy: str = "balanced") -> None:
        self._default_policy_name = default_policy
        self._current_policy: StealthPolicy | None = None
        self._custom_policies: dict[str, StealthPolicy] = {}

    def get_policy(self, policy_name: str | None = None) -> StealthPolicy:
        """Get stealth policy by name or current default."""
        name = policy_name or self._default_policy_name
        if name in self._custom_policies:
            return self._custom_policies[name]
        return STEALTH_POLICIES.get(name, STEALTH_POLICIES["balanced"])

    def set_policy(self, policy_name: str) -> None:
        """Set current stealth policy."""
        self._current_policy = self.get_policy(policy_name)
        logger.info("Stealth policy set to: %s", policy_name)

    def get_policy_for_guardrail(self, guardrail_report: dict[str, Any] | None) -> StealthPolicy:
        """Select stealth policy based on guardrail detection result.

        Args:
            guardrail_report: Guardrail detection report from guardrail_detector.py

        Returns:
            StealthPolicy appropriate for the detected guardrail severity
        """
        if guardrail_report is None:
            return self.get_policy("aggressive")

        if not guardrail_report.get("has_guardrail", False):
            return self.get_policy("aggressive")

        severity = guardrail_report.get("severity", "none")
        if severity == "strict":
            return self.get_policy("paranoid")
        elif severity in ("moderate", "permissive"):
            return self.get_policy("balanced")
        else:
            return self.get_policy("balanced")

    def get_delay(self, policy: StealthPolicy | None = None) -> float:
        """Get randomized delay based on stealth policy.

        Includes jitter for randomization.

        Args:
            policy: Specific policy to use (None = current)

        Returns:
            Delay in seconds (with jitter)
        """
        policy = policy or self._current_policy or self.get_policy()
        delay_min, delay_max = policy.delay_range
        jitter = policy.jitter

        base_delay = random.uniform(delay_min, delay_max)
        jitter_amount = base_delay * jitter
        final_delay = base_delay + random.uniform(-jitter_amount, jitter_amount)

        return max(0.1, final_delay)

    def is_converter_allowed(
        self,
        converter_name: str,
        policy: StealthPolicy | None = None,
    ) -> bool:
        """Check if converter is allowed under current stealth policy.

        Args:
            converter_name: Converter name (e.g., "base64", "rot13")
            policy: Specific policy to use (None = current)

        Returns:
            True if converter is allowed
        """
        policy = policy or self._current_policy or self.get_policy()

        # Blacklist takes precedence
        if converter_name in policy.converter_blacklist:
            return False

            # If allowed_converters is specified, must be in list
        if policy.allowed_converters is not None:
            return converter_name in policy.allowed_converters
        return True

    def get_all_allowed_converters(self, policy: StealthPolicy | None = None) -> list[str]:
        """Get all converters allowed under current stealth policy.

        Returns:
            List of allowed converter names
        """
        policy = policy or self._current_policy or self.get_policy()

        ALL_CONVERTERS = [
            "base64",
            "rot13",
            "leet_speak",
            "humanizer",
            "unicode_smuggling",
            "homoglyph_chinese",
            "accent_obfuscation",
        ]

        return [c for c in ALL_CONVERTERS if self.is_converter_allowed(c, policy)]


# ====================================================================
# Module-level singleton
# ====================================================================

_default_stealth_manager: StealthLevelManager | None = None


def get_stealth_manager() -> StealthLevelManager:
    """Get or create the global StealthLevelManager singleton."""
    global _default_stealth_manager
    if _default_stealth_manager is None:
        _default_stealth_manager = StealthLevelManager(default_policy="balanced")
    return _default_stealth_manager
