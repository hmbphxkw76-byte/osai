"""Stealth Level Configuration - 

Academic basis:
    - Huang et al. (arXiv:2306.05685) - ": "
    - Russinovich et al. (2024) - PyRIT 
    - Mazeika et al. (arXiv:2406.18510) - WILDTEAMING: 

:
    paranoid:    - all ()
    balanced:    -  ()
    aggressive:  -  ( / CTF)
    silent_recon-only:  - /

:
    -  (delay_range)
    -  (max_probes)
    -  converter 
    - 
    - 
    - 

 (Rule 2: Stealth First):
     "balanced"  - 
    "paranoid"  ( 30-60s),
     Mark 
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
 """converter(s) Stealth Level 

    :
        name: 
        delay_range:  [min, max] ()
        max_probes: 
        allowed_converters:  converter 
        converter_blacklist:  converter 
        behavioral_verify: 
        guardrail_detection_strength:  ("full" / "light" / "none")
        aggressive_templates_allowed: 
        multi_turn_enabled: 
        jitter:  (+/- )
        max_concurrent_requests: 
        notes: 
 """
    name: str
    delay_range: tuple[float, float]
    max_probes: int
    allowed_converters: list[str] | None  # None = all
    converter_blacklist: list[str]
    behavioral_verify: bool
    guardrail_detection_strength: str
    aggressive_templates_allowed: bool
    multi_turn_enabled: bool
    jitter: float
    max_concurrent_requests: int
    notes: str = ""


# ====================================================================
# 
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
        notes=(
            ""
            ""
        ),
    ),

    "balanced": StealthPolicy(
        name="balanced",
        delay_range=(3.0, 10.0),
        max_probes=10,
        allowed_converters=None,  # All allowed
        converter_blacklist=[
            "rot13",  # , 
        ],
        behavioral_verify=True,
        guardrail_detection_strength="light",
        aggressive_templates_allowed=True,
        multi_turn_enabled=True,
        jitter=0.3,
        max_concurrent_requests=3,  # CI : 
        notes=": ",
    ),

    "aggressive": StealthPolicy(
        name="aggressive",
        delay_range=(0.5, 2.0),
        max_probes=20,
        allowed_converters=None,  # All
        converter_blacklist=[],
        behavioral_verify=False,  # 
        guardrail_detection_strength="minimal",
        aggressive_templates_allowed=True,
        multi_turn_enabled=True,
        jitter=0.1,
        max_concurrent_requests=5,  # CI : 
        notes=" CTF /  ASR",
    ),

    "silent_recon_only": StealthPolicy(
        name="silent_recon_only",
        delay_range=(60.0, 120.0),
        max_probes=1,  # 1 converter(s)
        allowed_converters=[],  # all converter
        converter_blacklist=["base64", "rot13", "leet_speak", "humanizer",
                             "unicode_smuggling", "homoglyph_chinese", "accent_obfuscation"],
        behavioral_verify=False,
        guardrail_detection_strength="minimal",
        aggressive_templates_allowed=False,
        multi_turn_enabled=False,
        jitter=0.8,
        max_concurrent_requests=1,
        notes=" + ",
    ),
}


# ====================================================================
# Stealth Level 
# ====================================================================


class StealthLevelManager:
 """

     GuardrailReport  stealth_level 

    Usage:
        >>> manager = StealthLevelManager()
        >>> # 
        >>> policy = manager.get_policy("balanced")
        >>> # ()
        >>> policy = manager.auto_select_policy(guardrail_report)
 """

    def __init__(self, default_level: str = "balanced") -> None:
 """

        Args:
            default_level:  stealth level
 """
        self._default_level = default_level
        self._current_policy: StealthPolicy | None = None

    def get_policy(self, level: str | None = None) -> StealthPolicy:
 """ level 

        Args:
            level:  (paranoid / balanced / aggressive / silent_recon_only)

        Returns:
            StealthPolicy 
 """
        level = level or self._default_level
        policy = STEALTH_POLICIES.get(level)
        if policy is None:
            logger.warning("Unknown stealth level '%s', falling back to 'balanced'", level)
            policy = STEALTH_POLICIES["balanced"]
        self._current_policy = policy
        return policy

    def auto_select_policy(self, guardrail_report: dict[str, Any] | None = None) -> StealthPolicy:
 """ stealth level

        :
            -  (strict) -> paranoid
            -  (moderate) -> balanced
            -  (permissive) -> balanced
            -  -> aggressive
            -  -> balanced ()

        Args:
            guardrail_report: guardrail_detector 

        Returns:
            StealthPolicy 
 """
        if guardrail_report is None:
            return self.get_policy("balanced")

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
 """ stealth level 

         jitter () 

        Args:
            policy:  ( None)

        Returns:
             ( jitter)
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
 """converter(s) stealth level 

        Args:
            converter_name: converter  ( "base64", "rot13")
            policy: 

        Returns:
            
 """
        policy = policy or self._current_policy or self.get_policy()

 # 
        if converter_name in policy.converter_blacklist:
            return False

 # , 
        if policy.allowed_converters is not None:
            return converter_name in policy.allowed_converters

        return True

    def get_all_allowed_converters(self, policy: StealthPolicy | None = None) -> list[str]:
 """ level all converter

        Returns:
            converter 
 """
        policy = policy or self._current_policy or self.get_policy()

        ALL_CONVERTERS = [
            "base64", "rot13", "leet_speak", "humanizer",
            "unicode_smuggling", "homoglyph_chinese", "accent_obfuscation",
        ]

        return [
            c for c in ALL_CONVERTERS if self.is_converter_allowed(c, policy)
        ]


# ====================================================================
# 
# ====================================================================

_default_stealth_manager: StealthLevelManager | None = None


def get_stealth_manager() -> StealthLevelManager:
 """ StealthLevelManager """
    global _default_stealth_manager
    if _default_stealth_manager is None:
        _default_stealth_manager = StealthLevelManager()
    return _default_stealth_manager
