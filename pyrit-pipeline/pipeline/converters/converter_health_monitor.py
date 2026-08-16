# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Converter Health Monitor — L5 execution resilience Layer 2 (R-022: PyRIT 原生 Converter 数据层增强).

Circuit Breaker pattern for Converter-level fault tolerance.

Solves the core problem:
  When an LLM-based Converter (e.g., DecompositionConverter) consistently
  fails with EmptyResponseException (204), the error propagates to the
  entire SequentialAttack, triggering ExceptionGroup + max_retries
  with no effect. This monitor tracks per-converter health and disables
  converters that fail consecutively beyond a threshold.

Design:
  1. Health check — pre-flight validate LLM converter availability
  2. Circuit breaker — disable converter after N consecutive failures
  3. Error degradation — skip converter on failure instead of crashing
  4. Statistics — record per-converter success/failure rates

Academic basis:
  Circuit Breaker Pattern (Michael Nygard, "Release It!")
  - closed: normal operation, tracking failure count
  - open: failure threshold reached, reject new requests
  - half-open: probe recovery (not used here, since converter state
    doesn't change within a single pipeline run)

> **Date**: 2026-8-2
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Default circuit breaker threshold: disable after 5 consecutive failures
# P3: 2→5, give converters more chances before disabling (API timeouts are not converter failures)
_DEFAULT_FAILURE_THRESHOLD = 5

# P4: LLM-based converters that CAN be circuit-broken (they make API calls)
# Only these converters will be disabled by the circuit breaker.
# Local (non-LLM) converters (UnicodeConfusable, Leetspeak, Base64, etc.)
# never make API calls and should NEVER be disabled.
_LLM_CONVERTER_NAMES: set[str] = {
    "PersuasionConverter",
    "ToneConverter",
    "TranslationConverter",
    "DecompositionConverter",
    "TaskFramingConverter",
    "NoiseConverter",
    "FlipConverter",
    "ScientificTranslationConverter",
    "MathObfuscationConverter",
    "TenseConverter",
    "VariationConverter",
    "PolicyPuppetryConverter",
}

# P3-1 (v45.5): 编码层 Converter 列表 — 连续失败时建议切换到语义层
_ENCODING_CONVERTER_NAMES: set[str] = {
    "ROT13Converter",
    "Base64Converter",
    "RandomCapitalLettersConverter",
    "UnicodeConfusableConverter",
    "LeetspeakConverter",
    "MorseConverter",
    "BinaryConverter",
    "HexConverter",
}

# P3-1 (v45.5): 语义层 Converter 候选 — 用于替换编码层
# 这些 Converter 在语义层面变换 prompt, 而非表示层编码,
# 可绕过语义级安全过滤而非表示级过滤.
# 学术依据: Wei et al. (arXiv:2307.15043) — 语义变换绕过语义过滤;
#   Zeng et al. (arXiv:2402.19181) — 语义层 ASR 30-40% >> 表示层 8-12%
_SEMANTIC_CONVERTER_FALLBACKS: list[str] = [
    "PersuasionConverter",
    "TaskFramingConverter",
    "ToneConverter",
    "PolicyPuppetryConverter",
]

# Regex patterns to extract Converter name from error messages
_CONVERTER_NAME_PATTERNS = [
    re.compile(r"converter identifier: (\w+)::", re.IGNORECASE),
    re.compile(r"converter\s+(\w+)\s+", re.IGNORECASE),
    re.compile(r"(\w+Converter)\b", re.IGNORECASE),
    re.compile(r"Component: converter.*?identifier: (\w+)", re.IGNORECASE),
]


@dataclass
class ConverterStats:
    """Runtime statistics for a single Converter."""

    name: str
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    errors: int = 0
    consecutive_failures: int = 0
    disabled: bool = False
    failure_reason: str = ""

    @property
    def success_rate(self) -> float:
        """Success rate (0.0-1.0)."""
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts

    @property
    def is_healthy(self) -> bool:
        """Whether the converter is healthy (not disabled)."""
        return not self.disabled


class ConverterHealthMonitor:
    """Converter health monitor — execution resilience Layer 2.

    Features:
    1. Pre-flight: validate LLM converter availability before execution
    2. Circuit breaker: disable converter after N consecutive failures
    3. Error degradation: skip failed converter instead of crashing SequentialAttack
    4. Statistics: record per-converter success/failure rates

    Integration:
    - stage_scenario.py: check is_disabled() when building technique_converters
    - stage_execute.py: record_failure() on ON_ERROR events
    - stage_output.py: get_stats() for health report in output
    """

    def __init__(self, failure_threshold: int = _DEFAULT_FAILURE_THRESHOLD) -> None:
        """Initialize ConverterHealthMonitor.

        Args:
            failure_threshold: disable converter after N consecutive failures
        """
        self._failure_threshold = failure_threshold
        self._stats: dict[str, ConverterStats] = {}

    def register(self, converter_name: str) -> None:
        """Register a Converter for monitoring."""
        if converter_name not in self._stats:
            self._stats[converter_name] = ConverterStats(name=converter_name)

    def is_disabled(self, converter_name: str) -> bool:
        """Check if a Converter has been disabled (circuit breaker open)."""
        stats = self._stats.get(converter_name)
        if stats is None:
            return False
        return stats.disabled

    def record_success(self, converter_name: str) -> None:
        """Record a Converter success. Resets consecutive failure count."""
        stats = self._stats.get(converter_name)
        if stats is None:
            stats = ConverterStats(name=converter_name)
            self._stats[converter_name] = stats
        stats.attempts += 1
        stats.successes += 1
        stats.consecutive_failures = 0

    def record_failure(self, converter_name: str, error_msg: str = "") -> None:
        """Record a Converter failure. Auto-disables after threshold.

        P4: Only LLM-based converters can be circuit-broken.
        Local converters (UnicodeConfusable, Leetspeak, etc.) never make
        API calls and should never be disabled.

        Args:
            converter_name: Name of the converter that failed
            error_msg: Error message for debugging
        """
        stats = self._stats.get(converter_name)
        if stats is None:
            stats = ConverterStats(name=converter_name)
            self._stats[converter_name] = stats
        stats.attempts += 1
        stats.failures += 1
        stats.consecutive_failures += 1
        if error_msg:
            stats.failure_reason = error_msg[:200]

        # P4: Skip circuit breaker for local (non-LLM) converters
        if converter_name not in _LLM_CONVERTER_NAMES:
            return

        # Circuit breaker check (only for LLM converters)
        if (
            not stats.disabled
            and stats.consecutive_failures >= self._failure_threshold
        ):
            stats.disabled = True
            logger.warning(
                "L2 Circuit Breaker: '%s' disabled after %d consecutive failures "
                "(reason: %s)",
                converter_name,
                stats.consecutive_failures,
                stats.failure_reason[:100],
            )

    def record_error(self, converter_name: str, error_msg: str = "") -> None:
        """Record a Converter-level error (system exception, not just failure).

        P4: Only LLM-based converters can be circuit-broken.
        """
        stats = self._stats.get(converter_name)
        if stats is None:
            stats = ConverterStats(name=converter_name)
            self._stats[converter_name] = stats
        stats.attempts += 1
        stats.errors += 1
        stats.consecutive_failures += 1
        if error_msg:
            stats.failure_reason = error_msg[:200]

        # P4: Skip circuit breaker for local (non-LLM) converters
        if converter_name not in _LLM_CONVERTER_NAMES:
            return

        if (
            not stats.disabled
            and stats.consecutive_failures >= self._failure_threshold
        ):
            stats.disabled = True
            logger.warning(
                "L2 Circuit Breaker: '%s' disabled after %d consecutive errors",
                converter_name,
                stats.consecutive_failures,
            )

    def get_stats(self) -> dict[str, dict[str, Any]]:
        """Get statistics summary for all monitored Converters."""
        return {
            name: {
                "attempts": s.attempts,
                "successes": s.successes,
                "failures": s.failures,
                "errors": s.errors,
                "success_rate": round(s.success_rate, 3),
                "consecutive_failures": s.consecutive_failures,
                "disabled": s.disabled,
                "failure_reason": s.failure_reason,
            }
            for name, s in self._stats.items()
        }

    def get_disabled_converters(self) -> list[str]:
        """Get list of all disabled (circuit-broken) Converter names."""
        return [name for name, s in self._stats.items() if s.disabled]

    def filter_chains(
        self,
        chain_names: list[str],
    ) -> tuple[list[str], list[str]]:
        """Filter Converter chain list, removing disabled chains.

        Returns:
            (enabled_chains, disabled_chains)
        """
        enabled = []
        disabled = []
        for chain in chain_names:
            if self.is_disabled(chain):
                disabled.append(chain)
            else:
                enabled.append(chain)
        return enabled, disabled

    def get_semantic_fallback(self, converter_name: str) -> str | None:
        """P3-1 (v45.5): 当编码层 Converter 连续失败时, 建议语义层替代.

        当编码层 Converter (ROT13/Base64等) 连续失败 >= threshold 时,
        返回一个语义层 Converter 名称作为替代.
        语义层 Converter 在语义层面变换 prompt, 可绕过语义级安全过滤.

        学术依据:
          - Wei et al. (arXiv:2307.15043): 编码攻击绕过表示级过滤但非语义级
          - Zeng et al. (arXiv:2402.19181): 语义层 ASR 30-40% >> 表示层 8-12%
          - Chao et al. (arXiv:2310.08437): PAIR 语义迭代越狱

        Args:
            converter_name: 当前失败的 Converter 名称.

        Returns:
            语义层 Converter 名称, 或 None (如果不需要替换).
        """
        # 仅对编码层 Converter 触发
        if converter_name not in _ENCODING_CONVERTER_NAMES:
            return None

        stats = self._stats.get(converter_name)
        if stats is None or stats.disabled:
            return None

        # 连续失败 >= threshold 时建议替换
        if stats.consecutive_failures >= self._failure_threshold:
            # 选择第一个未被禁用的语义层 Converter
            for semantic_name in _SEMANTIC_CONVERTER_FALLBACKS:
                semantic_stats = self._stats.get(semantic_name)
                if semantic_stats is None or not semantic_stats.disabled:
                    logger.info(
                        f"P3-1: Encoding converter '{converter_name}' failed "
                        f"{stats.consecutive_failures} times, "
                        f"suggesting semantic fallback: '{semantic_name}'"
                    )
                    return semantic_name

        return None

    def get_all_semantic_fallbacks(self) -> list[str]:
        """P3-1 (v45.5): 返回所有可用的语义层 Converter 候选.

        当多个编码层 Converter 同时失败时, 返回所有未被禁用的语义层 Converter.

        Returns:
            可用的语义层 Converter 名称列表.
        """
        available = []
        for name in _SEMANTIC_CONVERTER_FALLBACKS:
            stats = self._stats.get(name)
            if stats is None or not stats.disabled:
                available.append(name)
        return available

    def reset(self) -> None:
        """Reset all statistics (call at the start of a new run)."""
        for stats in self._stats.values():
            stats.consecutive_failures = 0
            stats.disabled = False
            stats.failure_reason = ""


def extract_converter_name_from_error(error_str: str) -> str | None:
    """Extract Converter name from an error message string.

    PyRIT error message format example:
      "Strategy execution failed for converter in PromptSendingAttack:
       Status Code: 204...
       converter identifier: DecompositionConverter::6de9e30a"

    Args:
        error_str: Error message string

    Returns:
        Converter name (e.g., "DecompositionConverter"), or None if not found
    """
    for pattern in _CONVERTER_NAME_PATTERNS:
        match = pattern.search(error_str)
        if match:
            return match.group(1)
    return None


def extract_chain_name_from_error(error_str: str) -> str | None:
    """Extract Converter chain name from an error message string.

    Converter chain name and Converter class name are different:
      chain name: "decomposition_chain"
      class name: "DecompositionConverter"

    Args:
        error_str: Error message string

    Returns:
        Chain name (e.g., "decomposition_chain"), or None if not found
    """
    _CONVERTER_CLASS_TO_CHAIN = {
        "decompositionconverter": "decomposition_chain",
        "persuasionconverter": "persuasion_authority",
        "toneconverter": "persuasion_authority",
        "translationconverter": "persuasion_authority",
        "taskframingconverter": "task_framing_chain",
        "suffixappendconverter": "suffix_append",
        "unicodeconfusableconverter": "semantic_evasion",
        "noisebypassconverter": "noise_bypass",
        "specialcharsconverter": "special_chars",
        "randomcaseconverter": "random_case",
        "leetspeakconverter": "semantic_evasion",
        "stealthevasionconverter": "stealth_evasion",
        "multiencodingconverter": "multi_encoding_v2",
        "encodingbypassconverter": "encoding_bypass",
    }

    converter_name = extract_converter_name_from_error(error_str)
    if converter_name:
        return _CONVERTER_CLASS_TO_CHAIN.get(converter_name.lower())
    return None
