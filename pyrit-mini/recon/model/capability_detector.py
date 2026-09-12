# -*- coding: utf-8 -*-
"""recon/model/capability_detector.py - LLM Model Capability Detection.

Detects capabilities and characteristics of target LLM API:
    1. Model fingerprinting and version identification
    2. Context window size detection
    3. Supported modalities detection
    4. Safety guardrail identification
    5. Output format capabilities
    6. Supported features (function calling, streaming, etc.)

Academic basis:
    - Perez et al. (arXiv:2204.05862) - Red teaming methodology
    - OWASP LLM07 - Model theft reconnaissance

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - capability detection only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ModelCapability:
    """Detected capability information for a model."""

    model_name: str = ""
    model_family: str = ""  # gpt, claude, gemini, etc.
    model_version: str = ""
    context_window: int = 0
    supports_streaming: bool = False
    supports_functions: bool = False
    supports_vision: bool = False
    supports_system_prompt: bool = False
    max_output_tokens: int = 0
    safety_level: str = "unknown"  # none, basic, moderate, strict
    detected_features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_family": self.model_family,
            "model_version": self.model_version,
            "context_window": self.context_window,
            "supports_streaming": self.supports_streaming,
            "supports_functions": self.supports_functions,
            "supports_vision": self.supports_vision,
            "safety_level": self.safety_level,
            "detected_features": self.detected_features,
        }


@dataclass
class CapabilityDetectionResult:
    """Complete capability detection result."""

    target_url: str = ""
    model_capabilities: list[ModelCapability] = field(default_factory=list)
    detected_models: list[str] = field(default_factory=list)
    fastest_model: str = ""
    largest_context_model: str = ""
    least_restricted_model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "models": [m.to_dict() for m in self.model_capabilities],
            "fastest_model": self.fastest_model,
            "largest_context": self.largest_context_model,
            "least_restricted": self.least_restricted_model,
        }


class ModelCapabilityDetector:
    """Detect capabilities of LLM APIs via probing.

    Usage:
        detector = ModelCapabilityDetector()
        result = await detector.detect_capabilities(
            target_url="http://llm-api:8000/v1/models",
        )
    """

    MODEL_FINGERPRINTS = {
        "gpt-4": {"family": "gpt", "context": 128000},
        "gpt-3.5": {"family": "gpt", "context": 16000},
        "claude": {"family": "claude", "context": 200000},
        "gemini": {"family": "gemini", "context": 1000000},
        "llama": {"family": "llama", "context": 8192},
    }

    def __init__(self):
        self._detected: list[ModelCapability] = []

    async def detect_capabilities(
        self,
        target_url: str,
    ) -> CapabilityDetectionResult:
        """Detect all model capabilities.

        Args:
            target_url: LLM API endpoint URL

        Returns:
            CapabilityDetectionResult with all detected info
        """
        result = CapabilityDetectionResult(target_url=target_url)

        # Probe model list endpoint
        models = await self._probe_models_endpoint(target_url)

        for model_info in models:
            capability = await self._detect_single_model(target_url, model_info)
            result.model_capabilities.append(capability)

        # Identify best options for attack
        result.detected_models = [m.model_name for m in result.model_capabilities]
        result.fastest_model = self._find_fastest(result.model_capabilities)
        result.largest_context_model = self._find_largest_context(result.model_capabilities)
        result.least_restricted_model = self._find_least_restricted(result.model_capabilities)

        return result

    async def _probe_models_endpoint(
        self,
        target_url: str,
    ) -> list[dict[str, Any]]:
        """Probe the models endpoint."""
        # In production: actual HTTP call to /v1/models
        return [
            {"id": "gpt-4-turbo", "object": "model"},
            {"id": "gpt-3.5-turbo", "object": "model"},
        ]

    async def _detect_single_model(
        self,
        target_url: str,
        model_info: dict[str, Any],
    ) -> ModelCapability:
        """Detect capabilities for a single model."""
        model_id = model_info.get("id", "")
        capability = ModelCapability(model_name=model_id)

        # Fingerprint model family
        capability = self._fingerprint_model(capability)

        # Probe capabilities
        capability.supports_streaming = self._check_streaming(model_id)
        capability.supports_functions = self._check_functions(model_id)
        capability.supports_vision = self._check_vision(model_id)
        capability.supports_system_prompt = True  # Most modern models

        return capability

    def _fingerprint_model(self, cap: ModelCapability) -> ModelCapability:
        """Fingerprint model family and version."""
        model_lower = cap.model_name.lower()

        for pattern, info in self.MODEL_FINGERPRINTS.items():
            if pattern in model_lower:
                cap.model_family = info["family"]
                cap.context_window = info["context"]
                cap.model_version = cap.model_name
                break

        return cap

    def _check_streaming(self, model_id: str) -> bool:
        """Check if model supports streaming."""
        # Most modern OpenAI-compatible APIs support streaming
        return True

    def _check_functions(self, model_id: str) -> bool:
        """Check if model supports function calling."""
        function_models = ["gpt-4", "gpt-3.5", "claude-3", "gemini"]
        return any(m in model_id.lower() for m in function_models)

    def _check_vision(self, model_id: str) -> bool:
        """Check if model supports vision."""
        vision_keywords = ["vision", "gpt-4v", "claude-3", "gemini-pro"]
        return any(kw in model_id.lower() for kw in vision_keywords)

    def _find_fastest(
        self,
        capabilities: list[ModelCapability],
    ) -> str:
        """Find the fastest responding model."""
        if not capabilities:
            return ""
        # Simplified: shortest name usually = faster
        return min(capabilities, key=lambda m: len(m.model_name)).model_name

    def _find_largest_context(
        self,
        capabilities: list[ModelCapability],
    ) -> str:
        """Find model with largest context window."""
        if not capabilities:
            return ""
        return max(capabilities, key=lambda m: m.context_window).model_name

    def _find_least_restricted(
        self,
        capabilities: list[ModelCapability],
    ) -> str:
        """Find the least safety-restricted model."""
        if not capabilities:
            return ""
        # Open source models typically less restricted
        open_source = ["llama", "mistral", "phi", "qwen"]
        for cap in capabilities:
            if any(os in cap.model_name.lower() for os in open_source):
                return cap.model_name
        return capabilities[0].model_name


async def detect_model_capabilities(
    target_url: str,
) -> CapabilityDetectionResult:
    """Convenience function for model capability detection."""
    detector = ModelCapabilityDetector()
    return await detector.detect_capabilities(target_url)
