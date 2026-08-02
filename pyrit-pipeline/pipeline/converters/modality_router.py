# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Modality Router — L5 Expert modality-aware technique filtering.

Uses PyRIT native TargetCapabilities to:
1. Check target capabilities (multi-turn/multi-message/JSON/system prompt/streaming)
2. Auto-route attacks based on target capabilities (skip unsupported)
3. Validate multimodal seed messages (text + image_path mixed)
4. Ensure seed message data types are supported by target

Design principles:
- Uses native TargetCapabilities (frozen BaseModel)
- Does not modify target instance capabilities
- Provides clear degradation strategy (skip or downgrade when unsupported)

Aligned with PyRIT:
- pyrit.prompt_target.common.target_capabilities.TargetCapabilities
- pyrit.prompt_target.common.target_capabilities.CapabilityName
- pyrit.models.PromptDataType (text/image_path/audio_path/video_path/...)

> **Date**: 2026-8-2
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Text-only capabilities (default for Ollama, vLLM, etc.)
TEXT_ONLY_CAPABILITIES: Any = None  # Lazy-initialized on first use


def _get_text_only_capabilities() -> Any:
    """Get text-only TargetCapabilities instance (lazy init)."""
    global TEXT_ONLY_CAPABILITIES
    if TEXT_ONLY_CAPABILITIES is None:
        try:
            from pyrit.prompt_target.common.target_capabilities import TargetCapabilities

            TEXT_ONLY_CAPABILITIES = TargetCapabilities()
        except ImportError:
            logger.debug("TargetCapabilities not available, using None as fallback")
    return TEXT_ONLY_CAPABILITIES


class ModalityRouter:
    """Modality-aware technique filter — uses PyRIT native TargetCapabilities.

    Automatically determines if an attack needs degradation or skip:
    - Multi-turn attack -> check supports_multi_turn
    - Multi-message pieces -> check supports_multi_message_pieces
    - Image input -> check input_modalities includes image_path
    - JSON output -> check supports_json_output
    - System Prompt -> check supports_system_prompt

    Usage:
        router = ModalityRouter()
        caps = router.get_capabilities(target)
        if router.supports_modality(target, "image_path", direction="input"):
            # Send multimodal message
            ...
        else:
            # Degrade to text-only
            logger.warning("Target doesn't support image input, downgrading to text")
    """

    # Map capability names to CapabilityName enum values
    _CAPABILITY_MAP: dict[str, str] = {
        "multi_turn": "MULTI_TURN",
        "multi_message_pieces": "MULTI_MESSAGE_PIECES",
        "json_schema": "JSON_SCHEMA",
        "json_output": "JSON_OUTPUT",
        "editable_history": "EDITABLE_HISTORY",
        "system_prompt": "SYSTEM_PROMPT",
        "streaming_audio": "STREAMING_AUDIO",
    }

    @staticmethod
    def get_capabilities(target: Any) -> Any:
        """Get the TargetCapabilities of a target.

        Priority:
        1. Target instance's capabilities attribute
        2. Target class's _DEFAULT_CONFIGURATION.capabilities
        3. Fallback to text-only default

        Args:
            target: PromptTarget instance

        Returns:
            TargetCapabilities instance
        """
        caps = getattr(target, "_capabilities", None)
        if caps is not None:
            return caps

        # Try from _DEFAULT_CONFIGURATION
        default_config = getattr(type(target), "_DEFAULT_CONFIGURATION", None)
        if default_config is not None:
            caps_attr = getattr(default_config, "capabilities", None)
            if caps_attr is not None:
                return caps_attr

        # Fallback to text-only default
        return _get_text_only_capabilities()

    @staticmethod
    def supports_modality(
        target: Any,
        data_type: str,
        direction: str = "input",
    ) -> bool:
        """Check if target supports a specified modality.

        Args:
            target: PromptTarget instance
            data_type: Data type (e.g., "text", "image_path", "audio_path", "video_path")
            direction: Direction — "input" or "output"

        Returns:
            bool: Whether supported
        """
        caps = ModalityRouter.get_capabilities(target)

        if direction == "input":
            supported = caps.supported_input_modalities
        elif direction == "output":
            supported = caps.supported_output_modalities
        else:
            logger.warning("Invalid direction: %s", direction)
            return False

        return data_type in supported

    @staticmethod
    def supports_audio_input(target: Any) -> bool:
        """Quick check: does target support audio input?"""
        return ModalityRouter.supports_modality(target, "audio_path", "input")

    @staticmethod
    def supports_image_input(target: Any) -> bool:
        """Quick check: does target support image input?"""
        return ModalityRouter.supports_modality(target, "image_path", "input")

    @staticmethod
    def supports_multi_turn(target: Any) -> bool:
        """Quick check: does target support multi-turn conversation?"""
        caps = ModalityRouter.get_capabilities(target)
        return getattr(caps, "supports_multi_turn", False)

    @staticmethod
    def filter_techniques_by_capability(
        techniques: list[str],
        target: Any,
        *,
        multi_turn_techniques: set[str] | None = None,
        multimodal_techniques: set[str] | None = None,
    ) -> tuple[list[str], list[str]]:
        """Filter technique list based on target capabilities.

        Techniques that require capabilities the target doesn't support
        are filtered out.

        Args:
            techniques: List of technique names
            target: PromptTarget instance
            multi_turn_techniques: Set of technique names that require multi-turn
            multimodal_techniques: Set of technique names that require multimodal

        Returns:
            (supported_techniques, filtered_techniques)
        """
        if target is None:
            return techniques, []

        supported: list[str] = []
        filtered: list[str] = []

        supports_mt = ModalityRouter.supports_multi_turn(target)
        supports_img = ModalityRouter.supports_image_input(target)

        multi_turn_set = multi_turn_techniques or set()
        multimodal_set = multimodal_techniques or set()

        for tech in techniques:
            tech_lower = tech.lower()

            # Check multi-turn requirement
            if tech_lower in multi_turn_set and not supports_mt:
                filtered.append(tech)
                logger.info("ModalityRouter: filtering '%s' (requires multi-turn, target doesn't support)", tech)
                continue

            # Check multimodal requirement
            if tech_lower in multimodal_set and not supports_img:
                filtered.append(tech)
                logger.info("ModalityRouter: filtering '%s' (requires image input, target doesn't support)", tech)
                continue

            supported.append(tech)

        return supported, filtered
