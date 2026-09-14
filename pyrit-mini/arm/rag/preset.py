"""arm/rag/preset — rag object-axis converter preset.

Real per-object converter configuration lives here (mirrors strike/rag/).
Delegates to arm.converter_presets for the actual L5 converter construction,
pinning the target_type that characterizes the rag attack surface.
"""
from __future__ import annotations

from typing import Any

from arm.converter_presets import (
    build_object_preset_converters,
    l5_optimal,
)

# Target type that characterizes the rag attack surface.
TARGET_TYPE = "mcp_agent"


def build_converters(
    technique_names: list[str],
    chain_names: list[str],
    converter_target: Any | None = None,
    model_family: str | None = None,
    *,
    target_fingerprint: dict[str, Any] | None = None,
    converter_overrides: dict[str, list[str]] | None = None,
    seeds: list[Any] | None = None,
) -> dict[str, list[Any]]:
    """Build the rag-specific technique-aware converter map.

    Delegates to ``arm.converter_presets.build_object_preset_converters``,
    which honors ``config/components/rag.yaml`` ``converter_presets`` (the
    high-ASR default combo) via ``core.technique_registry``, falling back to
    the target-aware ``build_converter_map`` (W0 zero regression).
    """
    return build_object_preset_converters(
        "rag",
        technique_names,
        chain_names,
        converter_target,
        model_family=model_family,
        target_type=TARGET_TYPE,
        target_fingerprint=target_fingerprint,
        converter_overrides=converter_overrides,
        seeds=seeds,
    )


def candidate_converters(
    converter_target: Any | None = None,
    *,
    model_family: str | None = None,
) -> list[Any]:
    """L5 candidate converters appropriate for the rag attack surface."""
    return l5_optimal(converter_target, target_type=TARGET_TYPE)
