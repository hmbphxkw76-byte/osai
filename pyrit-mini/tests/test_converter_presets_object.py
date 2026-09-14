"""Tests for arm.converter_presets.build_object_preset_converters.

Verifies the per-component ``converter_presets`` override path and the W0
fallback to ``build_converter_map`` (zero regression guarantee).
"""

from __future__ import annotations

from unittest import mock

import arm.converter_presets as cp


def test_prefers_converter_presets() -> None:
    fake_raw = {"id": "mcp", "converter_presets": ["DecompositionConverter", "PersuasionConverter"]}
    fake_convs = [object(), object()]

    class _Reg:
        def get(self, key):  # noqa: ANN001
            return fake_raw if key in ("mcp", "mcp_tool_poisoning") else None

    with mock.patch("core.registry.get_registry", lambda: _Reg()), mock.patch(
        "core.technique_registry.resolve_converters", return_value=fake_convs
    ), mock.patch(
        "arm.converter_selector._prune_low_asr_converters", side_effect=lambda c, ctx: c
    ):
        result = cp.build_object_preset_converters(
            "mcp",
            ["prompt_sending", "crescendo"],
            ["x"],
            target_type="mcp_agent",
        )

    # baseline technique gets empty list; others get the preset converters
    assert result["prompt_sending"] == []
    assert result["crescendo"] == fake_convs


def test_falls_back_to_build_converter_map() -> None:
    fallback = {"crescendo": [object()]}

    class _EmptyReg:
        def get(self, key):  # noqa: ANN001
            return None

    with mock.patch("core.registry.get_registry", lambda: _EmptyReg()), mock.patch.object(
        cp, "build_converter_map", return_value=fallback
    ) as m:
        result = cp.build_object_preset_converters(
            "mcp", ["crescendo"], ["x"], target_type="mcp_agent"
        )

    assert result is fallback
    m.assert_called_once()
