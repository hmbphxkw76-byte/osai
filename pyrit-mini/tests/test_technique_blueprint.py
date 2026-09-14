"""Tests for core.phases.technique_blueprint — unified optimal combination selector.

Patches the registry / ASR-rerank internals so the test needs no live PyRIT
target or real component YAML.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import core.phases.technique_blueprint as tb


def test_blueprint_resolves_seeds_converters_strike_scorer(tmp_path: Path) -> None:
    seed_dir = tmp_path / "seeds" / "mcp"
    seed_dir.mkdir(parents=True)
    (seed_dir / "x.prompt").write_text("seed")

    fake_raw = {
        "id": "mcp",
        "seed_sets": [str(seed_dir)],
        "converter_presets": ["FakeConv"],
        "assess": {"t0_check": "assess.component_scorers:t0_mcp_tool_poisoning_check"},
    }

    class _FakeReg:
        def get(self, key: str) -> dict:  # noqa: ANN001
            return fake_raw

    fake_convs = [object(), object()]

    with mock.patch.object(tb, "get_registry", lambda: _FakeReg()), mock.patch.object(
        tb, "resolve_converters", return_value=fake_convs
    ), mock.patch.object(tb, "_asr_rerank", side_effect=lambda c, ctx: c), mock.patch.object(
        tb, "_select_strike", return_value=[(1, "prompt_sending", 10)]
    ), mock.patch.object(tb, "_resolve_t0_scorer", return_value=lambda t: (False, 0.0, "x")):
        bp = tb.build_optimal_blueprint("mcp")

    assert bp.object_key == "mcp"
    assert len(bp.seed_files) == 1
    assert bp.converters == fake_convs
    assert bp.strike_strategies == [(1, "prompt_sending", 10)]
    assert callable(bp.t0_scorer)
    assert "mcp" in bp.to_dict()["object_key"]


def test_blueprint_unknown_object_returns_empty() -> None:
    class _EmptyReg:
        def get(self, key: str):  # noqa: ANN001
            return None

    with mock.patch.object(tb, "get_registry", lambda: _EmptyReg()):
        bp = tb.build_optimal_blueprint("nonexistent_obj")

    assert bp.object_key == "nonexistent_obj"
    assert bp.seed_files == []
    assert bp.converters == []
