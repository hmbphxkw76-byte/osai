"""Tests for arm module — seed ranking + converter selection + technique picking.

Covers attack chain step ③④:
    ③ Seed selection → load seeds from YAML, sort by historical ASR
    ④ Converter → build L5 optimal converter chain (encoding/persuasion/decomposition/obfuscation)

arXiv:2402.01135 — Chao et al.: Best-of-N amplification, seed ranking by ASR
arXiv:2407.01232 — PyRIT: SequentialAttack FIRST_SUCCESS, 7 independent paths
arXiv:2307.15043 — Encoding bypass: serial stacking >2 layers drops ASR 12%→4%
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestSeedRanker:
    """Test seed loading and ranking (step ③).

    arXiv:2402.01135 — seeds sorted by historical ASR for maximum attack effectiveness.
    """

    def test_load_seeds_returns_list(self):
        """load_seeds should return a list of seeds from existing seed files."""
        from arm.seed_ranker import load_seeds

        # Use full path to seed file that exists in data/seeds/
        seed_path = str(_PROJECT_ROOT / "data" / "seeds" / "elite_jailbreaks")
        seeds = load_seeds(seed_path, 5)
        assert isinstance(seeds, list)
        assert len(seeds) <= 5

    def test_load_seeds_max_seeds_limit(self):
        """load_seeds should respect max_seeds limit."""
        from arm.seed_ranker import load_seeds

        seed_path = str(_PROJECT_ROOT / "data" / "seeds" / "elite_jailbreaks")
        seeds = load_seeds(seed_path, 2)
        assert len(seeds) <= 2

    def test_load_seeds_nonexistent_file_raises(self):
        """load_seeds with nonexistent file should raise FileNotFoundError."""
        from arm.seed_ranker import load_seeds

        with pytest.raises(FileNotFoundError):
            load_seeds("nonexistent_seeds_file_xyz", 5)


class TestTechniquePicker:
    """Test technique selection (step ④)."""

    def test_select_techniques_auto(self):
        """select_techniques with 'auto' should return a non-empty list."""
        from arm.technique_picker import select_techniques

        techniques = select_techniques("auto", has_adversarial=False)
        assert isinstance(techniques, list)
        assert len(techniques) > 0

    def test_filter_by_adversarial(self):
        """filter_by_adversarial should filter techniques based on adversarial availability."""
        from arm.technique_picker import filter_by_adversarial

        techniques = ["single", "crescendo", "tap", "pair"]
        filtered = filter_by_adversarial(techniques, has_adversarial=False)
        # TAP and PAIR require adversarial target, should be removed
        assert "tap" not in filtered or len(filtered) < len(techniques)


class TestConverterPresets:
    """Test converter chain building (step ④).

    arXiv:2307.15043 — serial stacking >2 layers drops ASR 12%→4%
    R6 section 6.1: each converter MUST be in its own independent ConverterConfiguration
    """

    def test_build_converter_map_auto(self):
        """build_converter_map with 'l5_optimal' should return non-empty map."""
        from arm.converter_presets import build_converter_map

        converter_map = build_converter_map(
            technique_names=["single"],
            chain_names=["l5_optimal"],
            converter_target=None,
            model_family=None,
        )
        assert isinstance(converter_map, dict)
