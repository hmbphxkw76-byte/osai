"""Tests for arm/seed_ranker.py — ASR-based seed ranking."""

from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestSeedRanker:
    """Tests for load_seeds function."""

    def test_load_seeds_returns_list(self):
        """load_seeds should return a list of seeds from existing seed files."""
        from arm.seed_ranker import load_seeds

        # v2: Use new path with subdirectory prefix
        seed_path = str(_PROJECT_ROOT / "data" / "seeds" / "_core" / "T1_LLM01_elite_jailbreaks")
        seeds = load_seeds(seed_path, 5)
        assert isinstance(seeds, list)
        assert len(seeds) <= 5

    def test_load_seeds_max_seeds_limit(self):
        """load_seeds should respect max_seeds limit."""
        from arm.seed_ranker import load_seeds

        # v2: Use new path with subdirectory prefix
        seed_path = str(_PROJECT_ROOT / "data" / "seeds" / "_core" / "T1_LLM01_elite_jailbreaks")
        seeds = load_seeds(seed_path, 2)
        assert len(seeds) <= 2

    def test_load_seeds_nonexistent_file_raises(self):
        """load_seeds with nonexistent file should raise FileNotFoundError."""
        from arm.seed_ranker import load_seeds

        with pytest.raises(FileNotFoundError):
            load_seeds("nonexistent_seeds_file_xyz", 5)


class TestCapabilitySeedMap:
    """Tests for CAPABILITY_SEED_MAP — capability-to-seed-file mapping."""

    def test_mcp_capability_maps_to_mcp_seeds(self):
        """MCP capability should map to MCP seed files."""
        from arm.seed_ranker import CAPABILITY_SEED_MAP

        assert "mcp" in CAPABILITY_SEED_MAP
        mcp_seeds = CAPABILITY_SEED_MAP["mcp"]
        assert len(mcp_seeds) >= 1
        # v2: Check new path format
        assert any("_attack_surface" in s for s in mcp_seeds)

    def test_rag_capability_maps_to_rag_seeds(self):
        """RAG capability should map to RAG seed files."""
        from arm.seed_ranker import CAPABILITY_SEED_MAP

        assert "rag" in CAPABILITY_SEED_MAP
        rag_seeds = CAPABILITY_SEED_MAP["rag"]
        assert len(rag_seeds) >= 1
        # v2: Check new path format
        assert any("_attack_surface" in s or "_core" in s for s in rag_seeds)

    def test_function_calling_capability_maps_to_function_seeds(self):
        """function_calling capability should map to function call exploit seeds."""
        from arm.seed_ranker import CAPABILITY_SEED_MAP

        assert "function_calling" in CAPABILITY_SEED_MAP
        fc_seeds = CAPABILITY_SEED_MAP["function_calling"]
        assert len(fc_seeds) >= 1
        # v2: Check new path format
        assert any("_core" in s for s in fc_seeds)

    def test_a2a_protocol_has_backward_compat_alias(self):
        """a2a_protocol and a2a should both exist for backward compatibility."""
        from arm.seed_ranker import CAPABILITY_SEED_MAP

        assert "a2a_protocol" in CAPABILITY_SEED_MAP
        assert "a2a" in CAPABILITY_SEED_MAP
        assert CAPABILITY_SEED_MAP["a2a_protocol"] == CAPABILITY_SEED_MAP["a2a"]


class TestSeedRankingIntegration:
    """Integration tests for seed loading + ranking."""

    def test_load_mcp_seeds_from_new_directory(self):
        """Should load MCP seeds from new _attack_surface directory structure."""
        from arm.seed_ranker import load_seeds

        seed_path = "_attack_surface/T1_ASI02_mcp_full_surface/mcp_tool_enum"
        seeds = load_seeds(seed_path, 10)
        assert isinstance(seeds, list)
        # Should load seeds without error

    def test_load_rag_seeds_from_new_directory(self):
        """Should load RAG seeds from new _attack_surface directory structure."""
        from arm.seed_ranker import load_seeds

        seed_path = "_attack_surface/T1_LLM08_rag_full_surface/rag_full_attack_surface"
        seeds = load_seeds(seed_path, 10)
        assert isinstance(seeds, list)
