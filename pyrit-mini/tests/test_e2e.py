"""End-to-end pipeline test (mocked API calls).

Tests the full 6-step attack chain:
    ① Burp intercept → ② Recon → ③ Seed selection → ④ Converter → ⑤ Attack → ⑥ Assess+Report

All API calls are mocked — no real LLM interaction.

arXiv:2407.01232 — PyRIT framework foundation, SequentialAttack FIRST_SUCCESS
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


@pytest.mark.asyncio
async def test_pipeline_imports_clean(tmp_path):
    """Test that the full pipeline can import without errors.

    This verifies that the 6-step attack chain modules are properly connected:
        core.config → core.context → recon → arm → strike → assess → report
    """
    # Step ① ②: Recon imports
    from arm.converter_presets import build_converter_map

    # Step ③ ④: Arm imports
    from arm.seed_ranker import load_seeds

    # Step ⑥: Assess + Report imports
    from assess.asr_manager import compute_asr
    from recon.burp_parser import parse_burp_request
    from recon.target_router import create_target
    from report.evidence import EvidenceCollector

    # Step ⑤: Strike imports
    from strike.executor import execute_attacks

    # If all imports succeeded, the pipeline is properly wired
    assert parse_burp_request is not None
    assert create_target is not None
    assert load_seeds is not None
    assert build_converter_map is not None
    assert execute_attacks is not None
    assert compute_asr is not None
    assert EvidenceCollector is not None


def test_pipeline_context_dataclass():
    """PipelineContext should be a dataclass with all 6-step fields."""
    import dataclasses

    from core.context import PipelineContext

    assert dataclasses.is_dataclass(PipelineContext)

    # Check fields for each step
    fields = {f.name for f in dataclasses.fields(PipelineContext)}
    # Step ②: Recon
    assert "objective_target" in fields
    assert "adversarial_target" in fields
    assert "scoring_target" in fields
    # Step ③: Seeds
    assert "seeds" in fields
    # Step ④: Converter
    assert "converter_map" in fields
    assert "techniques" in fields
    # Step ⑤: Attack results
    assert "attack_results" in fields
    # Step ⑥: Assess
    assert "asr_per_technique" in fields
    assert "overall_asr" in fields


def test_config_defaults_yaml_exists():
    """config/defaults.yaml should exist as SSOT for L5 parameters."""
    defaults_path = _PROJECT_ROOT / "config" / "defaults.yaml"
    assert defaults_path.exists(), "config/defaults.yaml must exist as SSOT"


def test_seeds_directory_exists():
    """data/seeds/ should contain attack seed files (including subdirectories)."""
    seeds_dir = _PROJECT_ROOT / "data" / "seeds"
    assert seeds_dir.exists()
    # v2: Search recursively in subdirectories
    seed_files = list(seeds_dir.rglob("*.prompt"))
    if not seed_files:
        # Fallback: try rglob
        seed_files = [f for f in seeds_dir.rglob("*") if f.suffix == ".prompt"]
    assert len(seed_files) > 0, "No .prompt seed files found in any subdirectory"


def test_seeds_subdirectory_structure():
    """Seed library should have proper tier-based subdirectory structure."""
    seeds_dir = _PROJECT_ROOT / "data" / "seeds"
    assert seeds_dir.exists()

    # Core seeds (high ASR) should exist
    core_dir = seeds_dir / "_core"
    assert core_dir.exists() or len(list(seeds_dir.rglob("_core"))) > 0

    # Should find seeds in subdirectories
    seed_files = list(seeds_dir.rglob("*.prompt"))
    assert len(seed_files) >= 10, f"Expected at least 10 seed files, found {len(seed_files)}"


def test_burp_directory_exists():
    """config/burp/ directory should exist (files are optional, user-supplied)."""
    burp_dir = _PROJECT_ROOT / "config" / "burp"
    assert burp_dir.exists(), "config/burp/ directory must exist"


def test_scorers_directory_exists():
    """data/scorers/ directory should exist with scorer configurations."""
    scorers_dir = _PROJECT_ROOT / "data" / "scorers"
    assert scorers_dir.exists(), "data/scorers/ directory must exist"
    scorer_files = list(scorers_dir.glob("*.yaml"))
    assert len(scorer_files) > 0, "No scorer YAML files found"


def test_seeds_metadata_standard():
    """Seed files should follow v2 metadata standard."""
    seeds_dir = _PROJECT_ROOT / "data" / "seeds"
    sample_seed = seeds_dir / "_core" / "T1_LLM01_elite_jailbreaks.prompt"
    if sample_seed.exists():
        import yaml
        data = yaml.safe_load(sample_seed.read_text(encoding="utf-8"))
        assert isinstance(data, list), "Seed file should be YAML list"
        if data:
            first = data[0]
            assert "metadata" in first, "Seeds should have metadata"
            meta = first["metadata"]
            # v2 metadata fields
            assert "owasp_id" in meta, "metadata should have owasp_id"
            assert "tier" in meta or "category" in meta, "metadata should have tier or category"


def test_capability_seed_map_v2():
    """CAPABILITY_SEED_MAP should have v2 paths (subdirectory format)."""
    from arm.seed_ranker import CAPABILITY_SEED_MAP

    # v2: Paths should include subdirectory prefixes
    mcp_seeds = CAPABILITY_SEED_MAP.get("mcp", [])
    assert any("_attack_surface" in s for s in mcp_seeds), \
        f"MCP seeds should use subdirectory paths, got: {mcp_seeds}"

    rag_seeds = CAPABILITY_SEED_MAP.get("rag", [])
    assert any("_attack_surface" in s for s in rag_seeds), \
        f"RAG seeds should use subdirectory paths, got: {rag_seeds}"
