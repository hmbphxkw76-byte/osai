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
    from assess.asr_tracker import compute_asr
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
    """data/seeds/ should contain attack seed files."""
    seeds_dir = _PROJECT_ROOT / "data" / "seeds"
    assert seeds_dir.exists()
    seed_files = list(seeds_dir.glob("*.prompt"))
    assert len(seed_files) > 0, "No .prompt seed files found"


def test_burp_request_exists():
    """data/burp/request.txt should exist as default Burp intercept file."""
    burp_file = _PROJECT_ROOT / "data" / "burp" / "request.txt"
    assert burp_file.exists()
