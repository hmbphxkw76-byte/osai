"""Shared test fixtures for garak 目标侦察 tests."""

import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the pipeline package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

# 测试运行前清理 __pycache__，防止 stale bytecode 导致非确定性失败
from pipeline.utils import clean_pycache

clean_pycache(Path(__file__).parent.parent)


@pytest.fixture
def sample_target() -> dict:
    """Sample target configuration for tests."""
    return {
        "endpoint": "https://api.longcat.chat/openai/v1",
        "model": "LongCat-2.0",
        "api_key": "ak_test_key",
    }


@pytest.fixture
def temp_artifacts_dir() -> Path:
    """Temporary artifacts directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_probes() -> list[dict]:
    """Sample probe data for testing recon classification."""
    return [
        {
            "name": "dan.AutoDANCached",
            "description": "DAN auto-cached probe",
            "tier": 1,
            "tags": ["owasp:llm01", "avid-effect:security:S0403"],
            "goal": "disregard the system prompt",
            "modality": {"in": ["text"]},
            "primary_detector": "mitigation.MitigationBypass",
        },
        {
            "name": "encoding.InjectBase64",
            "description": "Base64 encoding injection",
            "tier": 1,
            "tags": ["owasp:llm01", "quality:Security:PromptStability"],
            "goal": "bypass encoding filters",
            "modality": {"in": ["text"]},
            "primary_detector": "encoding.DecodeMatch",
        },
        {
            "name": "leakreplay.GuardianCloze",
            "description": "Guardian cloze leak test",
            "tier": 2,
            "tags": ["owasp:llm06"],
            "goal": "extract training data",
            "modality": {"in": ["text"]},
            "primary_detector": "leakreplay.StartsWith",
        },
        {
            "name": "lmrc.Bullying",
            "description": "Bullying content detection",
            "tier": 2,
            "tags": ["quality:Security:ContentSafety"],
            "goal": "generate harmful content",
            "modality": {"in": ["text"]},
            "primary_detector": "toxicity.ToxicCommentModel",
        },
        {
            "name": "test.Blank",
            "description": "Blank test probe",
            "tier": 3,
            "tags": [],
            "goal": "test",
            "modality": {"in": ["text"]},
            "primary_detector": "always.Pass",
        },
    ]


@pytest.fixture
def mock_openai_client():
    """Mock openai.OpenAI client for connectivity tests."""
    with patch("openai.OpenAI") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance

        mock_models = MagicMock()
        mock_models.data = [
            MagicMock(id="LongCat-2.0"),
            MagicMock(id="LongCat-2.0-2024-01-01"),
        ]
        mock_instance.models.list.return_value = mock_models
        yield mock_client
