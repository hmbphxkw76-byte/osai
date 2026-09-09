"""
数据流完整性测试 — 共用 fixtures 和 mock 对象

被 test_data_flow_integrity.py 和 test_data_flow_forensic.py 共享。
包含 MockParserRequest / MockTargetFingerprint / create_mock_ctx 等测试工具。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.data_flow_hooks import reset_validator  # noqa: E402


class MockParserRequest:
    """Mock parsed request for testing."""
    target_fingerprint = {
        "model_family": "gpt-4",
        "language": "en",
        "capabilities": ["function_calling", "reasoning"],
    }


class MockTargetFingerprint:
    """Mock target fingerprint for testing."""
    model_family = "gpt-4"
    language = "en"


def create_mock_ctx(
    phase: str = "recon",
    include_mcpsec: bool = False,
    include_rag: bool = False,
) -> Any:
    """
    Create mock PipelineContext for testing.

    Args:
        phase: Simulated phase ("recon", "arm", "strike", "assess", "report")
        include_mcpsec: Whether to include MCPSec data
        include_rag: Whether to include RAG data
    """
    ctx = MagicMock()

    # Base fields -- present in all phases
    ctx.objective_target = MagicMock()
    ctx.parsed_request = MockParserRequest()

    # Recon output
    ctx.service_profile = {
        "model_name": "gpt-4",
        "auth_type": "bearer_token",
        "rag_kb_map": {"document_count": 10} if include_rag else {},
        "streaming_supported": True,
    }

    # MCPSec output
    ctx.mcpsec_surface = {
        "tools": [{"name": "search"}, {"name": "execute"}],
        "resources": [],
        "prompts": []
    } if include_mcpsec else {}
    ctx.mcpsec_scan_results = {
        "vulnerabilities": [
            {"severity": "high", "tool": "search", "description": "IDOR"}
        ]
    } if include_mcpsec else {}

    # ARM output
    ctx.seeds = [
        {"value": "test_seed_1", "category": "jailbreak"},
        {"value": "test_seed_2", "category": "role_play"},
        {"value": "test_seed_3", "category": "skeleton_key"},
    ]
    ctx.techniques = ["skeleton_key", "crescendo", "role_play"]
    ctx.converter_map = {
        "skeleton_key": ["Base64Converter", "StringJoinConverter"],
        "crescendo": ["TranslationConverter"],
        "role_play": ["ToneConverter", "StringJoinConverter"],
    }

    # Strike output
    ctx.attack_results = {
        "skeleton_key": [MagicMock(), MagicMock()],
        "crescendo": [MagicMock()],
        "role_play": [MagicMock(), MagicMock(), MagicMock()],
    }

    # Assess output
    ctx.asr_per_technique = {
        "skeleton_key": 66.67,
        "crescendo": 33.33,
        "role_play": 50.0,
    }
    ctx.overall_asr = 50.0
    ctx.dual_judge_stats = {
        "total_scored": 6,
        "agreements": 5,
        "disagreements": 1,
        "cohens_kappa": 0.78,
    }
    ctx.wilson_ci = (0.21, 0.79)

    # Audit log
    ctx.orchestration_log = [
        {"phase": "recon", "status": "completed"},
        {"phase": "arm", "status": "completed"},
        {"phase": "strike", "status": "completed"},
        {"phase": "assess", "status": "completed"},
        {"phase": "report", "status": "completed"},
    ]

    # Report/Evidence phase
    ctx.evidence_collection = MagicMock()
    ctx.evidence_collection.total_attacks = 6
    ctx.evidence_collection.successful_attacks = 3
    ctx.evidence_collection.findings = [
        {"title": "Prompt Injection", "severity": "high"},
        {"title": "Role Play Bypass", "severity": "medium"},
    ]
    ctx.evidence_collection.owasp_llm_compliance = {
        "LLM01": {"tested": 6, "success": 3, "asr": 50.0}
    }

    # ASR Forensic data (Why Success/Refusal)
    ctx.successful_evidence_log = [
        {
            "technique": "skeleton_key",
            "converter_chain": "Base64Converter+StringJoinConverter",
            "prompt_snippet": "Test prompt",
            "response_snippet": "Successful response",
            "timestamp": 1234567890.0,
        },
        {
            "technique": "role_play",
            "converter_chain": "ToneConverter",
            "prompt_snippet": "Role play prompt",
            "response_snippet": "Successful response",
            "timestamp": 1234567891.0,
        },
    ]
    ctx.refusal_classification_log = [
        {
            "technique": "crescendo",
            "converter_chain": "TranslationConverter",
            "refusal_type": "guardrail",
            "matched_pattern": "i cannot",
            "confidence": 0.8,
            "response_snippet": "I cannot help with that",
        },
        {
            "technique": "skeleton_key",
            "converter_chain": "Base64Converter",
            "refusal_type": "content_policy",
            "matched_pattern": "harmful",
            "confidence": 0.7,
            "response_snippet": "This content is harmful",
        },
        {
            "technique": "role_play",
            "converter_chain": "StringJoinConverter",
            "refusal_type": "format",
            "matched_pattern": "please rephrase",
            "confidence": 0.6,
            "response_snippet": "Please rephrase your request",
        },
    ]
    ctx.guardrail_triggers = [
        {
            "technique": "crescendo",
            "converter_chain": "TranslationConverter",
            "trigger_token": "i cannot",
            "rule_name": "guardrail_pattern_i_cannot",
            "confidence": 0.8,
            "context_snippet": "...I cannot help with that...",
        },
    ]
    ctx.timing_metadata = [
        {"technique": "skeleton_key", "converter_chain": "Base64Converter", "request_time": 1.0, "response_time": 2.5, "total_ms": 1500.0},
        {"technique": "crescendo", "converter_chain": "TranslationConverter", "request_time": 2.5, "response_time": 4.0, "total_ms": 1500.0},
        {"technique": "role_play", "converter_chain": "ToneConverter", "request_time": 4.0, "response_time": 5.2, "total_ms": 1200.0},
    ]

    return ctx


@pytest.fixture(autouse=True)
def _reset_validator():
    """在每个测试前重置全局验证器状态."""
    reset_validator()
    yield
    reset_validator()


@pytest.fixture
def mock_ctx():
    """返回默认 mock ctx."""
    return create_mock_ctx(phase="report")


@pytest.fixture
def mock_ctx_with_mcpsec():
    """返回包含 MCPSec 数据的 mock ctx."""
    return create_mock_ctx(phase="report", include_mcpsec=True, include_rag=True)
