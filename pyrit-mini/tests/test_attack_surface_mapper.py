# -*- coding: utf-8 -*-
"""Tests for arm/attack_surface_mapper.py — Unified attack surface mapping framework.

Tests cover:
    1. VectorCategory / RiskLevel enums
    2. AttackVector dataclass
    3. AttackPlan aggregation methods
    4. AttackSurfaceMapper initialization
    5. Entry point mapping
    6. Processing point mapping
    7. Exit point mapping
    8. Persistence point mapping
    9. Full attack plan generation
    10. Factory function
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from arm.attack_surface_mapper import (
    AttackPlan,
    AttackSurfaceMapper,
    AttackVector,
    RiskLevel,
    VectorCategory,
    create_attack_surface_mapper,
)


@pytest.fixture
def minimal_ctx() -> MagicMock:
    """Create a minimal PipelineContext mock."""
    ctx = MagicMock()
    ctx.service_profile = {
        "primary_endpoint": "https://api.target.com/v1/chat",
        "auth_type": "bearer_token",
        "gateway_type": "",
        "inter_agent_protocol": "",
        "webhook_endpoints": [],
        "file_upload": False,
        "external_url_processing": False,
        "api_integrations": [],
        "available_tools": [],
        "memory_enabled": False,
        "session_enabled": False,
        "rag_enabled": False,
        "agent_coordination": False,
        "external_actions": [],
        "handoff_targets": [],
        "state_mutable": False,
        "history_enabled": True,
        "config_accessible": False,
        "logging_enabled": True,
        "cache_enabled": False,
        "system_prompt_leakable": True,
    }
    ctx.capabilities = {}
    ctx.mcpsec_surface = {}
    return ctx


@pytest.fixture
def full_ctx() -> MagicMock:
    """Create a complex PipelineContext mock with all features enabled."""
    ctx = MagicMock()
    ctx.service_profile = {
        "primary_endpoint": "https://api.target.com/v1/chat",
        "upload_endpoint": "https://api.target.com/v1/upload",
        "auth_type": "bearer_token",
        "auth_endpoint": "https://api.target.com/v1/auth",
        "gateway_type": "kong",
        "gateway_endpoint": "https://api.target.com/gateway",
        "inter_agent_protocol": "a2a",
        "agent_comm_endpoint": "https://api.target.com/v1/agent-msg",
        "webhook_endpoints": ["https://api.target.com/webhook/events"],
        "file_upload": True,
        "external_url_processing": True,
        "api_integrations": ["https://api.target.com/v1/search"],
        "available_tools": [
            "http_request",
            "database_query",
            "file_reader",
            "send_email",
        ],
        "memory_enabled": True,
        "memory_endpoint": "https://api.target.com/v1/memory",
        "session_enabled": True,
        "session_endpoint": "https://api.target.com/v1/session",
        "rag_enabled": True,
        "rag_endpoint": "https://api.target.com/v1/rag",
        "agent_coordination": True,
        "coordination_endpoint": "https://api.target.com/v1/coord",
        "external_actions": ["send_email", "trigger_webhook"],
        "handoff_targets": ["finance_agent", "research_agent"],
        "state_mutable": True,
        "state_endpoint": "https://api.target.com/v1/state",
        "history_enabled": True,
        "history_endpoint": "https://api.target.com/v1/history",
        "config_accessible": True,
        "config_endpoint": "https://api.target.com/v1/config",
        "logging_enabled": True,
        "logging_endpoint": "https://api.target.com/v1/logs",
        "cache_enabled": True,
        "cache_endpoint": "https://api.target.com/v1/cache",
        "system_prompt_leakable": True,
    }
    ctx.capabilities = {"multi_agent": True, "rag": True}
    ctx.mcpsec_surface = {
        "tools": [
            {"name": "mcp_tool_a"},
            {"name": "mcp_tool_b"},
        ],
    }
    return ctx


class TestEnums:
    """Test VectorCategory and RiskLevel enums."""

    def test_vector_category_values(self) -> None:
        """Verify enum members exist with correct values."""
        assert VectorCategory.ENTRY.value == "entry"
        assert VectorCategory.PROCESSING.value == "processing"
        assert VectorCategory.EXIT.value == "exit"
        assert VectorCategory.PERSISTENCE.value == "persistence"

    def test_risk_level_ordering(self) -> None:
        """Verify risk level ordering (CRITICAL > HIGH > MEDIUM > LOW)."""
        assert RiskLevel.CRITICAL.value > RiskLevel.HIGH.value
        assert RiskLevel.HIGH.value > RiskLevel.MEDIUM.value
        assert RiskLevel.MEDIUM.value > RiskLevel.LOW.value


class TestAttackVector:
    """Test AttackVector dataclass."""

    def test_create_vector(self) -> None:
        """Verify AttackVector can be created with required fields."""
        vec = AttackVector(
            vector_id="test_vector",
            category=VectorCategory.ENTRY,
            subcategory="user_prompt",
            description="Test description",
            target_endpoint="https://example.com",
            owasp_id="LLM01",
            risk_level=RiskLevel.HIGH,
        )
        assert vec.vector_id == "test_vector"
        assert vec.category == VectorCategory.ENTRY
        assert vec.asr_prior == 0.5  # default
        assert vec.evidence == []  # default

    def test_vector_with_metadata(self) -> None:
        """Verify AttackVector with all optional fields."""
        vec = AttackVector(
            vector_id="test_full",
            category=VectorCategory.PROCESSING,
            subcategory="tool_confusion",
            description="Full vector",
            target_endpoint="https://example.com/api",
            owasp_id="ASI02",
            risk_level=RiskLevel.CRITICAL,
            asr_prior=0.85,
            evidence=["tool detected"],
            exploit_references=["arXiv:2307.00929"],
        )
        assert vec.asr_prior == 0.85
        assert len(vec.evidence) == 1
        assert len(vec.exploit_references) == 1


class TestAttackPlan:
    """Test AttackPlan dataclass."""

    def test_empty_plan_summary(self) -> None:
        """Verify empty plan returns zero counts."""
        plan = AttackPlan()
        summary = plan.summary()
        assert summary["total"] == 0
        assert summary["entry"] == 0

    def test_all_vectors_sorted(self) -> None:
        """Verify all_vectors returns sorted list by ASR descending."""
        plan = AttackPlan()
        plan.entry_vectors = [
            AttackVector(
                vector_id="v1",
                category=VectorCategory.ENTRY,
                subcategory="a",
                description="low",
                target_endpoint="",
                owasp_id="LLM01",
                risk_level=RiskLevel.LOW,
                asr_prior=0.3,
            ),
            AttackVector(
                vector_id="v2",
                category=VectorCategory.ENTRY,
                subcategory="b",
                description="high",
                target_endpoint="",
                owasp_id="LLM01",
                risk_level=RiskLevel.CRITICAL,
                asr_prior=0.9,
            ),
        ]
        result = plan.all_vectors()
        assert len(result) == 2
        assert result[0].asr_prior == 0.9
        assert result[1].asr_prior == 0.3

    def test_critical_vectors_filter(self) -> None:
        """Verify critical_vectors returns only CRITICAL."""
        plan = AttackPlan()
        plan.entry_vectors = [
            AttackVector(
                vector_id="crit",
                category=VectorCategory.ENTRY,
                subcategory="a",
                description="critical",
                target_endpoint="",
                owasp_id="LLM01",
                risk_level=RiskLevel.CRITICAL,
            ),
            AttackVector(
                vector_id="low",
                category=VectorCategory.ENTRY,
                subcategory="b",
                description="low",
                target_endpoint="",
                owasp_id="LLM01",
                risk_level=RiskLevel.LOW,
            ),
        ]
        critical = plan.critical_vectors()
        assert len(critical) == 1
        assert critical[0].vector_id == "crit"


class TestAttackSurfaceMapper:
    """Test AttackSurfaceMapper core functionality."""

    def test_init_extracts_context(self, minimal_ctx: MagicMock) -> None:
        """Verify mapper extracts data from context."""
        mapper = AttackSurfaceMapper(minimal_ctx)
        assert mapper.service_profile == minimal_ctx.service_profile
        assert mapper.capabilities == {}
        assert mapper.mcpsec_surface == {}

    def test_generate_plan_returns_plan(self, minimal_ctx: MagicMock) -> None:
        """Verify generate_attack_plan returns AttackPlan."""
        mapper = AttackSurfaceMapper(minimal_ctx)
        plan = mapper.generate_attack_plan()
        assert isinstance(plan, AttackPlan)

    def test_entry_points_always_has_prompt(self, minimal_ctx: MagicMock) -> None:
        """Verify entry vectors always includes direct prompt vector."""
        mapper = AttackSurfaceMapper(minimal_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.entry_vectors]
        assert "entry_prompt_direct" in ids

    def test_file_upload_creates_vector(self, full_ctx: MagicMock) -> None:
        """Verify file upload creates entry_file_upload vector."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.entry_vectors]
        assert "entry_file_upload" in ids

    def test_inter_agent_creates_vector(self, full_ctx: MagicMock) -> None:
        """Verify inter-agent protocol creates entry_inter_agent vector."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.entry_vectors]
        assert "entry_inter_agent" in ids

    def test_webhook_creates_vector(self, full_ctx: MagicMock) -> None:
        """Verify webhook endpoints create entry vectors."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.entry_vectors]
        assert any("entry_webhook" in vid for vid in ids)

    def test_tool_abuse_vector(self, full_ctx: MagicMock) -> None:
        """Verify tools detected creates tool abuse vector."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.processing_vectors]
        assert "proc_tool_abuse" in ids

    def test_http_tool_parameter_injection(self, full_ctx: MagicMock) -> None:
        """Verify HTTP tools create SSRF parameter injection vector."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.processing_vectors]
        assert "proc_param_injection_http" in ids

    def test_db_tool_parameter_injection(self, full_ctx: MagicMock) -> None:
        """Verify DB tools create SQL injection parameter injection vector."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.processing_vectors]
        assert "proc_param_injection_sql" in ids

    def test_file_tool_path_traversal(self, full_ctx: MagicMock) -> None:
        """Verify file tools create path traversal parameter injection vector."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.processing_vectors]
        assert "proc_param_injection_path" in ids

    def test_handoff_hijacking_vectors(self, full_ctx: MagicMock) -> None:
        """Verify handoff targets create exit handoff hijacking vectors."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.exit_vectors]
        assert "exit_handoff_0" in ids
        assert "exit_handoff_1" in ids

    def test_memory_persistence_vector(self, full_ctx: MagicMock) -> None:
        """Verify memory enabled creates persistence vector."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.persistence_vectors]
        assert "persist_shared_memory" in ids

    def test_history_persistence_vector(self, minimal_ctx: MagicMock) -> None:
        """Verify history enabled creates persistence vector."""
        mapper = AttackSurfaceMapper(minimal_ctx)
        plan = mapper.generate_attack_plan()
        ids = [v.vector_id for v in plan.persistence_vectors]
        assert "persist_history" in ids

    def test_plan_summary_counts(self, full_ctx: MagicMock) -> None:
        """Verify plan summary returns correct total count."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        summary = plan.summary()
        assert summary["total"] > 0
        assert summary["entry"] > 0
        assert summary["processing"] > 0
        assert summary["exit"] > 0
        assert summary["persistence"] > 0

    def test_vector_categories_correct(self, full_ctx: MagicMock) -> None:
        """Verify vectors have correct category assignments."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        for v in plan.entry_vectors:
            assert v.category == VectorCategory.ENTRY
        for v in plan.processing_vectors:
            assert v.category == VectorCategory.PROCESSING
        for v in plan.exit_vectors:
            assert v.category == VectorCategory.EXIT
        for v in plan.persistence_vectors:
            assert v.category == VectorCategory.PERSISTENCE

    def test_vectors_have_owasp_ids(self, full_ctx: MagicMock) -> None:
        """Verify all vectors have OWASP IDs assigned."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        for v in plan.all_vectors():
            assert v.owasp_id != ""
            assert v.owasp_id.startswith(("LLM", "ASI", "A"))

    def test_vectors_have_endpoints(self, full_ctx: MagicMock) -> None:
        """Verify vectors target specific endpoints."""
        mapper = AttackSurfaceMapper(full_ctx)
        plan = mapper.generate_attack_plan()
        for v in plan.all_vectors():
            assert v.target_endpoint != ""


class TestFactoryFunction:
    """Test factory function."""

    def test_create_attack_surface_mapper(self, minimal_ctx: MagicMock) -> None:
        """Verify factory returns configured mapper."""
        mapper = create_attack_surface_mapper(minimal_ctx)
        assert isinstance(mapper, AttackSurfaceMapper)
        assert mapper.service_profile == minimal_ctx.service_profile
