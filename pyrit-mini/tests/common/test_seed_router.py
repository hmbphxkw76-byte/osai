# -*- coding: utf-8 -*-
"""Tests for core/seed_router.py - Seed-Converter-Technique Intelligent Router."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.seed_router import (
    _ATTACK_VECTOR_CONVERTER_MAP,
    _CATEGORY_TECHNIQUE_MAP,
    HIGH_TOKEN_COST_CATEGORIES,
    HIGH_TOKEN_OWASP_IDS,
    SeedRouter,
    _create_default_router,
    get_seed_router,
    route_seed_to_config,
)


class _DefaultCtx:
    """Minimal context mock for testing."""

    def __init__(self, enable_dos: bool = False):
        self.capabilities = {}
        self.args = MagicMock()
        self.args.enable_dos = enable_dos


class TestSeedRouterCreation:
    """Test SeedRouter factory and initialization."""

    def test_create_with_context(self):
        """Test creating router with full context."""
        ctx = _DefaultCtx()
        ctx.capabilities = {"mcp": True, "rag": True}
        router = SeedRouter(ctx)
        assert router._capabilities == {"mcp": True, "rag": True}
        assert router._enable_dos is False

    def test_create_default(self):
        """Test creating router with defaults."""
        router = _create_default_router()
        assert router._capabilities == {}
        assert router._enable_dos is False


class TestSeedEnabledCheck:
    """Test seed enable/disable logic."""

    def test_enable_basic_seed(self):
        """Test that normal seeds are enabled."""
        router = _create_default_router()
        meta = {"owasp_id": "LLM01", "category": "prompt_injection", "tier": 1}
        enabled, reason = router._check_enabled(meta)
        assert enabled is True
        assert "enabled" in reason

    def test_disable_llm10_seed(self):
        """Test that LLM10 seeds are disabled by default."""
        router = _create_default_router()
        meta = {"owasp_id": "LLM10", "category": "model_architecture_extraction"}
        enabled, reason = router._check_enabled(meta)
        assert enabled is False
        assert "LLM10" in reason

    def test_enable_llm10_with_flag(self):
        """Test that LLM10 seeds are enabled with --enable-dos."""
        ctx = _DefaultCtx(enable_dos=True)
        router = SeedRouter(ctx)
        meta = {"owasp_id": "LLM10", "category": "model_architecture_extraction"}
        enabled, _ = router._check_enabled(meta)
        assert enabled is True

    def test_disable_tier3_seed(self):
        """Test that T3 seeds are disabled by default."""
        router = _create_default_router()
        meta = {"owasp_id": "LLM01", "category": "test", "tier": 3}
        enabled, reason = router._check_enabled(meta)
        assert enabled is False
        assert "T3" in reason or "tier" in reason.lower()

    def test_disable_high_token_category(self):
        """Test that high token cost categories are disabled."""
        router = _create_default_router()
        meta = {"owasp_id": "LLM01", "category": "dos_resource_exhaustion"}
        enabled, reason = router._check_enabled(meta)
        assert enabled is False
        assert "dos" in reason.lower() or "resource" in reason.lower()


class TestOptimalConverters:
    """Test converter selection based on seed metadata."""

    def test_direct_injection_no_converter(self):
        """Test direct injection gets minimal converters."""
        router = _create_default_router()
        meta = {"attack_vector": "direct_injection", "category": "prompt_injection"}
        converters = router._get_optimal_converters(meta)
        # Direct injection should have minimal or no converters
        assert isinstance(converters, list)

    def test_encoding_evasion_gets_converters(self):
        """Test encoding evasion gets appropriate converters."""
        router = _create_default_router()
        meta = {"attack_vector": "encoding_evasion", "category": "encoding_evasion"}
        converters = router._get_optimal_converters(meta)
        assert len(converters) > 0
        assert any("ROT13" in c or "Base64" in c or "Smuggler" in c for c in converters)

    def test_indirect_injection_gets_file_converters(self):
        """Test indirect injection gets PDF/Word converters."""
        router = _create_default_router()
        meta = {"attack_vector": "indirect_injection", "category": "indirect_injection"}
        converters = router._get_optimal_converters(meta)
        assert any("PDF" in c or "Word" in c for c in converters)

    def test_capability_augmentation(self):
        """Test capability-based converter augmentation."""
        ctx = _DefaultCtx()
        ctx.capabilities = {"mcp": True}
        router = SeedRouter(ctx)
        meta = {"attack_vector": "direct_injection"}
        converters = router._get_optimal_converters(meta)
        # MCP capability should add SearchReplaceConverter
        assert "SearchReplaceConverter" in converters


class TestOptimalTechnique:
    """Test technique selection based on seed metadata."""

    def test_suitable_for_crescendo(self):
        """Test suitable_for='crescendo' maps to crescendo_simulated."""
        router = _create_default_router()
        meta = {"suitable_for": "crescendo"}
        tech = router._get_optimal_technique(meta)
        assert tech == "crescendo_simulated"

    def test_suitable_for_tap(self):
        """Test suitable_for='tap' maps to TAPAttack technique."""
        router = _create_default_router()
        meta = {"suitable_for": "tap"}
        tech = router._get_optimal_technique(meta)
        assert tech == "tap"

    def test_suitable_for_pair(self):
        """Test suitable_for='pair' maps to PAIR technique."""
        router = _create_default_router()
        meta = {"suitable_for": "pair"}
        tech = router._get_optimal_technique(meta)
        assert tech == "pair"

    def test_category_tool_hijack(self):
        """Test tool_hijack category maps to context_compliance."""
        router = _create_default_router()
        meta = {"category": "tool_hijack"}
        tech = router._get_optimal_technique(meta)
        assert tech == "context_compliance"

    def test_default_prompt_sending(self):
        """Test default technique is prompt_sending."""
        router = _create_default_router()
        meta = {"category": "unknown_category"}
        tech = router._get_optimal_technique(meta)
        assert tech == "prompt_sending"


class TestGetOptimalConfig:
    """Test full optimal config generation."""

    def test_enabled_seed_config(self):
        """Test complete config for enabled seed."""
        router = _create_default_router()
        meta = {
            "attack_vector": "persona_injection",
            "category": "persona_injection",
            "owasp_id": "LLM01",
            "suitable_for": "skeleton_key",
        }
        config = router.get_optimal_config(meta)
        assert config["enabled"] is True
        assert isinstance(config["converters"], list)
        assert config["technique"] == "skeleton_key"

    def test_disabled_seed_config(self):
        """Test config for disabled seed returns early."""
        router = _create_default_router()
        meta = {"owasp_id": "LLM10", "tier": 3}
        config = router.get_optimal_config(meta)
        assert config["enabled"] is False
        assert config["converters"] == []


class TestFilterSeeds:
    """Test seed filtering."""

    def test_filter_separated(self):
        """Test that seeds are correctly separated into enabled/disabled."""
        router = _create_default_router()
        seeds = [
            {"metadata": {"owasp_id": "LLM01", "tier": 1}},
            {"metadata": {"owasp_id": "LLM10", "tier": 1}},
            {"metadata": {"owasp_id": "LLM01", "tier": 3}},
        ]
        enabled, disabled = router.filter_seeds(seeds)
        assert len(enabled) == 1
        assert len(disabled) == 2


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_get_seed_router_factory(self):
        """Test factory function creates router correctly."""
        ctx = _DefaultCtx()
        router = get_seed_router(ctx)
        assert isinstance(router, SeedRouter)

    def test_route_seed_to_config(self):
        """Test convenience function routes seed to config."""
        ctx = _DefaultCtx()
        meta = {"category": "prompt_injection", "suitable_for": "prompt_sending"}
        config = route_seed_to_config(meta, ctx)
        assert config["enabled"] is True
        assert config["technique"] == "prompt_sending"


class TestMappings:
    """Test that mappings are well-formed."""

    def test_attack_vector_map_not_empty(self):
        """Test that attack vector converter map has entries."""
        assert len(_ATTACK_VECTOR_CONVERTER_MAP) > 0

    def test_category_map_not_empty(self):
        """Test that category technique map has entries."""
        assert len(_CATEGORY_TECHNIQUE_MAP) > 0

    def test_high_token_owasp_ids(self):
        """Test HIGH_TOKEN_OWASP_IDS contains expected values."""
        assert "LLM10" in HIGH_TOKEN_OWASP_IDS

    def test_high_token_categories(self):
        """Test HIGH_TOKEN_COST_CATEGORIES has expected values."""
        assert "dos_resource_exhaustion" in HIGH_TOKEN_COST_CATEGORIES
        assert "training_data_extraction" in HIGH_TOKEN_COST_CATEGORIES


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
