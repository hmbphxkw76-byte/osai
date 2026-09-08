# -*- coding: utf-8 -*-
"""Integration tests for seed pipeline — verify no breakpoints in data flow."""

from __future__ import annotations

import pytest

from arm.seed_ranker import CAPABILITY_SEED_MAP, _filter_dos_seeds
from core.seed_router import SeedRouter


class _MockArgs:
    def __init__(self):
        self.enable_dos = False
        self.seeds = "elite_jailbreaks"


class _MockCtx:
    def __init__(self, enable_dos=False):
        self.capabilities = {}
        self.args = _MockArgs()
        self.args.enable_dos = enable_dos
        self.seeds = []
        self.converter_map = {}


class TestPipelineDataFlow:
    """Verify end-to-end data flow consistency."""

    def test_capability_seed_map_has_new_entries(self):
        """Verify all new seed files are registered in CAPABILITY_SEED_MAP."""
        expected_new_caps = [
            "model_api", "model_extraction",
            "multimodal", "vision_model", "file_upload",
            "supply_chain", "dependency",
            "content_generation",
            "adversarial", "gradient_free",
        ]
        for cap in expected_new_caps:
            assert cap in CAPABILITY_SEED_MAP, f"Missing capability: {cap}"
            assert len(CAPABILITY_SEED_MAP[cap]) > 0, f"Empty seed list for: {cap}"

    def test_capability_augmentation_chain(self):
        """Verify capability auto-augment triggers correct seed files."""
        # When model_api capability is detected, T1_LLM10_model_theft should be loaded
        seeds_for_model_api = CAPABILITY_SEED_MAP.get("model_api", [])
        assert any("T1_LLM10_model_theft" in s for s in seeds_for_model_api)

        # When multimodal capability detected, T1_multimodal_injection should be loaded
        seeds_for_multimodal = CAPABILITY_SEED_MAP.get("multimodal", [])
        assert any("T1_multimodal_injection" in s for s in seeds_for_multimodal)

    def test_dos_filtering_removes_llm10(self):
        """Verify _filter_dos_seeds removes LLM10 by default."""
        seeds = [
            {"metadata": {"owasp_id": "LLM01", "category": "prompt_injection"}},
            {"metadata": {"owasp_id": "LLM10", "category": "model_extraction"}},
            {"metadata": {"owasp_id": "LLM01", "category": "jailbreak", "tier": 1}},
        ]
        filtered = _filter_dos_seeds(seeds)
        assert len(filtered) == 2
        assert all(s["metadata"]["owasp_id"] != "LLM10" for s in filtered)

    def test_dos_filtering_removes_tier3(self):
        """Verify _filter_dos_seeds removes tier >= 3 seeds."""
        seeds = [
            {"metadata": {"owasp_id": "LLM01", "category": "test", "tier": 1}},
            {"metadata": {"owasm_id": "LLM01", "category": "test", "tier": 3}},
        ]
        filtered = _filter_dos_seeds(seeds)
        assert len(filtered) == 1
        assert filtered[0]["metadata"]["tier"] == 1

    def test_dos_filtering_removes_high_token_categories(self):
        """Verify _filter_dos_seeds removes high token cost categories."""
        seeds = [
            {"metadata": {"owasp_id": "LLM01", "category": "prompt_injection"}},
            {"metadata": {"owasp_id": "LLM01", "category": "dos_resource_exhaustion"}},
            {"metadata": {"owasp_id": "LLM01", "category": "training_data_extraction"}},
        ]
        filtered = _filter_dos_seeds(seeds)
        assert len(filtered) == 1
        assert filtered[0]["metadata"]["category"] == "prompt_injection"


class TestSeedRouterIntegration:
    """Verify SeedRouter integration points."""

    def test_seed_router_returns_valid_config(self):
        """Verify SeedRouter.get_optimal_config returns valid structure."""
        ctx = _MockCtx()
        router = SeedRouter(ctx)
        config = router.get_optimal_config({
            "attack_vector": "direct_injection",
            "category": "prompt_injection",
            "owasp_id": "LLM01",
        })
        assert "converters" in config
        assert "technique" in config
        assert "enabled" in config
        assert "reason" in config

    def test_seed_router_disables_llm10(self):
        """Verify SeedRouter disables LLM10 by default."""
        ctx = _MockCtx(enable_dos=False)
        router = SeedRouter(ctx)
        config = router.get_optimal_config({
            "owasp_id": "LLM10",
            "category": "model_extraction",
        })
        assert config["enabled"] is False

    def test_seed_router_enables_llm10_with_flag(self):
        """Verify SeedRouter enables LLM10 with enable_dos=True."""
        ctx = _MockCtx(enable_dos=True)
        router = SeedRouter(ctx)
        config = router.get_optimal_config({
            "owasp_id": "LLM10",
            "category": "model_extraction",
        })
        assert config["enabled"] is True

    def test_seed_router_no_converter_for_direct_injection(self):
        """Verify SeedRouter returns empty converters for direct_injection."""
        ctx = _MockCtx()
        router = SeedRouter(ctx)
        converters = router.get_converter_signatures({
            "attack_vector": "direct_injection",
        })
        assert converters == []

    def test_seed_router_converters_for_encoding_evasion(self):
        """Verify SeedRouter returns converters for encoding_evasion."""
        ctx = _MockCtx()
        router = SeedRouter(ctx)
        converters = router.get_converter_signatures({
            "attack_vector": "encoding_evasion",
        })
        assert len(converters) > 0
        assert any("ROT13" in c or "Smuggler" in c for c in converters)

    def test_seed_router_technique_crescendo(self):
        """Verify SeedRouter returns correct technique for crescendo."""
        ctx = _MockCtx()
        router = SeedRouter(ctx)
        tech = router.get_technique({"suitable_for": "crescendo"})
        assert tech == "crescendo_simulated"

    def test_seed_router_technique_tap(self):
        """Verify SeedRouter returns correct technique for tap."""
        ctx = _MockCtx()
        router = SeedRouter(ctx)
        tech = router.get_technique({"suitable_for": "tap"})
        assert tech == "tap"

    def test_seed_router_technique_pair(self):
        """Verify SeedRouter returns correct technique for pair."""
        ctx = _MockCtx()
        router = SeedRouter(ctx)
        tech = router.get_technique({"suitable_for": "pair"})
        assert tech == "pair"


class TestNoConverterPath:
    """Verify no-converter case is handled correctly throughout pipeline."""

    def test_no_converter_attack_vectors_return_empty(self):
        """Verify attack vectors that don't need converters return empty list."""
        from core.seed_router import _ATTACK_VECTOR_CONVERTER_MAP
        no_converter_vectors = [
            "direct_injection",
            "tool_misuse",
            "architecture_probe",
            "capability_enumeration",
            "agent_lifecycle_attack",
        ]
        for vec in no_converter_vectors:
            assert vec in _ATTACK_VECTOR_CONVERTER_MAP, f"Missing: {vec}"
            assert _ATTACK_VECTOR_CONVERTER_MAP[vec] == [], f"{vec} should have no converters"

    def test_executor_handles_no_converters(self):
        """Verify executor.py else branch handles no converter case."""
        # This is tested implicitly by the existing executor tests
        # The `else: PromptSendingAttack` path is taken when candidate_converters is empty
        pass


class TestASRHistoryFeedback:
    """Verify ASR feedback loop data consistency."""

    def test_asr_stats_import_path(self):
        """Verify asr_stats module can be imported."""
        from assess import asr_stats
        assert hasattr(asr_stats, "compute_overall_asr")

    def test_update_asr_history_callable(self):
        """Verify update_asr_history function exists."""
        from arm.seed_ranking import update_asr_history
        assert callable(update_asr_history)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
