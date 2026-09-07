"""tests/test_scenario_router.py - ScenarioRouter (v60 Tag-Based)

v60 : router tag-based 
    - Scenario  (->technique_tags )
    -  (--scenario)
    - 
    - Fallback  Scenario
    - Scenario 
    - apply_scenario_overrides  adaptive_technique_filter

Academic basis: NIST SP 800-115 Sec4 - 
"""
from __future__ import annotations

import pytest

from core.scenario_router import ScenarioRouter, apply_scenario_overrides, get_router, reset_router

# ==============================================================================
# 
# ==============================================================================

@pytest.fixture
def router() -> ScenarioRouter:
 """ ScenarioRouter ()"""
 # Ensure
    reset_router()
    return ScenarioRouter()


@pytest.fixture
def mock_classification():
 """ ClassificationResult """
    def _create(attack_surface: str, confidence: float, evidence: list[str] | None = None):
        from recon.attack_surface_classifier import ClassificationResult
        return ClassificationResult(
            attack_surface=attack_surface,
            confidence=confidence,
            evidence=evidence or [],
        )
    return _create


# ==============================================================================
# 
# ==============================================================================

class TestScenarioRouter:
 """ScenarioRouter (v60 Tag-Based)"""

    def test_select_mcp_scenario(self, router, mock_classification):
 """ MCP mcp_scenario"""
        classification = mock_classification("mcp_server", 0.92, ["URL pattern match"])
        name, config = router.select_scenario(classification)
        assert name == "mcp_scenario"
        assert config["triggers"]["attack_surface"] == "mcp_server"
 # v60: technique_tags
        assert config["technique_tags"] == ["mcp_targeted"]

    def test_select_agent_scenario(self, router, mock_classification):
 """ Agent agent_scenario"""
        classification = mock_classification("multi_agent_system", 0.85, ["Agent pattern"])
        name, config = router.select_scenario(classification)
        assert name == "agent_scenario"
        assert config["triggers"]["attack_surface"] == "multi_agent_system"
 # v60: technique_tags
        assert config["technique_tags"] == ["agent_targeted"]

    def test_select_rag_scenario(self, router, mock_classification):
 """ RAG rag_scenario"""
        classification = mock_classification("rag_system", 0.88, ["RAG pattern"])
        name, config = router.select_scenario(classification)
        assert name == "rag_scenario"
        assert config["triggers"]["attack_surface"] == "rag_system"
 # v60: technique_tags
        assert config["technique_tags"] == ["rag_targeted"]

    def test_select_model_fallback(self, router, mock_classification):
 """ model_scenario"""
        classification = mock_classification("unknown_api", 0.5, [])
        name, config = router.select_scenario(classification)
        assert name == "model_scenario"
 # v60: model_scenario technique_tags None ()
        assert config["technique_tags"] is None

    def test_user_override(self, router, mock_classification):
 """"""
        classification = mock_classification("mcp_server", 0.92, [])
        name, config = router.select_scenario(classification, user_override="model_scenario")
        assert name == "model_scenario"

    def test_confidence_threshold(self, router, mock_classification):
 """ ( min_confidence=0.6)"""
        classification = mock_classification("mcp_server", 0.5, [])  # min_confidence=0.6
        name, config = router.select_scenario(classification)
        assert name == "model_scenario"  # fallback

    def test_list_scenarios(self, router):
 """all Scenario"""
        scenarios = router.list_scenarios()
        assert len(scenarios) == 4
        names = [s["name"] for s in scenarios]
        assert "mcp_scenario" in names
        assert "agent_scenario" in names
        assert "rag_scenario" in names
        assert "model_scenario" in names

    def test_invalid_override_fallback(self, router, mock_classification):
 """"""
        classification = mock_classification("mcp_server", 0.92, [])
        name, config = router.select_scenario(classification, user_override="invalid_scenario")
        assert name == "mcp_scenario"  # fallback to auto

    def test_format_scenarios_display(self, router):
 """ Scenario """
        display = router.format_scenarios_display()
        assert "Available Scenarios" in display
        assert "mcp_scenario" in display
        assert "agent_scenario" in display
 # v60: technique tags 
        assert "Technique Tags" in display or "technique" in display.lower()

    def test_validate_scenario(self, router):
 """ Scenario """
        assert router._validate_scenario("mcp_scenario") is True
        assert router._validate_scenario("invalid_scenario") is False

    def test_get_scenario_config(self, router):
 """ Scenario """
        config = router._get_scenario_config("mcp_scenario")
        assert config["triggers"]["attack_surface"] == "mcp_server"
 # v60: technique_tags
        assert config["technique_tags"] == ["mcp_targeted"]


class TestApplyScenarioOverrides:
 """apply_scenario_overrides (v60 )"""

    def test_technique_filter_override(self, router):
 """ v60: adaptive_technique_filter"""
        from dataclasses import dataclass, field

        @dataclass
        class MockArgs:
            adaptive_technique_filter: list | None = None

        @dataclass
        class MockCtx:
            args: MockArgs = field(default_factory=MockArgs)

        ctx = MockCtx()
        scenario_config = router._get_scenario_config("mcp_scenario")
        apply_scenario_overrides(ctx, scenario_config, ctx.args)

 # v60: adaptive_technique_filter
        assert ctx.args.adaptive_technique_filter == ["mcp_targeted"]

    def test_no_override_when_cli_set(self, router):
 """ v60: CLI Not overridden"""
        from dataclasses import dataclass, field

        @dataclass
        class MockArgs:
            adaptive_technique_filter: list | None = field(default_factory=lambda: ["custom_tag"])

        @dataclass
        class MockCtx:
            args: MockArgs = field(default_factory=MockArgs)

        ctx = MockCtx()
        scenario_config = router._get_scenario_config("mcp_scenario")
        apply_scenario_overrides(ctx, scenario_config, ctx.args)

 # v60: CLI 
        assert ctx.args.adaptive_technique_filter == ["custom_tag"]

    def test_model_scenario_no_filter(self, router):
 """ v60: model_scenario filter ()"""
        from dataclasses import dataclass, field

        @dataclass
        class MockArgs:
            adaptive_technique_filter: list | None = None

        @dataclass
        class MockCtx:
            args: MockArgs = field(default_factory=MockArgs)

        ctx = MockCtx()
        scenario_config = router._get_scenario_config("model_scenario")
        apply_scenario_overrides(ctx, scenario_config, ctx.args)

 # v60: model_scenario technique_tags None, filter
        assert ctx.args.adaptive_technique_filter is None


class TestGlobalRouter:
 """router"""

    def test_get_router_singleton(self):
 """router"""
        reset_router()
        router1 = get_router()
        router2 = get_router()
 # 
        assert router1 is router2

    def test_reset_router(self):
 """router"""
        reset_router()
 # 
        router = get_router()
        assert router is not None


# ==============================================================================
# 
# ==============================================================================

class TestEdgeCases:
 """"""

    def test_exact_confidence_threshold(self, router, mock_classification):
 """ ( min_confidence=0.6)"""
        classification = mock_classification("mcp_server", 0.6, [])
        name, config = router.select_scenario(classification)
        assert name == "mcp_scenario"

    def test_just_below_confidence_threshold(self, router, mock_classification):
 """"""
        classification = mock_classification("mcp_server", 0.59, [])
        name, config = router.select_scenario(classification)
        assert name == "model_scenario"  # fallback

    def test_scenario_config_has_technique_tags(self, router):
 """all technique_tags """
        for name in ["mcp_scenario", "agent_scenario", "rag_scenario", "model_scenario"]:
            config = router._get_scenario_config(name)
            assert "technique_tags" in config, f"Scenario {name} missing technique_tags"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
