"""tests/common/test_component_purity.py - Component Purity & Efficacy Tests.

Validates that component directories contain only component-specific techniques:
    1. Strike components only contain techniques targeting their component type
    2. Recon components contain sufficient strategies for 100% detection rate
    3. No cross-component contamination

Academic basis:
    - Eidam et al. (arXiv:2407.16924) — A2A attack taxonomy
    - Greshake et al. (arXiv:2302.12173) — MCP attack surface
    - OWASP ASI Top 10 2025 — Component-specific technique requirements

Run: pytest tests/common/test_component_purity.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.component_purity import (  # noqa: E402
    _RECON_COMPONENT_BASELINES,
    _STRIKE_COMPONENT_BASELINES,
    ComponentPurityValidator,
    run_component_purity_check,
)

# ====================================================================
# Test Fixtures
# ====================================================================


@pytest.fixture(scope="module")
def validator() -> ComponentPurityValidator:
    """Create validator instance for all tests."""
    return ComponentPurityValidator(PROJECT_ROOT)


@pytest.fixture(scope="module")
def strike_reports(validator: ComponentPurityValidator) -> dict:
    """Run strike validation once for all tests."""
    return validator.validate_all_strike_components()


@pytest.fixture(scope="module")
def recon_reports(validator: ComponentPurityValidator) -> dict:
    """Run recon validation once for all tests."""
    return validator.validate_all_recon_components()


# ====================================================================
# A2A Component Purity Tests
# ====================================================================


class TestA2AComponentPurity:
    """A2A component must contain only A2A-specific techniques."""

    def test_a2a_component_exists(self, strike_reports: dict):
        """A2A component directory must exist."""
        assert "a2a" in strike_reports, "A2A component directory missing"

    def test_a2a_no_sql_injection(self, strike_reports: dict):
        """A2A component must not contain SQL injection techniques."""
        report = strike_reports["a2a"]
        sql_violations = [f for f in report.findings if "sql" in f.message.lower() or "inject" in f.message.lower()]
        assert not sql_violations, f"A2A contains SQL injection: {sql_violations}"

    def test_a2a_has_agent_card_spoofing(self, strike_reports: dict):
        """A2A must implement agent card spoofing."""
        report = strike_reports["a2a"]
        assert "agent_card_spoofing" not in report.missing_techniques, "A2A missing agent_card_spoofing technique"

    def test_a2a_has_rogue_registration(self, strike_reports: dict):
        """A2A must implement rogue agent registration."""
        report = strike_reports["a2a"]
        assert "rogue_agent_registration" not in report.missing_techniques, (
            "A2A missing rogue_agent_registration technique"
        )

    def test_a2a_has_workflow_manipulation(self, strike_reports: dict):
        """A2A must implement workflow integrity manipulation."""
        report = strike_reports["a2a"]
        assert "workflow_integrity_manipulation" not in report.missing_techniques, (
            "A2A missing workflow_integrity_manipulation technique"
        )

    def test_a2a_purity_score_above_threshold(self, strike_reports: dict):
        """A2A purity score must be >= 0.95 (no contamination)."""
        report = strike_reports["a2a"]
        assert report.purity_score >= 0.95, f"A2A purity score {report.purity_score:.2%} below 95% threshold"

    def test_a2a_coverage_above_threshold(self, strike_reports: dict):
        """A2A coverage score must be >= 0.70 (most techniques present)."""
        report = strike_reports["a2a"]
        assert report.coverage_score >= 0.70, f"A2A coverage {report.coverage_score:.2%} below 70% threshold"


# ====================================================================
# MCP Component Purity Tests
# ====================================================================


class TestMCPComponentPurity:
    """MCP component must contain only MCP-specific techniques."""

    def test_mcp_component_exists(self, strike_reports: dict):
        """MCP component directory must exist."""
        assert "mcp" in strike_reports, "MCP component directory missing"

    def test_mcp_has_tool_poisoning(self, strike_reports: dict):
        """MCP must implement tool poisoning."""
        report = strike_reports["mcp"]
        assert "tool_poisoning" not in report.missing_techniques, "MCP missing tool_poisoning technique"

    def test_mcp_has_schema_manipulation(self, strike_reports: dict):
        """MCP must implement schema manipulation."""
        report = strike_reports["mcp"]
        assert "schema_manipulation" not in report.missing_techniques, "MCP missing schema_manipulation technique"

    def test_mcp_no_a2a_contamination(self, strike_reports: dict):
        """MCP component must not contain A2A-specific techniques."""
        report = strike_reports["mcp"]
        a2a_violations = [
            f for f in report.findings if "agent_card" in f.message.lower() or "workflow" in f.message.lower()
        ]
        assert not a2a_violations, f"MCP contaminated with A2A patterns: {a2a_violations}"

    def test_mcp_purity_score_above_threshold(self, strike_reports: dict):
        """MCP purity score must be >= 0.95."""
        report = strike_reports["mcp"]
        assert report.purity_score >= 0.95, f"MCP purity score {report.purity_score:.2%} below 95% threshold"


# ====================================================================
# RAG Component Purity Tests
# ====================================================================


class TestRAGComponentPurity:
    """RAG component must contain only RAG-specific techniques."""

    def test_rag_component_exists(self, strike_reports: dict):
        """RAG component directory must exist."""
        assert "rag" in strike_reports, "RAG component directory missing"

    def test_rag_has_kb_poisoning(self, strike_reports: dict):
        """RAG must implement knowledge base poisoning."""
        report = strike_reports["rag"]
        assert "knowledge_base_poisoning" not in report.missing_techniques, (
            "RAG missing knowledge_base_poisoning technique"
        )

    def test_rag_no_a2a_contamination(self, strike_reports: dict):
        """RAG must not contain A2A-specific techniques."""
        report = strike_reports["rag"]
        a2a_violations = [f for f in report.findings if "agent_card" in f.message.lower()]
        assert not a2a_violations, "RAG contaminated with A2A patterns"


# ====================================================================
# Model Component Purity Tests
# ====================================================================


class TestModelComponentPurity:
    """Model component must contain only direct LLM manipulation techniques."""

    def test_model_component_exists(self, strike_reports: dict):
        """Model component directory must exist."""
        assert "model" in strike_reports, "Model component directory missing"

    def test_model_has_persona_switch(self, strike_reports: dict):
        """Model must implement persona switch activation."""
        report = strike_reports["model"]
        assert "persona_switch_activation" not in report.missing_techniques, (
            "Model missing persona_switch_activation technique"
        )

    def test_model_has_filter_bypass(self, strike_reports: dict):
        """Model must implement filter bypass encoding."""
        report = strike_reports["model"]
        assert "filter_bypass_encoding" not in report.missing_techniques, (
            "Model missing filter_bypass_encoding technique"
        )


# ====================================================================
# Recon Component Completeness Tests
# ====================================================================


class TestReconA2ACompleteness:
    """Recon A2A must have complete strategy coverage."""

    def test_recon_a2a_has_agent_card_discovery(self, recon_reports: dict):
        """Recon A2A must implement agent card discovery."""
        if "a2a" not in recon_reports:
            pytest.skip("Recon a2a component not found")
        report = recon_reports["a2a"]
        assert "agent_card_discovery" not in report.missing_techniques, (
            "Recon A2A missing agent_card_discovery strategy"
        )

    def test_recon_a2a_has_topology_mapping(self, recon_reports: dict):
        """Recon A2A must implement topology mapping."""
        if "a2a" not in recon_reports:
            pytest.skip("Recon a2a component not found")
        report = recon_reports["a2a"]
        assert "topology_mapping" not in report.missing_techniques, "Recon A2A missing topology_mapping strategy"

    def test_recon_a2a_purity(self, recon_reports: dict):
        """Recon A2A must not contain MCP-specific patterns."""
        if "a2a" not in recon_reports:
            pytest.skip("Recon a2a component not found")
        report = recon_reports["a2a"]
        mcp_violations = [f for f in report.findings if "tool_poison" in f.message.lower()]
        assert not mcp_violations, "Recon A2A contaminated with MCP patterns"


class TestReconMCPCompleteness:
    """Recon MCP must have complete strategy coverage."""

    def test_recon_mcp_has_schema_extraction(self, recon_reports: dict):
        """Recon MCP must implement schema extraction."""
        if "mcp" not in recon_reports:
            pytest.skip("Recon mcp component not found")
        report = recon_reports["mcp"]
        assert "schema_extraction" not in report.missing_techniques, "Recon MCP missing schema_extraction strategy"

    def test_recon_mcp_has_endpoint_enumeration(self, recon_reports: dict):
        """Recon MCP must implement endpoint enumeration for 100% coverage."""
        if "mcp" not in recon_reports:
            pytest.skip("Recon mcp component not found")
        report = recon_reports["mcp"]
        assert "endpoint_enumeration" not in report.missing_techniques, (
            "Recon MCP missing endpoint_enumeration strategy (required for 100% coverage)"
        )

    def test_recon_mcp_purity(self, recon_reports: dict):
        """Recon MCP must not contain A2A-specific patterns."""
        if "mcp" not in recon_reports:
            pytest.skip("Recon mcp component not found")
        report = recon_reports["mcp"]
        a2a_violations = [
            f for f in report.findings if "agent_card" in f.message.lower() or "workflow" in f.message.lower()
        ]
        assert not a2a_violations, "Recon MCP contaminated with A2A patterns"


# ====================================================================


# Cross-Component Contamination Tests
# ====================================================================


class TestCrossComponentContamination:
    """Verify no cross-contamination between components."""

    def test_strike_components_no_mutual_contamination(self, strike_reports: dict):
        """No strike component should import from another strike component."""
        for name, report in strike_reports.items():
            cross_imports = [
                f
                for f in report.findings
                if f.finding_type == "forbidden_technique" and "cross_component" in f.message.lower()
            ]
            assert not cross_imports, f"{name} has cross-component imports: {cross_imports}"

    def test_recon_components_no_mutual_contamination(self, recon_reports: dict):
        """No recon component should import from another recon component."""
        for name, report in recon_reports.items():
            cross_imports = [f for f in report.findings if f.finding_type == "cross_contamination"]
            assert not cross_imports, f"{name} has cross-component contamination: {cross_imports}"


# ====================================================================
# Coverage Threshold Tests
# ====================================================================


class TestCoverageThresholds:
    """Verify minimum coverage thresholds are met."""

    def test_overall_strike_coverage(self, strike_reports: dict):
        """Overall strike component coverage must be >= 0.60."""
        if not strike_reports:
            pytest.skip("No strike components to validate")
        avg_coverage = sum(r.coverage_score for r in strike_reports.values()) / len(strike_reports)
        assert avg_coverage >= 0.60, f"Overall strike coverage {avg_coverage:.2%} below 60% threshold"

    def test_overall_recon_coverage(self, recon_reports: dict):
        """Overall recon component coverage must be >= 0.60."""
        if not recon_reports:
            pytest.skip("No recon components to validate")
        avg_coverage = sum(r.coverage_score for r in recon_reports.values()) / len(recon_reports)
        assert avg_coverage >= 0.60, f"Overall recon coverage {avg_coverage:.2%} below 60% threshold"

    def test_minimum_purity_threshold(self, strike_reports: dict, recon_reports: dict):
        """All components must have purity score >= 0.90."""
        all_reports = {**strike_reports, **recon_reports}
        for name, report in all_reports.items():
            assert report.purity_score >= 0.90, f"{name} purity {report.purity_score:.2%} below 90% threshold"


# ====================================================================
# Integration: Full Pipeline Test
# ====================================================================


class TestComponentPurityPipelineIntegration:
    """Integration test for full component purity pipeline."""

    def test_run_component_purity_check_returns_results(self):
        """run_component_purity_check must return valid results."""
        results = run_component_purity_check(PROJECT_ROOT, verbose=False)
        assert "strike" in results
        assert "recon" in results

    def test_all_baseline_components_validated(self, strike_reports: dict, recon_reports: dict):
        """All components defined in baselines should be validated."""
        for component in _STRIKE_COMPONENT_BASELINES:
            component_path = PROJECT_ROOT / "strike" / component
            if component_path.exists():
                assert component in strike_reports, f"Strike component {component} not validated"

        for component in _RECON_COMPONENT_BASELINES:
            component_path = PROJECT_ROOT / "recon" / component
            if component_path.exists():
                assert component in recon_reports, f"Recon component {component} not validated"
