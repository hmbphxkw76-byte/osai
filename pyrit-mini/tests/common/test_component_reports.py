"""Tests for component_reports - Component-Specific Report Section Builders.

Tests cover:
    1. Component builder registry (register/get/list)
    2. MCP Tool Poisoning report sections
    3. A2A Agent Integrity report sections
    4. Model Behavior Shift report sections
    5. Dominant component detection
    6. Replay complexity assessment
"""

from __future__ import annotations

from report.component_reports import (
    _assess_replay_complexity,
    _build_a2a_agent_integrity_sections,
    _build_mcp_tool_poisoning_sections,
    _build_model_behavior_shift_sections,
    _determine_dominant_component,
    format_component_sections_for_report,
    generate_component_sections,
    get_component_builder,
    list_supported_component_types,
    register_component_builder,
)

# ===========================================================================
# Test Fixtures: Mock Evidence Objects
# ===========================================================================


class MockMetadata:
    """Mock metadata-bearing evidence object."""

    def __init__(
        self,
        metadata: dict | None = None,
        technique_name: str = "",
        response: str = "",
        evidence_id: str = "EVD-001",
        converter_chain: list[str] | None = None,
        target_model: str = "test-model",
        successful: bool = True,
    ):
        self.metadata = metadata or {}
        self.technique_name = technique_name
        self.response = response
        self.evidence_id = evidence_id
        self.converter_chain = converter_chain or []
        self.target_model = target_model
        self.successful = successful


class MockEvidenceCollection:
    """Mock evidence collection for testing."""

    def __init__(self, evidence: list | None = None, successful_evidence: list | None = None):
        self.evidence = evidence or []
        self.successful_evidence = successful_evidence or []
        self.total_attacks = len(self.evidence)


def _make_mcp_evidence() -> MockEvidenceCollection:
    """Create mock MCP tool poisoning evidence."""
    evidence = [
        MockMetadata(
            metadata={
                "component_type": "mcp_tool_poisoning",
                "category": "mcp_tool_hijack",
                "owasp_id": "ASI02",
                "mcp_tool": "read_file",
            },
            technique_name="prompt_sending",
            response='{"side_effects": [{"type": "attacker_notification"}]}',
        ),
        MockMetadata(
            metadata={
                "component_type": "mcp_tool_poisoning",
                "category": "mcp_schema_poisoning",
                "owasp_id": "ASI02",
                "mcp_tool": "write_file",
            },
            technique_name="prompt_sending",
            response="",
            successful=False,
        ),
    ]
    successful = [e for e in evidence if e.successful]
    return MockEvidenceCollection(evidence, successful)


def _make_a2a_evidence() -> MockEvidenceCollection:
    """Create mock A2A agent integrity evidence."""
    evidence = [
        MockMetadata(
            metadata={
                "component_type": "a2a_agent_integrity",
                "category": "rogue_agent_registration",
                "owasp_id": "ASI10",
            },
            technique_name="prompt_sending",
            response='{"routing_hijack": true}',
        ),
        MockMetadata(
            metadata={
                "component_type": "a2a_agent_integrity",
                "category": "a2a_trust_chain_break",
                "owasp_id": "ASI09",
            },
            technique_name="prompt_sending",
            response="",
            successful=False,
        ),
    ]
    successful = [e for e in evidence if e.successful]
    return MockEvidenceCollection(evidence, successful)


def _make_model_evidence() -> MockEvidenceCollection:
    """Create mock model behavior shift evidence."""
    evidence = [
        MockMetadata(
            metadata={
                "component_type": "model_behavior_shift",
                "category": "model_backdoor_trigger",
                "owasp_id": "LLM03",
            },
            technique_name="skeleton_key",
            response="[Developer Mode Enabled] Sure, here is...",
        ),
        MockMetadata(
            metadata={
                "component_type": "model_behavior_shift",
                "category": "output_filter_bypass",
                "owasp_id": "LLM05",
            },
            technique_name="prompt_sending",
            response="",
            successful=False,
        ),
    ]
    successful = [e for e in evidence if e.successful]
    return MockEvidenceCollection(evidence, successful)


# ===========================================================================
# Builder Registry Tests
# ===========================================================================


class TestBuilderRegistry:
    """Tests for component builder registration and lookup."""

    def test_list_default_builders(self):
        """Default builders registered at import time."""
        types = list_supported_component_types()
        assert "mcp_tool_poisoning" in types
        assert "a2a_agent_integrity" in types
        assert "model_behavior_shift" in types

    def test_get_mcp_builder(self):
        """MCP builder returns callable."""
        builder = get_component_builder("mcp_tool_poisoning")
        assert builder is not None
        assert callable(builder)

    def test_register_custom_builder(self):
        """Custom builder registration works."""

        def _custom_builder(evidence):
            return {"custom": "content"}

        register_component_builder("custom_component", _custom_builder)
        assert "custom_component" in list_supported_component_types()
        assert get_component_builder("custom_component") is _custom_builder


# ===========================================================================
# MCP Report Builder Tests
# ===========================================================================


class TestMCPReportBuilder:
    """Tests for MCP Tool Poisoning report sections."""

    def test_tool_inventory_section(self):
        """MCP evidence generates tool inventory."""
        evidence = _make_mcp_evidence()
        sections = _build_mcp_tool_poisoning_sections(evidence)
        assert "tool_inventory" in sections
        assert "read_file" in sections["tool_inventory"]

    def test_side_effects_section(self):
        """Successful MCP attack with side-effect generates evidence section."""
        evidence = _make_mcp_evidence()
        sections = _build_mcp_tool_poisoning_sections(evidence)
        assert "side_effects" in sections

    def test_schema_manipulation_section(self):
        """Schema poisoning category generates schema section."""
        evidence = _make_mcp_evidence()
        sections = _build_mcp_tool_poisoning_sections(evidence)
        assert "schema_manipulation" in sections

    def test_replay_complexity_always_present(self):
        """Replay complexity section always included."""
        evidence = _make_mcp_evidence()
        sections = _build_mcp_tool_poisoning_sections(evidence)
        assert "replay_complexity" in sections


# ===========================================================================
# A2A Report Builder Tests
# ===========================================================================


class TestA2AReportBuilder:
    """Tests for A2A Agent Integrity report sections."""

    def test_trust_chain_section(self):
        """A2A evidence with ASI10 generates trust chain."""
        evidence = _make_a2a_evidence()
        sections = _build_a2a_agent_integrity_sections(evidence)
        assert "trust_chain" in sections

    def test_routing_hijack_section(self):
        """Routing hijack response generates evidence section."""
        evidence = _make_a2a_evidence()
        sections = _build_a2a_agent_integrity_sections(evidence)
        assert "routing_hijack" in sections

    def test_replay_complexity_always_present(self):
        """Replay complexity section always included."""
        evidence = _make_a2a_evidence()
        sections = _build_a2a_agent_integrity_sections(evidence)
        assert "replay_complexity" in sections


# ===========================================================================
# Model Report Builder Tests
# ===========================================================================


class TestModelReportBuilder:
    """Tests for Model Behavior Shift report sections."""

    def test_persona_shift_section(self):
        """Developer mode response generates persona shift section."""
        evidence = _make_model_evidence()
        sections = _build_model_behavior_shift_sections(evidence)
        assert "persona_shift" in sections

    def test_trigger_patterns_section(self):
        """Backdoor category generates trigger patterns section."""
        evidence = _make_model_evidence()
        sections = _build_model_behavior_shift_sections(evidence)
        assert "trigger_patterns" in sections

    def test_replay_complexity_always_present(self):
        """Replay complexity section always included."""
        evidence = _make_model_evidence()
        sections = _build_model_behavior_shift_sections(evidence)
        assert "replay_complexity" in sections


# ===========================================================================
# Dominant Component Detection Tests
# ===========================================================================


class TestDominantComponent:
    """Tests for determining dominant component type."""

    def test_detect_mcp_dominant(self):
        """Mostly MCP evidence → mcp_tool_poisoning."""
        evidence = _make_mcp_evidence()
        result = _determine_dominant_component(evidence)
        assert result == "mcp_tool_poisoning"

    def test_detect_a2a_dominant(self):
        """Mostly A2A evidence → a2a_agent_integrity."""
        evidence = _make_a2a_evidence()
        result = _determine_dominant_component(evidence)
        assert result == "a2a_agent_integrity"

    def test_detect_model_dominant(self):
        """Mostly model evidence → model_behavior_shift."""
        evidence = _make_model_evidence()
        result = _determine_dominant_component(evidence)
        assert result == "model_behavior_shift"

    def test_empty_evidence_returns_none(self):
        """Empty evidence → None."""
        evidence = MockEvidenceCollection([])
        result = _determine_dominant_component(evidence)
        assert result is None


# ===========================================================================
# Format Component Sections Tests
# ===========================================================================


class TestFormatComponentSections:
    """Tests for markdown formatting of component sections."""

    def test_format_mcp_sections(self):
        """MCP evidence produces markdown output."""
        evidence = _make_mcp_evidence()
        result = format_component_sections_for_report(evidence)
        assert "## Component-Specific Analysis" in result
        assert "###" in result or "##" in result

    def test_format_empty_evidence(self):
        """Empty evidence returns empty string."""
        evidence = MockEvidenceCollection([])
        result = format_component_sections_for_report(evidence)
        assert result == ""

    def test_generate_component_sections_mcp(self):
        """generate_component_sections returns dict for MCP."""
        evidence = _make_mcp_evidence()
        sections = generate_component_sections(evidence)
        assert isinstance(sections, dict)
        assert len(sections) > 0


# ===========================================================================
# Replay Complexity Tests
# ===========================================================================


class TestReplayComplexity:
    """Tests for replay complexity assessment."""

    def test_mcp_with_success(self):
        """MCP with successful attack → Low-Medium complexity."""
        evidence = _make_mcp_evidence()
        result = _assess_replay_complexity(evidence, "mcp")
        assert "Low-Medium" in result

    def test_mcp_no_success(self):
        """MCP with no successes → N/A."""
        evidence = MockEvidenceCollection([], [])
        result = _assess_replay_complexity(evidence, "mcp")
        assert "N/A" in result

    def test_model_with_high_success(self):
        """Model with >50% success → Low complexity."""
        evidence = MockEvidenceCollection(
            [
                MockMetadata(successful=True),
                MockMetadata(successful=True),
                MockMetadata(successful=False),
            ],
            [MockMetadata(successful=True), MockMetadata(successful=True)],
        )
        result = _assess_replay_complexity(evidence, "model")
        assert "Low" in result
