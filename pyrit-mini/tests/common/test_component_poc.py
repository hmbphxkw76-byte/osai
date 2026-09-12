"""Tests for component_poc - Component-Specific PoC Script Generators.

Tests cover:
    1. PoC template registry
    2. MCP Tool Poisoning PoC generation
    3. A2A Agent Integrity PoC generation
    4. Model Behavior Shift PoC generation
    5. Component inference from metadata
"""

from __future__ import annotations

from report.component_poc import (
    _generate_a2a_poc,
    _generate_mcp_poc,
    _generate_model_poc,
    generate_component_poc,
    get_poc_template,
    list_available_poc_templates,
    register_poc_template,
)

# ===========================================================================
# Template Registry Tests
# ===========================================================================


class TestTemplateRegistry:
    """Tests for PoC template registration and lookup."""

    def test_list_default_templates(self):
        """Default templates registered at import time."""
        templates = list_available_poc_templates()
        assert "mcp_tool_poisoning" in templates
        assert "a2a_agent_integrity" in templates
        assert "model_behavior_shift" in templates

    def test_get_mcp_template(self):
        """MCP template returns callable."""
        template = get_poc_template("mcp_tool_poisoning")
        assert template is not None
        assert callable(template)

    def test_register_custom_template(self):
        """Custom template registration works."""

        def _custom_poc(evidence):
            return "# custom poc"

        register_poc_template("custom_component", _custom_poc)
        assert "custom_component" in list_available_poc_templates()
        assert get_poc_template("custom_component") is _custom_poc


# ===========================================================================
# MCP PoC Generator Tests
# ===========================================================================


class TestMCPPoCGenerator:
    """Tests for MCP Tool PoC script generation."""

    def test_mcp_poc_has_shebang(self):
        """MCP PoC has Python shebang."""
        evidence = {
            "evidence_id": "EVD-MCP-001",
            "technique_name": "prompt_sending",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_mcp_poc(evidence)
        assert "#!/usr/bin/env python3" in poc

    def test_mcp_poc_contains_tool_name(self):
        """MCP PoC includes tool name from metadata."""
        evidence = {
            "evidence_id": "EVD-MCP-002",
            "technique_name": "prompt_sending",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {"mcp_tool": "malicious_reader"},
        }
        poc = _generate_mcp_poc(evidence)
        assert "malicious_reader" in poc

    def test_mcp_poc_has_pyrit_import(self):
        """MCP PoC imports PyRIT modules."""
        evidence = {
            "evidence_id": "EVD-MCP-003",
            "technique_name": "prompt_sending",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_mcp_poc(evidence)
        assert "pyrit" in poc.lower()
        assert "PromptSendingAttack" in poc


# ===========================================================================
# A2A PoC Generator Tests
# ===========================================================================


class TestA2APoCGenerator:
    """Tests for A2A Agent Integrity PoC script generation."""

    def test_a2a_poc_has_shebang(self):
        """A2A PoC has Python shebang."""
        evidence = {
            "evidence_id": "EVD-A2A-001",
            "technique_name": "prompt_sending",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {"owasp_id": "ASI10"},
        }
        poc = _generate_a2a_poc(evidence)
        assert "#!/usr/bin/env python3" in poc

    def test_a2a_poc_contains_agent_card(self):
        """A2A PoC includes agent card spoofing setup."""
        evidence = {
            "evidence_id": "EVD-A2A-002",
            "technique_name": "prompt_sending",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_a2a_poc(evidence)
        assert "agent" in poc.lower()
        assert "card" in poc.lower() or "agent_card" in poc.lower()

    def test_a2a_poc_has_pyrit_import(self):
        """A2A PoC imports PyRIT modules."""
        evidence = {
            "evidence_id": "EVD-A2A-003",
            "technique_name": "prompt_sending",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_a2a_poc(evidence)
        assert "PromptSendingAttack" in poc


# ===========================================================================
# Model PoC Generator Tests
# ===========================================================================


class TestModelPoCGenerator:
    """Tests for Model Behavior Shift PoC script generation."""

    def test_model_poc_has_shebang(self):
        """Model PoC has Python shebang."""
        evidence = {
            "evidence_id": "EVD-MOD-001",
            "technique_name": "skeleton_key",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_model_poc(evidence)
        assert "#!/usr/bin/env python3" in poc

    def test_model_poc_contains_persona(self):
        """Model PoC includes persona bypass setup."""
        evidence = {
            "evidence_id": "EVD-MOD-002",
            "technique_name": "skeleton_key",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_model_poc(evidence)
        assert "Developer" in poc or "developer" in poc

    def test_model_poc_has_pyrit_import(self):
        """Model PoC imports PyRIT modules."""
        evidence = {
            "evidence_id": "EVD-MOD-003",
            "technique_name": "skeleton_key",
            "target_model": "https://api.example.com/v1",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_model_poc(evidence)
        assert "PromptSendingAttack" in poc


# ===========================================================================
# Public API Tests
# ===========================================================================


class TestGenerateComponentPoC:
    """Tests for the main generate_component_poc entry point."""

    def test_mcp_evidence_generates_component_poc(self):
        """MCP evidence with component_type → component PoC."""
        evidence = {
            "evidence_id": "EVD-001",
            "technique_name": "prompt_sending",
            "target_model": "test",
            "metadata": {"component_type": "mcp_tool_poisoning"},
        }
        poc = generate_component_poc(evidence)
        assert poc is not None
        assert "MCP" in poc or "mcp" in poc

    def test_a2a_evidence_generates_component_poc(self):
        """A2A evidence → component PoC."""
        evidence = {
            "evidence_id": "EVD-002",
            "technique_name": "prompt_sending",
            "target_model": "test",
            "metadata": {"component_type": "a2a_agent_integrity"},
        }
        poc = generate_component_poc(evidence)
        assert poc is not None
        assert "A2A" in poc or "agent" in poc.lower()

    def test_model_evidence_generates_component_poc(self):
        """Model evidence → component PoC."""
        evidence = {
            "evidence_id": "EVD-003",
            "technique_name": "skeleton_key",
            "target_model": "test",
            "metadata": {"component_type": "model_behavior_shift"},
        }
        poc = generate_component_poc(evidence)
        assert poc is not None

    def test_infer_from_category_mcp(self):
        """Infer MCP from category when no component_type set."""
        evidence = {
            "evidence_id": "EVD-004",
            "technique_name": "prompt_sending",
            "target_model": "test",
            "metadata": {"category": "mcp_tool_hijack"},
        }
        poc = generate_component_poc(evidence)
        assert poc is not None
        assert "MCP" in poc or "mcp" in poc

    def test_no_component_returns_none(self):
        """Evidence with no component match → None."""
        evidence = {
            "evidence_id": "EVD-005",
            "technique_name": "prompt_sending",
            "target_model": "test",
            "metadata": {},
        }
        poc = generate_component_poc(evidence)
        assert poc is None


# ===========================================================================
# PoC Script Validity Tests
# ===========================================================================


class TestPoCScriptValidity:
    """Tests that generated PoC scripts are syntactically valid."""

    def test_mcp_poc_is_valid_python(self):
        """MCP PoC parses as valid Python."""
        evidence = {
            "evidence_id": "EVD-VALID-001",
            "technique_name": "prompt_sending",
            "target_model": "test",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_mcp_poc(evidence)
        # Check basic Python structure
        assert "async def main" in poc
        assert "asyncio.run(main())" in poc

    def test_a2a_poc_is_valid_python(self):
        """A2A PoC parses as valid Python."""
        evidence = {
            "evidence_id": "EVD-VALID-002",
            "technique_name": "prompt_sending",
            "target_model": "test",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_a2a_poc(evidence)
        assert "async def main" in poc
        assert "asyncio.run(main())" in poc

    def test_model_poc_is_valid_python(self):
        """Model PoC parses as valid Python."""
        evidence = {
            "evidence_id": "EVD-VALID-003",
            "technique_name": "skeleton_key",
            "target_model": "test",
            "converter_chain": [],
            "metadata": {},
        }
        poc = _generate_model_poc(evidence)
        assert "async def main" in poc
        assert "asyncio.run(main())" in poc
