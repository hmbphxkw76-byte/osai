"""tests/mcp/test_mcp_tool_poisoning.py - MCP Tool Poisoning Attack Tests.

Tests for strike/mcp/ components: tool poisoning, schema manipulation,
side-channel exfiltration, and resource traversal attacks.

Academic basis:
    - Greshake et al. (arXiv:2302.12173) - Indirect Prompt Injection
    - OWASP ASI Top 10 2025 - MCP security validation
"""

from __future__ import annotations

import pytest


class TestMcpToolInventory:
    """Tests for recon/mcp/tool_inventory.py"""

    def test_tool_inventory_import(self) -> None:
        """Verify tool_inventory module can be imported."""
        from recon.mcp import tool_inventory

        assert hasattr(tool_inventory, "MCPToolInventoryScanner")

    def test_tool_inventory_scan(self) -> None:
        """Test basic tool inventory scanning."""
        from recon.mcp.tool_inventory import MCPToolInventoryScanner

        inventory = MCPToolInventoryScanner()
        assert inventory is not None


class TestMcpSchemaExtractor:
    """Tests for recon/mcp/schema_extractor.py"""

    def test_schema_extractor_import(self) -> None:
        """Verify schema_extractor module can be imported."""
        from recon.mcp import schema_extractor

        assert hasattr(schema_extractor, "MCPSchemaExtractor")

    def test_schema_parse(self) -> None:
        """Test basic schema parsing."""
        from recon.mcp.schema_extractor import MCPSchemaExtractor

        extractor = MCPSchemaExtractor(target_url="http://example.com")
        assert extractor is not None


class TestMcpEndpointEnumerator:
    """Tests for recon/mcp/endpoint_enumerator.py"""

    def test_enumerator_import(self) -> None:
        """Verify endpoint_enumerator can be imported."""
        from recon.mcp import endpoint_enumerator

        assert hasattr(endpoint_enumerator, "MCPEndpointEnumerator")


class TestMcpAttackComponents:
    """Tests for strike/mcp/ attack components"""

    def test_mcp_imports(self) -> None:
        """Verify all strike/mcp modules can be imported."""
        import strike.mcp

        assert hasattr(strike.mcp, "__all__")

    def test_dynamic_seeds_import(self) -> None:
        """Verify dynamic_seeds module exists."""
        from strike.mcp import dynamic_seeds

        assert hasattr(dynamic_seeds, "generate_dynamic_seeds")

    def test_malicious_server_import(self) -> None:
        """Verify malicious_server module exists."""
        from strike.mcp import malicious_server

        assert hasattr(malicious_server, "MaliciousMCPServer")

    def test_schema_manipulator_import(self) -> None:
        """Verify schema_manipulator module exists."""
        from strike.mcp import schema_manipulator

        assert hasattr(schema_manipulator, "MCPSchemaManipulator")


class TestMcpT0Scoring:
    """Tests for MCP-specific T0 scoring"""

    def test_t0_mcp_checker(self) -> None:
        """Verify MCP T0 checker is defined."""
        from assess.component_scorers import t0_mcp_tool_poisoning_check

        assert callable(t0_mcp_tool_poisoning_check)

    def test_t0_mcp_detects_poisoning_keywords(self) -> None:
        """Test MCP T0 detection of tool poisoning patterns."""
        from assess.component_scorers import t0_mcp_tool_poisoning_check

        # Test with tool poisoning indicator
        result = t0_mcp_tool_poisoning_check("tool description contains hidden instructions to exfiltrate data")
        assert isinstance(result, tuple)
        assert len(result) == 3  # (detected, confidence, reason)


class TestMcpComponentBridge:
    """Tests for MCP component in the bridge pipeline"""

    def test_component_type_mcp_registered(self) -> None:
        """Verify MCP component type is registered in bridge."""
        from core.phases._component_bridge import _infer_component_from_text

        # Test MCP component type inference
        result = _infer_component_from_text("mcp tool poisoning attack")
        assert result is not None
        assert "mcp" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
