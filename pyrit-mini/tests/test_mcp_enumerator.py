# arXiv:2302.12173 — Indirect prompt injection via tool output
"""Tests for recon/mcp_enumerator.py — MCP endpoint enumeration.

Covers:
    - _extract_tools_from_response: JSON-RPC tools/list parsing
    - _extract_resources_from_response: JSON-RPC resources/list parsing
    - _extract_prompts_from_response: JSON-RPC prompts/list parsing
    - _extract_server_info: MCP initialize response parsing
    - build_mcp_attack_seeds: attack seed generation from MCP enumeration

学术依据:
    - Anthropic MCP Specification (2024) §3.2 — JSON-RPC methods
    - Greshake et al. (arXiv:2302.12173) §4 — 间接提示注入
    - Zhan et al. (arXiv:2307.00929) §3.3 — InjecAgent 参数注入
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestExtractToolsFromResponse:
    """Test _extract_tools_from_response — JSON-RPC tools/list parsing."""

    def test_standard_mcp_tools_list(self):
        """Standard MCP tools/list response should be parsed."""
        from recon.mcp_enumerator import _extract_tools_from_response

        response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read file contents",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"}
                            },
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "write_file",
                        "description": "Write file contents",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"},
                            },
                            "required": ["path", "content"],
                        },
                    },
                ]
            },
            "id": "test-1",
        }
        tools = _extract_tools_from_response(response)
        assert len(tools) == 2
        assert tools[0]["name"] == "read_file"
        assert tools[0]["description"] == "Read file contents"
        assert "path" in tools[0]["inputSchema"]["properties"]
        assert tools[1]["name"] == "write_file"

    def test_empty_tools_list(self):
        """Empty tools list should return empty list."""
        from recon.mcp_enumerator import _extract_tools_from_response

        response = {"jsonrpc": "2.0", "result": {"tools": []}, "id": "test"}
        tools = _extract_tools_from_response(response)
        assert tools == []

    def test_no_result_key(self):
        """Response without 'result' key should return empty list."""
        from recon.mcp_enumerator import _extract_tools_from_response

        response = {"jsonrpc": "2.0", "id": "test"}
        tools = _extract_tools_from_response(response)
        assert tools == []

    def test_tools_not_list(self):
        """Non-list tools should return empty list."""
        from recon.mcp_enumerator import _extract_tools_from_response

        response = {"result": {"tools": "not a list"}}
        tools = _extract_tools_from_response(response)
        assert tools == []

    def test_tool_without_name_filtered(self):
        """Tool without name should be filtered out."""
        from recon.mcp_enumerator import _extract_tools_from_response

        response = {
            "result": {
                "tools": [
                    {"name": "valid_tool", "description": "A valid tool"},
                    {"description": "No name field"},
                ]
            }
        }
        tools = _extract_tools_from_response(response)
        assert len(tools) == 1
        assert tools[0]["name"] == "valid_tool"

    def test_default_description_and_schema(self):
        """Missing description/inputSchema should get defaults."""
        from recon.mcp_enumerator import _extract_tools_from_response

        response = {
            "result": {
                "tools": [{"name": "bare_tool"}]
            }
        }
        tools = _extract_tools_from_response(response)
        assert tools[0]["description"] == ""
        assert tools[0]["inputSchema"] == {}


class TestExtractResourcesFromResponse:
    """Test _extract_resources_from_response — JSON-RPC resources/list parsing."""

    def test_standard_resources_list(self):
        """Standard MCP resources/list response should be parsed."""
        from recon.mcp_enumerator import _extract_resources_from_response

        response = {
            "result": {
                "resources": [
                    {"uri": "file:///config.json", "name": "config", "description": "Config file"},
                    {"uri": "file:///secrets.env", "name": "secrets", "description": "Secrets file"},
                ]
            }
        }
        resources = _extract_resources_from_response(response)
        assert len(resources) == 2
        assert resources[0]["uri"] == "file:///config.json"
        assert resources[0]["name"] == "config"

    def test_empty_resources(self):
        """Empty resources list should return empty list."""
        from recon.mcp_enumerator import _extract_resources_from_response

        response = {"result": {"resources": []}}
        resources = _extract_resources_from_response(response)
        assert resources == []

    def test_resource_with_only_name(self):
        """Resource with only name (no uri) should be included."""
        from recon.mcp_enumerator import _extract_resources_from_response

        response = {
            "result": {
                "resources": [{"name": "config_only"}]
            }
        }
        resources = _extract_resources_from_response(response)
        assert len(resources) == 1
        assert resources[0]["name"] == "config_only"
        assert resources[0]["uri"] == ""


class TestExtractPromptsFromResponse:
    """Test _extract_prompts_from_response — JSON-RPC prompts/list parsing."""

    def test_standard_prompts_list(self):
        """Standard MCP prompts/list response should be parsed."""
        from recon.mcp_enumerator import _extract_prompts_from_response

        response = {
            "result": {
                "prompts": [
                    {"name": "code_review", "description": "Review code"},
                    {"name": "summarize", "description": "Summarize text"},
                ]
            }
        }
        prompts = _extract_prompts_from_response(response)
        assert len(prompts) == 2
        assert prompts[0]["name"] == "code_review"
        assert prompts[0]["description"] == "Review code"

    def test_prompt_without_name_filtered(self):
        """Prompt without name should be filtered out."""
        from recon.mcp_enumerator import _extract_prompts_from_response

        response = {
            "result": {
                "prompts": [
                    {"description": "No name"},
                    {"name": "valid_prompt", "description": "Valid"},
                ]
            }
        }
        prompts = _extract_prompts_from_response(response)
        assert len(prompts) == 1
        assert prompts[0]["name"] == "valid_prompt"


class TestExtractServerInfo:
    """Test _extract_server_info — MCP initialize response parsing."""

    def test_standard_server_info(self):
        """Standard MCP initialize response should be parsed."""
        from recon.mcp_enumerator import _extract_server_info

        response = {
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "my-mcp-server", "version": "1.2.0"},
            }
        }
        info = _extract_server_info(response)
        assert info is not None
        assert info["name"] == "my-mcp-server"
        assert info["version"] == "1.2.0"
        assert info["protocol_version"] == "2024-11-05"

    def test_no_server_info(self):
        """Response without serverInfo should return None."""
        from recon.mcp_enumerator import _extract_server_info

        response = {"result": {"protocolVersion": "2024-11-05"}}
        info = _extract_server_info(response)
        assert info is None

    def test_empty_server_info(self):
        """Empty serverInfo dict should return None."""
        from recon.mcp_enumerator import _extract_server_info

        response = {"result": {"serverInfo": {}}}
        info = _extract_server_info(response)
        assert info is None


class TestBuildMcpAttackSeeds:
    """Test build_mcp_attack_seeds — attack seed generation."""

    def test_tool_injection_seeds(self):
        """Should generate injection seeds for each tool."""
        from recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [
            {
                "name": "read_file",
                "description": "Read file",
                "inputSchema": {
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        ]
        resources = []
        seeds = build_mcp_attack_seeds(tools, resources)
        assert len(seeds) >= 1
        # Find the tool injection seed
        tool_seeds = [s for s in seeds if s["metadata"]["category"] == "mcp_tool_call_injection"]
        assert len(tool_seeds) == 1
        assert tool_seeds[0]["metadata"]["mcp_tool_name"] == "read_file"
        assert "path" in tool_seeds[0]["metadata"]["mcp_tool_params"]
        assert "read_file" in tool_seeds[0]["value"]

    def test_resource_extraction_seeds(self):
        """Should generate extraction seeds for each resource."""
        from recon.mcp_enumerator import build_mcp_attack_seeds

        resources = [
            {"uri": "file:///config.json", "name": "config", "description": ""},
        ]
        seeds = build_mcp_attack_seeds([], resources)
        res_seeds = [s for s in seeds if s["metadata"]["category"] == "mcp_resource_extraction"]
        assert len(res_seeds) == 1
        assert "config" in res_seeds[0]["value"]

    def test_cross_tool_seed(self):
        """Should generate cross-tool seed when 2+ tools."""
        from recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [
            {"name": "tool1", "description": "", "inputSchema": {}},
            {"name": "tool2", "description": "", "inputSchema": {}},
        ]
        seeds = build_mcp_attack_seeds(tools, [])
        cross_seeds = [s for s in seeds if s["metadata"]["category"] == "mcp_cross_tool_exploit"]
        assert len(cross_seeds) == 1
        assert "tool1" in cross_seeds[0]["value"]
        assert "tool2" in cross_seeds[0]["value"]

    def test_no_tools_no_resources(self):
        """No tools or resources → empty seeds."""
        from recon.mcp_enumerator import build_mcp_attack_seeds

        seeds = build_mcp_attack_seeds([], [])
        assert seeds == []

    def test_seed_metadata_has_arxiv_reference(self):
        """All seeds should have arxiv_reference in metadata."""
        from recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [{"name": "test_tool", "description": "", "inputSchema": {}}]
        seeds = build_mcp_attack_seeds(tools, [])
        for seed in seeds:
            assert "arxiv_reference" in seed["metadata"]
            assert "arXiv:" in seed["metadata"]["arxiv_reference"]

    def test_seed_has_owasp_id(self):
        """All seeds should have OWASP ID."""
        from recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [{"name": "test_tool", "description": "", "inputSchema": {}}]
        seeds = build_mcp_attack_seeds(tools, [])
        for seed in seeds:
            assert seed["metadata"]["owasp_id"] == "ASI02"

    def test_seed_has_skeleton_key_prefix(self):
        """Seeds should contain skeleton key prefix for jailbreak."""
        from recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [{"name": "test_tool", "description": "", "inputSchema": {}}]
        seeds = build_mcp_attack_seeds(tools, [])
        for seed in seeds:
            assert "SK" in seed["value"] or "skeleton-key" in seed["value"]
