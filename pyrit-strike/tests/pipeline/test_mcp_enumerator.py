"""MCP 枚举模块单元测试。

测试覆盖:
    1. _extract_tools_from_response — 从 JSON-RPC 响应提取 tools
    2. _extract_resources_from_response — 提取 resources
    3. _extract_prompts_from_response — 提取 prompts
    4. _extract_server_info — 提取 server info
    5. build_mcp_attack_seeds — 从枚举结果生成攻击种子
    6. enumerate_mcp_endpoint — 集成测试 (mocked httpx)
    7. _error_based_enumeration — 错误推断枚举 (mocked)
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# _extract_tools_from_response
# ═══════════════════════════════════════════════════════


class TestExtractToolsFromResponse:
    """测试 _extract_tools_from_response — 从 JSON-RPC 响应提取 tools."""

    def test_standard_response(self):
        """标准 MCP tools/list 响应."""
        from pipeline.recon.mcp_enumerator import _extract_tools_from_response

        response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read file contents",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
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
        assert tools[0]["inputSchema"]["required"] == ["path"]
        assert tools[1]["name"] == "write_file"

    def test_empty_tools(self):
        """空 tools 列表."""
        from pipeline.recon.mcp_enumerator import _extract_tools_from_response

        response = {"jsonrpc": "2.0", "result": {"tools": []}, "id": "test-2"}
        tools = _extract_tools_from_response(response)
        assert tools == []

    def test_missing_result(self):
        """缺少 result 字段."""
        from pipeline.recon.mcp_enumerator import _extract_tools_from_response

        response = {"jsonrpc": "2.0", "id": "test-3"}
        tools = _extract_tools_from_response(response)
        assert tools == []

    def test_missing_tools_key(self):
        """result 中缺少 tools 键."""
        from pipeline.recon.mcp_enumerator import _extract_tools_from_response

        response = {"jsonrpc": "2.0", "result": {}, "id": "test-4"}
        tools = _extract_tools_from_response(response)
        assert tools == []

    def test_tool_without_name(self):
        """tool 缺少 name 字段 — 应被过滤."""
        from pipeline.recon.mcp_enumerator import _extract_tools_from_response

        response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"description": "No name"},
                    {"name": "valid_tool", "description": "Valid"},
                ]
            },
            "id": "test-5",
        }
        tools = _extract_tools_from_response(response)
        assert len(tools) == 1
        assert tools[0]["name"] == "valid_tool"

    def test_non_dict_result(self):
        """result 不是 dict."""
        from pipeline.recon.mcp_enumerator import _extract_tools_from_response

        response = {"jsonrpc": "2.0", "result": "not a dict", "id": "test-6"}
        tools = _extract_tools_from_response(response)
        assert tools == []


# ═══════════════════════════════════════════════════════
# _extract_resources_from_response
# ═══════════════════════════════════════════════════════


class TestExtractResourcesFromResponse:
    """测试 _extract_resources_from_response — 从 JSON-RPC 响应提取 resources."""

    def test_standard_response(self):
        """标准 resources/list 响应."""
        from pipeline.recon.mcp_enumerator import _extract_resources_from_response

        response = {
            "jsonrpc": "2.0",
            "result": {
                "resources": [
                    {"uri": "file:///etc/passwd", "name": "passwd", "description": "System users"},
                    {"uri": "file:///etc/shadow", "name": "shadow", "description": "Password hashes"},
                ]
            },
            "id": "test-res-1",
        }
        resources = _extract_resources_from_response(response)
        assert len(resources) == 2
        assert resources[0]["uri"] == "file:///etc/passwd"
        assert resources[0]["name"] == "passwd"
        assert resources[1]["uri"] == "file:///etc/shadow"

    def test_empty_resources(self):
        """空 resources 列表."""
        from pipeline.recon.mcp_enumerator import _extract_resources_from_response

        response = {"jsonrpc": "2.0", "result": {"resources": []}, "id": "test-res-2"}
        resources = _extract_resources_from_response(response)
        assert resources == []

    def test_missing_result(self):
        """缺少 result 字段."""
        from pipeline.recon.mcp_enumerator import _extract_resources_from_response

        response = {"jsonrpc": "2.0", "id": "test-res-3"}
        resources = _extract_resources_from_response(response)
        assert resources == []


# ═══════════════════════════════════════════════════════
# _extract_prompts_from_response
# ═══════════════════════════════════════════════════════


class TestExtractPromptsFromResponse:
    """测试 _extract_prompts_from_response — 从 JSON-RPC 响应提取 prompts."""

    def test_standard_response(self):
        """标准 prompts/list 响应."""
        from pipeline.recon.mcp_enumerator import _extract_prompts_from_response

        response = {
            "jsonrpc": "2.0",
            "result": {
                "prompts": [
                    {"name": "code_review", "description": "Review code"},
                    {"name": "security_audit", "description": "Security audit"},
                ]
            },
            "id": "test-prm-1",
        }
        prompts = _extract_prompts_from_response(response)
        assert len(prompts) == 2
        assert prompts[0]["name"] == "code_review"
        assert prompts[1]["name"] == "security_audit"

    def test_empty_prompts(self):
        """空 prompts 列表."""
        from pipeline.recon.mcp_enumerator import _extract_prompts_from_response

        response = {"jsonrpc": "2.0", "result": {"prompts": []}, "id": "test-prm-2"}
        prompts = _extract_prompts_from_response(response)
        assert prompts == []

    def test_prompt_without_name(self):
        """prompt 缺少 name — 应被过滤."""
        from pipeline.recon.mcp_enumerator import _extract_prompts_from_response

        response = {
            "jsonrpc": "2.0",
            "result": {
                "prompts": [
                    {"description": "No name"},
                    {"name": "valid_prompt"},
                ]
            },
            "id": "test-prm-3",
        }
        prompts = _extract_prompts_from_response(response)
        assert len(prompts) == 1
        assert prompts[0]["name"] == "valid_prompt"


# ═══════════════════════════════════════════════════════
# _extract_server_info
# ═══════════════════════════════════════════════════════


class TestExtractServerInfo:
    """测试 _extract_server_info — 从 initialize 响应提取 server info."""

    def test_standard_response(self):
        """标准 MCP initialize 响应."""
        from pipeline.recon.mcp_enumerator import _extract_server_info

        response = {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": True, "resources": True},
                "serverInfo": {"name": "mcp-server", "version": "1.0"},
            },
            "id": "test-srv-1",
        }
        info = _extract_server_info(response)
        assert info is not None
        assert info["name"] == "mcp-server"
        assert info["version"] == "1.0"
        assert info["protocol_version"] == "2024-11-05"
        assert info["capabilities"] == {"tools": True, "resources": True}

    def test_missing_server_info(self):
        """缺少 serverInfo 字段."""
        from pipeline.recon.mcp_enumerator import _extract_server_info

        response = {
            "jsonrpc": "2.0",
            "result": {"protocolVersion": "2024-11-05"},
            "id": "test-srv-2",
        }
        info = _extract_server_info(response)
        assert info is None

    def test_missing_result(self):
        """缺少 result 字段."""
        from pipeline.recon.mcp_enumerator import _extract_server_info

        response = {"jsonrpc": "2.0", "id": "test-srv-3"}
        info = _extract_server_info(response)
        assert info is None


# ═══════════════════════════════════════════════════════
# build_mcp_attack_seeds
# ═══════════════════════════════════════════════════════


class TestBuildMcpAttackSeeds:
    """测试 build_mcp_attack_seeds — 从枚举结果生成攻击种子."""

    def test_seeds_from_tools(self):
        """从 tools 生成参数注入种子."""
        from pipeline.recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [
            {
                "name": "read_file",
                "description": "Read file contents",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
            {
                "name": "execute_command",
                "description": "Execute shell command",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cmd": {"type": "string"}},
                    "required": ["cmd"],
                },
            },
        ]
        resources = []

        seeds = build_mcp_attack_seeds(tools, resources)
        # 2 tool seeds + 1 cross-tool seed = 3
        assert len(seeds) == 3
        # 检查 tool 注入种子
        tool_seeds = [s for s in seeds if s["metadata"]["category"] == "mcp_tool_call_injection"]
        assert len(tool_seeds) == 2
        assert tool_seeds[0]["metadata"]["mcp_tool_name"] == "read_file"
        assert tool_seeds[1]["metadata"]["mcp_tool_name"] == "execute_command"
        # 检查 cross-tool 种子
        cross_seeds = [s for s in seeds if s["metadata"]["category"] == "mcp_cross_tool_exploit"]
        assert len(cross_seeds) == 1

    def test_seeds_from_resources(self):
        """从 resources 生成读取种子."""
        from pipeline.recon.mcp_enumerator import build_mcp_attack_seeds

        tools = []
        resources = [
            {"uri": "file:///etc/passwd", "name": "passwd", "description": "System users"},
            {"uri": "file:///app/config", "name": "config", "description": "App config"},
        ]

        seeds = build_mcp_attack_seeds(tools, resources)
        assert len(seeds) == 2
        res_seeds = [s for s in seeds if s["metadata"]["category"] == "mcp_resource_extraction"]
        assert len(res_seeds) == 2
        assert res_seeds[0]["metadata"]["mcp_resource_uri"] == "file:///etc/passwd"

    def test_seeds_from_tools_and_resources(self):
        """从 tools + resources 生成混合种子."""
        from pipeline.recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [{"name": "search", "description": "Search", "inputSchema": {}}]
        resources = [{"uri": "file:///data", "name": "data", "description": ""}]

        seeds = build_mcp_attack_seeds(tools, resources)
        # 1 tool + 1 resource + 0 cross-tool (need >= 2 tools) = 2
        assert len(seeds) == 2

    def test_empty_inputs(self):
        """空 tools 和 resources."""
        from pipeline.recon.mcp_enumerator import build_mcp_attack_seeds

        seeds = build_mcp_attack_seeds([], [])
        assert seeds == []

    def test_seed_metadata_has_arxiv_reference(self):
        """种子 metadata 包含 arXiv 引用."""
        from pipeline.recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [{"name": "read_file", "description": "", "inputSchema": {}}]
        seeds = build_mcp_attack_seeds(tools, [])
        assert "arxiv_reference" in seeds[0]["metadata"]
        assert "2302.12173" in seeds[0]["metadata"]["arxiv_reference"]

    def test_seed_uses_skeleton_key_prefix(self):
        """种子使用 Skeleton Key 前缀."""
        from pipeline.recon.mcp_enumerator import build_mcp_attack_seeds

        tools = [{"name": "exec", "description": "", "inputSchema": {}}]
        seeds = build_mcp_attack_seeds(tools, [])
        assert "SK." in seeds[0]["value"]
        assert "skeleton-key" in seeds[0]["value"].lower()


# ═══════════════════════════════════════════════════════
# enumerate_mcp_endpoint (mocked)
# ═══════════════════════════════════════════════════════


class TestEnumerateMcpEndpoint:
    """测试 enumerate_mcp_endpoint — 集成测试 (mocked httpx)."""

    @pytest.fixture
    def mock_parsed_request(self):
        """Mock ParsedBurpRequest."""
        mock = MagicMock()
        mock.use_tls = True
        mock.host = "target.example.com"
        mock.path = "/api/mcp"
        mock.method = "POST"
        mock.raw_headers = [
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer test-token"),
        ]
        return mock

    @pytest.mark.asyncio
    async def test_successful_enumeration(self, mock_parsed_request):
        """成功枚举 — MCP server 返回 tools/resources/prompts."""
        from pipeline.recon.mcp_enumerator import enumerate_mcp_endpoint

        # Mock httpx.AsyncClient
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "read_file", "description": "Read", "inputSchema": {}},
                ],
                "resources": [
                    {"uri": "file:///etc/hosts", "name": "hosts", "description": "DNS hosts"},
                ],
                "prompts": [
                    {"name": "analyze", "description": "Analyze code"},
                ],
            },
            "id": "test",
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await enumerate_mcp_endpoint(mock_parsed_request)

        assert results["has_mcp"] is True
        assert len(results["tools"]) == 1
        assert results["tools"][0]["name"] == "read_file"
        assert len(results["resources"]) == 1
        assert results["resources"][0]["uri"] == "file:///etc/hosts"
        assert len(results["prompts"]) == 1
        assert results["prompts"][0]["name"] == "analyze"
        assert results["tool_names"] == ["read_file"]

    @pytest.mark.asyncio
    async def test_no_mcp_endpoint(self, mock_parsed_request):
        """目标不是 MCP server — HTTP 错误."""
        from pipeline.recon.mcp_enumerator import enumerate_mcp_endpoint

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await enumerate_mcp_endpoint(mock_parsed_request)

        assert results["has_mcp"] is False
        assert results["tools"] == []
        assert results["tool_names"] == []

    @pytest.mark.asyncio
    async def test_none_parsed_request(self):
        """parsed_request 为 None — 返回空结果."""
        from pipeline.recon.mcp_enumerator import enumerate_mcp_endpoint

        results = await enumerate_mcp_endpoint(None)
        assert results["has_mcp"] is False
        assert results["tools"] == []

    @pytest.mark.asyncio
    async def test_jsonrpc_error_response(self, mock_parsed_request):
        """JSON-RPC error 响应 — has_mcp 仍为 False."""
        from pipeline.recon.mcp_enumerator import enumerate_mcp_endpoint

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": "test",
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await enumerate_mcp_endpoint(mock_parsed_request)

        assert results["has_mcp"] is False


# ═══════════════════════════════════════════════════════
# _error_based_enumeration (mocked)
# ═══════════════════════════════════════════════════════


class TestErrorBasedEnumeration:
    """测试 _error_based_enumeration — 错误推断枚举."""

    @pytest.fixture
    def mock_parsed_request(self):
        """Mock ParsedBurpRequest."""
        mock = MagicMock()
        mock.use_tls = False
        mock.host = "localhost"
        mock.path = "/mcp"
        mock.method = "POST"
        mock.raw_headers = [("Content-Type", "application/json")]
        return mock

    @pytest.mark.asyncio
    async def test_error_with_available_tools(self, mock_parsed_request):
        """错误响应中包含可用 tool 列表."""
        from pipeline.recon.mcp_enumerator import _error_based_enumeration

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32602,
                "message": "Invalid params",
                "data": {
                    "availableTools": [
                        {"name": "read_file", "description": "Read file"},
                        {"name": "write_file", "description": "Write file"},
                    ],
                },
            },
            "id": "probe-1",
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            tools = await _error_based_enumeration(mock_parsed_request)

        assert len(tools) == 2
        assert tools[0]["name"] == "read_file"
        assert tools[1]["name"] == "write_file"

    @pytest.mark.asyncio
    async def test_error_with_tool_names_in_message(self, mock_parsed_request):
        """错误消息文本中包含可用 tool 名称."""
        from pipeline.recon.mcp_enumerator import _error_based_enumeration

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32602,
                "message": "Unknown tool '__strike_probe_invalid__'. Available tools: [read_file, exec_cmd, search]",
            },
            "id": "probe-2",
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            tools = await _error_based_enumeration(mock_parsed_request)

        assert len(tools) == 3
        tool_names = [t["name"] for t in tools]
        assert "read_file" in tool_names
        assert "exec_cmd" in tool_names
        assert "search" in tool_names

    @pytest.mark.asyncio
    async def test_error_no_tools_found(self, mock_parsed_request):
        """错误响应中没有 tool 信息."""
        from pipeline.recon.mcp_enumerator import _error_based_enumeration

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32603, "message": "Internal error"},
            "id": "probe-3",
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("httpx.AsyncClient", return_value=mock_client):
            tools = await _error_based_enumeration(mock_parsed_request)

        assert tools == []
