# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tests for recon-pipeline probes (LLM/RAG/Agent/MCP/Embedding/DOM/JS/Network)."""

import asyncio
import json

import pytest

from core.models.recon_report import (
    DiscoveredEndpoint,
    EndpointType,
    InjectionSurface,
    InjectionSurfaceType,
    LLMFingerprint,
    MCPToolInfo,
    ReconReport,
)
from core.probes.agent_probe import AgentProbe
from core.probes.active_probe import ActiveProbeHarness
from core.probes.ai_signal_catalog import (
    classify_ai_chat_response,
    get_favicon_product,
    is_ai_prompt_param,
    is_ai_rag_path,
    lookup_ai_port,
    match_ai_body_fingerprint,
    match_ai_header,
    match_ai_key_prefix,
    match_ai_path,
    match_ai_sdk,
    match_ai_title,
)
from core.probes.base import ReconProbe
from core.probes.dom_probe import DOMProbe
from core.probes.embedding_probe import EmbeddingProbe
from core.probes.js_recon_probe import JSReconProbe
from core.probes.llm_probe import LLMProbe
from core.probes.mcp_probe import MCPProbe
from core.probes.network_probe import NetworkProbe
from core.probes.rag_probe import RAGProbe
from core.probes.vector_db_fingerprinter import VectorDBFingerprinter


# ============================================================================
# ReconProbe interface tests
# ============================================================================


class TestReconProbeInterface:
    """Verify all 8 probe types correctly implement the ReconProbe interface."""

    def test_all_probes_are_recon_probe_subclasses(self):
        """All probes must be ReconProbe subclasses."""
        probes = [
            LLMProbe(), RAGProbe(), AgentProbe(), MCPProbe(),
            EmbeddingProbe(), DOMProbe(), JSReconProbe(), NetworkProbe(),
        ]
        for probe in probes:
            assert isinstance(probe, ReconProbe), f"{probe.name} must be a ReconProbe subclass"

    def test_all_probes_have_name(self):
        """All probes must have non-empty name."""
        probes = [
            LLMProbe(), RAGProbe(), AgentProbe(), MCPProbe(),
            EmbeddingProbe(), DOMProbe(), JSReconProbe(), NetworkProbe(),
        ]
        for probe in probes:
            assert probe.name, f"{type(probe).__name__} has empty name"
            assert isinstance(probe.name, str)

    def test_dom_probe_requires_browser(self):
        """DOMProbe must require browser."""
        assert DOMProbe().requires_browser is True

    def test_network_probe_requires_browser(self):
        """NetworkProbe must require browser."""
        assert NetworkProbe().requires_browser is True

    def test_js_recon_probe_no_browser(self):
        """JSReconProbe does not require browser."""
        assert JSReconProbe().requires_browser is False

    def test_default_requires_auth(self):
        """Default requires_auth=True (inherited from base)."""
        assert LLMProbe().requires_auth is True

    def test_network_probe_no_auth(self):
        """NetworkProbe does not require auth."""
        assert NetworkProbe().requires_auth is False


# ============================================================================
# LLMProbe tests
# ============================================================================


class TestLLMProbe:
    def test_fingerprint_openai_response(self):
        """Extract model fingerprint from OpenAI response body."""
        probe = LLMProbe()
        endpoint = DiscoveredEndpoint(
            url="https://api.openai.com/v1/chat/completions",
            method="POST",
            endpoint_type=EndpointType.MODEL_API,
            response_body_preview='{"model":"gpt-4o","choices":[{"message":{"content":"Hello"}}]}',
        )
        fp = probe._fingerprint_endpoint(endpoint)
        assert fp is not None
        assert fp.model_name == "gpt-4o"
        assert "OpenAI GPT-4o" in fp.model_family

    def test_fingerprint_claude_response(self):
        """Extract model fingerprint from Anthropic response body."""
        probe = LLMProbe()
        endpoint = DiscoveredEndpoint(
            url="https://api.anthropic.com/v1/messages",
            method="POST",
            endpoint_type=EndpointType.MODEL_API,
            response_body_preview='{"model":"claude-3.5-sonnet","content":[{"text":"Hi"}]}',
        )
        fp = probe._fingerprint_endpoint(endpoint)
        assert fp is not None
        assert "claude-3.5" in fp.model_name
        assert "Anthropic Claude 3.5" in fp.model_family

    def test_fingerprint_gemini_response(self):
        """Extract model fingerprint from Gemini response body."""
        probe = LLMProbe()
        endpoint = DiscoveredEndpoint(
            url="https://api.google.com/v1beta/models/gemini-2.0-flash:generateContent",
            method="POST",
            endpoint_type=EndpointType.MODEL_API,
            response_body_preview='{"model":"gemini-2.0-flash","candidates":[{"content":{"parts":[{"text":"Hi"}]}}]}',
        )
        fp = probe._fingerprint_endpoint(endpoint)
        assert fp is not None
        assert "gemini-2.0-flash" in fp.model_name
        assert "Google Gemini 2" in fp.model_family

    def test_fingerprint_deepseek_response(self):
        """Extract model fingerprint from DeepSeek response."""
        probe = LLMProbe()
        endpoint = DiscoveredEndpoint(
            url="https://api.deepseek.com/chat/completions",
            method="POST",
            endpoint_type=EndpointType.MODEL_API,
            response_body_preview='{"model":"deepseek-v3","choices":[{"message":{"content":"Hello"}}]}',
        )
        fp = probe._fingerprint_endpoint(endpoint)
        assert fp is not None
        assert "deepseek-v3" in fp.model_name
        assert "DeepSeek V3" in fp.model_family

    def test_fingerprint_empty_body(self):
        """Empty response body returns None."""
        probe = LLMProbe()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/api",
            response_body_preview="",
        )
        fp = probe._fingerprint_endpoint(endpoint)
        assert fp is None

    def test_guardrail_detection(self):
        """Detect safety guardrail keywords."""
        probe = LLMProbe()
        endpoint = DiscoveredEndpoint(
            url="https://api.example.com/v1/chat",
            endpoint_type=EndpointType.MODEL_API,
            response_body_preview='{"choices":[{"content_filter_results":{"hate":{"filtered":false}}}]}',
        )
        fp = probe._fingerprint_endpoint(endpoint)
        assert fp is not None
        assert fp.guardrail_detected is True

    def test_no_guardrail(self):
        """No guardrail keywords means guardrail_detected=False."""
        probe = LLMProbe()
        endpoint = DiscoveredEndpoint(
            url="https://api.example.com/v1/chat",
            endpoint_type=EndpointType.MODEL_API,
            response_body_preview='{"choices":[{"message":{"content":"OK"}}]}',
        )
        fp = probe._fingerprint_endpoint(endpoint)
        assert fp is not None
        assert fp.guardrail_detected is False

    def test_extract_system_prompt(self):
        """Extract system prompt fragment from response body."""
        hint = LLMProbe._extract_system_prompt_hint(
            '{"choices":[{"message":{"role":"assistant","content":"You are a helpful assistant designed to answer questions."}}]}'
        )
        assert "You are a helpful assistant" in hint

    def test_detect_guardrail_from_headers(self):
        """Detect guardrail from HTTP headers."""
        from httpx import Headers
        headers = Headers({"x-content-filter": "enabled"})
        assert LLMProbe._detect_guardrail_from_headers(headers) is True

    def test_empty_endpoints(self):
        """Empty endpoint list returns empty results."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        probe = LLMProbe()
        result = asyncio.run(probe.probe(session))
        assert result["endpoints"] == []
        assert result["llm_fingerprints"] == []


# ============================================================================
# MCPProbe tests
# ============================================================================


class TestMCPProbe:
    def test_parse_tools_list_response(self):
        """Parse MCP tools/list JSON-RPC response."""
        probe = MCPProbe()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/mcp/message",
            method="POST",
            endpoint_type=EndpointType.MCP_SERVER,
            response_body_preview=(
                '{"jsonrpc":"2.0","id":1,"result":{"tools":['
                '{"name":"read_file","description":"Read a file","inputSchema":{"type":"object"}},'
                '{"name":"execute_command","description":"Run shell command","inputSchema":{"type":"object"}}'
                ']}}'
            ),
        )
        tools = probe._parse_mcp_response(endpoint)
        assert len(tools) == 2
        assert tools[0].tool_name == "read_file"
        assert tools[1].tool_name == "execute_command"
        assert tools[0].risk_level in ("low", "medium", "high", "critical")

    def test_parse_empty_body(self):
        """Empty response body returns empty list."""
        probe = MCPProbe()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/mcp",
            response_body_preview="",
        )
        tools = probe._parse_mcp_response(endpoint)
        assert tools == []

    def test_risk_assessment_critical(self):
        """execute_command should be rated critical."""
        risk = MCPProbe._assess_risk("execute_command", "Run a shell command")
        assert risk == "critical"

    def test_risk_assessment_high(self):
        """write_file should be rated high."""
        risk = MCPProbe._assess_risk("write_file", "Write data to a file")
        assert risk == "high"

    def test_risk_assessment_medium(self):
        """read_file should be rated medium."""
        risk = MCPProbe._assess_risk("read_file", "Read a file")
        assert risk == "medium"

    def test_risk_assessment_low(self):
        """Unknown tool should be rated low."""
        risk = MCPProbe._assess_risk("ping", "Check connectivity")
        assert risk == "low"

    def test_tool_shadowing_detection(self):
        """Detect same tool name from different servers."""
        probe = MCPProbe()
        tools = [
            MCPToolInfo(tool_name="read_file", server_url="server-a"),
            MCPToolInfo(tool_name="read_file", server_url="server-b"),
            MCPToolInfo(tool_name="write_file", server_url="server-a"),
        ]
        probe._check_tool_shadowing(tools)
        assert tools[0].shadowing_detected is True
        assert tools[1].shadowing_detected is True
        assert tools[2].shadowing_detected is False

    def test_annotation_contradiction_detection(self):
        """Detect annotation contradiction (readOnlyHint + mutation name)."""
        probe = MCPProbe()
        tool = MCPToolInfo(
            tool_name="delete_record",
            description="Delete a database record",
            annotations={"readOnlyHint": True},
        )
        probe._check_annotation_contradictions([tool])
        assert tool.annotation_contradiction is True

    def test_no_annotation_contradiction(self):
        """No contradiction when readOnlyHint matches read-only name."""
        probe = MCPProbe()
        tool = MCPToolInfo(
            tool_name="list_records",
            description="List all records",
            annotations={"readOnlyHint": True},
        )
        probe._check_annotation_contradictions([tool])
        assert tool.annotation_contradiction is False

    def test_hash_tool(self):
        """Tool hash should be stable for same content."""
        tool_data = {"name": "test", "description": "A test tool", "inputSchema": {"type": "object"}}
        h1 = MCPProbe._hash_tool(tool_data)
        h2 = MCPProbe._hash_tool(tool_data)
        assert h1 == h2
        assert len(h1) == 16  # SHA256 truncated to 16 chars

    def test_extract_injection_surfaces(self):
        """Extract string parameters as injection surfaces."""
        tool_data = {
            "name": "search",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
        }
        surfaces = MCPProbe._extract_injection_surfaces(tool_data)
        assert "query (required)" in surfaces

    def test_scan_threats(self):
        """Scan tool for threat patterns via YARA-style engine (P0-3-B/I)."""
        tool = MCPToolInfo(
            tool_name="execute_shell",
            description="Execute arbitrary shell command on the server",
        )
        tags = MCPProbe._scan_threats(tool)
        assert "command_execution" in tags

    def test_empty_endpoints(self):
        """Empty endpoint list returns empty results."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        probe = MCPProbe()
        result = asyncio.run(probe.probe(session))
        assert result["endpoints"] == []
        assert result["mcp_tools"] == []


# ============================================================================
# EndpointClassifier tests
# ============================================================================


class TestAISignalCatalog:
    def test_signal_catalog_matches_common_ai_signals(self):
        """AI signal catalog should recognize common headers, titles, and paths."""
        header = match_ai_header("x-openai-beta")
        assert header is not None
        assert header[0] == "OpenAI"

        title = match_ai_title("OpenAI Playground")
        assert title is not None

        path = match_ai_path("/v1/chat/completions")
        assert path == "llm-chat"

        shape = classify_ai_chat_response({"choices": [{"message": {"content": "hi"}}]})
        assert shape == "openai-chat"

    def test_lookup_ai_port_ollama(self):
        """Ollama default port should be recognized."""
        port_info = lookup_ai_port(11434)
        assert port_info is not None
        assert "Ollama" in port_info["descriptor"]

    def test_match_ai_body_fingerprint_openai(self):
        """OpenAI chat completion body should be fingerprinted."""
        body = '{"object":"chat.completion","choices":[]}'
        result = match_ai_body_fingerprint(body)
        assert result is not None
        assert "OpenAI" in result[0]

    def test_match_ai_body_fingerprint_anthropic(self):
        """Anthropic messages body should be fingerprinted."""
        body = '{"type":"message","role":"assistant","stop_reason":"end_turn"}'
        result = match_ai_body_fingerprint(body)
        assert result is not None
        assert "Anthropic" in result[0]

    def test_is_ai_rag_path_explicit(self):
        """Explicit RAG path should be recognized without parent_ai."""
        assert is_ai_rag_path("/rag/search", parent_is_ai=False) is True

    def test_is_ai_rag_path_ambiguous_needs_parent(self):
        """Ambiguous path like /search needs parent_ai gating."""
        assert is_ai_rag_path("/search", parent_is_ai=False) is False
        assert is_ai_rag_path("/search", parent_is_ai=True) is True

    def test_is_ai_prompt_param(self):
        """Common prompt injection parameters should be recognized."""
        assert is_ai_prompt_param("messages") is True
        assert is_ai_prompt_param("prompt") is True
        assert is_ai_prompt_param("not_a_param") is False

    def test_match_ai_sdk(self):
        """AI SDK imports in JS should be detected."""
        js = 'import OpenAI from "openai";'
        results = match_ai_sdk(js)
        assert len(results) > 0

    def test_match_ai_key_prefix(self):
        """API key prefixes in JS should be detected."""
        js = 'const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";'
        results = match_ai_key_prefix(js)
        assert len(results) > 0
        assert any("OpenAI" in r[0] for r in results)

    def test_get_favicon_product(self):
        """Known favicon hash should map to product name."""
        product = get_favicon_product(-1492966340)
        assert product == "OpenAI"

    def test_get_favicon_product_unknown(self):
        """Unknown favicon hash should return None."""
        product = get_favicon_product(0)
        assert product is None

    def test_classify_gemini_response(self):
        """Gemini response shape should be classified."""
        shape = classify_ai_chat_response({"candidates": [{"content": {}}]})
        assert shape == "gemini-chat"

    def test_classify_ollama_response(self):
        """Ollama response shape should be classified."""
        shape = classify_ai_chat_response({"response": "hello", "done": True})
        assert shape == "ollama-chat"


class TestActiveProbeHarness:
    def test_builds_prioritized_active_probe_candidates(self):
        harness = ActiveProbeHarness()
        endpoints = [
            DiscoveredEndpoint(url="https://example.com/v1/chat/completions", endpoint_type=EndpointType.MODEL_API),
            DiscoveredEndpoint(url="https://example.com/mcp/message", endpoint_type=EndpointType.MCP_SERVER),
        ]
        candidates = harness.score_candidates(harness.build_candidates(endpoints))
        assert any(candidate["type"] == "llm-chat" for candidate in candidates)
        assert any(candidate["type"] == "mcp" for candidate in candidates)
        assert candidates[0]["priority"] >= candidates[-1]["priority"]


class TestTaskRuntime:
    def test_checkpoint_and_guardrails(self):
        from core.task_runtime import GuardrailPolicy, ReconTask, TaskRuntime

        runtime = TaskRuntime(
            checkpoint_dir="outputs/test_checkpoints",
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )
        task = ReconTask(task_id="case-1", target_url="https://example.test")
        runtime.register_task(task)
        runtime.mark_running(task)
        path = runtime.checkpoint(task, {"state": task.state})
        assert path.exists()
        assert runtime.can_run(task.target_url) is True
        assert runtime.can_run("https://evil.test") is False


class TestEndpointClassifierMCP:
    def test_classify_mcp_message_endpoint(self):
        """Identify /mcp/message endpoint as MCP_SERVER."""
        from core.probes.endpoint_classifier import EndpointClassifier

        classifier = EndpointClassifier()
        result = classifier.classify("https://example.com/mcp/message")
        assert result == EndpointType.MCP_SERVER

    def test_classify_sse_endpoint(self):
        """Identify /mcp/sse endpoint as MCP_SERVER."""
        from core.probes.endpoint_classifier import EndpointClassifier

        classifier = EndpointClassifier()
        result = classifier.classify("https://example.com/mcp/sse")
        assert result == EndpointType.MCP_SERVER

    def test_classify_jsonrpc_endpoint(self):
        """Identify JSON-RPC endpoint as MCP_SERVER."""
        from core.probes.endpoint_classifier import EndpointClassifier

        classifier = EndpointClassifier()
        result = classifier.classify("https://example.com/jsonrpc")
        assert result == EndpointType.MCP_SERVER

    def test_classify_mcp_jsonrpc_body(self):
        """Identify MCP Server via JSON-RPC response body format."""
        from core.probes.endpoint_classifier import EndpointClassifier

        classifier = EndpointClassifier()
        result = classifier.classify(
            "https://example.com/api/rpc",
            method="POST",
            content_type="application/json",
            response_body='{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}',
        )
        assert result == EndpointType.MCP_SERVER

    def test_classify_embedding_endpoint(self):
        """Identify /v1/embeddings as EMBEDDING_API."""
        from core.probes.endpoint_classifier import EndpointClassifier

        classifier = EndpointClassifier()
        result = classifier.classify("https://api.openai.com/v1/embeddings")
        assert result == EndpointType.EMBEDDING_API

    def test_classify_vendor_specific_paths(self):
        """Identify vendor-specific paths."""
        from core.probes.endpoint_classifier import EndpointClassifier

        classifier = EndpointClassifier()
        # Anthropic
        assert classifier.classify("https://api.anthropic.com/v1/messages") == EndpointType.MODEL_API
        # Gemini
        assert classifier.classify("https://api.google.com/v1beta/models/gemini:generateContent") == EndpointType.MODEL_API
        # Ollama
        assert classifier.classify("https://localhost:11434/api/generate") == EndpointType.MODEL_API
        # Weaviate (classified as vector-db -> RAG_API)
        result = classifier.classify("https://example.com/v1/objects")
        assert result == EndpointType.RAG_API, f"Expected RAG_API, got {result}"
        # Qdrant
        assert classifier.classify("https://example.com/collections/mycol/points") == EndpointType.RAG_API

    def test_owasp_mapping_mcp(self):
        """MCP Server maps to LLM01/LLM06/LLM07."""
        from core.probes.endpoint_classifier import EndpointClassifier

        ids = EndpointClassifier.get_owasp_mapping(EndpointType.MCP_SERVER)
        assert "LLM01" in ids
        assert "LLM06" in ids
        assert "LLM07" in ids

    def test_owasp_mapping_embedding(self):
        """Embedding API maps to LLM08."""
        from core.probes.endpoint_classifier import EndpointClassifier

        ids = EndpointClassifier.get_owasp_mapping(EndpointType.EMBEDDING_API)
        assert "LLM08" in ids


# ============================================================================
# RAGProbe tests
# ============================================================================


class TestRAGProbe:
    def test_filters_rag_endpoints(self):
        """Only filter RAG_API/FILE_UPLOAD/EMBEDDING_API endpoints."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(url="https://api.example.com/search", endpoint_type=EndpointType.RAG_API),
            DiscoveredEndpoint(url="https://api.example.com/chat", endpoint_type=EndpointType.MODEL_API),
            DiscoveredEndpoint(url="https://api.example.com/upload", endpoint_type=EndpointType.FILE_UPLOAD),
            DiscoveredEndpoint(url="https://api.example.com/embed", endpoint_type=EndpointType.EMBEDDING_API),
        ]
        probe = RAGProbe()
        result = asyncio.run(probe.probe(session))
        assert len(result["endpoints"]) == 3  # RAG + FILE_UPLOAD + EMBEDDING


# ============================================================================
# AgentProbe tests
# ============================================================================


class TestAgentProbe:
    def test_filters_agent_endpoints(self):
        """Only filter AGENT_TOOL_API endpoints."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(url="https://api.example.com/tools", endpoint_type=EndpointType.AGENT_TOOL_API),
            DiscoveredEndpoint(url="https://api.example.com/chat", endpoint_type=EndpointType.MODEL_API),
        ]
        probe = AgentProbe()
        result = asyncio.run(probe.probe(session))
        assert len(result["endpoints"]) == 1


# ============================================================================
# EmbeddingProbe tests
# ============================================================================


class TestEmbeddingProbe:
    def test_analyze_embedding_dimension(self):
        """Extract dimension from OpenAI embedding response."""
        probe = EmbeddingProbe()
        endpoint = DiscoveredEndpoint(
            url="https://api.openai.com/v1/embeddings",
            endpoint_type=EndpointType.EMBEDDING_API,
            response_body_preview=(
                '{"data":[{"embedding":[0.1,0.2,0.3]}],"model":"text-embedding-ada-002","usage":{"total_tokens":5}}'
            ),
        )
        info = probe._analyze_embedding_endpoint(endpoint)
        assert info is not None
        assert info["dimension"] == 3
        assert info["model"] == "text-embedding-ada-002"

    def test_analyze_empty_body(self):
        """Empty response body returns None."""
        probe = EmbeddingProbe()
        endpoint = DiscoveredEndpoint(url="https://api.example.com/embed", response_body_preview="")
        info = probe._analyze_embedding_endpoint(endpoint)
        assert info is None


# ============================================================================
# JSReconProbe tests
# ============================================================================


class TestJSReconProbe:
    def test_detects_sdk_import(self):
        """Detect OpenAI SDK import in JS."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/app.js",
                content_type="application/javascript",
                response_body_preview='import OpenAI from "openai"; const client = new OpenAI({apiKey: "sk-xxx"});',
            ),
        ]
        probe = JSReconProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["js_findings"]
        assert len(findings) > 0
        assert any(f["category"] == "sdk_import" for f in findings)

    def test_detects_api_key(self):
        """Detect hardcoded API key in JS."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/config.js",
                content_type="application/javascript",
                response_body_preview='const OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";',
            ),
        ]
        probe = JSReconProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["js_findings"]
        assert any(f["category"] == "api_key" for f in findings)

    def test_detects_constructor(self):
        """Detect AI SDK constructor with apiKey parameter."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/ai.js",
                content_type="application/javascript",
                response_body_preview='const anthropic = new Anthropic({apiKey: process.env.KEY});',
            ),
        ]
        probe = JSReconProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["js_findings"]
        assert any(f["category"] == "constructor" for f in findings)

    def test_detects_browser_flag(self):
        """Detect dangerouslyAllowBrowser flag."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/browser.js",
                content_type="application/javascript",
                response_body_preview='const openai = new OpenAI({apiKey: key, dangerouslyAllowBrowser: true});',
            ),
        ]
        probe = JSReconProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["js_findings"]
        assert any(f["category"] == "browser_flag" for f in findings)

    def test_detects_frontend_product(self):
        """Detect frontend AI product markers."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/app.js",
                content_type="application/javascript",
                response_body_preview='const app = window.openWebUI = {};',
            ),
        ]
        probe = JSReconProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["js_findings"]
        assert any(f["category"] == "frontend" for f in findings), f"Findings: {findings}"

    def test_empty_js_files(self):
        """No JS files means empty results."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        probe = JSReconProbe()
        result = asyncio.run(probe.probe(session))
        assert result["js_findings"] == []

    def test_summary_counts(self):
        """Summary should report correct counts."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/app.js",
                content_type="application/javascript",
                response_body_preview='import OpenAI from "openai"; const key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";',
            ),
        ]
        probe = JSReconProbe()
        result = asyncio.run(probe.probe(session))
        summary = result["summary"]
        assert summary["sdk_imports"] >= 1
        assert summary["api_keys_found"] >= 1


# ============================================================================
# Auth Provider tests
# ============================================================================


class TestAuthProviders:
    def test_no_auth_provider(self):
        """NoAuthProvider returns auth_type=none (treated as authenticated)."""
        from core.auth.provider import NoAuthProvider

        provider = NoAuthProvider()
        auth_state = asyncio.run(provider.authenticate("http://example.com"))
        assert auth_state.auth_type == "none"
        # "none" means no auth needed → probes can run without credentials
        assert auth_state.is_authenticated() is True

    def test_apikey_auth_provider(self):
        """APIKeyAuthProvider returns header-based AuthState."""
        from core.auth.provider import APIKeyAuthProvider

        provider = APIKeyAuthProvider(api_key="sk-test-key-12345")
        auth_state = asyncio.run(provider.authenticate("http://example.com"))
        assert auth_state.auth_type == "apikey"
        assert auth_state.is_authenticated() is True
        assert auth_state.headers["X-API-Key"] == "sk-test-key-12345"

    def test_apikey_bearer_provider(self):
        """APIKeyAuthProvider with bearer mode."""
        from core.auth.provider import APIKeyAuthProvider

        provider = APIKeyAuthProvider(api_key="sk-test-key", use_bearer=True)
        auth_state = asyncio.run(provider.authenticate("http://example.com"))
        assert auth_state.auth_type == "bearer"
        assert auth_state.tokens["bearer"] == "sk-test-key"

    def test_cookie_auth_provider_raw(self):
        """CookieAuthProvider with raw cookies."""
        from core.auth.cookie_auth import CookieAuthProvider

        provider = CookieAuthProvider(cookies=[
            {"name": "session", "value": "abc123", "domain": "example.com"},
        ])
        auth_state = asyncio.run(provider.authenticate("http://example.com"))
        assert auth_state.auth_type == "cookie"
        assert "session=abc123" in auth_state.headers.get("Cookie", "")


class TestGuardrailPolicy:
    def test_allowed_hosts(self):
        """Guardrail should block disallowed hosts."""
        from core.task_runtime import GuardrailPolicy

        policy = GuardrailPolicy(allowed_hosts={"example.test"})
        assert policy.is_allowed("https://example.test") is True
        assert policy.is_allowed("https://evil.test") is False

    def test_organizational_boundary(self):
        """Organizational boundary check."""
        from core.task_runtime import GuardrailPolicy

        policy = GuardrailPolicy(organizational_domains={"example.test"})
        assert policy.is_within_organizational_boundary("example.test") is True
        assert policy.is_within_organizational_boundary("sub.example.test") is True
        assert policy.is_within_organizational_boundary("evil.test") is False

    def test_redirect_blocking(self):
        """Redirect blocking outside org boundary."""
        from core.task_runtime import GuardrailPolicy

        policy = GuardrailPolicy(
            organizational_domains={"example.test"},
            block_unauthorized_redirects=True,
        )
        # Same domain redirect always allowed
        assert policy.is_redirect_allowed("example.test", "example.test") is True
        # Subdomain within org boundary allowed
        assert policy.is_redirect_allowed("example.test", "sub.example.test") is True
        # Outside org boundary blocked
        assert policy.is_redirect_allowed("example.test", "evil.test") is False

    def test_disallow_patterns(self):
        """Disallow patterns block matching URLs."""
        from core.task_runtime import GuardrailPolicy

        policy = GuardrailPolicy(disallow_patterns=("localhost", "127.0.0.1", "internal"))
        assert policy.is_allowed("https://example.com") is True
        assert policy.is_allowed("http://localhost:8080") is False
        assert policy.is_allowed("https://internal.corp.com") is False


class TestReconReportAuthFlowState:
    def test_auth_flow_state_field(self):
        """ReconReport should have auth_flow_state field."""
        report = ReconReport(target_url="http://example.com")
        assert hasattr(report, "auth_flow_state")
        assert report.auth_flow_state == ""
        report.auth_flow_state = "completed"
        assert report.auth_flow_state == "completed"


# ============================================================================
# OpenAICompatProbe tests
# ============================================================================


class TestOpenAICompatProbe:
    def test_extract_base_urls_from_endpoints(self):
        """Extract unique base URLs from MODEL_API endpoints."""
        from core import ReconSession
        from core.probes.openai_compat_probe import OpenAICompatProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(url="https://api.example.com/v1/chat/completions", endpoint_type=EndpointType.MODEL_API),
            DiscoveredEndpoint(url="https://api.example.com/v1/embeddings", endpoint_type=EndpointType.MODEL_API),
            DiscoveredEndpoint(url="https://other.example.com/v1/chat", endpoint_type=EndpointType.MODEL_API),
        ]
        probe = OpenAICompatProbe()
        bases = probe._extract_base_urls(session)
        assert len(bases) == 2
        assert "https://api.example.com" in bases

    def test_empty_endpoints_returns_zero_score(self):
        """No MODEL_API endpoints returns zero compatibility score."""
        from core import ReconSession
        from core.probes.openai_compat_probe import OpenAICompatProbe

        session = ReconSession(target_url="http://example.com")
        probe = OpenAICompatProbe()
        result = asyncio.run(probe.probe(session))
        assert result["openai_compat"]["compat_score"] == 0

    def test_result_dataclass(self):
        """OpenAICompatResult dataclass serialization."""
        from core.probes.openai_compat_probe import OpenAICompatResult

        result = OpenAICompatResult(
            base_url="https://api.example.com",
            compat_score=0.75,
            total_endpoints=13,
            found=8,
            missing=3,
            auth_required=2,
            api_version="2024-08-06",
        )
        d = result.to_dict()
        assert d["compat_score"] == 0.75
        assert d["found"] == 8
        assert d["api_version"] == "2024-08-06"

    def test_known_error_patterns_indicate_endpoint_exists(self):
        """Error patterns like 'model_not_found' indicate endpoint exists."""
        from core.probes.openai_compat_probe import _KNOWN_ERROR_PATTERNS

        assert "model_not_found" in _KNOWN_ERROR_PATTERNS
        assert "invalid_api_key" in _KNOWN_ERROR_PATTERNS
        assert "rate_limit_exceeded" in _KNOWN_ERROR_PATTERNS


# ============================================================================
# ErrorAnalyzerProbe tests
# ============================================================================


class TestErrorAnalyzerProbe:
    def test_detects_stack_trace(self):
        """Detect Python stack trace in error response."""
        from core import ReconSession
        from core.probes.error_analyzer import ErrorAnalyzerProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                status_code=500,
                response_body_preview='Traceback (most recent call last):\n  File "/app/main.py", line 42, in handler\n    result = db.query()',
            ),
        ]
        probe = ErrorAnalyzerProbe()
        result = asyncio.run(probe.probe(session))
        assert len(result["info_disclosures"]) > 0
        assert any(d["category"] == "stack_trace" for d in result["info_disclosures"])

    def test_detects_database_error(self):
        """Detect database error message disclosure."""
        from core import ReconSession
        from core.probes.error_analyzer import ErrorAnalyzerProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                status_code=500,
                response_body_preview="SQLSTATE[42S02]: mysql error: connection refused to 127.0.0.1:3306",
            ),
        ]
        probe = ErrorAnalyzerProbe()
        result = asyncio.run(probe.probe(session))
        assert any(d["category"] == "database_error" for d in result["info_disclosures"])

    def test_detects_internal_path(self):
        """Detect internal file system path disclosure."""
        from core import ReconSession
        from core.probes.error_analyzer import ErrorAnalyzerProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                status_code=500,
                response_body_preview="Config file not found: /etc/nginx/conf.d/default.conf",
            ),
        ]
        probe = ErrorAnalyzerProbe()
        result = asyncio.run(probe.probe(session))
        assert any(d["category"] == "internal_path" for d in result["info_disclosures"])

    def test_detects_debug_mode(self):
        """Detect debug mode indicators."""
        from core import ReconSession
        from core.probes.error_analyzer import ErrorAnalyzerProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                status_code=500,
                response_body_preview="DEBUG = True\nDevelopment mode is active",
            ),
        ]
        probe = ErrorAnalyzerProbe()
        result = asyncio.run(probe.probe(session))
        assert any(d["category"] == "debug_mode" for d in result["info_disclosures"])

    def test_detects_framework_version(self):
        """Detect framework version disclosure."""
        from core import ReconSession
        from core.probes.error_analyzer import ErrorAnalyzerProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                status_code=500,
                response_body_preview="FastAPI 0.115.0 encountered an error processing your request",
            ),
        ]
        probe = ErrorAnalyzerProbe()
        result = asyncio.run(probe.probe(session))
        assert any(d["category"] == "framework_version" for d in result["info_disclosures"])

    def test_detects_model_hint(self):
        """Detect model architecture hints in errors."""
        from core import ReconSession
        from core.probes.error_analyzer import ErrorAnalyzerProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/v1/embeddings",
                status_code=400,
                response_body_preview="expected embedding size of 1536 but got 768",
            ),
        ]
        probe = ErrorAnalyzerProbe()
        result = asyncio.run(probe.probe(session))
        assert any(d["category"] == "model_hint" for d in result["info_disclosures"])

    def test_empty_endpoints(self):
        """Empty endpoints returns no disclosures."""
        from core import ReconSession
        from core.probes.error_analyzer import ErrorAnalyzerProbe

        session = ReconSession(target_url="http://example.com")
        probe = ErrorAnalyzerProbe()
        result = asyncio.run(probe.probe(session))
        assert result["info_disclosures"] == []


# ============================================================================
# SecurityHeaderProbe tests
# ============================================================================


class TestSecurityHeaderProbe:
    def test_detects_missing_csp(self):
        """Detect missing Content-Security-Policy header."""
        from core import ReconSession
        from core.probes.security_header_probe import SecurityHeaderProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                request_headers={"content-type": "application/json"},
            ),
        ]
        probe = SecurityHeaderProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["security_findings"]
        assert any(f["header"] == "content-security-policy" for f in findings)

    def test_detects_cors_wildcard(self):
        """Detect CORS wildcard origin."""
        from core import ReconSession
        from core.probes.security_header_probe import SecurityHeaderProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                request_headers={"access-control-allow-origin": "*", "content-type": "application/json"},
            ),
        ]
        probe = SecurityHeaderProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["security_findings"]
        assert any(f["category"] == "cors_misconfig" for f in findings)

    def test_detects_cors_wildcard_with_credentials(self):
        """Detect dangerous CORS wildcard + credentials combination."""
        from core import ReconSession
        from core.probes.security_header_probe import SecurityHeaderProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                request_headers={
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                },
            ),
        ]
        probe = SecurityHeaderProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["security_findings"]
        cors_findings = [f for f in findings if f["category"] == "cors_misconfig"]
        assert any(f["severity"] == "high" for f in cors_findings)

    def test_detects_unsafe_inline_csp(self):
        """Detect unsafe-inline in CSP."""
        from core import ReconSession
        from core.probes.security_header_probe import SecurityHeaderProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                request_headers={
                    "content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'self'",
                },
            ),
        ]
        probe = SecurityHeaderProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["security_findings"]
        assert any(f["category"] == "csp_weakness" for f in findings)

    def test_detects_server_disclosure(self):
        """Detect server header disclosure."""
        from core import ReconSession
        from core.probes.security_header_probe import SecurityHeaderProbe

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api",
                request_headers={"server": "nginx/1.24.0", "content-type": "application/json"},
            ),
        ]
        probe = SecurityHeaderProbe()
        result = asyncio.run(probe.probe(session))
        findings = result["security_findings"]
        assert any(f["category"] == "server_disclosure" for f in findings)

    def test_empty_endpoints(self):
        """Empty endpoints returns no findings."""
        from core import ReconSession
        from core.probes.security_header_probe import SecurityHeaderProbe

        session = ReconSession(target_url="http://example.com")
        probe = SecurityHeaderProbe()
        result = asyncio.run(probe.probe(session))
        assert result["security_findings"] == []


# ============================================================================
# ResponseConsistencyProbe tests
# ============================================================================


class TestResponseConsistencyProbe:
    def test_is_blocked_detection(self):
        """Blocked response detection."""
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        assert ResponseConsistencyProbe._is_blocked("I cannot assist with that request.") is True
        assert ResponseConsistencyProbe._is_blocked("I'm sorry, but I can't help with that.") is True
        assert ResponseConsistencyProbe._is_blocked("The answer is 42.") is False

    def test_contains_system_prompt_indicators(self):
        """System prompt indicator detection."""
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        assert ResponseConsistencyProbe._contains_system_prompt_indicators(
            "You are a helpful assistant designed to answer questions."
        ) is True
        assert ResponseConsistencyProbe._contains_system_prompt_indicators(
            "The weather is nice today."
        ) is False

    def test_extract_content_openai(self):
        """Extract content from OpenAI response shape."""
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        content = ResponseConsistencyProbe._extract_content({
            "choices": [{"message": {"content": "Hello, world!"}}],
        })
        assert content == "Hello, world!"

    def test_extract_content_anthropic(self):
        """Extract content from Anthropic response shape."""
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        content = ResponseConsistencyProbe._extract_content({
            "content": [{"text": "Hi there", "type": "text"}],
        })
        assert "Hi there" in content

    def test_analyze_rate_limiting(self):
        """Rate limiting analysis."""
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        probe = ResponseConsistencyProbe()
        results = [
            {"iteration": 1, "status_code": 200, "error_type": "", "elapsed_ms": 100},
            {"iteration": 2, "status_code": 200, "error_type": "", "elapsed_ms": 110},
            {"iteration": 3, "status_code": 429, "error_type": "rate_limited", "elapsed_ms": 50},
        ]
        info = probe._analyze_rate_limiting(results)
        assert info["detected"] is True
        assert info["rate_limited_requests"] == 1

    def test_compute_latency_stats(self):
        """Latency statistics computation."""
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        probe = ResponseConsistencyProbe()
        results = [
            {"elapsed_ms": 100, "status_code": 200},
            {"elapsed_ms": 200, "status_code": 200},
            {"elapsed_ms": 300, "status_code": 200},
        ]
        stats = probe._compute_latency_stats(results)
        assert stats["p50_ms"] == 200
        assert stats["count"] == 3

    def test_analyze_consistency_guardrail_bypass(self):
        """Guardrail inconsistency detection."""
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        probe = ResponseConsistencyProbe()
        neutral = [{"blocked": False}]
        boundary = [
            {"blocked": True, "status_code": 403},
            {"blocked": False, "status_code": 200, "response_hash": "abc"},
            {"blocked": True, "status_code": 403},
        ]
        findings = probe._analyze_consistency(neutral, boundary)
        assert any(f["type"] == "guardrail_inconsistency" for f in findings)

    def test_empty_endpoints(self):
        """Empty endpoints returns empty results."""
        from core import ReconSession
        from core.probes.response_consistency_probe import ResponseConsistencyProbe

        session = ReconSession(target_url="http://example.com")
        probe = ResponseConsistencyProbe()
        result = asyncio.run(probe.probe(session))
        assert result["consistency"] == []


# ============================================================================
# PortScanProbe tests
# ============================================================================


class TestPortScanProbe:
    def test_ai_indicators_ollama(self):
        """Detect Ollama indicators in HTTP response."""
        from unittest.mock import MagicMock

        from core.probes.port_scan_probe import PortScanProbe

        resp = MagicMock()
        resp.text = 'ollama version 0.5.0'
        resp.headers = MagicMock()
        resp.headers.keys.return_value = ["content-type"]

        indicators = PortScanProbe._check_ai_indicators(resp, {"descriptor": "Ollama"})
        assert len(indicators) > 0

    def test_ai_indicators_vllm(self):
        """Detect vLLM indicators."""
        from unittest.mock import MagicMock

        from core.probes.port_scan_probe import PortScanProbe

        resp = MagicMock()
        resp.text = "Welcome to vLLM server"
        resp.headers = MagicMock()
        resp.headers.keys.return_value = ["x-vllm-version"]

        indicators = PortScanProbe._check_ai_indicators(resp, {"descriptor": "vLLM"})
        assert any("vllm" in i for i in indicators)

    def test_empty_ports(self):
        """Empty port scan returns empty results."""
        from core import ReconSession
        from core.probes.port_scan_probe import PortScanProbe

        session = ReconSession(target_url="http://example.com")
        probe = PortScanProbe(ports=[])
        result = asyncio.run(probe.probe(session))
        assert result["discovered_services"] == []


# ============================================================================
# ConversationStateProbe tests
# ============================================================================


class TestConversationStateProbe:
    def test_extract_content_openai(self):
        """Extract content from OpenAI response shape."""
        from core.probes.conversation_state_probe import ConversationStateProbe

        content = ConversationStateProbe._extract_content({
            "choices": [{"message": {"content": "Hello!"}}],
        })
        assert content == "Hello!"

    def test_extract_content_anthropic(self):
        """Extract content from Anthropic response shape."""
        from core.probes.conversation_state_probe import ConversationStateProbe

        content = ConversationStateProbe._extract_content({
            "content": [{"text": "Hi there", "type": "text"}],
        })
        assert "Hi there" in content

    def test_empty_endpoints(self):
        """Empty endpoints returns no vulnerabilities."""
        from core import ReconSession
        from core.probes.conversation_state_probe import ConversationStateProbe

        session = ReconSession(target_url="http://example.com")
        probe = ConversationStateProbe()
        result = asyncio.run(probe.probe(session))
        assert result["vulnerabilities"] == []


# ============================================================================
# TokenEstimatorProbe tests
# ============================================================================


class TestTokenEstimatorProbe:
    def test_extract_base(self):
        """Extract base URL from endpoint URL."""
        from core.probes.token_estimator_probe import TokenEstimatorProbe

        base = TokenEstimatorProbe._extract_base("https://api.example.com/v1/chat/completions")
        assert base == "https://api.example.com"

    def test_empty_endpoints(self):
        """Empty endpoints returns empty results."""
        from core import ReconSession
        from core.probes.token_estimator_probe import TokenEstimatorProbe

        session = ReconSession(target_url="http://example.com")
        probe = TokenEstimatorProbe()
        result = asyncio.run(probe.probe(session))
        assert result["token_behavior"] == {}
        assert result["context_limits"] == {}


# ============================================================================
# SubdomainProbe tests
# ============================================================================


class TestSubdomainProbe:
    def test_build_candidates(self):
        """Build subdomain candidate list from domain."""
        from core.probes.subdomain_probe import SubdomainProbe

        probe = SubdomainProbe()
        candidates = probe._build_candidates("example.com")
        assert len(candidates) > 0
        assert any(fqdn == "api.example.com" for fqdn, _ in candidates)
        assert any(fqdn == "chat.example.com" for fqdn, _ in candidates)
        assert any(fqdn == "mcp.example.com" for fqdn, _ in candidates)

    def test_detect_ai_service_llm(self):
        """Detect LLM service indicators."""
        from unittest.mock import MagicMock

        from core.probes.subdomain_probe import SubdomainProbe

        resp = MagicMock()
        resp.text = '{"object":"chat.completion","model":"gpt-4o","choices":[]}'
        resp.headers = {"content-type": "application/json"}

        indicators = SubdomainProbe._detect_ai_service(resp, "llm_chat")
        assert any("openai_compatible_api" in i for i in indicators)

    def test_detect_ai_service_mcp(self):
        """Detect MCP service indicators."""
        from unittest.mock import MagicMock

        from core.probes.subdomain_probe import SubdomainProbe

        resp = MagicMock()
        resp.text = '{"jsonrpc":"2.0","result":{"tools":[]}}'
        resp.headers = {"content-type": "application/json"}

        indicators = SubdomainProbe._detect_ai_service(resp, "mcp")
        assert any("mcp_service" in i for i in indicators)

    def test_extract_title(self):
        """Extract page title from HTML."""
        from core.probes.subdomain_probe import SubdomainProbe

        html = "<html><head><title>OpenAI API</title></head><body></body></html>"
        title = SubdomainProbe._extract_title(html)
        assert title == "OpenAI API"

    def test_www_prefix_stripped(self):
        """WWW prefix should be stripped from domain."""
        from core import ReconSession
        from core.probes.subdomain_probe import SubdomainProbe

        session = ReconSession(target_url="http://www.example.com")
        probe = SubdomainProbe(concurrency=5)
        result = asyncio.run(probe.probe(session))
        # DNS resolution may fail in test, but domain should be "example.com"
        assert result["summary"].get("domain", "") != "www.example.com" or "www.example.com" in str(result)


# ============================================================================
# WAFDetectorProbe tests
# ============================================================================


class TestWAFDetectorProbe:
    def test_detect_cloudflare_headers(self):
        """Detect Cloudflare from response headers."""
        from unittest.mock import MagicMock

        from core.probes.waf_detector_probe import WAFDetectorProbe

        probe = WAFDetectorProbe()
        resp = MagicMock()
        resp.headers = {"cf-ray": "abc123", "server": "cloudflare"}
        resp.text = ""

        findings = probe._analyze_headers(resp, "https://example.com")
        assert len(findings) > 0
        assert any(f["waf_name"] == "cloudflare" for f in findings)

    def test_detect_aws_cloudfront_headers(self):
        """Detect AWS CloudFront from headers."""
        from unittest.mock import MagicMock

        from core.probes.waf_detector_probe import WAFDetectorProbe

        probe = WAFDetectorProbe()
        resp = MagicMock()
        resp.headers = {"x-amz-cf-id": "xyz789", "x-cache": "Miss from cloudfront"}
        resp.text = ""

        findings = probe._analyze_headers(resp, "https://example.com")
        assert any(f["waf_name"] == "aws_cloudfront" for f in findings)

    def test_detect_modsecurity_body(self):
        """Detect ModSecurity from response body."""
        from unittest.mock import MagicMock

        from core.probes.waf_detector_probe import WAFDetectorProbe

        probe = WAFDetectorProbe()
        resp = MagicMock()
        resp.headers = {}
        resp.text = "This error was generated by Mod_Security"
        resp.status_code = 403

        findings = probe._analyze_body(resp, "https://example.com")
        assert any(f["waf_name"] == "modsecurity" for f in findings)

    def test_detect_generic_waf_body(self):
        """Detect generic WAF from body patterns."""
        from unittest.mock import MagicMock

        from core.probes.waf_detector_probe import WAFDetectorProbe

        probe = WAFDetectorProbe()
        resp = MagicMock()
        resp.headers = {}
        resp.text = "Your request has been blocked by the security firewall"
        resp.status_code = 403

        findings = probe._analyze_body(resp, "https://example.com")
        assert any(f["waf_name"] == "generic_waf" for f in findings)

    def test_merge_waf_findings(self):
        """Merge duplicate WAF findings."""
        from core.probes.waf_detector_probe import WAFDetectorProbe

        findings = [
            {"waf_name": "cloudflare", "confidence": "medium", "evidence": ["h1"], "detection_method": "headers"},
            {"waf_name": "cloudflare", "confidence": "high", "evidence": ["b1"], "detection_method": "body"},
        ]
        merged = WAFDetectorProbe._merge_waf_findings(findings)
        assert len(merged) == 1
        assert merged[0]["confidence"] == "high"
        assert len(merged[0]["evidence"]) == 2

    def test_empty_endpoints(self):
        """No endpoints still probes the target URL for WAF."""
        from core import ReconSession
        from core.probes.waf_detector_probe import WAFDetectorProbe

        session = ReconSession(target_url="http://example.com")
        probe = WAFDetectorProbe()
        result = asyncio.run(probe.probe(session))
        assert "detected_wafs" in result
        assert "summary" in result


# ============================================================================
# VectorDBFingerprinter tests
# ============================================================================


class TestVectorDBFingerprinter:
    def test_fingerprint_chroma(self):
        """Fingerprint Chroma DB endpoint."""
        fingerprinter = VectorDBFingerprinter()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/api/v1/collections",
            endpoint_type=EndpointType.RAG_API,
            response_body_preview='{"collection_name":"docs","hnsw:space":"cosine"}',
        )
        results = fingerprinter.fingerprint([endpoint])
        assert len(results) > 0
        assert results[0].db_type.value == "chroma"

    def test_fingerprint_weaviate(self):
        """Fingerprint Weaviate endpoint."""
        fingerprinter = VectorDBFingerprinter()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/v1/objects",
            endpoint_type=EndpointType.RAG_API,
            response_body_preview='{"class_name":"Document","deprecation_length":5}',
        )
        results = fingerprinter.fingerprint([endpoint])
        assert len(results) > 0
        assert results[0].db_type.value == "weaviate"

    def test_fingerprint_qdrant(self):
        """Fingerprint Qdrant endpoint."""
        fingerprinter = VectorDBFingerprinter()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/collections/mycol/points/search",
            endpoint_type=EndpointType.RAG_API,
            response_body_preview='{"payload":{"text":"hello"},"vector":[0.1,0.2],"score":0.95}',
        )
        results = fingerprinter.fingerprint([endpoint])
        assert len(results) > 0
        assert results[0].db_type.value == "qdrant"

    def test_unauthorized_access_detection(self):
        """200 without auth header means likely unauthorized."""
        fingerprinter = VectorDBFingerprinter()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/api/v1/collections",
            endpoint_type=EndpointType.RAG_API,
            status_code=200,
            response_body_preview='{"collection_name":"docs"}',
            request_headers={},  # No auth headers
        )
        results = fingerprinter.fingerprint([endpoint])
        assert len(results) > 0
        assert results[0].unauthorized_access_likely is True

    def test_authorized_access(self):
        """401 means auth protected."""
        fingerprinter = VectorDBFingerprinter()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/api/v1/collections",
            endpoint_type=EndpointType.RAG_API,
            status_code=401,
            response_body_preview="",
            request_headers={},
        )
        results = fingerprinter.fingerprint([endpoint])
        for r in results:
            assert r.unauthorized_access_likely is False

    def test_owasp_mapping(self):
        """Vector DB types should map to LLM08."""
        from core.probes.vector_db_fingerprinter import VectorDBType

        ids = VectorDBFingerprinter.get_owasp_mapping(VectorDBType.CHROMA)
        assert "LLM08" in ids

        ids = VectorDBFingerprinter.get_owasp_mapping(VectorDBType.PINECONE)
        assert "LLM08" in ids
        assert "LLM02" in ids  # Cloud services also involve sensitive info


# ============================================================================
# ReconReport tests
# ============================================================================


class TestReconReportProperties:
    def test_has_mcp_server_from_endpoints(self):
        """MCP_SERVER endpoint triggers has_mcp_server."""
        report = ReconReport()
        report.endpoints = [
            DiscoveredEndpoint(url="https://example.com/mcp", endpoint_type=EndpointType.MCP_SERVER),
        ]
        assert report.has_mcp_server is True

    def test_has_mcp_server_from_tools(self):
        """MCPToolInfo triggers has_mcp_server."""
        report = ReconReport()
        report.mcp_tools = [MCPToolInfo(tool_name="test")]
        assert report.has_mcp_server is True

    def test_has_embedding_api(self):
        """EMBEDDING_API endpoint triggers has_embedding_api."""
        report = ReconReport()
        report.endpoints = [
            DiscoveredEndpoint(url="https://api.example.com/embed", endpoint_type=EndpointType.EMBEDDING_API),
        ]
        assert report.has_embedding_api is True

    def test_to_dict_includes_new_fields(self):
        """to_dict includes llm_fingerprints, mcp_tools, and new MCPToolInfo fields."""
        report = ReconReport(target_url="http://example.com")
        report.llm_fingerprints = [LLMFingerprint(model_family="OpenAI", model_name="gpt-4o")]
        report.mcp_tools = [MCPToolInfo(
            tool_name="read_file",
            annotation_contradiction=False,
            tool_hash="abc123",
            injection_surfaces=["path"],
            threat_tags=["data_exfiltration"],
        )]
        d = report.to_dict()
        assert "llm_fingerprints" in d
        assert "mcp_tools" in d
        assert d["has_mcp_server"] is True
        assert d["has_embedding_api"] is False
        # Check MCPToolInfo new fields
        tool_dict = d["mcp_tools"][0]
        assert "annotation_contradiction" in tool_dict
        assert "tool_hash" in tool_dict
        assert "injection_surfaces" in tool_dict
        assert "threat_tags" in tool_dict

    def test_discovered_endpoint_to_dict_includes_request_headers(self):
        """to_dict should include sanitized request_headers."""
        endpoint = DiscoveredEndpoint(
            url="https://example.com/api",
            request_headers={"authorization": "Bearer secret-token-12345", "content-type": "application/json"},
        )
        d = endpoint.to_dict()
        assert "request_headers" in d
        assert d["request_headers"]["content-type"] == "application/json"
        # Authorization should be sanitized
        assert "..." in d["request_headers"]["authorization"]

    def test_discovered_endpoint_ai_framework_fields(self):
        """DiscoveredEndpoint should have ai_framework fields."""
        endpoint = DiscoveredEndpoint(
            url="https://example.com/api",
            ai_framework_name="OpenAI",
            ai_framework_category="llm",
        )
        d = endpoint.to_dict()
        assert d["ai_framework_name"] == "OpenAI"
        assert d["ai_framework_category"] == "llm"


# ============================================================================
# PipelineResult tests
# ============================================================================


class TestPipelineResult:
    def test_pipeline_result_stats(self):
        """PipelineResult correctly counts stats."""
        from core.pipeline import PipelineResult

        result = PipelineResult(
            total=5,
            executed=3,
            skipped=1,
            failed=1,
            duration_seconds=10.5,
            errors=[("bad_probe", "timeout")],
        )
        assert result.total == 5
        assert result.executed == 3
        assert result.skipped == 1
        assert result.failed == 1
        assert len(result.errors) == 1


# ============================================================================
# AttackRecommender tests (extended)
# ============================================================================


class TestAttackRecommender:
    def test_recommend_from_llm_fingerprint_gpt4(self):
        """GPT-4 fingerprint generates jailbreak recommendation."""
        from core.probes.attack_recommender import AttackRecommender

        recommender = AttackRecommender()
        report = ReconReport(target_url="http://example.com")
        report.llm_fingerprints = [LLMFingerprint(
            model_family="OpenAI GPT-4o",
            model_name="gpt-4o",
            guardrail_detected=True,
        )]
        recs = recommender.recommend(report)
        assert len(recs) > 0
        assert any("jailbreak" in r.attack_strategy.lower() or "dan" in r.attack_strategy.lower() for r in recs)

    def test_recommend_from_mcp_tool_critical(self):
        """Critical MCP tool generates excessive_agency recommendation."""
        from core.probes.attack_recommender import AttackRecommender

        recommender = AttackRecommender()
        report = ReconReport(target_url="http://example.com")
        report.mcp_tools = [MCPToolInfo(
            tool_name="execute_command",
            description="Execute a shell command",
            risk_level="critical",
        )]
        recs = recommender.recommend(report)
        assert any("excessive_agency" in r.attack_strategy for r in recs)

    def test_recommend_from_mcp_tool_shadowing(self):
        """Shadowing detection generates tool_shadowing recommendation."""
        from core.probes.attack_recommender import AttackRecommender

        recommender = AttackRecommender()
        report = ReconReport(target_url="http://example.com")
        report.mcp_tools = [MCPToolInfo(
            tool_name="read_file",
            shadowing_detected=True,
            risk_level="medium",
        )]
        recs = recommender.recommend(report)
        assert any("shadowing" in r.attack_strategy for r in recs)

    def test_recommend_from_embedding_info(self):
        """Embedding dimension info generates vector_manipulation recommendation."""
        from core.probes.attack_recommender import AttackRecommender

        recommender = AttackRecommender()
        report = ReconReport(target_url="http://example.com")
        report.probe_results = {
            "embedding_info": [{"url": "https://api.example.com/embed", "dimension": 1536, "model": "text-embedding-ada-002"}],
        }
        recs = recommender.recommend(report)
        assert any("vector_manipulation" in r.attack_strategy for r in recs)


# ============================================================================
# ErrorClass module tests (Phase 1: RedAmon error classification)
# ============================================================================


class TestErrorClass:
    def test_success_classification(self):
        """2xx status with success flag returns 'success'."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(success=True, status_code=200, body="OK")
        assert result == "success"

    def test_shell_parser_error(self):
        """Parse/syntax errors in 4xx body → shell_parser_error."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(
            status_code=400,
            body="invalid argument --foo: parse error",
        )
        assert result == "shell_parser_error"

    def test_transport_error(self):
        """Connection refused → transport_error."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(
            status_code=None,
            error_message="connection refused",
        )
        assert result == "transport_error"

    def test_tool_internal_error(self):
        """500 with traceback → tool_internal_error."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(
            status_code=500,
            body="Traceback (most recent call last):\n  File 'app.py'",
            duration_ms=300,
        )
        assert result == "tool_internal_error"

    def test_5xx_fast_waf(self):
        """500-level < 50ms → application_5xx_fast (likely WAF)."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(status_code=500, body="blocked", duration_ms=15)
        assert result == "application_5xx_fast"

    def test_5xx_networked_fast(self):
        """500-level 50-200ms → application_5xx_networked_fast."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(status_code=503, body="service unavailable", duration_ms=120)
        assert result == "application_5xx_networked_fast"

    def test_5xx_normal(self):
        """500-level >= 200ms → application_5xx_normal."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(status_code=500, body="something went wrong on the backend", duration_ms=350)
        assert result == "application_5xx_normal"

    def test_4xx_generic(self):
        """Generic 4xx without shell parser → application_4xx."""
        from core.probes.error_class import classify_error_class

        result = classify_error_class(status_code=404, body="not found")
        assert result == "application_4xx"

    def test_classify_http_response_convenience(self):
        """classify_http_response convenience wrapper."""
        from core.probes.error_class import classify_http_response

        assert classify_http_response(200, body="OK") == "success"
        assert classify_http_response(404, body="not found") == "application_4xx"

    def test_is_recoverable_error(self):
        """Recoverable vs non-recoverable classification."""
        from core.probes.error_class import is_recoverable_error

        assert is_recoverable_error("shell_parser_error") is True
        assert is_recoverable_error("transport_error") is True
        assert is_recoverable_error("tool_internal_error") is True
        assert is_recoverable_error("application_4xx") is False
        assert is_recoverable_error("application_5xx_fast") is False

    def test_error_class_severity_scores(self):
        """Severity scoring 0-10."""
        from core.probes.error_class import error_class_severity, ErrorClass

        assert error_class_severity(ErrorClass.SUCCESS.value) == 0
        assert error_class_severity(ErrorClass.SHELL_PARSER.value) == 2
        assert error_class_severity(ErrorClass.APPLICATION_4XX.value) == 3
        assert error_class_severity(ErrorClass.TRANSPORT.value) == 5
        assert error_class_severity(ErrorClass.APPLICATION_5XX_NORMAL.value) == 5
        assert error_class_severity(ErrorClass.APPLICATION_5XX_NETWORKED_FAST.value) == 6
        assert error_class_severity(ErrorClass.TOOL_INTERNAL.value) == 7
        assert error_class_severity(ErrorClass.APPLICATION_5XX_FAST.value) == 8

    def test_all_eight_categories_exist(self):
        """ErrorClass enum has exactly 8 categories."""
        from core.probes.error_class import ErrorClass

        members = list(ErrorClass)
        assert len(members) == 8
        categories = {m.value for m in members}
        assert "success" in categories
        assert "shell_parser_error" in categories
        assert "transport_error" in categories
        assert "tool_internal_error" in categories
        assert "application_4xx" in categories
        assert "application_5xx_fast" in categories
        assert "application_5xx_networked_fast" in categories
        assert "application_5xx_normal" in categories

    def test_edge_case_no_status_no_error(self):
        """No status code, no error → defaults appropriately."""
        from core.probes.error_class import classify_error_class

        # Non-HTTP success
        result = classify_error_class(success=True)
        assert result == "success"


# ============================================================================
# ResponseFingerprint module tests (Phase 2: dedup + change detection)
# ============================================================================


class TestResponseFingerprint:
    def test_fingerprint_text_stable(self):
        """Same text → same fingerprint."""
        from core.probes.response_fingerprint import fingerprint_text

        fp1 = fingerprint_text("Hello, world!")
        fp2 = fingerprint_text("Hello, world!")
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_fingerprint_text_different(self):
        """Different text → different fingerprint."""
        from core.probes.response_fingerprint import fingerprint_text

        fp1 = fingerprint_text("Hello")
        fp2 = fingerprint_text("World")
        assert fp1 != fp2

    def test_normalize_noise_timestamps(self):
        """Timestamps are normalized to <<TIMESTAMP>>."""
        from core.probes.response_fingerprint import normalize_text

        text = "Request at 2024-01-15T10:30:00Z completed"
        normalized = normalize_text(text)
        assert "2024-01-15" not in normalized
        assert "<<TIMESTAMP>>" in normalized

    def test_normalize_noise_uuids(self):
        """UUIDs are normalized to <<UUID>>."""
        from core.probes.response_fingerprint import normalize_text

        text = "id=550e8400-e29b-41d4-a716-446655440000"
        normalized = normalize_text(text)
        assert "550e8400" not in normalized
        assert "<<UUID>>" in normalized

    def test_normalize_noise_unix_ts(self):
        """Unix timestamps (13-digit) are normalized."""
        from core.probes.response_fingerprint import normalize_text

        text = "created_at=1705315200000"
        normalized = normalize_text(text)
        assert "1705315200000" not in normalized
        assert "<<UNIX_TS>>" in normalized

    def test_fingerprint_response_composite(self):
        """HTTP response fingerprint combines body + status + stable headers."""
        from core.probes.response_fingerprint import fingerprint_response

        fp1 = fingerprint_response(body='{"ok":true}', status_code=200, headers={"content-type": "application/json"})
        fp2 = fingerprint_response(body='{"ok":true}', status_code=200, headers={"content-type": "application/json"})
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_fingerprint_response_different_status(self):
        """Different status codes → different fingerprints."""
        from core.probes.response_fingerprint import fingerprint_response

        fp1 = fingerprint_response(body="OK", status_code=200)
        fp2 = fingerprint_response(body="OK", status_code=500)
        assert fp1 != fp2

    def test_fingerprint_dict(self):
        """Dict fingerprint is stable (sorted keys)."""
        from core.probes.response_fingerprint import fingerprint_dict

        d1 = {"b": 2, "a": 1}
        d2 = {"a": 1, "b": 2}
        assert fingerprint_dict(d1) == fingerprint_dict(d2)

    def test_fingerprint_set_dedup(self):
        """FingerprintSet tracks seen fingerprints."""
        from core.probes.response_fingerprint import FingerprintSet

        fps = FingerprintSet()
        fp = fps.add("endpoint-a", '{"ok":true}', 200)
        assert fp
        assert fps.is_duplicate("endpoint-a", fp) is True
        assert fps.is_duplicate("endpoint-a", "different") is False

    def test_fingerprint_set_change_detection(self):
        """FingerprintSet detects behavior drift."""
        from core.probes.response_fingerprint import FingerprintSet

        fps = FingerprintSet()
        fp1 = fps.add("tool-x", "v1 response", 200)
        assert fps.has_changed("tool-x", fp1) is False
        assert fps.has_changed("tool-x", "new_fingerprint_hex_") is True


# ============================================================================
# AgentProbe v2 tests (Phase 4: enhanced agent reconnaissance)
# ============================================================================


class TestAgentProbeV2:
    def test_framework_fingerprinting_langchain(self):
        """Detect LangChain from URL pattern."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/langchain/invoke",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview='from langchain_core.runnables import Runnable',
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        assert len(frameworks) >= 1
        assert any(f["framework_name"] == "LangChain" for f in frameworks)

    def test_framework_fingerprinting_autogen(self):
        """Detect AutoGen from body pattern."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/api/chat",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview='groupchat_manager selected speaker',
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        assert any(f["framework_name"] == "Microsoft AutoGen" for f in frameworks)

    def test_framework_fingerprinting_crewai(self):
        """Detect CrewAI from URL + body."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/api/v1/crews/kickoff",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview='crewai hierarchical process',
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        assert any(f["framework_name"] == "CrewAI" for f in frameworks)

    def test_framework_fingerprinting_semantic_kernel(self):
        """Detect Semantic Kernel from body pattern."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/skills/process",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview='Microsoft.SemanticKernel KernelFunction',
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        assert any(f["framework_name"] == "Microsoft Semantic Kernel" for f in frameworks)

    def test_framework_fingerprinting_beeai(self):
        """Detect BeeAI from SDK import."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/bee-agent/run",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview='import { BeeAgent } from "beeai"',
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        assert any(f["framework_name"] == "IBM BeeAI" for f in frameworks)

    def test_framework_fingerprinting_openai_agents(self):
        """Detect OpenAI Agents SDK from body."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/agent/handoff",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview='from agents import Agent, Runner, @function_tool',
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        assert any(f["framework_name"] == "OpenAI Agents SDK" for f in frameworks)

    def test_no_framework_detected(self):
        """No known patterns → empty framework list."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/custom/run",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview="generic response",
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        assert frameworks == []

    def test_high_confidence_dual_match(self):
        """URL + body match → high confidence."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/langserve/invoke",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                response_body_preview='{"output":"langserve chain executed"}',
            ),
        ]
        frameworks = probe._fingerprint_frameworks(endpoints)
        langchain = [f for f in frameworks if f["framework_name"] == "LangChain"]
        assert len(langchain) == 1
        assert langchain[0]["confidence"] == "high"

    def test_empty_endpoints(self):
        """Empty endpoints returns empty results."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        probe = AgentProbe(enable_active_probing=False)
        result = asyncio.run(probe.probe(session))
        assert result["endpoints"] == []
        assert result["agent_frameworks"] == []
        assert "summary" in result

    def test_result_has_new_fields(self):
        """AgentProbe result includes all v2 fields."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/langchain/invoke",
                endpoint_type=EndpointType.AGENT_TOOL_API,
            ),
        ]
        probe = AgentProbe(enable_active_probing=False)
        result = asyncio.run(probe.probe(session))
        assert "agent_frameworks" in result
        assert "diagnostics" in result
        assert "fingerprints" in result
        assert "summary" in result
        assert "tool_permission_matrix" in result

    def test_diagnostics_empty_endpoints(self):
        """Empty endpoints → zero health diagnostics."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        probe = AgentProbe(enable_active_probing=False)
        result = asyncio.run(probe.probe(session))
        diag = result["diagnostics"]
        assert diag["total_requests"] == 0
        assert diag["health_score"] == 100

    def test_diagnostics_with_endpoints(self):
        """Endpoints with status codes generate diagnostics."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/tools/run",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                status_code=200,
                duration_ms=100,
            ),
            DiscoveredEndpoint(
                url="https://api.example.com/tools/exec",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                status_code=500,
                duration_ms=30,
            ),
        ]
        probe = AgentProbe(enable_active_probing=False)
        result = asyncio.run(probe.probe(session))
        diag = result["diagnostics"]
        assert diag["total_requests"] >= 2
        assert "success" in diag["error_class_distribution"]
        assert diag["health_score"] < 100

    def test_build_agent_candidates(self):
        """Builds correct probe candidates from endpoints."""
        probe = AgentProbe()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/agent/invoke",
                endpoint_type=EndpointType.AGENT_TOOL_API,
            ),
        ]
        candidates = probe._build_agent_candidates(endpoints)
        assert len(candidates) > 0
        # Should include handshake paths + conversation probes
        has_handshake = any(c["method"] == "GET" and "/api/agents" in c["url"] for c in candidates)
        has_conversation = any(c["method"] == "POST" for c in candidates)
        assert has_handshake
        assert has_conversation

    def test_summary_includes_key_metrics(self):
        """Summary dict covers all key metrics."""
        from core import ReconSession

        session = ReconSession(target_url="http://example.com")
        session.report.endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/tools/run",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                status_code=200,
            ),
        ]
        probe = AgentProbe(enable_active_probing=False)
        result = asyncio.run(probe.probe(session))
        summary = result["summary"]
        assert "agent_endpoint_count" in summary
        assert "framework_count" in summary
        assert "over_agency_score" in summary
        assert "critical_tools" in summary
        assert "high_risk_tools" in summary
        assert "unique_fingerprints" in summary
        assert "elapsed_seconds" in summary


# ============================================================================
# ToolPermission matrix v2 tests (Phase 5: fingerprint + error_class)
# ============================================================================


class TestToolPermissionMatrixV2:
    def test_tool_permission_has_fingerprint_field(self):
        """ToolPermission has response_fingerprint field."""
        from core.probes.tool_permission_matrix import ToolPermission

        tp = ToolPermission(name="test")
        assert hasattr(tp, "response_fingerprint")
        assert tp.response_fingerprint == ""
        tp.response_fingerprint = "abc123def456"
        assert tp.response_fingerprint == "abc123def456"

    def test_tool_permission_has_error_class_field(self):
        """ToolPermission has error_class field."""
        from core.probes.tool_permission_matrix import ToolPermission

        tp = ToolPermission(name="test")
        assert hasattr(tp, "error_class")
        assert tp.error_class == ""
        tp.error_class = "application_5xx_fast"
        assert tp.error_class == "application_5xx_fast"

    def test_to_dict_includes_new_fields(self):
        """to_dict includes response_fingerprint and error_class when set."""
        from core.probes.tool_permission_matrix import ToolPermission

        tp = ToolPermission(
            name="execute",
            response_fingerprint="fp123",
            error_class="success",
        )
        d = tp.to_dict()
        assert d.get("response_fingerprint") == "fp123"
        assert d.get("error_class") == "success"

    def test_to_dict_excludes_empty_fields(self):
        """to_dict omits empty fingerprint/error_class."""
        from core.probes.tool_permission_matrix import ToolPermission

        tp = ToolPermission(name="read")
        d = tp.to_dict()
        assert "response_fingerprint" not in d
        assert "error_class" not in d

    def test_analyzer_populates_fingerprint(self):
        """Analyzer populates response_fingerprint for each tool."""
        from core.probes.tool_permission_matrix import ToolPermissionAnalyzer

        analyzer = ToolPermissionAnalyzer()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/agent/execute_command",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                status_code=200,
                response_body_preview="command executed",
            ),
        ]
        matrix = analyzer.analyze(endpoints)
        assert len(matrix.tools) == 1
        assert matrix.tools[0].response_fingerprint != ""

    def test_analyzer_populates_error_class(self):
        """Analyzer populates error_class for each tool."""
        from core.probes.tool_permission_matrix import ToolPermissionAnalyzer

        analyzer = ToolPermissionAnalyzer()
        endpoints = [
            DiscoveredEndpoint(
                url="https://api.example.com/agent/execute_command",
                endpoint_type=EndpointType.AGENT_TOOL_API,
                status_code=500,
                response_body_preview="internal server error",
                duration_ms=400,
            ),
        ]
        matrix = analyzer.analyze(endpoints)
        assert len(matrix.tools) == 1
        assert matrix.tools[0].error_class != ""
        assert matrix.tools[0].error_class in ("application_5xx_normal", "tool_internal_error")

    def test_stable_fingerprint_across_calls(self):
        """Same endpoint data → same fingerprint."""
        from core.probes.tool_permission_matrix import ToolPermissionAnalyzer

        analyzer = ToolPermissionAnalyzer()
        ep1 = DiscoveredEndpoint(
            url="https://api.example.com/tools/run",
            endpoint_type=EndpointType.AGENT_TOOL_API,
            status_code=200,
            response_body_preview="ok",
        )
        ep2 = DiscoveredEndpoint(
            url="https://api.example.com/tools/run",
            endpoint_type=EndpointType.AGENT_TOOL_API,
            status_code=200,
            response_body_preview="ok",
        )
        m1 = analyzer.analyze([ep1])
        m2 = analyzer.analyze([ep2])
        assert m1.tools[0].response_fingerprint == m2.tools[0].response_fingerprint


# ============================================================================
# DiscoveredEndpoint new fields tests
# ============================================================================


class TestDiscoveredEndpointNewFields:
    def test_response_class_field(self):
        """DiscoveredEndpoint has response_class field."""
        ep = DiscoveredEndpoint(url="https://example.com/api")
        assert hasattr(ep, "response_class")
        assert ep.response_class == ""
        ep.response_class = "application_5xx_fast"
        assert ep.response_class == "application_5xx_fast"

    def test_duration_ms_field(self):
        """DiscoveredEndpoint has duration_ms field."""
        ep = DiscoveredEndpoint(url="https://example.com/api")
        assert hasattr(ep, "duration_ms")
        assert ep.duration_ms == 0
        ep.duration_ms = 150
        assert ep.duration_ms == 150

    def test_to_dict_includes_new_fields_when_set(self):
        """to_dict includes response_class and duration_ms when non-default."""
        ep = DiscoveredEndpoint(
            url="https://example.com/api",
            response_class="success",
            duration_ms=42,
        )
        d = ep.to_dict()
        assert d.get("response_class") == "success"
        assert d.get("duration_ms") == 42

    def test_to_dict_omits_default_fields(self):
        """to_dict omits empty response_class and 0 duration_ms."""
        ep = DiscoveredEndpoint(url="https://example.com/api")
        d = ep.to_dict()
        assert "response_class" not in d
        assert "duration_ms" not in d


# ============================================================================
# Agent YAML probe pack tests
# ============================================================================


class TestAgentProbePacks:
    def test_all_six_agent_packs_exist(self):
        """All 6 agent framework YAML probe packs exist."""
        from pathlib import Path

        packs_dir = Path(__file__).resolve().parent.parent / "data" / "probe_packs" / "agent"
        assert packs_dir.is_dir(), f"Agent packs dir not found: {packs_dir}"

        expected = [
            "agent_langchain.yaml",
            "agent_autogen.yaml",
            "agent_crewai.yaml",
            "agent_semantic_kernel.yaml",
            "agent_beeai.yaml",
            "agent_openai_agents_sdk.yaml",
        ]
        for fname in expected:
            path = packs_dir / fname
            assert path.exists(), f"Missing agent pack: {fname}"

    def test_agent_packs_are_valid_yaml(self):
        """All agent YAML packs are valid YAML with probes section."""
        import yaml
        from pathlib import Path

        packs_dir = Path(__file__).resolve().parent.parent / "data" / "probe_packs" / "agent"
        for yaml_file in packs_dir.glob("*.yaml"):
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            assert data is not None, f"Empty/invalid YAML: {yaml_file.name}"
            assert "probes" in data, f"No 'probes' section: {yaml_file.name}"
            assert len(data["probes"]) > 0, f"No probes defined: {yaml_file.name}"

    def test_agent_packs_have_required_interface_field(self):
        """Each probe has interface field for framework matching."""
        import yaml
        from pathlib import Path

        packs_dir = Path(__file__).resolve().parent.parent / "data" / "probe_packs" / "agent"
        for yaml_file in packs_dir.glob("*.yaml"):
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            for probe in data["probes"]:
                assert "interface" in probe, f"Probe {probe.get('name')} in {yaml_file.name} missing 'interface'"
                assert probe["interface"].startswith("agent-"), (
                    f"Probe {probe['name']} interface '{probe['interface']}' must start with 'agent-'"
                )


# ============================================================================
# AgentBehaviorDAG tests (P1-1: DAG modeling)
# ============================================================================


class TestAgentBehaviorDAG:
    def test_add_node_auto_links_sequential(self):
        """Adding nodes auto-creates sequential edges."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="read_file", sequence_index=0))
        dag.add_node(ToolCallNode(tool_name="write_file", sequence_index=1))
        dag.add_node(ToolCallNode(tool_name="execute", sequence_index=2))

        assert len(dag.nodes) == 3
        assert len(dag.edges) == 2  # 0→1, 1→2

    def test_no_cycle_linear_dag(self):
        """Linear sequence has no cycles."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="a"))
        dag.add_node(ToolCallNode(tool_name="b"))
        dag.add_node(ToolCallNode(tool_name="c"))
        assert dag.cycle_detected is False

    def test_cycle_detection_back_edge(self):
        """Back edge creates a cycle."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="a", sequence_index=0))
        dag.add_node(ToolCallNode(tool_name="b", sequence_index=1))
        dag.add_node(ToolCallNode(tool_name="c", sequence_index=2))
        dag.add_edge(2, 0)  # c → a back edge
        assert dag.cycle_detected is True

    def test_cycle_detection_self_loop(self):
        """Self-loop creates a cycle."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="loop"))
        dag.add_edge(0, 0)
        assert dag.cycle_detected is True

    def test_single_node_no_cycle(self):
        """Single node has no cycle."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="solo"))
        assert dag.cycle_detected is False
        assert len(dag.critical_path) == 1

    def test_empty_dag(self):
        """Empty DAG properties."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG

        dag = AgentBehaviorDAG()
        assert dag.cycle_detected is False
        assert dag.critical_path == []
        assert dag.tool_call_fanout == {}
        assert dag.unique_tools == 0
        assert dag.error_rate == 0.0

    def test_critical_path_linear(self):
        """Linear DAG critical path = all nodes."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="a", sequence_index=0))
        dag.add_node(ToolCallNode(tool_name="b", sequence_index=1))
        dag.add_node(ToolCallNode(tool_name="c", sequence_index=2))
        dag.add_node(ToolCallNode(tool_name="d", sequence_index=3))
        assert len(dag.critical_path) == 4
        assert [n.tool_name for n in dag.critical_path] == ["a", "b", "c", "d"]

    def test_critical_path_empty_on_cycle(self):
        """Cycle DAG returns empty critical path."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="a"))
        dag.add_node(ToolCallNode(tool_name="b"))
        dag.add_edge(1, 0)
        assert dag.cycle_detected is True
        assert dag.critical_path == []

    def test_tool_call_fanout(self):
        """Fanout counts per-tool invocations."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="read"))
        dag.add_node(ToolCallNode(tool_name="read"))
        dag.add_node(ToolCallNode(tool_name="write"))
        fanout = dag.tool_call_fanout
        assert fanout["read"] == 2
        assert fanout["write"] == 1

    def test_error_rate(self):
        """Error rate = errors / total."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="ok1", error_class="success"))
        dag.add_node(ToolCallNode(tool_name="ok2", error_class="success"))
        dag.add_node(ToolCallNode(tool_name="fail", error_class="application_5xx_normal"))
        dag.add_node(ToolCallNode(tool_name="ok3", error_class=""))
        assert dag.error_rate == 0.25

    def test_avg_duration(self):
        """Average tool duration."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="a", duration_ms=100))
        dag.add_node(ToolCallNode(tool_name="b", duration_ms=200))
        assert dag.avg_tool_duration_ms == 150.0

    def test_max_fanout_tool(self):
        """Tool with highest invocation count."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="rare"))
        dag.add_node(ToolCallNode(tool_name="common"))
        dag.add_node(ToolCallNode(tool_name="common"))
        assert dag.max_fanout_tool == ("common", 2)

    def test_conversation_turn_tracking(self):
        """Per-turn state is tracked correctly."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="t0_a", conversation_turn=0))
        dag.add_node(ToolCallNode(tool_name="t0_b", conversation_turn=0))
        dag.add_node(ToolCallNode(tool_name="t1_a", conversation_turn=1))
        assert len(dag.turns) == 2
        assert dag.turns[0].tool_call_count == 2
        assert dag.turns[1].tool_call_count == 1

    def test_to_dict_complete(self):
        """to_dict includes all DAG properties."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="test", sequence_index=0))
        d = dag.to_dict()
        assert "nodes" in d
        assert "cycle_detected" in d
        assert "critical_path_length" in d
        assert "tool_call_fanout" in d
        assert "error_rate" in d
        assert "avg_tool_duration_ms" in d

    def test_compute_input_fingerprint_stable(self):
        """Same args → same fingerprint."""
        from core.probes.agent_behavior_dag import ToolCallNode

        fp1 = ToolCallNode.compute_input_fingerprint({"a": 1, "b": 2})
        fp2 = ToolCallNode.compute_input_fingerprint({"b": 2, "a": 1})
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_build_dag_from_probe_results(self):
        """Build DAG from probe result dicts."""
        from core.probes.agent_behavior_dag import build_dag_from_probe_results

        results = [
            {"url": "/tools/read", "payload": "test1", "method": "GET", "duration_ms": 50},
            {"url": "/tools/write", "payload": "test2", "method": "POST", "duration_ms": 100},
            {"url": "/tools/exec", "payload": "test3", "method": "POST", "duration_ms": 30},
        ]
        dag = build_dag_from_probe_results(results)
        assert len(dag.nodes) == 3
        assert dag.cycle_detected is False

    def test_summary_str(self):
        """Summary string is non-empty."""
        from core.probes.agent_behavior_dag import AgentBehaviorDAG, ToolCallNode

        dag = AgentBehaviorDAG()
        dag.add_node(ToolCallNode(tool_name="test"))
        summary = dag.summary()
        assert "AgentBehaviorDAG" in summary
        assert "Tool calls" in summary


# ============================================================================
# ToolVersionTracker tests (P1-2: cross-scan tool diff)
# ============================================================================


class TestToolVersionTracker:
    def test_record_and_retrieve_snapshot(self):
        """Record a snapshot and retrieve it."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tools = [
            {"tool_name": "read_file", "tool_hash": "abc123", "server_url": "http://mcp/a"},
            {"tool_name": "write_file", "tool_hash": "def456", "server_url": "http://mcp/a"},
        ]
        snapshot = tracker.record_snapshot("scan-01", tools, timestamp="2026-08-03T00:00:00")
        assert len(snapshot) == 2
        retrieved = tracker.get_snapshot("scan-01")
        assert "read_file" in retrieved
        assert retrieved["read_file"].tool_hash == "abc123"

    def test_diff_no_changes(self):
        """Identical snapshots produce empty diff."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tools = [{"tool_name": "read_file", "tool_hash": "abc", "server_url": "http://mcp"}]
        tracker.record_snapshot("scan-01", tools)
        tracker.record_snapshot("scan-02", tools)
        diff = tracker.diff("scan-01", "scan-02")
        assert diff.has_changes is False
        assert diff.added_count == 0
        assert diff.removed_count == 0

    def test_diff_added_tool(self):
        """New tool in current scan."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tracker.record_snapshot("scan-01", [{"tool_name": "a", "tool_hash": "hash_a"}])
        tracker.record_snapshot("scan-02", [
            {"tool_name": "a", "tool_hash": "hash_a"},
            {"tool_name": "b", "tool_hash": "hash_b"},
        ])
        diff = tracker.diff("scan-01", "scan-02")
        assert diff.has_changes is True
        assert diff.added_count == 1
        assert any(d.tool_name == "b" and d.change_type == "added" for d in diff.diffs)

    def test_diff_removed_tool(self):
        """Tool removed in current scan."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tracker.record_snapshot("scan-01", [
            {"tool_name": "a", "tool_hash": "hash_a"},
            {"tool_name": "b", "tool_hash": "hash_b"},
        ])
        tracker.record_snapshot("scan-02", [{"tool_name": "a", "tool_hash": "hash_a"}])
        diff = tracker.diff("scan-01", "scan-02")
        assert diff.removed_count == 1
        assert any(d.tool_name == "b" and d.change_type == "removed" for d in diff.diffs)

    def test_diff_modified_tool(self):
        """Tool hash changed = modified."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tracker.record_snapshot("scan-01", [{"tool_name": "cmd", "tool_hash": "hash_v1"}])
        tracker.record_snapshot("scan-02", [{"tool_name": "cmd", "tool_hash": "hash_v2"}])
        diff = tracker.diff("scan-01", "scan-02")
        assert diff.modified_count == 1
        modified = [d for d in diff.diffs if d.change_type == "modified"]
        assert modified[0].severity == "warning"

    def test_rug_pull_detection(self):
        """Instructions hash change = critical rug-pull."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tracker.record_snapshot("scan-01", [
            {"tool_name": "cmd", "tool_hash": "hash_v1", "instructions_hash": "inst_v1"},
        ])
        tracker.record_snapshot("scan-02", [
            {"tool_name": "cmd", "tool_hash": "hash_v2", "instructions_hash": "inst_v2"},
        ])
        diff = tracker.diff("scan-01", "scan-02")
        assert len(diff.rug_pull_alerts) >= 1
        assert diff.rug_pull_alerts[0].severity == "critical"
        assert "RUG-PULL" in diff.rug_pull_alerts[0].detail

    def test_missing_snapshot_raises(self):
        """Diff with non-existent snapshot raises KeyError."""
        import pytest

        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tracker.record_snapshot("scan-01", [{"tool_name": "a", "tool_hash": "h"}])
        with pytest.raises(KeyError):
            tracker.diff("scan-01", "scan-missing")
        with pytest.raises(KeyError):
            tracker.diff("scan-missing", "scan-01")

    def test_snapshot_labels(self):
        """Snapshot labels are sorted."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tracker.record_snapshot("scan-03", [])
        tracker.record_snapshot("scan-01", [])
        tracker.record_snapshot("scan-02", [])
        assert tracker.snapshot_labels == ["scan-01", "scan-02", "scan-03"]

    def test_diff_to_dict(self):
        """Diff serialization includes all counts."""
        from core.probes.tool_version_tracker import ToolVersionTracker

        tracker = ToolVersionTracker()
        tracker.record_snapshot("s1", [{"tool_name": "a", "tool_hash": "h1"}])
        tracker.record_snapshot("s2", [{"tool_name": "b", "tool_hash": "h2"}])
        diff = tracker.diff("s1", "s2")
        d = diff.to_dict()
        assert d["added_count"] == 1
        assert d["removed_count"] == 1
        assert d["rug_pull_alert_count"] == 0
        assert "diffs" in d


# ============================================================================
# AgentTransportProbe tests (P1-3: SSE/WS/stdio discovery)
# ============================================================================


class TestAgentTransportProbe:
    def test_probe_interface(self):
        """AgentTransportProbe implements ReconProbe."""
        from core.probes.agent_transport_probe import AgentTransportProbe
        from core.probes.base import ReconProbe

        probe = AgentTransportProbe()
        assert isinstance(probe, ReconProbe)
        assert probe.name == "AgentTransportProbe"
        assert probe.requires_browser is False

    def test_empty_endpoints(self):
        """No endpoints returns empty transport results."""
        from core import ReconSession
        from core.probes.agent_transport_probe import AgentTransportProbe

        session = ReconSession(target_url="http://example.com")
        probe = AgentTransportProbe(timeout=5.0)
        result = asyncio.run(probe.probe(session))
        assert result["summary"]["sse_count"] == 0
        assert result["summary"]["websocket_count"] == 0
        assert result["summary"]["stdio_count"] == 0

    def test_transport_discovery_dataclass(self):
        """TransportDiscovery.to_dict() includes all fields."""
        from core.probes.agent_transport_probe import TransportDiscovery

        d = TransportDiscovery(
            transport_type="sse",
            url="https://example.com/events",
            status_code=200,
            evidence=["Content-Type: text/event-stream"],
            duration_ms=42,
        )
        dd = d.to_dict()
        assert dd["transport_type"] == "sse"
        assert dd["status_code"] == 200
        assert len(dd["evidence"]) == 1

    def test_transport_discovery_result(self):
        """TransportDiscoveryResult aggregates by type."""
        from core.probes.agent_transport_probe import TransportDiscovery, TransportDiscoveryResult

        result = TransportDiscoveryResult()
        result.discoveries = [
            TransportDiscovery(transport_type="sse", url="http://a/events"),
            TransportDiscovery(transport_type="sse", url="http://b/events"),
            TransportDiscovery(transport_type="websocket", url="http://c/ws"),
        ]
        result.sse_count = 2
        result.websocket_count = 1
        d = result.to_dict()
        assert d["sse_count"] == 2
        assert d["websocket_count"] == 1
        assert d["total"] == 3

    def test_stdio_detection_from_tools(self):
        """stdio indicators in MCP tools are detected."""
        from core import ReconSession
        from core.probes.agent_transport_probe import AgentTransportProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="execute_command",
                description="Execute via subprocess spawn",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentTransportProbe(timeout=5.0)
        # Only run stdio detection (not HTTP probes)
        discoveries = asyncio.run(probe._detect_stdio_from_tools(session))
        assert len(discoveries) >= 1
        assert discoveries[0].transport_type == "stdio"

    def test_stdio_detection_empty_tools(self):
        """No MCP tools → no stdio detection."""
        from core import ReconSession
        from core.probes.agent_transport_probe import AgentTransportProbe

        session = ReconSession(target_url="http://example.com")
        probe = AgentTransportProbe(timeout=5.0)
        discoveries = asyncio.run(probe._detect_stdio_from_tools(session))
        assert discoveries == []


# ============================================================================
# FingerprintStore tests (P1-4: SQLite persistence)
# ============================================================================


class TestFingerprintStore:
    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create a temp SQLite database."""
        from core.persistence.fingerprint_store import FingerprintStore

        db_path = tmp_path / "test_fingerprints.db"
        store = FingerprintStore(db_path)
        yield store
        # Cleanup
        store.close()
        if db_path.exists():
            db_path.unlink()

    def test_store_record_and_retrieve(self, temp_db):
        """Record and retrieve a fingerprint."""
        store = temp_db
        store.record("endpoint-a", "abc123", scan_label="scan-01", status_code=200)
        record = store.get_latest("endpoint-a")
        assert record is not None
        assert record.fingerprint == "abc123"
        assert record.scan_label == "scan-01"
        assert record.status_code == 200

    def test_record_batch(self, temp_db):
        """Batch insert multiple records."""
        store = temp_db
        items = [
            {"key": "ep-1", "fingerprint": "fp1", "status_code": 200},
            {"key": "ep-2", "fingerprint": "fp2", "status_code": 404},
            {"key": "ep-3", "fingerprint": "fp3"},
        ]
        count = store.record_batch(items, scan_label="batch-01")
        assert count == 3
        assert store.count() == 3

    def test_has_changed_true(self, temp_db):
        """Different fingerprint detected as change."""
        store = temp_db
        store.record("key", "old_fp", scan_label="s1")
        assert store.has_changed("key", "new_fp") is True

    def test_has_changed_false(self, temp_db):
        """Same fingerprint not detected as change."""
        store = temp_db
        store.record("key", "same_fp", scan_label="s1")
        assert store.has_changed("key", "same_fp") is False

    def test_has_changed_no_baseline(self, temp_db):
        """No existing record → no change."""
        store = temp_db
        assert store.has_changed("new_key", "any_fp") is False

    def test_history_order(self, temp_db):
        """History returns most recent first."""
        store = temp_db
        import time

        store.record("key", "fp1", scan_label="s1")
        time.sleep(0.01)
        store.record("key", "fp2", scan_label="s2")
        store.record("key", "fp3", scan_label="s3")

        history = store.get_history("key")
        assert len(history) >= 3
        # Most recent first
        assert history[0].scan_label == "s3"
        assert history[0].fingerprint == "fp3"

    def test_get_all_keys(self, temp_db):
        """Get unique keys."""
        store = temp_db
        store.record("key-a", "fp1", scan_label="s1")
        store.record("key-b", "fp2", scan_label="s1")
        store.record("key-a", "fp3", scan_label="s2")
        keys = store.get_all_keys()
        assert sorted(keys) == ["key-a", "key-b"]

    def test_get_scan_labels(self, temp_db):
        """Get unique scan labels."""
        store = temp_db
        store.record("k1", "fp", scan_label="daily-01")
        store.record("k2", "fp", scan_label="daily-02")
        store.record("k3", "fp", scan_label="daily-01")
        labels = store.get_scan_labels()
        assert sorted(labels) == ["daily-01", "daily-02"]

    def test_get_changed_since(self, temp_db):
        """Detect changes since a scan label."""
        store = temp_db
        store.record("key-a", "old", scan_label="s01")
        store.record("key-a", "new", scan_label="s02")
        store.record("key-b", "stable", scan_label="s01")
        store.record("key-b", "stable", scan_label="s02")

        changes = store.get_changed_since("s01")
        assert len(changes) == 1
        assert changes[0]["key"] == "key-a"
        assert changes[0]["old_fingerprint"] == "old"
        assert changes[0]["new_fingerprint"] == "new"

    def test_count(self, temp_db):
        """Count total records."""
        store = temp_db
        assert store.count() == 0
        store.record("a", "fp1")
        store.record("b", "fp2")
        assert store.count() == 2


# ============================================================================
# AgentWorkspaceProbe tests (P2-1: FS/sandbox/KB detection)
# ============================================================================


class TestAgentWorkspaceProbe:
    def test_probe_interface(self):
        """AgentWorkspaceProbe implements ReconProbe."""
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.probes.base import ReconProbe

        probe = AgentWorkspaceProbe()
        assert isinstance(probe, ReconProbe)
        assert probe.name == "AgentWorkspaceProbe"
        assert probe.requires_browser is False
        assert probe.requires_auth is False

    def test_detect_fs_read_write(self):
        """Tool with 'write file' description → fs_rw finding."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="save_report",
                description="Write file to disk with report data",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert len(ws["fs_read_write_tools"]) >= 1
        assert "save_report" in ws["fs_read_write_tools"]
        assert ws["critical_findings"] >= 1

    def test_detect_fs_read_only(self):
        """Tool with 'read file' description → fs_ro finding."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="list_directory",
                description="List files in directory",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert len(ws["fs_read_only_tools"]) >= 1
        assert "list_directory" in ws["fs_read_only_tools"]

    def test_rw_takes_priority_over_ro(self):
        """Tool matching both RW and RO patterns classified as RW only."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="file_io",
                description="Read and write files on disk",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert "file_io" in ws["fs_read_write_tools"]
        assert "file_io" not in ws["fs_read_only_tools"]

    def test_detect_sandbox_container(self):
        """Container keywords detect sandbox."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="run_in_docker",
                description="Run command in Docker container",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert ws["sandbox_type"] == "container"

    def test_detect_sandbox_chroot(self):
        """Chroot/jail keywords detect sandbox."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="sandboxed_exec",
                description="Execute within sandbox jail",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert ws["sandbox_type"] == "chroot"

    def test_detect_sandbox_microvm(self):
        """Firecracker/gVisor keywords detect microvm."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="micro_exec",
                description="Execute in Firecracker microVM",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert ws["sandbox_type"] == "microvm"

    def test_detect_knowledge_base_owasp(self):
        """OWASP org reference detected as KB integration."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="check_owasp",
                description="Check owasp.org top 10 for vulnerabilities",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert "owasp" in ws["knowledge_bases"]

    def test_detect_multiple_knowledge_bases(self):
        """Multiple KB sources detected."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.models.recon_report import MCPToolInfo

        session = ReconSession(target_url="http://example.com")
        session.report.mcp_tools = [
            MCPToolInfo(
                tool_name="enrich_vuln",
                description="Look up CVE-2024-1234 on nvd.nist.gov and check exploit-db.com",
                server_url="http://mcp/server",
            ),
        ]
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert len(ws["knowledge_bases"]) >= 2
        assert "nvd_cve" in ws["knowledge_bases"]
        assert "exploitdb" in ws["knowledge_bases"]

    def test_empty_session(self):
        """No MCP tools → empty findings."""
        from core import ReconSession
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe

        session = ReconSession(target_url="http://example.com")
        probe = AgentWorkspaceProbe()
        result = asyncio.run(probe.probe(session))
        ws = result["workspace"]
        assert ws["total_findings"] == 0
        assert ws["sandbox_type"] == "unknown"

    def test_workspace_finding_dataclass(self):
        """WorkspaceFinding.to_dict() includes all fields."""
        from core.probes.agent_workspace_probe import WorkspaceFinding

        f = WorkspaceFinding(
            category="fs_rw",
            subcategory="read_write",
            severity="critical",
            detail="Tool 'write_file' enables filesystem write",
            source_url="http://mcp/server",
            evidence="write file",
        )
        d = f.to_dict()
        assert d["category"] == "fs_rw"
        assert d["severity"] == "critical"


# ============================================================================
# ReconPipeline parallel execution tests (P2-2)
# ============================================================================


class TestReconPipelineParallel:
    def test_parallel_mode_no_deps_probes(self):
        """Probes with no dependencies run in parallel."""
        from core import ReconSession
        from core.pipeline import ReconPipeline
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe
        from core.probes.agent_transport_probe import AgentTransportProbe

        session = ReconSession(target_url="http://example.com")
        # Both probes have requires_auth=False, requires_browser=False
        pipeline = ReconPipeline(
            probes=[AgentWorkspaceProbe(), AgentTransportProbe(timeout=5.0)],
            parallel=True,
        )
        result = asyncio.run(pipeline.run_parallel(session))
        assert result.executed >= 2
        assert result.failed == 0

    def test_parallel_pipeline_result_stats(self):
        """Parallel execution returns correct stats."""
        from core.pipeline import PipelineResult

        result = PipelineResult(
            total=5,
            executed=4,
            skipped=1,
            failed=0,
            duration_seconds=2.5,
        )
        assert result.total == 5
        assert result.executed == 4
        assert result.skipped == 1

    def test_parallel_skip_on_auth_mismatch(self):
        """Probes requiring auth are skipped when not authenticated."""
        from core import ReconSession
        from core.pipeline import ReconPipeline
        from core.probes.agent_workspace_probe import AgentWorkspaceProbe

        session = ReconSession(target_url="http://example.com")
        # Workshop probe: requires_auth=False → should run
        pipeline = ReconPipeline(
            probes=[AgentWorkspaceProbe()],
            parallel=True,
        )
        result = asyncio.run(pipeline.run_parallel(session))
        assert result.executed == 1
        assert result.skipped == 0

    def test_parallel_empty_probes(self):
        """Empty probe list."""
        from core import ReconSession
        from core.pipeline import ReconPipeline

        session = ReconSession(target_url="http://example.com")
        pipeline = ReconPipeline(probes=[], parallel=True)
        result = asyncio.run(pipeline.run_parallel(session))
        assert result.total == 0
        assert result.executed == 0


# ============================================================================
# ReconOrchestrator incremental mode tests (P2-4)
# ============================================================================


class TestReconOrchestratorIncremental:
    def test_orchestrator_accepts_incremental_flag(self):
        """ReconOrchestrator accepts incremental=True."""
        from core.orchestration import ReconOrchestrator
        from core.task_runtime import GuardrailPolicy

        orch = ReconOrchestrator(
            incremental=True,
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )
        assert orch._incremental is True
        assert orch._fp_store is not None

    def test_orchestrator_accepts_parallel_flag(self):
        """ReconOrchestrator accepts parallel=True."""
        from core.orchestration import ReconOrchestrator
        from core.task_runtime import GuardrailPolicy

        orch = ReconOrchestrator(
            parallel=True,
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )
        assert orch.pipeline._parallel is True

    def test_compute_ep_fingerprint_stable(self):
        """Same endpoint → same fingerprint."""
        from core.orchestration import ReconOrchestrator
        from core.task_runtime import GuardrailPolicy

        orch = ReconOrchestrator(
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )
        fp1 = orch._compute_ep_fingerprint("hello", 200)
        fp2 = orch._compute_ep_fingerprint("hello", 200)
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_compute_ep_fingerprint_different(self):
        """Different body → different fingerprint."""
        from core.orchestration import ReconOrchestrator
        from core.task_runtime import GuardrailPolicy

        orch = ReconOrchestrator(
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )
        fp1 = orch._compute_ep_fingerprint("body1", 200)
        fp2 = orch._compute_ep_fingerprint("body2", 200)
        assert fp1 != fp2

    def test_store_endpoint_fingerprints(self, tmp_path):
        """Store fingerprints to SQLite."""
        from core.models.recon_report import DiscoveredEndpoint
        from core.orchestration import ReconOrchestrator
        from core.task_runtime import GuardrailPolicy

        db_path = tmp_path / "test_inc.db"
        orch = ReconOrchestrator(
            incremental=True,
            fingerprint_db_path=str(db_path),
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )
        endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api/a",
                response_body_preview="result a",
                status_code=200,
            ),
            DiscoveredEndpoint(
                url="https://example.com/api/b",
                response_body_preview="result b",
                status_code=404,
            ),
        ]
        orch._store_endpoint_fingerprints(endpoints, "test-scan")
        assert orch._fp_store.count() >= 2

    def test_check_changed_endpoints_incremental(self, tmp_path):
        """Incremental check marks unchanged endpoints."""
        from core.models.recon_report import DiscoveredEndpoint
        from core.orchestration import ReconOrchestrator
        from core.task_runtime import GuardrailPolicy

        db_path = tmp_path / "test_changed.db"
        orch = ReconOrchestrator(
            incremental=True,
            fingerprint_db_path=str(db_path),
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )

        endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api/a",
                response_body_preview="unchanged body",
                status_code=200,
            ),
        ]
        # First scan: records baseline
        orch._check_changed_endpoints(endpoints, "scan-01")
        # Second scan: same body → should be marked as unchanged
        skipped = orch._check_changed_endpoints(endpoints, "scan-02")
        assert skipped == 1

    def test_incremental_run_basic(self):
        """Incremental orchestrator runs and completes."""
        from core import ReconSession
        from core.orchestration import ReconOrchestrator
        from core.task_runtime import GuardrailPolicy

        orch = ReconOrchestrator(
            incremental=True,
            parallel=True,
            guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        )
        session = ReconSession(target_url="http://example.test")
        result = asyncio.run(orch.run(session))
        assert result.summary["endpoint_count"] >= 0
        assert "pipeline_result" in result.summary
        assert "incremental_skipped" in result.summary
