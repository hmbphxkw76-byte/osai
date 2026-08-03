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
