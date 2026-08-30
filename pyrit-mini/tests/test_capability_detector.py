# arXiv:2302.12173 — Indirect prompt injection, capability probing
"""Tests for recon/capability_detector.py — capability detection functions.

Covers:
    - _build_probe_body: template-based probe body construction
    - _probe_capabilities: keyword + structural capability detection
    - _detect_model_family: model family inference from response text
    - _detect_language: Chinese/English language detection
    - _infer_json_path: JSON response path inference

学术依据:
    - Greshake et al. (arXiv:2302.12173) — 间接提示注入探测
    - Zhan et al. (arXiv:2307.00929) — InjecAgent
    - Mazeika et al. (arXiv:2406.18510) — WILDTEAMING 模型族
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestBuildProbeBody:
    """Test _build_probe_body — template-based probe body construction."""

    def test_with_prompt_placeholder(self):
        """Body with {PROMPT} placeholder should get it replaced."""
        from recon.capability_detector import _build_probe_body

        class MockParsed:
            body = '{"prompt": "{PROMPT}", "model": "gpt-4o"}'
            chat_id = None

        result = _build_probe_body(MockParsed(), "hello world")
        data = json.loads(result)
        assert data["prompt"] == "hello world"
        assert data["model"] == "gpt-4o"

    def test_with_chat_id_placeholder(self):
        """Body with {CHAT_ID} should get it replaced from parsed.chat_id."""
        from recon.capability_detector import _build_probe_body

        class MockParsed:
            body = '{"prompt": "{PROMPT}", "session_id": "{CHAT_ID}"}'
            chat_id = "sess-123"

        result = _build_probe_body(MockParsed(), "test")
        data = json.loads(result)
        assert data["prompt"] == "test"
        assert data["session_id"] == "sess-123"

    def test_no_placeholder_fallback(self):
        """Body without {PROMPT} should fallback to {"prompt": probe_text}."""
        from recon.capability_detector import _build_probe_body

        class MockParsed:
            body = '{"model": "gpt-4o"}'
            chat_id = None

        result = _build_probe_body(MockParsed(), "hi")
        data = json.loads(result)
        assert data["prompt"] == "hi"

    def test_empty_body_fallback(self):
        """Empty body should fallback to {"prompt": probe_text}."""
        from recon.capability_detector import _build_probe_body

        class MockParsed:
            body = ""
            chat_id = None

        result = _build_probe_body(MockParsed(), "probe")
        data = json.loads(result)
        assert data["prompt"] == "probe"


class TestProbeCapabilities:
    """Test _probe_capabilities — capability detection from response text."""

    def test_agent_keyword_detection(self):
        """Agent capability should be detected from keywords."""
        from recon.capability_detector import _probe_capabilities

        response = "I have access to tools and can use them to help you."
        caps = _probe_capabilities(response)
        assert caps["agent"] is True

    def test_rag_keyword_detection(self):
        """RAG capability should be detected from keywords."""
        from recon.capability_detector import _probe_capabilities

        response = "Based on the retrieved knowledge base, here is the answer."
        caps = _probe_capabilities(response)
        assert caps["rag"] is True

    def test_mcp_keyword_detection(self):
        """MCP capability should be detected from keywords."""
        from recon.capability_detector import _probe_capabilities

        response = "I'm connected to an MCP server with model context protocol tools."
        caps = _probe_capabilities(response)
        assert caps["mcp"] is True

    def test_embedding_keyword_detection(self):
        """Embedding capability should be detected from keywords."""
        from recon.capability_detector import _probe_capabilities

        response = "I use vector search and embedding for semantic search."
        caps = _probe_capabilities(response)
        assert caps["embedding"] is True

    def test_multi_agent_keyword_detection(self):
        """Multi-agent capability should be detected."""
        from recon.capability_detector import _probe_capabilities

        response = "I collaborate with multiple agents in a team of agents."
        caps = _probe_capabilities(response)
        assert caps["multi_agent"] is True

    def test_code_execution_keyword_detection(self):
        """Code execution capability should be detected."""
        from recon.capability_detector import _probe_capabilities

        response = "I can execute code in a sandbox python execution environment."
        caps = _probe_capabilities(response)
        assert caps["code_execution"] is True

    def test_web_search_keyword_detection(self):
        """Web search capability should be detected."""
        from recon.capability_detector import _probe_capabilities

        response = "I can search the web for online search results."
        caps = _probe_capabilities(response)
        assert caps["web_search"] is True

    def test_mcp_structural_pattern(self):
        """MCP structural pattern (JSON-RPC) should be detected."""
        from recon.capability_detector import _probe_capabilities

        response = '{"jsonrpc": "2.0", "result": {"tools": []}}'
        caps = _probe_capabilities(response)
        assert caps["mcp"] is True

    def test_agent_structural_pattern(self):
        """Agent structural pattern (function_call) should be detected."""
        from recon.capability_detector import _probe_capabilities

        response = '{"function_call": {"name": "get_weather", "arguments": {}}}'
        caps = _probe_capabilities(response)
        assert caps["agent"] is True

    def test_rag_structural_pattern(self):
        """RAG structural pattern (source_documents) should be detected."""
        from recon.capability_detector import _probe_capabilities

        response = '{"source_documents": [{"content": "...", "similarity_score": 0.95}]}'
        caps = _probe_capabilities(response)
        assert caps["rag"] is True

    def test_embedding_structural_pattern(self):
        """Embedding structural pattern should be detected."""
        from recon.capability_detector import _probe_capabilities

        response = '{"embedding": [0.1, 0.2, 0.3], "similarity": 0.85}'
        caps = _probe_capabilities(response)
        assert caps["embedding"] is True

    def test_no_capabilities_detected(self):
        """No capabilities should be detected from generic response."""
        from recon.capability_detector import _probe_capabilities

        response = "Hello, how can I help you today?"
        caps = _probe_capabilities(response)
        assert caps["agent"] is False
        assert caps["rag"] is False
        assert caps["mcp"] is False

    def test_empty_response(self):
        """Empty or short response should return all False."""
        from recon.capability_detector import _probe_capabilities

        caps = _probe_capabilities("")
        assert caps["agent"] is False

    def test_model_family_included(self):
        """Model family should be included in capabilities when detected."""
        from recon.capability_detector import _probe_capabilities

        response = "I am ChatGPT, based on GPT-4o."
        caps = _probe_capabilities(response)
        assert caps.get("model_family") == "gpt"


class TestDetectModelFamily:
    """Test _detect_model_family — model family inference."""

    def test_gpt_family(self):
        """GPT model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("I am ChatGPT based on GPT-4o") == "gpt"
        assert _detect_model_family("powered by OpenAI GPT-5") == "gpt"

    def test_claude_family(self):
        """Claude model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("I am Claude, made by Anthropic") == "claude"

    def test_gemini_family(self):
        """Gemini model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("I am Gemini 2.5 Pro by Google AI") == "gemini"

    def test_llama_family(self):
        """Llama model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("I am Llama 4 by Meta AI") == "llama"

    def test_qwen_family(self):
        """Qwen model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("我是通义千问 Qwen3") == "qwen"

    def test_deepseek_family(self):
        """DeepSeek model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("我是深度求索 DeepSeek-V3") == "deepseek"

    def test_glm_family(self):
        """GLM model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("我是智谱 GLM-5") == "glm"

    def test_grok_family(self):
        """Grok model family should be detected."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("I am Grok 4 by xAI") == "grok"

    def test_unknown_family(self):
        """Unknown text should return None."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("Hello world") is None

    def test_empty_text(self):
        """Empty text should return None."""
        from recon.capability_detector import _detect_model_family

        assert _detect_model_family("") is None
        assert _detect_model_family("ab") is None


class TestDetectLanguage:
    """Test _detect_language — Chinese/English language detection."""

    def test_chinese_detection(self):
        """Chinese text (>5% CJK) should be detected as 'zh'."""
        from recon.capability_detector import _detect_language

        text = "你好世界，这是一个测试用的中文文本"
        assert _detect_language(text) == "zh"

    def test_english_detection(self):
        """English text should be detected as 'en'."""
        from recon.capability_detector import _detect_language

        text = "Hello world, this is an English test response."
        assert _detect_language(text) == "en"

    def test_short_text_returns_none(self):
        """Text shorter than 10 chars should return None."""
        from recon.capability_detector import _detect_language

        assert _detect_language("short") is None

    def test_empty_text(self):
        """Empty text should return None."""
        from recon.capability_detector import _detect_language

        assert _detect_language("") is None


class TestInferJsonPath:
    """Test _infer_json_path — JSON response path inference."""

    def test_openai_chat_format(self):
        """OpenAI chat format: choices[0].message.content."""
        from recon.capability_detector import _infer_json_path

        content = json.dumps({
            "choices": [{"message": {"content": "Hello world"}}]
        })
        path = _infer_json_path(content)
        assert path is not None
        assert "choices" in path
        assert "message" in path
        assert "content" in path

    def test_simple_response_format(self):
        """Simple format: {response: "text"}."""
        from recon.capability_detector import _infer_json_path

        content = json.dumps({"response": "Hello there, how are you?"})
        path = _infer_json_path(content)
        assert path == "response"

    def test_nested_format(self):
        """Nested format: data.results[0].text."""
        from recon.capability_detector import _infer_json_path

        content = json.dumps({
            "data": {"results": [{"text": "Hello world response"}]}
        })
        path = _infer_json_path(content)
        assert path is not None
        assert "data" in path
        assert "results" in path

    def test_non_json_returns_none(self):
        """Non-JSON content should return None."""
        from recon.capability_detector import _infer_json_path

        assert _infer_json_path("plain text response") is None

    def test_short_string_value_skipped(self):
        """Short string values (< 6 chars) should be skipped."""
        from recon.capability_detector import _infer_json_path

        content = json.dumps({"code": "hi", "response": "Hello world"})
        path = _infer_json_path(content)
        assert path == "response"
