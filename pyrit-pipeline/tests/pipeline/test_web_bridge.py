# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Web Bridge 测试 — 两流水线自动串联。."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


class TestWebBridgeConfig:
    """测试 --web-bridge 参数解析。."""

    def test_web_bridge_flag_default_false(self, monkeypatch):
        """--web-bridge 默认为 False。."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", ["main"])
        args = parse_args()
        assert hasattr(args, "web_bridge")
        assert args.web_bridge is False

    def test_web_bridge_flag_enabled(self, monkeypatch):
        """--web-bridge 可以被启用。."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "https://example.com",
            "--web-bridge",
        ])
        args = parse_args()
        assert args.web_bridge is True

    def test_cdp_port_default(self, monkeypatch):
        """--cdp-port 默认为 9222。."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", ["main"])
        args = parse_args()
        assert args.cdp_port == 9222

    def test_cdp_port_custom(self, monkeypatch):
        """--cdp-port 可以自定义。."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--cdp-port", "9333",
        ])
        args = parse_args()
        assert args.cdp_port == 9333

    def test_web_bridge_does_not_affect_direct_mode(self, monkeypatch):
        """不带 --web-bridge 时 --target-url 仍走直连模式。."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "https://api.example.com/v1/chat/completions",
        ])
        args = parse_args()
        assert args.web_bridge is False
        assert args.target_url is not None


class TestWebBridgeCapabilityDetection:
    """测试能力探测函数。."""

    def test_detect_agent_capability_english(self):
        """检测英文 Agent 能力关键词。."""
        from pipeline.integrations.web_bridge import _detect_agent_capability

        assert _detect_agent_capability("I have access to tools and can call functions") is True
        assert _detect_agent_capability("I am an agent with tool use capability") is True
        assert _detect_agent_capability("Hello, I am a simple chatbot") is False

    def test_detect_agent_capability_chinese(self):
        """检测中文 Agent 能力关键词。."""
        from pipeline.integrations.web_bridge import _detect_agent_capability

        assert _detect_agent_capability("我能使用工具来完成 tasks") is True
        assert _detect_agent_capability("我可以调用外部 API") is True

    def test_detect_rag_capability(self):
        """检测 RAG 能力。."""
        from pipeline.integrations.web_bridge import _detect_rag_capability

        assert _detect_rag_capability("I can search the knowledge base for information") is True
        assert _detect_rag_capability("Using retrieval augmented generation") is True
        assert _detect_rag_capability("I don't have any database access") is False

    def test_detect_mcp_capability(self):
        """检测 MCP 能力。."""
        from pipeline.integrations.web_bridge import _detect_mcp_capability

        assert _detect_mcp_capability("Connected to MCP server") is True
        assert _detect_mcp_capability("Using model context protocol") is True
        assert _detect_mcp_capability("No support for this protocol") is False

    def test_detect_embedding_capability(self):
        """检测 Embedding 能力。."""
        from pipeline.integrations.web_bridge import _detect_embedding_capability

        assert _detect_embedding_capability("I use embedding for semantic search") is True
        assert _detect_embedding_capability("Vector representation available") is True
        assert _detect_embedding_capability("No support for vector operations") is False


class TestWebBridgeExtractResponse:
    """测试响应文本提取。."""

    def test_extract_openai_format(self):
        """提取 OpenAI 格式响应。."""
        from pipeline.integrations.web_bridge import _extract_response_text

        resp = {
            "choices": [
                {"message": {"content": "Hello from the model"}}
            ]
        }
        assert _extract_response_text(resp) == "Hello from the model"

    def test_extract_simple_format(self):
        """提取简单格式响应。."""
        from pipeline.integrations.web_bridge import _extract_response_text

        resp = {"response": "Simple response"}
        assert _extract_response_text(resp) == "Simple response"

    def test_extract_nested_format(self):
        """提取嵌套格式响应。."""
        from pipeline.integrations.web_bridge import _extract_response_text

        resp = {"data": {"content": "Nested content"}}
        assert _extract_response_text(resp) == "Nested content"

    def test_extract_empty(self):
        """空响应返回空字符串。."""
        from pipeline.integrations.web_bridge import _extract_response_text

        assert _extract_response_text({}) == ""

    def test_extract_model_name(self):
        """提取模型名称。."""
        from pipeline.integrations.web_bridge import _extract_model_from_response

        assert _extract_model_from_response({"model": "gpt-4"}) == "gpt-4"
        assert _extract_model_from_response({"model_name": "claude-3"}) == "claude-3"
        assert _extract_model_from_response({"data": {"model": "llama"}}) == "llama"
        assert _extract_model_from_response({}) == ""


class TestWebBridgeRecommendations:
    """测试攻击推荐构建。."""

    def test_build_recommendations_default(self):
        """默认推荐包含 prompt_sending 和 skeleton_key。."""
        from pipeline.integrations.web_bridge import _build_recommendations

        recs = _build_recommendations(False, False, False)
        owasp_ids = [r.owasp_id for r in recs]
        assert "LLM01" in owasp_ids
        assert "LLM02" in owasp_ids

    def test_build_recommendations_with_agent(self):
        """Agent 能力推荐 red_teaming。."""
        from pipeline.integrations.web_bridge import _build_recommendations

        recs = _build_recommendations(True, False, False)
        strategies = [r.attack_strategy for r in recs]
        assert "red_teaming" in strategies

    def test_build_recommendations_with_rag(self):
        """RAG 能力推荐 many_shot。."""
        from pipeline.integrations.web_bridge import _build_recommendations

        recs = _build_recommendations(False, True, False)
        strategies = [r.attack_strategy for r in recs]
        assert "many_shot" in strategies

    def test_build_recommendations_with_mcp(self):
        """MCP 能力推荐 pair。."""
        from pipeline.integrations.web_bridge import _build_recommendations

        recs = _build_recommendations(False, False, True)
        strategies = [r.attack_strategy for r in recs]
        assert "pair" in strategies


class TestWebBridgeInferModel:
    """测试模型名称推断。."""

    def test_infer_model_from_url(self):
        """从 URL 推断模型名称。."""
        from pipeline.integrations.web_bridge import _infer_model_name

        assert _infer_model_name("https://api.example.com/v1/chat") == "api_example_com"
        assert _infer_model_name("https://chat.longcat.chat:8080") == "chat_longcat_chat_8080"


class TestWebBridgeIntegration:
    """Web Bridge 集成测试 (mock 外部依赖)。."""

    def test_web_bridge_import(self):
        """Web Bridge 模块可以正常导入。."""
        from pipeline.integrations.web_bridge import run_web_bridge

        assert callable(run_web_bridge)

    @pytest.mark.asyncio
    async def test_web_bridge_no_target_url(self):
        """无 target_url 时返回 False。."""
        from pipeline.integrations.web_bridge import run_web_bridge

        ctx = MagicMock()
        ctx.args = SimpleNamespace(target_url=None, web_bridge=True)
        ctx.metadata = {}

        result = await run_web_bridge(ctx)
        assert result is False
