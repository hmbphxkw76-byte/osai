# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Web Bridge 测试 — 两流水线自动串联。."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


class TestWebBridgeConfig:
    """测试 --web-bridge 参数解析 (v43: 已废弃, 保留向后兼容)."""

    def test_web_bridge_flag_default_false(self, monkeypatch):
        """--web-bridge 默认为 False."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", ["main"])
        args = parse_args()
        assert hasattr(args, "web_bridge")
        assert args.web_bridge is False

    def test_web_bridge_flag_enabled(self, monkeypatch):
        """--web-bridge 可以被启用 (向后兼容)."""
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
        """不带 --web-bridge 时 --target-url 仍可正常使用 (v43: 统一入口)."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "https://api.example.com/v1/chat/completions",
        ])
        args = parse_args()
        assert args.web_bridge is False
        assert args.target_url is not None


class TestUnifiedTargetConfig:
    """v43 统一目标入口参数测试。"""

    def test_burp_request_param(self, monkeypatch):
        """--burp-request 参数解析."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--burp-request", "data/burp/request.txt",
        ])
        args = parse_args()
        assert args.burp_request == "data/burp/request.txt"

    def test_burp_request_default_none(self, monkeypatch):
        """--burp-request 默认为 None."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", ["main"])
        args = parse_args()
        assert args.burp_request is None

    def test_api_key_param(self, monkeypatch):
        """--api-key 参数解析."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--api-key", "sk-test-123",
        ])
        args = parse_args()
        assert args.api_key == "sk-test-123"

    def test_api_response_path_param(self, monkeypatch):
        """--api-response-path 参数解析."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--api-response-path", "response",
        ])
        args = parse_args()
        assert args.api_response_path == "response"

    def test_api_response_path_default(self, monkeypatch):
        """--api-response-path 默认为 choices[0].message.content."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", ["main"])
        args = parse_args()
        assert args.api_response_path == "choices[0].message.content"

    def test_target_profile_param(self, monkeypatch):
        """--target-profile 参数解析."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/labs/PI_02",
            "--target-profile", "web_redteam/targets/same_domain/pi02.yaml",
        ])
        args = parse_args()
        assert args.target_profile == "web_redteam/targets/same_domain/pi02.yaml"

    def test_target_profile_alias_web_target_profile(self, monkeypatch):
        """--web-target-profile 作为 --target-profile 的别名."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/labs/PI_02",
            "--web-target-profile", "web_redteam/targets/same_domain/old.yaml",
        ])
        args = parse_args()
        assert args.target_profile == "web_redteam/targets/same_domain/old.yaml"


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


# ============================================================
# v44.2: Burp SSE/HTTPS 自动适配测试
# ============================================================


class TestBurpSSEDetection:
    """v44.2: _detect_sse_from_request 测试."""

    def test_sse_accept_header(self):
        """Accept: text/event-stream 触发 SSE."""
        from pipeline.stages.stage_target_classify import _detect_sse_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Accept: text/event-stream\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_sse_from_request(request) is True

    def test_sse_stream_field_true(self):
        """请求体 Stream:true 触发 SSE."""
        from pipeline.stages.stage_target_classify import _detect_sse_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}","Stream":true}'
        )
        assert _detect_sse_from_request(request) is True

    def test_sse_stream_field_lowercase(self):
        """请求体 stream:true (小写) 触发 SSE."""
        from pipeline.stages.stage_target_classify import _detect_sse_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"query":"{PROMPT}","stream":true}'
        )
        assert _detect_sse_from_request(request) is True

    def test_sse_url_path_keyword(self):
        """URL 路径包含 /stream 触发 SSE."""
        from pipeline.stages.stage_target_classify import _detect_sse_from_request

        request = (
            "POST /api/stream HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_sse_from_request(request) is True

    def test_non_sse_json_api(self):
        """标准 JSON API 不触发 SSE."""
        from pipeline.stages.stage_target_classify import _detect_sse_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}","Stream":false}'
        )
        assert _detect_sse_from_request(request) is False

    def test_sse_cross_domain_real_case(self):
        """跨域 SSE Burp 请求 (Accept: text/event-stream + Stream:true)."""
        from pipeline.stages.stage_target_classify import _detect_sse_from_request

        request = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: llm-api.example.edu.cn\r\n"
            "Authorization: Bearer test-bearer-token-1234\r\n"
            "Accept: text/event-stream\r\n"
            "Content-Type: application/json\r\n"
            "Origin: https://portal.example.edu.cn\r\n"
            "\r\n"
            '{"Inputs":{"stuNo":"S20240001","CourseName":""},'
            '"Stream":true,"Query":"{PROMPT}",'
            '"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"UserId":"S20240001"}'
        )
        assert _detect_sse_from_request(request) is True


class TestBurpTLSDetection:
    """v44.2: _detect_tls_from_request 测试."""

    def test_tls_from_origin_https(self):
        """Origin: https:// 触发 TLS."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Origin: https://app.example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is True

    def test_tls_from_referer_https(self):
        """Referer: https:// 触发 TLS."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Referer: https://app.example.com/chat\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is True

    def test_tls_from_host_443(self):
        """Host 包含 :443 触发 TLS."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is True

    def test_tls_non_localhost_default_https(self):
        """非 localhost 域名默认 HTTPS."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: llm-api.example.edu.cn\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is True

    def test_no_tls_localhost(self):
        """localhost 不启用 TLS."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: localhost:8080\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is False

    def test_no_tls_127(self):
        """127.0.0.1 不启用 TLS."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: 127.0.0.1:11434\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is False

    def test_no_tls_http_port(self):
        """明确 HTTP 端口 (:8080) 不启用 TLS."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com:8080\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is False

    def test_tls_cross_domain_real_case(self):
        """跨域 Burp 请求 — Origin https + 非 localhost 域名."""
        from pipeline.stages.stage_target_classify import _detect_tls_from_request

        request = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: llm-api.example.edu.cn\r\n"
            "Authorization: Bearer test-bearer-token-1234\r\n"
            "Origin: https://portal.example.edu.cn\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"Query":"{PROMPT}"}'
        )
        assert _detect_tls_from_request(request) is True


class TestBurpSchemeInference:
    """v44.2: _infer_scheme_from_burp 测试."""

    def test_scheme_from_origin_https(self):
        """从 Origin 推断 https."""
        from pipeline.stages.stage_target_classify import _infer_scheme_from_burp

        lines = [
            "POST /api/chat HTTP/1.1",
            "Host: api.example.com",
            "Origin: https://app.example.com",
        ]
        assert _infer_scheme_from_burp("api.example.com", lines, "https://app.example.com") == "https"

    def test_scheme_from_origin_http(self):
        """从 Origin 推断 http."""
        from pipeline.stages.stage_target_classify import _infer_scheme_from_burp

        lines = [
            "POST /api/chat HTTP/1.1",
            "Host: localhost:8080",
            "Origin: http://localhost:3000",
        ]
        assert _infer_scheme_from_burp("localhost:8080", lines, "http://localhost:3000") == "http"

    def test_scheme_from_host_443(self):
        """Host :443 → https."""
        from pipeline.stages.stage_target_classify import _infer_scheme_from_burp

        lines = ["POST /api HTTP/1.1", "Host: example.com:443"]
        assert _infer_scheme_from_burp("example.com:443", lines) == "https"

    def test_scheme_localhost(self):
        """localhost → http."""
        from pipeline.stages.stage_target_classify import _infer_scheme_from_burp

        lines = ["POST /api HTTP/1.1", "Host: localhost"]
        assert _infer_scheme_from_burp("localhost", lines) == "http"

    def test_scheme_default_https(self):
        """非 localhost 域名默认 https."""
        from pipeline.stages.stage_target_classify import _infer_scheme_from_burp

        lines = ["POST /api HTTP/1.1", "Host: api.example.com"]
        assert _infer_scheme_from_burp("api.example.com", lines) == "https"

    def test_scheme_http_port(self):
        """明确 HTTP 端口 → http."""
        from pipeline.stages.stage_target_classify import _infer_scheme_from_burp

        lines = ["POST /api HTTP/1.1", "Host: example.com:8080"]
        assert _infer_scheme_from_burp("example.com:8080", lines) == "http"


class TestBurpFallbackSSECallback:
    """v44.2: _build_fallback_sse_callback 测试."""

    def test_sse_extraction_openai_format(self):
        """OpenAI 格式 SSE (choices[0].delta.content) 提取."""
        from pipeline.stages.stage_target_classify import _build_fallback_sse_callback

        callback = _build_fallback_sse_callback()
        response = (
            'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":" world"}}]}\n\n'
            "data: [DONE]\n\n"
        )
        result = callback(response)
        assert result == "Hello world"

    def test_sse_extraction_pascalcase(self):
        """PascalCase 格式 SSE (Choices[0].Delta.Content) 提取."""
        from pipeline.stages.stage_target_classify import _build_fallback_sse_callback

        callback = _build_fallback_sse_callback()
        response = (
            'data: {"Choices":[{"Delta":{"Content":"你"}}]}\n\n'
            'data: {"Choices":[{"Delta":{"Content":"好"}}]}\n\n'
            'data: {"Choices":[{"Delta":{"Content":""},"FinishReason":"Stop"}]}\n\n'
            "data: [DONE]\n\n"
        )
        result = callback(response)
        assert result == "你好"

    def test_sse_extraction_cross_domain_real_case(self):
        """跨域 SSE 响应提取 (PascalCase + 模型名)."""
        from pipeline.stages.stage_target_classify import _build_fallback_sse_callback

        callback = _build_fallback_sse_callback()
        response = (
            'data: {"Object":"abc","Choices":[{"Delta":{"Content":"你"}}],'
            '"Id":"chat-1","Model":"example-model-v1"}\n\n'
            'data: {"Object":"abc","Choices":[{"Delta":{"Content":"好"}}],'
            '"Id":"chat-1","Model":"example-model-v1"}\n\n'
            'data: {"Object":"abc","Choices":[{"Delta":{"Content":"呀"}}],'
            '"Id":"chat-1","Model":"example-model-v1"}\n\n'
            'data: {"Object":"abc","Choices":[{"Delta":{"Content":""},"FinishReason":"Stop"}],'
            '"Id":"chat-1","Model":"example-model-v1"}\n\n'
            "data: [DONE]\n\n"
        )
        result = callback(response)
        assert result == "你好呀"

    def test_sse_empty_response(self):
        """空 SSE 响应返回空字符串."""
        from pipeline.stages.stage_target_classify import _build_fallback_sse_callback

        callback = _build_fallback_sse_callback()
        assert callback("") == ""


class TestBurpFallbackJSONCallback:
    """v44.2: _build_fallback_json_callback 测试."""

    def test_json_extraction_camelcase(self):
        """OpenAI camelCase 路径提取."""
        from pipeline.stages.stage_target_classify import _build_fallback_json_callback

        callback = _build_fallback_json_callback("choices[0].message.content")
        response = '{"choices":[{"message":{"content":"Hello"}}]}'
        assert callback(response) == "Hello"

    def test_json_extraction_pascalcase(self):
        """PascalCase 路径提取 (如 Choices[0].Delta.Content)."""
        from pipeline.stages.stage_target_classify import _build_fallback_json_callback

        callback = _build_fallback_json_callback("Choices[0].Delta.Content")
        response = '{"Choices":[{"Delta":{"Content":"Hello"}}]}'
        assert callback(response) == "Hello"

    def test_json_invalid_returns_raw(self):
        """无效 JSON 返回原始响应."""
        from pipeline.stages.stage_target_classify import _build_fallback_json_callback

        callback = _build_fallback_json_callback("choices[0].message.content")
        assert callback("not valid json") == "not valid json"


class TestSafeGet:
    """v44.2: _safe_get 测试."""

    def test_safe_get_nested_dict(self):
        """嵌套字典安全提取."""
        from pipeline.stages.stage_target_classify import _safe_get

        data = {"choices": [{"delta": {"content": "hello"}}]}
        assert _safe_get(data, "choices", 0, "delta", "content") == "hello"

    def test_safe_get_pascalcase(self):
        """PascalCase 嵌套提取."""
        from pipeline.stages.stage_target_classify import _safe_get

        data = {"Choices": [{"Delta": {"Content": "hello"}}]}
        assert _safe_get(data, "Choices", 0, "Delta", "Content") == "hello"

    def test_safe_get_missing_key(self):
        """缺失键返回 None."""
        from pipeline.stages.stage_target_classify import _safe_get

        data = {"choices": [{"delta": {}}]}
        assert _safe_get(data, "choices", 0, "delta", "content") is None

    def test_safe_get_index_error(self):
        """索引越界返回 None."""
        from pipeline.stages.stage_target_classify import _safe_get

        data = {"choices": []}
        assert _safe_get(data, "choices", 0, "delta", "content") is None
