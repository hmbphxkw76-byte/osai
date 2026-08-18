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


# ============================================================
# v44.3: 动态会话ID + SSE路径探测 + Stream:false变体 测试
# ============================================================


class TestDynamicSessionFields:
    """v44.3 P1: _inject_dynamic_session_fields 测试."""

    def test_replace_uuid_chatid(self):
        """UUID 格式的 ChatId 被替换为新 UUID."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_session_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Type: application/json\r\n'
            '\r\n'
            '{"Query":"{PROMPT}",'
            '"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"UserId":"S20240001"}'
        )
        result = _inject_dynamic_session_fields(request)

        # ChatId 应被替换 (原 UUID 不再存在)
        assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in result
        # 新 UUID 应存在
        import re
        uuid_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert uuid_pattern.search(result)

    def test_replace_non_uuid_session_id(self):
        """非 UUID 格式的会话 ID (如学号) 也被替换."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_session_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"Query":"{PROMPT}",'
            '"UserId":"S20240001"}'
        )
        result = _inject_dynamic_session_fields(request)
        # UserId "S20240001" (长度>8) 应被替换
        assert "S20240001" not in result

    def test_no_session_id_unchanged(self):
        """无会话 ID 字段的请求保持不变."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_session_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"message":"{PROMPT}"}'
        )
        result = _inject_dynamic_session_fields(request)
        assert result == request

    def test_short_session_id_not_replaced(self):
        """短于8字符的会话 ID 不被替换 (避免误判)."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_session_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"ChatId":"abc","Query":"{PROMPT}"}'
        )
        result = _inject_dynamic_session_fields(request)
        # "abc" 长度 ≤ 8, 不替换
        assert '"ChatId":"abc"' in result

    def test_multiple_session_fields_replaced(self):
        """多个会话 ID 字段同时被替换."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_session_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"SessionId":"b2c3d4e5-f6a7-8901-bcde-f12345678901",'
            '"Query":"{PROMPT}"}'
        )
        result = _inject_dynamic_session_fields(request)
        assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in result
        assert "b2c3d4e5-f6a7-8901-bcde-f12345678901" not in result

    def test_invalid_json_unchanged(self):
        """无效 JSON 请求体保持不变."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_session_fields

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            "not json"
        )
        result = _inject_dynamic_session_fields(request)
        assert result == request

    def test_prompt_placeholder_preserved(self):
        """{PROMPT} 占位符在替换后保持不变."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_session_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"Query":"{PROMPT}"}'
        )
        result = _inject_dynamic_session_fields(request)
        assert "{PROMPT}" in result


class TestAutoDetectSSEContentPath:
    """v44.3 P2: _auto_detect_sse_content_path 测试."""

    def test_openai_camelcase(self):
        """OpenAI camelCase 格式: choices[0].delta.content."""
        from pipeline.stages.stage_target_classify import _auto_detect_sse_content_path

        sse = 'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
        path = _auto_detect_sse_content_path(sse)
        assert "choices" in path
        assert "delta" in path
        assert "content" in path

    def test_pascalcase_dotnet(self):
        """PascalCase .NET 格式: Choices[0].Delta.Content."""
        from pipeline.stages.stage_target_classify import _auto_detect_sse_content_path

        sse = 'data: {"Choices":[{"Delta":{"Content":"hello"}}]}\n\n'
        path = _auto_detect_sse_content_path(sse)
        assert "Choices" in path
        assert "Delta" in path
        assert "Content" in path

    def test_done_ignored(self):
        """[DONE] 行被跳过."""
        from pipeline.stages.stage_target_classify import _auto_detect_sse_content_path

        sse = 'data: [DONE]\n\ndata: {"choices":[{"delta":{"content":"world"}}]}\n\n'
        path = _auto_detect_sse_content_path(sse)
        assert "choices" in path

    def test_empty_response_default(self):
        """空响应返回默认路径."""
        from pipeline.stages.stage_target_classify import _auto_detect_sse_content_path

        path = _auto_detect_sse_content_path("")
        assert path == "choices[0].delta.content"

    def test_invalid_json_default(self):
        """无效 JSON 返回默认路径."""
        from pipeline.stages.stage_target_classify import _auto_detect_sse_content_path

        sse = "data: not json\n\n"
        path = _auto_detect_sse_content_path(sse)
        assert path == "choices[0].delta.content"

    def test_top_level_content(self):
        """顶层 content 字段."""
        from pipeline.stages.stage_target_classify import _auto_detect_sse_content_path

        sse = 'data: {"content":"hello world"}\n\n'
        path = _auto_detect_sse_content_path(sse)
        assert path == "content"


class TestBuildNonStreamVariant:
    """v44.3 P3: _build_non_stream_variant 测试."""

    def test_stream_true_converted(self):
        """Stream:true 被转换为 Stream:false."""
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Accept: text/event-stream\r\n'
            '\r\n'
            '{"Query":"{PROMPT}","Stream":true}'
        )
        result = _build_non_stream_variant(request)
        assert result is not None
        assert '"Stream": false' in result
        assert "text/event-stream" not in result
        assert "application/json" in result

    def test_stream_false_no_variant(self):
        """Stream:false 不产生变体."""
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"Query":"{PROMPT}","Stream":false}'
        )
        result = _build_non_stream_variant(request)
        assert result is None

    def test_no_stream_field_adds_stream_false(self):
        """v62 P0: 无 Stream 字段时自动添加 stream:false 变体.

        预检探针已确认目标是 SSE, 即使请求体无 stream 字段,
        也应尝试添加 stream:false 构造非流式变体, 避免 ReadTimeout.
        """
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"Query":"{PROMPT}"}'
        )
        result = _build_non_stream_variant(request)
        # v62: 现在返回非流式变体 (添加了 stream:false)
        assert result is not None
        assert "stream" in result.lower()
        assert "false" in result.lower()

    def test_lowercase_stream_field(self):
        """小写 stream 字段也支持."""
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"query":"{PROMPT}","stream":true}'
        )
        result = _build_non_stream_variant(request)
        assert result is not None
        assert '"stream": false' in result

    def test_prompt_preserved_in_variant(self):
        """{PROMPT} 占位符在变体中保持不变."""
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"Query":"{PROMPT}","Stream":true}'
        )
        result = _build_non_stream_variant(request)
        assert result is not None
        assert "{PROMPT}" in result

    def test_invalid_json_no_variant(self):
        """无效 JSON 不产生变体."""
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            "not json"
        )
        result = _build_non_stream_variant(request)
        assert result is None


class TestInjectDynamicFields:
    """v44.3 P4: _inject_dynamic_fields 测试."""

    def test_auto_replace_session_ids(self):
        """自动替换会话 ID 字段."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"Query":"{PROMPT}"}'
        )
        result = _inject_dynamic_fields(request)
        assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in result

    def test_custom_field_overrides(self):
        """自定义字段覆盖."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"CustomField":"original",'
            '"Query":"{PROMPT}"}'
        )
        result = _inject_dynamic_fields(
            request,
            field_overrides={"CustomField": "overridden"},
        )
        assert '"CustomField": "overridden"' in result

    def test_prompt_placeholder_preserved(self):
        """{PROMPT} 占位符保留."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_fields

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"Query":"{PROMPT}"}'
        )
        result = _inject_dynamic_fields(request)
        assert "{PROMPT}" in result

    def test_no_body_unchanged(self):
        """无请求体保持不变."""
        from pipeline.stages.stage_target_classify import _inject_dynamic_fields

        request = "POST /api/chat HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = _inject_dynamic_fields(request)
        assert result == request


class TestGenerateSessionUUID:
    """v44.3: _generate_session_uuid 测试."""

    def test_generates_valid_uuid(self):
        """生成有效的 UUID v4."""
        import re

        from pipeline.stages.stage_target_classify import _generate_session_uuid

        result = _generate_session_uuid()
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert uuid_pattern.match(result)

    def test_generates_unique_uuids(self):
        """连续生成的 UUID 不重复."""
        from pipeline.stages.stage_target_classify import _generate_session_uuid

        uuids = {_generate_session_uuid() for _ in range(100)}
        assert len(uuids) == 100


# ============================================================
# v44.4: Content-Length修正 + Stream:false回退 + 预检探针 + 多文件轮转
# ============================================================


class TestFixContentLength:
    """v44.4 P4: _fix_content_length 测试."""

    def test_update_existing_content_length(self):
        """更新已存在的 Content-Length."""
        from pipeline.stages.stage_target_classify import _fix_content_length

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 10\r\n"
            "\r\n"
            '{"a":"bcdefghi"}'
        )
        result = _fix_content_length(request)
        # 新 body 长度 = 16 字节
        assert "Content-Length: 16" in result

    def test_add_missing_content_length(self):
        """添加缺失的 Content-Length."""
        from pipeline.stages.stage_target_classify import _fix_content_length

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"query":"hello"}'
        )
        result = _fix_content_length(request)
        assert "Content-Length:" in result
        # body 长度 = 17 字节
        assert "Content-Length: 17" in result

    def test_no_body_unchanged(self):
        """无 body 时添加 Content-Length: 0 (RFC 7230 标准行为)."""
        from pipeline.stages.stage_target_classify import _fix_content_length

        request = "POST /api/chat HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = _fix_content_length(request)
        # 无 body 时添加 Content-Length: 0 (RFC 7230 Section 3.3.2)
        assert "Content-Length: 0" in result

    def test_unicode_body_length(self):
        """Unicode body 按字节计算长度."""
        from pipeline.stages.stage_target_classify import _fix_content_length

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 1\r\n"
            "\r\n"
            '{"msg":"你好"}'
        )
        result = _fix_content_length(request)
        # "你好" 是 6 字节 (UTF-8), 总 body = 16 字节
        body = '{"msg":"你好"}'
        expected_len = len(body.encode("utf-8"))
        assert f"Content-Length: {expected_len}" in result

    def test_content_length_after_dynamic_injection(self):
        """动态注入后 Content-Length 被修正."""
        from pipeline.stages.stage_target_classify import (
            _fix_content_length,
            _inject_dynamic_session_fields,
        )

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Content-Length: 100\r\n'
            '\r\n'
            '{"ChatId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890",'
            '"Query":"{PROMPT}"}'
        )
        # 动态注入会改变 body 长度
        injected = _inject_dynamic_session_fields(request)
        # 修正 Content-Length
        fixed = _fix_content_length(injected)
        # 验证 Content-Length 已更新 (不再是 100)
        assert "Content-Length: 100" not in fixed


class TestStreamFalseFallback:
    """v44.4 P1: Stream:false 回退 Target 注册测试."""

    def test_sse_fallback_registered_in_metadata(self):
        """验证 SSE 回退 Target 的 metadata 标志存在 (逻辑测试)."""
        # 此测试验证函数逻辑: _build_non_stream_variant 返回非 None
        # 则 _bridge_burp_api 应设置 burp_sse_fallback_registered=True
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            'Accept: text/event-stream\r\n'
            '\r\n'
            '{"Query":"{PROMPT}","Stream":true}'
        )
        variant = _build_non_stream_variant(request)
        assert variant is not None
        # 如果 variant 存在, 则 _bridge_burp_api 会注册 SSE 回退 Target

    def test_no_fallback_when_not_sse(self):
        """v62 P0: 非 SSE 请求不产生回退 Target.

        注意: _build_non_stream_variant 现在会在无 stream 字段时
        添加 stream:false 变体, 但此变体仅在 is_sse=True 时被使用.
        此测试验证函数本身的行为, 非SSE的判断由调用处控制.
        """
        from pipeline.stages.stage_target_classify import _build_non_stream_variant

        request = (
            'POST /api/chat HTTP/1.1\r\n'
            'Host: example.com\r\n'
            '\r\n'
            '{"Query":"{PROMPT}"}'
        )
        # v62: 现在返回非流式变体 (添加了 stream:false)
        variant = _build_non_stream_variant(request)
        assert variant is not None
        assert "stream" in variant.lower()


class TestParseBurpRequestFiles:
    """v44.4 P3: _parse_burp_request_files 测试."""

    def test_single_file(self):
        """单文件解析."""
        from pipeline.stages.stage_target_classify import _parse_burp_request_files

        result = _parse_burp_request_files("data/burp/request.txt")
        assert result == ["data/burp/request.txt"]

    def test_multiple_files(self):
        """多文件解析 (逗号分隔)."""
        from pipeline.stages.stage_target_classify import _parse_burp_request_files

        result = _parse_burp_request_files("file1.txt,file2.txt,file3.txt")
        assert len(result) == 3
        assert "file1.txt" in result
        assert "file2.txt" in result
        assert "file3.txt" in result

    def test_empty_arg(self):
        """空参数返回空列表."""
        from pipeline.stages.stage_target_classify import _parse_burp_request_files

        assert _parse_burp_request_files("") == []
        assert _parse_burp_request_files(None) == []  # type: ignore[arg-type]

    def test_whitespace_trimmed(self):
        """空格被去除."""
        from pipeline.stages.stage_target_classify import _parse_burp_request_files

        result = _parse_burp_request_files(" file1.txt , file2.txt ")
        assert result == ["file1.txt", "file2.txt"]

    def test_trailing_comma_ignored(self):
        """末尾逗号被忽略."""
        from pipeline.stages.stage_target_classify import _parse_burp_request_files

        result = _parse_burp_request_files("file1.txt,file2.txt,")
        assert len(result) == 2


class TestBurpPreFlightProbe:
    """v44.4 P2: _burp_pre_flight_probe 测试."""

    @pytest.mark.asyncio
    async def test_probe_returns_defaults_on_error(self):
        """连接失败时返回默认值."""
        from pipeline.stages.stage_target_classify import _burp_pre_flight_probe

        result = await _burp_pre_flight_probe(
            raw_request="POST /api HTTP/1.1\r\nHost: nonexistent.invalid\r\n\r\n{}",
            target_url="https://nonexistent.invalid",
            use_tls=True,
        )
        # 失败时返回默认值
        assert "is_sse" in result
        assert "response_path" in result
        assert "stream_false_supported" in result
        # 连接失败时 is_sse=False
        assert result["is_sse"] is False

    @pytest.mark.asyncio
    async def test_probe_json_response(self):
        """JSON 响应被正确探测 (使用 mock)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from pipeline.stages.stage_target_classify import _burp_pre_flight_probe

        # Mock httpx.AsyncClient — code uses client.stream() not client.request()
        mock_response = MagicMock()
        mock_response.headers = {"content-type": "application/json"}
        mock_response.text = '{"choices":[{"message":{"content":"hello"}}]}'
        mock_response.aread = AsyncMock(return_value=b'{"choices":[{"message":{"content":"hello"}}]}')

        mock_stream_cm = MagicMock()
        mock_stream_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_stream_cm.__aexit__ = AsyncMock(return_value=None)

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.stream = MagicMock(return_value=mock_stream_cm)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await _burp_pre_flight_probe(
                raw_request=(
                    'POST /v1/chat HTTP/1.1\r\n'
                    'Host: api.example.com\r\n'
                    '\r\n'
                    '{"Query":"{PROMPT}"}'
                ),
                target_url="https://api.example.com",
                use_tls=True,
            )

        assert result["is_sse"] is False
        assert result["stream_false_supported"] is True
        path = result["response_path"]
        assert "choices" in path or "message" in path or "content" in path

    @pytest.mark.asyncio
    async def test_probe_sse_response(self):
        """SSE 响应被正确探测 (使用 mock)."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from pipeline.stages.stage_target_classify import _burp_pre_flight_probe

        mock_response = MagicMock()
        mock_response.headers = {"content-type": "text/event-stream"}
        mock_response.text = (
            'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
            'data: [DONE]\n\n'
        )
        # SSE code uses aiter_text() — mock as async iterator
        async def _mock_aiter_text():
            yield 'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
            yield "data: [DONE]\n\n"
        mock_response.aiter_text = _mock_aiter_text

        mock_stream_cm = MagicMock()
        mock_stream_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_stream_cm.__aexit__ = AsyncMock(return_value=None)

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.stream = MagicMock(return_value=mock_stream_cm)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await _burp_pre_flight_probe(
                raw_request=(
                    'POST /v1/chat HTTP/1.1\r\n'
                    'Host: api.example.com\r\n'
                    'Accept: text/event-stream\r\n'
                    '\r\n'
                    '{"Query":"{PROMPT}","Stream":true}'
                ),
                target_url="https://api.example.com",
                use_tls=True,
            )

        assert result["is_sse"] is True
        assert "choices" in result["response_path"] or "delta" in result["response_path"]


# ============================================================
# v44.5: 自动 {PROMPT} 注入 + Burp 请求文件自动发现
# ============================================================


class TestAutoPromptInjection:
    """v44.5 P1: enhance_burp_request 自动注入 {PROMPT} 测试."""

    def test_inject_into_openai_messages_format(self):
        """OpenAI messages 格式自动注入."""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = (
            "POST /v1/chat/completions HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"hello world"}]}'
        )
        result = enhance_burp_request(raw_request)
        assert "{PROMPT}" in result

    def test_inject_into_simple_prompt_field(self):
        """简单 prompt 字段自动注入."""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"introduce yourself"}'
        )
        result = enhance_burp_request(raw_request)
        assert "{PROMPT}" in result
        # 原始 prompt 值应被替换
        assert "introduce yourself" not in result

    def test_inject_into_query_field(self):
        """Query 字段自动注入 (常见非标准 API)."""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = (
            "POST /api/labs/PI_01/chat HTTP/1.1\r\n"
            "Host: 127.0.0.1:8080\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"introduce yourself"}'
        )
        result = enhance_burp_request(raw_request)
        assert "{PROMPT}" in result

    def test_no_inject_when_prompt_exists(self):
        """已有 {PROMPT} 时不重复注入."""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"messages":[{"role":"user","content":"{PROMPT}"}]}'
        )
        result = enhance_burp_request(raw_request)
        # 只应有一个 {PROMPT}
        assert result.count("{PROMPT}") == 1

    def test_auth_headers_injected(self):
        """认证 headers 被注入到请求头."""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"hello"}'
        )
        result = enhance_burp_request(
            raw_request,
            auth_headers={"Authorization": "Bearer test-token-123"},
        )
        assert "Authorization: Bearer test-token-123" in result

    def test_auth_headers_not_duplicated(self):
        """已有 Authorization 时不重复添加."""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer existing-token\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"hello"}'
        )
        result = enhance_burp_request(
            raw_request,
            auth_headers={"Authorization": "Bearer new-token"},
        )
        # 原有 Authorization 不被覆盖
        assert "existing-token" in result
        assert "new-token" not in result

    def test_real_burp_request_file_format(self):
        """真实 Burp 导出请求文件格式 (无 {PROMPT}) 自动注入."""
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        # 模拟真实 Burp 导出的请求 (如 data/burp/request.txt)
        raw_request = (
            "POST /api/labs/PI_01/chat HTTP/1.1\r\n"
            "Host: 127.0.0.1:8080\r\n"
            "Content-Length: 31\r\n"
            "Content-Type: application/json\r\n"
            "Accept: */*\r\n"
            "Origin: http://127.0.0.1:8080\r\n"
            "Referer: http://127.0.0.1:8080/labs/PI_01\r\n"
            "\r\n"
            '{\n  "prompt":"introduce yourself"\n}'
        )
        result = enhance_burp_request(raw_request)
        assert "{PROMPT}" in result


class TestBurpFileAutoDiscovery:
    """v44.5 P2: _discover_burp_request_file 自动发现测试."""

    def test_exact_host_port_match(self, tmp_path, monkeypatch):
        """精确匹配 {host}_{port}_request.txt."""
        from pipeline.stages.stage_target_classify import _discover_burp_request_file

        # 创建临时 data/burp/ 目录
        burp_dir = tmp_path / "data" / "burp"
        burp_dir.mkdir(parents=True)
        req_file = burp_dir / "127.0.0.1_8080_request.txt"
        req_file.write_text("POST /api HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n", encoding="utf-8")

        # 切换工作目录到 tmp_path
        monkeypatch.chdir(tmp_path)

        result = _discover_burp_request_file("http://127.0.0.1:8080/api/chat")
        assert result is not None
        assert "127.0.0.1_8080_request.txt" in result

    def test_host_wildcard_match(self, tmp_path, monkeypatch):
        """Host 通配匹配 {host}_*_request.txt (不同端口)."""
        from pipeline.stages.stage_target_classify import _discover_burp_request_file

        burp_dir = tmp_path / "data" / "burp"
        burp_dir.mkdir(parents=True)
        # 已有 8080 端口文件, 但目标端口不同 (8081)
        req_file = burp_dir / "127.0.0.1_8080_request.txt"
        req_file.write_text("POST /api HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n", encoding="utf-8")

        monkeypatch.chdir(tmp_path)

        result = _discover_burp_request_file("http://127.0.0.1:8081/api/chat")
        # 精确匹配不存在, 但通配匹配应找到
        assert result is not None
        assert "127.0.0.1_8080_request.txt" in result

    def test_host_no_port_match(self, tmp_path, monkeypatch):
        """Host 无端口匹配 {host}_request.txt."""
        from pipeline.stages.stage_target_classify import _discover_burp_request_file

        burp_dir = tmp_path / "data" / "burp"
        burp_dir.mkdir(parents=True)
        req_file = burp_dir / "example.com_request.txt"
        req_file.write_text("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")

        monkeypatch.chdir(tmp_path)

        result = _discover_burp_request_file("https://example.com/api/chat")
        assert result is not None
        assert "example.com_request.txt" in result

    def test_default_request_txt_fallback(self, tmp_path, monkeypatch):
        """默认 request.txt 兜底."""
        from pipeline.stages.stage_target_classify import _discover_burp_request_file

        burp_dir = tmp_path / "data" / "burp"
        burp_dir.mkdir(parents=True)
        req_file = burp_dir / "request.txt"
        req_file.write_text("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")

        monkeypatch.chdir(tmp_path)

        result = _discover_burp_request_file("https://unknown.com/api/chat")
        assert result is not None
        assert "request.txt" in result

    def test_no_burp_dir_returns_none(self, tmp_path, monkeypatch):
        """data/burp/ 目录不存在时返回 None."""
        from pipeline.stages.stage_target_classify import _discover_burp_request_file

        monkeypatch.chdir(tmp_path)

        result = _discover_burp_request_file("http://127.0.0.1:8080/api/chat")
        assert result is None

    def test_no_matching_file_returns_none(self, tmp_path, monkeypatch):
        """无匹配文件时返回 None (有目录但无文件)."""
        from pipeline.stages.stage_target_classify import _discover_burp_request_file

        burp_dir = tmp_path / "data" / "burp"
        burp_dir.mkdir(parents=True)

        monkeypatch.chdir(tmp_path)

        result = _discover_burp_request_file("http://127.0.0.1:8080/api/chat")
        assert result is None

    def test_priority_exact_over_default(self, tmp_path, monkeypatch):
        """精确匹配优先于默认 request.txt."""
        from pipeline.stages.stage_target_classify import _discover_burp_request_file

        burp_dir = tmp_path / "data" / "burp"
        burp_dir.mkdir(parents=True)
        # 同时存在精确匹配和默认文件
        exact_file = burp_dir / "127.0.0.1_8080_request.txt"
        exact_file.write_text("exact", encoding="utf-8")
        default_file = burp_dir / "request.txt"
        default_file.write_text("default", encoding="utf-8")

        monkeypatch.chdir(tmp_path)

        result = _discover_burp_request_file("http://127.0.0.1:8080/api/chat")
        assert result is not None
        assert "127.0.0.1_8080_request.txt" in result
        assert "request.txt" not in result.split("/")[-1] or "127.0.0.1_8080_request.txt" in result


# ============================================================
# v44.6: 请求体字段名自动发现 + Offensive Profile
# ============================================================


class TestDiscoverPromptField:
    """v44.6: _discover_prompt_field 自动发现 prompt 字段测试."""

    def test_standard_prompt_field(self):
        """标准 prompt 字名."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {"prompt": "hello world", "model": "gpt-4"}
        result = _discover_prompt_field(data)
        assert result == "prompt"

    def test_non_standard_field_name(self):
        """非标准字段名 (userInput)."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {"userInput": "tell me a joke", "model": "gpt-4"}
        result = _discover_prompt_field(data)
        assert result == "userInput"

    def test_case_insensitive_match(self):
        """大小写不敏感匹配 (PascalCase Query)."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {"Query": "what is AI?", "Model": "gpt-4"}
        result = _discover_prompt_field(data)
        assert result == "Query"

    def test_nested_inputs_query(self):
        """嵌套结构 Inputs.Query (真实 Burp 请求)."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {
            "Inputs": {
                "stuNo": "S20240001",
                "CourseName": "CS101",
            },
            "Stream": True,
            "Query": "introduce yourself",
            "ChatId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        }
        result = _discover_prompt_field(data)
        assert result == "Query"

    def test_nested_inputs_with_prompt_inside(self):
        """嵌套结构 — prompt 在嵌套 dict 内."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {
            "model": "gpt-4",
            "inputs": {"prompt": "hello world"},
        }
        result = _discover_prompt_field(data)
        assert result is not None
        assert "prompt" in result

    def test_heuristic_single_string_field(self):
        """启发式 — 唯一字符串字段被识别."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {"question": "what is 2+2?", "count": 42, "enabled": True}
        result = _discover_prompt_field(data)
        assert result == "question"

    def test_heuristic_longest_string_field(self):
        """启发式 — 多字符串字段选值最长的."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {
            "name": "ab",
            "description": "This is a very long description that should be selected as the most likely prompt field",
        }
        result = _discover_prompt_field(data)
        assert result == "description"

    def test_no_string_field_returns_none(self):
        """无字符串字段返回 None."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {"count": 42, "enabled": True, "ratio": 0.5}
        result = _discover_prompt_field(data)
        assert result is None

    def test_short_string_ignored(self):
        """短于 3 字符的字符串字段被忽略."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {"ab": "hi", "model": "gpt-4"}
        # "hi" 长度 2, 被 < 3 条件过滤; "gpt-4" 长度 5, 应被选中
        result = _discover_prompt_field(data)
        assert result == "model"

    def test_numeric_string_ignored(self):
        """纯数字字符串被忽略."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {"id": "12345", "question": "what is AI?"}
        result = _discover_prompt_field(data)
        assert result == "question"

    def test_real_burp_request_body(self):
        """真实 Burp 导出请求体格式."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        # 模拟真实 data/burp/request.txt 的 body
        data = {"prompt": "introduce yourself"}
        result = _discover_prompt_field(data)
        assert result == "prompt"

    def test_complex_nested_with_session_fields(self):
        """复杂嵌套结构 (含会话字段)."""
        from pipeline.integrations.recon_target_bridge import _discover_prompt_field

        data = {
            "Inputs": {"stuNo": "S20240001", "CourseName": ""},
            "Stream": True,
            "Query": "introduce yourself",
            "ChatId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "UserId": "S20240001",
        }
        result = _discover_prompt_field(data)
        # Query 是已知字段名, 应被直接匹配
        assert result == "Query"


class TestInjectPromptPlaceholderV446:
    """v44.6: _inject_prompt_placeholder 非标准字段名注入测试."""

    def test_inject_into_user_input(self):
        """非标准字段名 userInput 自动注入."""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"userInput":"hello world","model":"gpt-4"}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result
        assert "hello world" not in result

    def test_inject_into_question(self):
        """非标准字段名 question 自动注入."""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"question":"what is AI?"}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result

    def test_inject_into_nested_inputs_prompt(self):
        """嵌套结构 inputs.prompt 自动注入."""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"model":"gpt-4","inputs":{"prompt":"hello world"}}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result

    def test_inject_into_pascalcase_query(self):
        """PascalCase Query 字段自动注入 (真实 Burp 请求格式)."""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"Inputs":{"stuNo":"S20240001"},"Query":"introduce yourself","Stream":true}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result
        assert "introduce yourself" not in result

    def test_inject_heuristic_unknown_field(self):
        """启发式 — 未知字段名也能注入."""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{"customPromptField":"tell me about security"}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result

    def test_inject_real_burp_file_format(self):
        """真实 Burp 导出文件格式 (多行 JSON)."""
        from pipeline.integrations.recon_target_bridge import _inject_prompt_placeholder

        body = '{\n  "prompt":"introduce yourself"\n}'
        result = _inject_prompt_placeholder(body, "application/json")
        assert "{PROMPT}" in result


class TestOffensiveProfile:
    """v44.6: --offensive-profile 参数预设测试."""

    def test_offensive_profile_default_false(self, monkeypatch):
        """--offensive-profile 默认为 False."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", ["main"])
        args = parse_args()
        assert args.offensive_profile is False

    def test_offensive_profile_enabled(self, monkeypatch):
        """--offensive-profile 可以被启用."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
        ])
        args = parse_args()
        assert args.offensive_profile is True

    def test_offensive_profile_sets_max_attempts(self, monkeypatch):
        """启用后 max_attempts 被设为 3."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
        ])
        args = parse_args()
        assert args.max_attempts == 3

    def test_offensive_profile_sets_max_concurrency(self, monkeypatch):
        """启用后 max_concurrency 被设为 3."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
        ])
        args = parse_args()
        assert args.max_concurrency == 3

    def test_offensive_profile_sets_epsilon_decay(self, monkeypatch):
        """启用后 epsilon_decay 被设为 True."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
        ])
        args = parse_args()
        assert args.epsilon_decay is True

    def test_offensive_profile_sets_converters(self, monkeypatch):
        """启用后 converters 被注入 15 个 Converter."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
        ])
        args = parse_args()
        assert args.converters is not None
        assert len(args.converters) == 15
        assert "rot13" in args.converters
        assert "base64" in args.converters

    def test_offensive_profile_sets_html_report(self, monkeypatch):
        """启用后 html_report 被设为 True."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
        ])
        args = parse_args()
        assert args.html_report is True

    def test_offensive_profile_sets_analyze(self, monkeypatch):
        """启用后 analyze 被设为 True."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
        ])
        args = parse_args()
        assert args.analyze is True

    def test_offensive_profile_user_override_max_attempts(self, monkeypatch):
        """用户显式指定 --max-attempts 覆盖预设值."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
            "--max-attempts", "5",
        ])
        args = parse_args()
        assert args.max_attempts == 5

    def test_offensive_profile_user_override_converters(self, monkeypatch):
        """用户显式指定 --converters 覆盖预设值."""
        from pipeline.config import parse_args

        monkeypatch.setattr("sys.argv", [
            "main",
            "--target-url", "http://127.0.0.1:8080/api/chat",
            "--offensive-profile",
            "--converters", "rot13", "base64",
        ])
        args = parse_args()
        assert args.converters == ["rot13", "base64"]
