"""Recon 模块测试 — burp_parser, auth_bridge。

覆盖:
    - Burp 请求解析 (method, url, headers, body, SSE, placeholder, fingerprint)
    - TLS 推断
    - URL 构建
    - {PROMPT} 占位符注入 (JSON field, messages array, default)
    - 目标指纹提取 (framework, auth, app_type)
    - HTTP 请求重建 (CRLF, Content-Length)
    - SSE 回调解析 (标准 SSE, OpenAI 兼容, 纯 JSON, 空响应)
    - JSON 路径推断
    - 语言检测
    - JSONSafeHTTPTarget JSON 安全注入
    - 认证状态加载 + Cookie/Bearer/自定义 header 注入
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# burp_parser: _parse_raw_http
# ═══════════════════════════════════════════════════════


class TestParseRawHttp:
    """测试 _parse_raw_http — 原始 HTTP 请求解析."""

    def test_basic_post_request(self):
        """解析基本 POST 请求."""
        from pipeline.recon.burp_parser import _parse_raw_http

        raw = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        parsed = _parse_raw_http(raw)
        assert parsed.method == "POST"
        assert parsed.path == "/api/chat"
        assert parsed.http_version == "HTTP/1.1"
        assert parsed.host == "localhost"
        assert parsed.body == '{"prompt":"{PROMPT}"}'
        assert parsed.has_prompt_placeholder is True

    def test_get_request_without_body(self):
        """GET 请求无 body."""
        from pipeline.recon.burp_parser import _parse_raw_http

        raw = "GET /api/info HTTP/1.1\r\nHost: localhost\r\n\r\n"
        parsed = _parse_raw_http(raw)
        assert parsed.method == "GET"
        assert parsed.body == ""
        assert parsed.has_prompt_placeholder is False

    def test_invalid_request_line_raises(self):
        """无效请求行抛出 ValueError."""
        from pipeline.recon.burp_parser import _parse_raw_http

        with pytest.raises(ValueError, match="Invalid HTTP request line"):
            _parse_raw_http("INVALID LINE\r\n\r\n")

    def test_headers_preserved_with_case(self):
        """Header 大小写保留."""
        from pipeline.recon.burp_parser import _parse_raw_http

        raw = (
            "POST /api HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        parsed = _parse_raw_http(raw)
        assert len(parsed.raw_headers) == 2
        assert parsed.raw_headers[0] == ("Host", "localhost")
        assert parsed.raw_headers[1] == ("Content-Type", "application/json")
        # headers dict 使用小写 key
        assert parsed.headers["host"] == "localhost"
        assert parsed.headers["content-type"] == "application/json"

    def test_sse_detection_from_accept_header(self):
        """从 Accept header 检测 SSE."""
        from pipeline.recon.burp_parser import _parse_raw_http

        raw = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Accept: text/event-stream\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        parsed = _parse_raw_http(raw)
        assert parsed.is_sse is True

    def test_sse_detection_from_body_stream_flag(self):
        """从 body stream:true 检测 SSE."""
        from pipeline.recon.burp_parser import _parse_raw_http

        raw = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}","stream":true}'
        )
        parsed = _parse_raw_http(raw)
        assert parsed.is_sse is True

    def test_non_sse_request(self):
        """非 SSE 请求."""
        from pipeline.recon.burp_parser import _parse_raw_http

        raw = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Accept: */*\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        parsed = _parse_raw_http(raw)
        assert parsed.is_sse is False


# ═══════════════════════════════════════════════════════
# burp_parser: TLS 推断
# ═══════════════════════════════════════════════════════


class TestInferTls:
    """测试 _infer_tls."""

    def test_https_scheme(self):
        from pipeline.recon.burp_parser import _infer_tls

        assert _infer_tls("https://example.com/api", {}) is True

    def test_http_scheme(self):
        from pipeline.recon.burp_parser import _infer_tls

        assert _infer_tls("http://example.com/api", {}) is False

    def test_localhost_no_tls(self):
        from pipeline.recon.burp_parser import _infer_tls

        assert _infer_tls("/api/chat", {"host": "localhost"}) is False

    def test_127_0_0_1_no_tls(self):
        from pipeline.recon.burp_parser import _infer_tls

        assert _infer_tls("/api/chat", {"host": "127.0.0.1:8080"}) is False

    def test_remote_host_defaults_tls(self):
        from pipeline.recon.burp_parser import _infer_tls

        assert _infer_tls("/api/chat", {"host": "api.example.com"}) is True

    def test_x_forwarded_proto_https(self):
        from pipeline.recon.burp_parser import _infer_tls

        assert _infer_tls("/api/chat", {"host": "proxy.local", "x-forwarded-proto": "https"}) is True

    def test_x_forwarded_proto_http(self):
        from pipeline.recon.burp_parser import _infer_tls

        assert _infer_tls("/api/chat", {"host": "proxy.local", "x-forwarded-proto": "http"}) is False


# ═══════════════════════════════════════════════════════
# burp_parser: URL 构建
# ═══════════════════════════════════════════════════════


class TestBuildFullUrl:
    """测试 _build_full_url."""

    def test_https_url(self):
        from pipeline.recon.burp_parser import _build_full_url

        assert _build_full_url("https://example.com/api", "example.com", True) == "https://example.com/api"

    def test_http_url(self):
        from pipeline.recon.burp_parser import _build_full_url

        assert _build_full_url("/api/chat", "localhost", False) == "http://localhost/api/chat"

    def test_https_url_from_tls(self):
        from pipeline.recon.burp_parser import _build_full_url

        assert _build_full_url("/api/chat", "api.example.com", True) == "https://api.example.com/api/chat"


# ═══════════════════════════════════════════════════════
# burp_parser: {PROMPT} 占位符注入
# ═══════════════════════════════════════════════════════


class TestInjectPlaceholder:
    """测试 _inject_placeholder."""

    def test_inject_into_prompt_field(self):
        from pipeline.recon.burp_parser import _inject_placeholder

        body = json.dumps({"prompt": "hello"})
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_inject_into_message_field(self):
        from pipeline.recon.burp_parser import _inject_placeholder

        body = json.dumps({"message": "hello"})
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["message"] == "{PROMPT}"

    def test_inject_into_messages_array(self):
        from pipeline.recon.burp_parser import _inject_placeholder

        body = json.dumps({"messages": [{"role": "user", "content": "hello"}]})
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["messages"][-1]["content"] == "{PROMPT}"

    def test_inject_default_prompt_field(self):
        from pipeline.recon.burp_parser import _inject_placeholder

        body = json.dumps({"unrelated": "value"})
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_non_json_body_returns_original(self):
        from pipeline.recon.burp_parser import _inject_placeholder

        body = "plain text body"
        result = _inject_placeholder(body)
        assert result == body


# ═══════════════════════════════════════════════════════
# burp_parser: 目标指纹提取
# ═══════════════════════════════════════════════════════


class TestExtractFingerprint:
    """测试 _extract_fingerprint."""

    def test_nextjs_framework(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({"server": "Next.js"}, "/api/chat", "localhost")
        assert fp["framework"] == "Next.js"

    def test_express_framework(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({"x-powered-by": "Express"}, "/api/chat", "localhost")
        assert fp["framework"] == "Express.js"

    def test_fastapi_framework(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({"server": "FastAPI"}, "/api/chat", "localhost")
        assert fp["framework"] == "FastAPI"

    def test_django_framework(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({"x-powered-by": "Django"}, "/api/chat", "localhost")
        assert fp["framework"] == "Django"

    def test_unknown_framework(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({}, "/api/chat", "localhost")
        assert fp["framework"] == "Unknown"

    def test_bearer_auth(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({"authorization": "Bearer token123"}, "/api/chat", "localhost")
        assert fp["auth_type"] == "Bearer Token"

    def test_basic_auth(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({"authorization": "Basic dXNlcjpwYXNz"}, "/api/chat", "localhost")
        assert fp["auth_type"] == "Basic Auth"

    def test_cookie_auth(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({"cookie": "session=abc"}, "/api/chat", "localhost")
        assert fp["auth_type"] == "Cookie-based"

    def test_no_auth(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({}, "/api/chat", "localhost")
        assert fp["auth_type"] == "None"

    def test_testing_app_type(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({}, "/challenges/IT_02/chat", "target.example.com")
        assert fp["app_type"] == "Testing/Arena"

    def test_chat_app_type(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({}, "/api/chat", "localhost")
        assert fp["app_type"] == "Chat Application"

    def test_agent_app_type(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({}, "/api/agent/run", "localhost")
        assert fp["app_type"] == "Agent Application"

    def test_rag_app_type(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({}, "/api/rag/knowledge", "localhost")
        assert fp["app_type"] == "RAG Application"

    def test_web_app_type(self):
        from pipeline.recon.burp_parser import _extract_fingerprint

        fp = _extract_fingerprint({}, "/api/info", "localhost")
        assert fp["app_type"] == "Web Application"


# ═══════════════════════════════════════════════════════
# burp_parser: HTTP 请求重建
# ═══════════════════════════════════════════════════════


class TestBuildRawHttpRequest:
    """测试 build_raw_http_request."""

    def test_rebuild_basic_request(self):
        from pipeline.recon.burp_parser import ParsedBurpRequest, build_raw_http_request

        parsed = ParsedBurpRequest(
            method="POST",
            url="http://localhost/api/chat",
            host="localhost",
            path="/api/chat",
            headers={"host": "localhost", "content-type": "application/json"},
            raw_headers=[("Host", "localhost"), ("Content-Type", "application/json")],
            body='{"prompt":"hello"}',
        )
        result = build_raw_http_request(parsed)
        assert "POST /api/chat HTTP/1.1" in result
        assert "Host: localhost" in result
        assert "Content-Type: application/json" in result
        assert "Content-Length:" in result
        assert '{"prompt":"hello"}' in result

    def test_rebuild_skips_existing_content_length(self):
        from pipeline.recon.burp_parser import ParsedBurpRequest, build_raw_http_request

        parsed = ParsedBurpRequest(
            method="POST",
            url="http://localhost/api",
            host="localhost",
            path="/api",
            raw_headers=[("Host", "localhost"), ("Content-Length", "100")],
            body='{"prompt":"hello"}',
        )
        result = build_raw_http_request(parsed)
        # Original Content-Length should be removed, new one added
        assert result.count("Content-Length:") == 1

    def test_rebuild_no_body(self):
        from pipeline.recon.burp_parser import ParsedBurpRequest, build_raw_http_request

        parsed = ParsedBurpRequest(
            method="GET",
            url="http://localhost/api",
            host="localhost",
            path="/api",
            raw_headers=[("Host", "localhost")],
            body="",
        )
        result = build_raw_http_request(parsed)
        assert "GET /api HTTP/1.1" in result
        assert "Content-Length:" not in result


# ═══════════════════════════════════════════════════════
# burp_parser: SSE 回调解析
# ═══════════════════════════════════════════════════════


class TestSseCallback:
    """测试 SSE 回调解析."""

    def test_standard_sse_response(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = (
            'data: {"content": "Hello"}\n\n'
            'data: {"content": " world"}\n\n'
        )
        result = callback(response)
        assert result == "Hello world"

    def test_openai_compatible_sse(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = (
            'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":" world"}}]}\n\n'
            'data: [DONE]\n\n'
        )
        result = callback(response)
        assert result == "Hello world"

    def test_done_marker_skipped(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = 'data: [DONE]\n\ndata: {"content": "OK"}\n\n'
        result = callback(response)
        assert result == "OK"

    def test_stop_marker_skipped(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = 'data: [STOP]\n\ndata: {"content": "OK"}\n\n'
        result = callback(response)
        assert result == "OK"

    def test_empty_response(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = ""
        result = callback(response)
        assert result == ""

    def test_whitespace_only_response(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = "   \n  \n  "
        result = callback(response)
        assert result == ""

    def test_bytes_content(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = None
        response.content = b'data: {"content": "hello"}\n\n'
        result = callback(response)
        assert result == "hello"

    def test_non_sse_json_fallback(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = '{"content": "direct json response"}'
        result = callback(response)
        assert "direct json response" in result

    def test_answer_path(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = 'data: {"answer": "the answer"}\n\n'
        result = callback(response)
        assert result == "the answer"

    def test_response_path(self):
        from pipeline.recon.burp_parser import _make_sse_callback

        callback = _make_sse_callback()
        response = MagicMock()
        response.text = 'data: {"response": "the response"}\n\n'
        result = callback(response)
        assert result == "the response"


# ═══════════════════════════════════════════════════════
# burp_parser: _extract_nested
# ═══════════════════════════════════════════════════════


class TestExtractNested:
    """测试 _extract_nested."""

    def test_dict_single_key(self):
        from pipeline.recon.burp_parser import _extract_nested

        assert _extract_nested({"a": 1}, "a") == 1

    def test_dict_nested_keys(self):
        from pipeline.recon.burp_parser import _extract_nested

        assert _extract_nested({"a": {"b": 2}}, "a", "b") == 2

    def test_list_index(self):
        from pipeline.recon.burp_parser import _extract_nested

        assert _extract_nested([10, 20, 30], 1) == 20

    def test_nested_dict_list(self):
        from pipeline.recon.burp_parser import _extract_nested

        assert _extract_nested({"choices": [{"delta": {"content": "hi"}}]}, "choices", 0, "delta", "content") == "hi"

    def test_key_not_found_returns_none(self):
        from pipeline.recon.burp_parser import _extract_nested

        assert _extract_nested({"a": 1}, "b") is None

    def test_list_out_of_range_returns_none(self):
        from pipeline.recon.burp_parser import _extract_nested

        assert _extract_nested([1], 5) is None

    def test_none_input_returns_none(self):
        from pipeline.recon.burp_parser import _extract_nested

        assert _extract_nested(None, "a") is None


# ═══════════════════════════════════════════════════════
# burp_parser: JSON 路径推断
# ═══════════════════════════════════════════════════════


class TestInferJsonPath:
    """测试 _infer_json_path."""

    def test_flat_json(self):
        from pipeline.recon.burp_parser import _infer_json_path

        content = json.dumps({"content": "hello world this is a long string"})
        path = _infer_json_path(content)
        assert path == "content"

    def test_nested_json(self):
        from pipeline.recon.burp_parser import _infer_json_path

        content = json.dumps({"data": {"message": "a long enough string here"}})
        path = _infer_json_path(content)
        assert path == "data.message"

    def test_json_with_list(self):
        from pipeline.recon.burp_parser import _infer_json_path

        content = json.dumps({"choices": [{"message": {"content": "hello world long text"}}]})
        path = _infer_json_path(content)
        assert path == "choices[0].message.content"

    def test_non_json_returns_none(self):
        from pipeline.recon.burp_parser import _infer_json_path

        assert _infer_json_path("not json") is None

    def test_short_string_skipped(self):
        from pipeline.recon.burp_parser import _infer_json_path

        # len <= 5 的字符串会被跳过
        content = json.dumps({"key": "abc"})
        path = _infer_json_path(content)
        # 没有长字符串可找到 -> 返回 None
        assert path is None


# ═══════════════════════════════════════════════════════
# burp_parser: 语言检测
# ═══════════════════════════════════════════════════════


class TestDetectLanguage:
    """测试 _detect_language."""

    def test_chinese_response(self):
        from pipeline.recon.burp_parser import _detect_language

        text = "你好，我是一个AI助手，很高兴为你服务。" * 3
        assert _detect_language(text) == "zh"

    def test_english_response(self):
        from pipeline.recon.burp_parser import _detect_language

        text = "Hello, I am an AI assistant, happy to help you with your questions."
        assert _detect_language(text) == "en"

    def test_short_text_returns_none(self):
        from pipeline.recon.burp_parser import _detect_language

        assert _detect_language("hi") is None

    def test_empty_text_returns_none(self):
        from pipeline.recon.burp_parser import _detect_language

        assert _detect_language("") is None


# ═══════════════════════════════════════════════════════
# burp_parser: parse_burp_request (文件 I/O)
# ═══════════════════════════════════════════════════════


class TestParseBurpRequest:
    """测试 parse_burp_request — 文件 I/O."""

    def test_parse_from_file(self, tmp_path):
        from pipeline.recon.burp_parser import parse_burp_request

        raw = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"prompt":"hello"}'
        )
        req_file = tmp_path / "request.txt"
        # Use newline="" to prevent Windows \r\n → \r\r\n conversion
        with open(req_file, "w", encoding="utf-8", newline="") as f:
            f.write(raw)

        parsed = parse_burp_request(str(req_file))
        assert parsed.method == "POST"
        assert parsed.host == "localhost"
        assert parsed.has_prompt_placeholder is True
        assert parsed.body == '{"prompt": "{PROMPT}"}'

    def test_parse_real_burp_request(self):
        """使用项目中的真实 Burp 请求文件."""
        req_path = _PROJECT_ROOT / "data" / "burp" / "request.txt"
        if req_path.exists():
            from pipeline.recon.burp_parser import parse_burp_request

            parsed = parse_burp_request(str(req_path))
            assert parsed.method == "POST"
            assert "/api/" in parsed.path
            assert parsed.has_prompt_placeholder is True
            assert parsed.target_fingerprint.get("app_type") in (
                "Agent Application", "Chat Application", "Web Application",
                "RAG Application", "Lab/Arena",
            )


# ═══════════════════════════════════════════════════════
# burp_parser: JSONSafeHTTPTarget
# ═══════════════════════════════════════════════════════


class TestJsonSafeHTTPTarget:
    """测试 JSONSafeHTTPTarget JSON 安全注入."""

    def test_json_body_safe_injection(self):
        """JSON body 中的特殊字符被正确转义."""
        from pipeline.recon.burp_parser import JSONSafeHTTPTarget

        target = JSONSafeHTTPTarget(
            http_request=(
                "POST /api/chat HTTP/1.1\r\n"
                "Host: localhost\r\n"
                'Content-Type: application/json\r\n'
                "\r\n"
                '{"prompt":"{PROMPT}"}'
            ),
            prompt_regex_string="{PROMPT}",
            callback_function=lambda r: str(r),
        )

        request = MagicMock()
        request.converted_value = 'hello\nworld"quoted\\path'

        result = target._inject_prompt_into_request(request)
        # 结果应该是有效的 JSON
        import json as json_mod

        body = result.split("\r\n\r\n", 1)[1]
        data = json_mod.loads(body)
        assert data["prompt"] == 'hello\nworld"quoted\\path'

    def test_non_json_body_falls_back_to_regex(self):
        """非 JSON body 走原始正则替换."""
        from pipeline.recon.burp_parser import JSONSafeHTTPTarget

        target = JSONSafeHTTPTarget(
            http_request="POST /api HTTP/1.1\r\nHost: localhost\r\n\r\n{PROMPT}",
            prompt_regex_string="{PROMPT}",
            callback_function=lambda r: str(r),
        )

        request = MagicMock()
        request.converted_value = "plain text"

        result = target._inject_prompt_into_request(request)
        assert "plain text" in result

    def test_no_placeholder_returns_original(self):
        """没有 {PROMPT} 占位符返回原始请求."""
        from pipeline.recon.burp_parser import JSONSafeHTTPTarget

        target = JSONSafeHTTPTarget(
            http_request="POST /api HTTP/1.1\r\nHost: localhost\r\n\r\n{}",
            prompt_regex_string="{PROMPT}",
            callback_function=lambda r: str(r),
        )

        request = MagicMock()
        request.converted_value = "test"

        result = target._inject_prompt_into_request(request)
        # No {PROMPT} placeholder → original request returned (with Host header)
        assert result == "POST /api HTTP/1.1\r\nHost: localhost\r\n\r\n{}"

    def test_nested_json_placeholder_replacement(self):
        """嵌套 JSON 中所有 {PROMPT} 被替换."""
        from pipeline.recon.burp_parser import JSONSafeHTTPTarget

        target = JSONSafeHTTPTarget(
            http_request=(
                "POST /api HTTP/1.1\r\nHost: localhost\r\n\r\n"
                '{"messages":[{"content":"{PROMPT}"}],"extra":"{PROMPT}"}'
            ),
            prompt_regex_string="{PROMPT}",
            callback_function=lambda r: str(r),
        )

        request = MagicMock()
        request.converted_value = "injected"

        result = target._inject_prompt_into_request(request)
        body = result.split("\r\n\r\n", 1)[1]
        data = json.loads(body)
        assert data["messages"][0]["content"] == "injected"
        assert data["extra"] == "injected"


# ═══════════════════════════════════════════════════════
# burp_parser: _select_callback
# ═══════════════════════════════════════════════════════


class TestSelectCallback:
    """测试 _select_callback."""

    def test_sse_callback_selected(self):
        from pipeline.recon.burp_parser import ParsedBurpRequest, _select_callback

        parsed = ParsedBurpRequest(
            method="POST", url="http://localhost/api", host="localhost", path="/api",
            is_sse=True,
        )
        callback = _select_callback(parsed)
        assert callable(callback)

    def test_default_json_callback_selected(self):
        from pipeline.recon.burp_parser import ParsedBurpRequest, _select_callback

        parsed = ParsedBurpRequest(
            method="POST", url="http://localhost/api", host="localhost", path="/api",
            is_sse=False,
        )
        callback = _select_callback(parsed)
        assert callable(callback)


# ═══════════════════════════════════════════════════════
# auth_bridge: 认证状态加载 + 注入
# ═══════════════════════════════════════════════════════


class TestAuthBridgeLoad:
    """测试 load_auth_state."""

    def test_none_path_returns_none(self):
        from pipeline.recon.auth_bridge import load_auth_state

        assert load_auth_state(None) is None

    def test_nonexistent_file_returns_none(self):
        from pipeline.recon.auth_bridge import load_auth_state

        assert load_auth_state("/nonexistent/auth.json") is None

    def test_valid_auth_state(self, tmp_path):
        from pipeline.recon.auth_bridge import load_auth_state

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({"token": "abc123"}), encoding="utf-8")
        result = load_auth_state(str(auth_file))
        assert result is not None
        assert result["token"] == "abc123"

    def test_invalid_json_returns_none(self, tmp_path):
        from pipeline.recon.auth_bridge import load_auth_state

        auth_file = tmp_path / "auth.json"
        auth_file.write_text("not valid json {{{", encoding="utf-8")
        assert load_auth_state(str(auth_file)) is None


class TestAuthBridgeInject:
    """测试 inject_auth_headers."""

    def test_inject_bearer_token(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        result = inject_auth_headers(raw, {"token": "test-token-123"})
        assert "Authorization: Bearer test-token-123" in result

    def test_inject_bearer_token_alt_key(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        result = inject_auth_headers(raw, {"bearer_token": "alt-token"})
        assert "Authorization: Bearer alt-token" in result

    def test_inject_cookie(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        result = inject_auth_headers(raw, {"cookies": {"session": "abc123", "csrf": "xyz789"}})
        assert "Cookie: session=abc123; csrf=xyz789" in result

    def test_no_auth_state_returns_original(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        assert inject_auth_headers(raw, None) == raw

    def test_empty_auth_state_returns_original(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        assert inject_auth_headers(raw, {}) == raw

    def test_custom_headers_injected(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        result = inject_auth_headers(raw, {"headers": {"X-Custom-Header": "value123"}})
        assert "X-Custom-Header: value123" in result

    def test_existing_headers_not_overwritten(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        raw = "POST /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: existing\r\n\r\n{}"
        result = inject_auth_headers(raw, {"token": "new-token"})
        # existing Authorization header should not be overwritten
        assert "existing" in result
        assert "new-token" not in result

    def test_content_length_updated_with_body(self):
        from pipeline.recon.auth_bridge import inject_auth_headers

        body = '{"data":"test"}'
        raw = f"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\n{body}"
        result = inject_auth_headers(raw, {"token": "tok"})
        # Content-Length should be recalculated
        assert f"Content-Length: {len(body)}" in result
