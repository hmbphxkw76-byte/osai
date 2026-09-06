# arXiv:2407.01232 — PyRIT, burp request parsing
"""Tests for recon/burp_parser.py — _inject_placeholder function.

Covers case-insensitive placeholder injection for various JSON body formats.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestInjectPlaceholder:
    """Test _inject_placeholder with various JSON body formats."""

    def test_pascalcase_query(self):
        """Test with PascalCase 'Query' field."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({
            "Inputs": {"stuNo": "123", "CourseName": ""},
            "Stream": True,
            "Query": "介绍你自己",
            "ChatId": "",
            "UserId": "123",
        }, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["Query"] == "{PROMPT}"
        assert data["Stream"] is True
        assert data["Inputs"]["stuNo"] == "123"

    def test_lowercase_prompt(self):
        """Test with lowercase 'prompt' field."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({"prompt": "hello", "model": "gpt-4o"}, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_openai_messages_format(self):
        """Test with OpenAI messages format."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "hello"},
            ],
        }, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["messages"][-1]["content"] == "{PROMPT}"

    def test_no_matching_field_fallback(self):
        """Test fallback when no matching field found."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({"model": "gpt-4o", "temperature": 0.7}, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_non_json_body(self):
        """Test with non-JSON body (should be unchanged)."""
        from recon.burp_parser import _inject_placeholder

        body = "plain text body"
        result = _inject_placeholder(body)
        assert result == body

    def test_pascalcase_prompt_field(self):
        """Test with PascalCase 'Prompt' field."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({"Prompt": "hello", "Model": "gpt-4o"}, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["Prompt"] == "{PROMPT}"


class TestChatIdDetection:
    """Test chat session ID field detection and placeholder injection."""

    def test_deepseek_chat_session_id_non_empty(self):
        """DeepSeek body with non-empty chat_session_id should get {CHAT_ID}."""
        from recon.burp_parser import _detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "chat_session_id": "c3533794-15bc-492e-bde7-b094bedcc931",
            "prompt": "hello",
        }, ensure_ascii=False)
        new_body, field, has_ph = _detect_and_inject_chat_id_placeholder(body)
        assert field == "chat_session_id"
        assert has_ph is True
        data = json.loads(new_body)
        assert data["chat_session_id"] == "{CHAT_ID}"

    def test_deepseek_chat_session_id_empty(self):
        """DeepSeek body with empty chat_session_id should get {CHAT_ID}."""
        from recon.burp_parser import _detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "chat_session_id": "",
            "prompt": "hello",
        }, ensure_ascii=False)
        new_body, field, has_ph = _detect_and_inject_chat_id_placeholder(body)
        assert field == "chat_session_id"
        assert has_ph is True
        data = json.loads(new_body)
        assert data["chat_session_id"] == "{CHAT_ID}"

    def test_qwen_session_id_non_empty(self):
        """Qwen body with non-empty session_id should get {CHAT_ID}."""
        from recon.burp_parser import _detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "session_id": "4701629fe58943de95c63828bf64177c",
            "messages": [{"content": "hello"}],
        }, ensure_ascii=False)
        new_body, field, has_ph = _detect_and_inject_chat_id_placeholder(body)
        assert field == "session_id"
        assert has_ph is True

    def test_qwen_req_id_non_empty(self):
        """Qwen body with non-empty req_id should get {CHAT_ID}."""
        from recon.burp_parser import _detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "req_id": "9938efd64807421d82af66ff5c676dbe",
            "session_id": "4701629fe58943de95c63828bf64177c",
        }, ensure_ascii=False)
        new_body, field, has_ph = _detect_and_inject_chat_id_placeholder(body)
        # req_id should be detected first (appears first in JSON)
        assert field == "req_id"
        assert has_ph is True

    def test_request_txt_chat_id_empty(self):
        """request.txt body with empty ChatId should get {CHAT_ID}."""
        from recon.burp_parser import _detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "Query": "hello",
            "ChatId": "",
        }, ensure_ascii=False)
        new_body, field, has_ph = _detect_and_inject_chat_id_placeholder(body)
        assert field == "ChatId"
        assert has_ph is True

    def test_no_chat_id_field(self):
        """Body without any chat ID field should not get {CHAT_ID}."""
        from recon.burp_parser import _detect_and_inject_chat_id_placeholder

        body = json.dumps({"prompt": "hello", "model": "gpt-4o"}, ensure_ascii=False)
        new_body, field, has_ph = _detect_and_inject_chat_id_placeholder(body)
        assert field is None
        assert has_ph is False
        assert new_body == body


class TestSseResponseParsing:
    """Test SSE response parsing for various formats including DeepSeek JSON Patch."""

    def test_deepseek_json_patch_format(self):
        """DeepSeek SSE uses JSON Patch format with 'v' field."""
        from recon.burp_parser import _make_sse_callback

        sse_text = (
            'event: ready\n'
            'data: {"request_message_id":1,"response_message_id":2}\n\n'
            'data: {"v":"Hello"}\n\n'
            'data: {"v":" world"}\n\n'
            'data: {"p":"response/fragments/-1/content","o":"APPEND","v":"!"}\n\n'
            'data: {"p":"response/status","o":"SET","v":"FINISHED"}\n\n'
        )

        class MockResponse:
            def __init__(self, text):
                self.text = text
                self.content = text.encode("utf-8")

        callback = _make_sse_callback()
        result = callback(MockResponse(sse_text))
        assert "Hello" in result
        assert "world" in result
        # APPEND to content path should be included
        assert "!" in result
        # SET status should NOT be included
        assert "FINISHED" not in result

    def test_deepseek_v_field_with_nested_object(self):
        """DeepSeek SSE with {'v': {'response': {...}}} should extract content."""
        from recon.burp_parser import _make_sse_callback

        sse_text = (
            'data: {"v":{"response":{"content":"nested content"}}}\n\n'
        )

        class MockResponse:
            def __init__(self, text):
                self.text = text
                self.content = text.encode("utf-8")

        callback = _make_sse_callback()
        result = callback(MockResponse(sse_text))
        assert "nested content" in result

    def test_standard_sse_content_field(self):
        """Standard SSE with 'content' field should work."""
        from recon.burp_parser import _make_sse_callback

        sse_text = (
            'data: {"content":"Hello"}\n\n'
            'data: {"content":" world"}\n\n'
            'data: [DONE]\n\n'
        )

        class MockResponse:
            def __init__(self, text):
                self.text = text
                self.content = text.encode("utf-8")

        callback = _make_sse_callback()
        result = callback(MockResponse(sse_text))
        assert "Hello" in result
        assert "world" in result

    def test_openai_sse_delta_format(self):
        """OpenAI SSE with delta.content should work."""
        from recon.burp_parser import _make_sse_callback

        sse_text = (
            'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":" world"}}]}\n\n'
            'data: [DONE]\n\n'
        )

        class MockResponse:
            def __init__(self, text):
                self.text = text
                self.content = text.encode("utf-8")

        callback = _make_sse_callback()
        result = callback(MockResponse(sse_text))
        assert "Hello" in result
        assert "world" in result


class TestChatIdExtraction:
    """Test chat ID extraction from HTTP responses."""

    def test_extract_deepseek_chat_session_id(self):
        """Extract chat_session_id from SSE response."""
        from recon.burp_parser import _extract_chat_id_from_response

        response = 'data: {"chat_session_id": "new-session-123"}'
        result = _extract_chat_id_from_response(response)
        assert result == "new-session-123"

    def test_extract_session_id(self):
        """Extract session_id from SSE response."""
        from recon.burp_parser import _extract_chat_id_from_response

        response = 'data: {"session_id": "qwen-session-456"}'
        result = _extract_chat_id_from_response(response)
        assert result == "qwen-session-456"

    def test_extract_object_field(self):
        """Extract Object field (request.txt format)."""
        from recon.burp_parser import _extract_chat_id_from_response

        response = 'data: {"Object": "obj-uuid-789"}'
        result = _extract_chat_id_from_response(response)
        assert result == "obj-uuid-789"

    def test_extract_case_insensitive(self):
        """Extract chat_session_id with different casing."""
        from recon.burp_parser import _extract_chat_id_from_response

        response = 'data: {"Chat_Session_Id": "mixed-case-id"}'
        result = _extract_chat_id_from_response(response)
        assert result == "mixed-case-id"

    def test_extract_none_when_no_id(self):
        """Return None when no ID field present."""
        from recon.burp_parser import _extract_chat_id_from_response

        response = 'data: {"content": "hello world"}'
        result = _extract_chat_id_from_response(response)
        assert result is None


class TestSseDetection:
    """Test SSE detection from request and response."""

    def test_detect_sse_from_response_content_type(self, tmp_path):
        """SSE should be detected from response Content-Type header."""
        from recon.burp_parser import parse_burp_request

        request_file = tmp_path / "request.txt"
        request_file.write_bytes(
            b"POST /api/chat HTTP/2\r\n"
            b"Host: chat.example.com\r\n"
            b"Accept: */*\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"prompt":"{PROMPT}"}\r\n'
            b"\r\n"
            b"HTTP/2 200 OK\r\n"
            b"Content-Type: text/event-stream; charset=utf-8\r\n"
            b"\r\n"
            b'data: {"content":"hello"}\r\n'
        )
        parsed = parse_burp_request(str(request_file))
        assert parsed.is_sse is True

    def test_detect_sse_from_accept_header(self, tmp_path):
        """SSE should be detected from Accept: text/event-stream header."""
        from recon.burp_parser import parse_burp_request

        request_file = tmp_path / "request.txt"
        request_file.write_bytes(
            b"POST /api/chat HTTP/1.1\r\n"
            b"Host: localhost:8080\r\n"
            b"Accept: text/event-stream\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"prompt":"{PROMPT}"}',
        )
        parsed = parse_burp_request(str(request_file))
        assert parsed.is_sse is True

    def test_detect_sse_from_body_stream_flag(self, tmp_path):
        """SSE should be detected from body stream:true flag."""
        from recon.burp_parser import parse_burp_request

        request_file = tmp_path / "request.txt"
        request_file.write_bytes(
            b"POST /api/chat HTTP/1.1\r\n"
            b"Host: localhost:8080\r\n"
            b"Accept: application/json\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"prompt":"{PROMPT}","stream":true}',
        )
        parsed = parse_burp_request(str(request_file))
        assert parsed.is_sse is True


class TestFullParseAllFormats:
    """Test full parse of all three Burp file formats."""

    @pytest.mark.skipif(
        not Path("config/targets/burp/request.txt").exists(),
        reason="config/targets/burp/request.txt not present (optional sample data)",
    )
    def test_parse_request_txt(self):
        """Parse request.txt (localhost MM_05 chat format)."""
        from recon.burp_parser import parse_burp_request

        parsed = parse_burp_request("config/targets/burp/request.txt")
        assert parsed.method == "POST"
        assert parsed.is_sse is True
        assert parsed.has_prompt_placeholder is True
        assert parsed.original_prompt_value == "hello"

    @pytest.mark.skipif(
        not Path("config/targets/burp/qwen.txt").exists(),
        reason="config/targets/burp/qwen.txt not present (optional sample data)",
    )
    def test_parse_qwen_txt(self):
        """Parse qwen.txt — file format may change between exports (GET/POST).

        Qwen 的 Burp 文件可能是:
        - GET /api/v1/model/list (模型列表, 无 body)
        - POST /api/v2/chat (聊天, 有 body 含 prompt)
        通用适配器应能处理两种情况而不崩溃。
        """
        from recon.burp_parser import parse_burp_request

        parsed = parse_burp_request("config/targets/burp/qwen.txt")
        assert parsed.method in ("GET", "POST")
        # GET 请求可能无 body, 无 prompt 占位符; POST 有 body 时应有
        # 不硬编码期望值, 只要解析不崩溃即可

    @pytest.mark.skipif(
        not Path("config/targets/burp/deepseek.txt").exists(),
        reason="config/targets/burp/deepseek.txt not present (optional sample data)",
    )
    def test_parse_deepseek_txt(self):
        """Parse deepseek.txt (DeepSeek format with chat_session_id)."""
        from recon.burp_parser import parse_burp_request

        parsed = parse_burp_request("config/targets/burp/deepseek.txt")
        assert parsed.method == "POST"
        assert parsed.is_sse is True  # Detected from response Content-Type
        assert parsed.has_prompt_placeholder is True
        assert parsed.chat_id_field == "chat_session_id"
        assert parsed.has_chat_id_placeholder is True
        assert parsed.chat_id == "c3533794-15bc-492e-bde7-b094bedcc931"
        assert "{CHAT_ID}" in parsed.body

    @pytest.mark.skipif(
        not Path("config/targets/burp/deepseek.txt").exists(),
        reason="config/targets/burp/deepseek.txt not present (optional sample data)",
    )
    def test_parse_deepseek_sse_response(self):
        """Parse DeepSeek SSE response and verify content extraction."""
        from recon.burp_parser import _make_sse_callback, _split_request_response

        raw = Path("config/targets/burp/deepseek.txt").read_text(encoding="utf-8", errors="replace")
        normalized = raw.replace("\r\n", "\n")
        _, response_section = _split_request_response(normalized)

        assert response_section is not None

        class MockResponse:
            def __init__(self, text):
                self.text = text
                self.content = text.encode("utf-8")

        callback = _make_sse_callback()
        result = callback(MockResponse(response_section))
        # Should contain DeepSeek self-introduction content
        assert len(result) > 100  # Should be substantial content
        assert "DeepSeek" in result or "deep" in result.lower()

    @pytest.mark.skipif(
        not Path("config/targets/burp/baidu.txt").exists(),
        reason="config/targets/burp/baidu.txt not present (optional sample data)",
    )
    def test_parse_baidu_txt(self):
        """Parse baidu.txt (Baidu with deeply nested body structure)."""
        from recon.burp_parser import parse_burp_request

        parsed = parse_burp_request("config/targets/burp/baidu.txt")
        assert parsed.method == "POST"
        assert parsed.is_sse is True  # Accept: text/event-stream
        assert parsed.has_prompt_placeholder is True
        # {PROMPT} should be injected into the deeply nested path:
        # message.query[0].data.text.query
        body_data = json.loads(parsed.body)

        # Navigate the nested path to find {PROMPT}
        prompt_val = (
            body_data["message"]["query"][0]["data"]["text"]["query"]
        )
        assert prompt_val == "{PROMPT}"


class TestRecursivePromptInjection:
    """Test recursive deep nested prompt injection for complex body structures."""

    def test_deep_nested_baidu_like_structure(self):
        """Baidu-style deeply nested body should find prompt at nested path."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({
            "message": {
                "inputMethod": "chat_search",
                "query": [
                    {
                        "type": "TEXT",
                        "data": {
                            "text": {
                                "query": "吉隆口岸大楼只剩钢筋骨架",
                                "extData": "{}",
                            }
                        }
                    }
                ],
                "source": "pc_csaitab",
            },
            "sa": "aihome_searchbox_defaultword",
        }, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        # {PROMPT} should be at message.query[0].data.text.query
        assert data["message"]["query"][0]["data"]["text"]["query"] == "{PROMPT}"
        # Other fields should be unchanged
        assert data["message"]["source"] == "pc_csaitab"
        assert data["sa"] == "aihome_searchbox_defaultword"

    def test_flat_structure_still_works(self):
        """Flat body structure (DeepSeek style) should still work via recursive."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({
            "chat_session_id": "abc123",
            "prompt": "hello world",
        }, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_no_prompt_found_adds_fallback(self):
        """When no natural language text exists, fallback to adding prompt field."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({
            "model": "gpt-4o",
            "temperature": 0.7,
            "max_tokens": 100,
        }, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_recursive_finds_highest_score(self):
        """When multiple string fields exist, recursive search picks highest score."""
        from recon.burp_parser import _inject_placeholder

        body = json.dumps({
            "config": {
                "name": "config_value",  # short ascii, no prompt name hint
                "nested": {
                    "query": "这是一个很长的中文 prompt",  # natural lang + query name
                }
            }
        }, ensure_ascii=False)
        result = _inject_placeholder(body)
        data = json.loads(result)
        # The nested query field should win (natural lang + name hint)
        assert data["config"]["nested"]["query"] == "{PROMPT}"
        assert data["config"]["name"] == "config_value"  # unchanged
