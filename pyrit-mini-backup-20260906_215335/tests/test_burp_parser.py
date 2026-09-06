# arXiv:2407.01232 — PyRIT, burp request parsing
"""Tests for recon/burp_parser.py and its split submodules.

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
    """Test inject_prompt_placeholder with various JSON body formats."""

    def test_pascalcase_query(self):
        """Test with PascalCase 'Query' field."""
        from recon.prompt_injector import inject_prompt_placeholder

        body = json.dumps({
            "Inputs": {"stuNo": "123", "CourseName": ""},
            "Stream": True,
            "Query": "介绍你自己",
            "ChatId": "",
            "UserId": "123",
        }, ensure_ascii=False)
        result = inject_prompt_placeholder(body)
        data = json.loads(result)
        assert data["Query"] == "{PROMPT}"
        assert data["Stream"] is True
        assert data["Inputs"]["stuNo"] == "123"

    def test_lowercase_prompt(self):
        """Test with lowercase 'prompt' field."""
        from recon.prompt_injector import inject_prompt_placeholder

        body = json.dumps({"prompt": "hello", "model": "gpt-4o"}, ensure_ascii=False)
        result = inject_prompt_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_openai_messages_format(self):
        """Test with OpenAI messages format."""
        from recon.prompt_injector import inject_prompt_placeholder

        body = json.dumps({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "hello"},
            ],
        }, ensure_ascii=False)
        result = inject_prompt_placeholder(body)
        data = json.loads(result)
        assert data["messages"][-1]["content"] == "{PROMPT}"

    def test_no_matching_field_fallback(self):
        """Test fallback when no matching field found."""
        from recon.prompt_injector import inject_prompt_placeholder

        body = json.dumps({"model": "gpt-4o", "temperature": 0.7}, ensure_ascii=False)
        result = inject_prompt_placeholder(body)
        data = json.loads(result)
        assert data["prompt"] == "{PROMPT}"

    def test_non_json_body(self):
        """Test with non-JSON body (should be unchanged)."""
        from recon.prompt_injector import inject_prompt_placeholder

        body = "plain text body"
        result = inject_prompt_placeholder(body)
        assert result == body

    def test_pascalcase_prompt_field(self):
        """Test with PascalCase 'Prompt' field."""
        from recon.prompt_injector import inject_prompt_placeholder

        body = json.dumps({"Prompt": "hello", "Model": "gpt-4o"}, ensure_ascii=False)
        result = inject_prompt_placeholder(body)
        data = json.loads(result)
        assert data["Prompt"] == "{PROMPT}"


class TestChatIdDetection:
    """Test chat session ID field detection and placeholder injection."""

    def test_deepseek_chat_session_id_non_empty(self):
        """DeepSeek body with non-empty chat_session_id should get {CHAT_ID}."""
        from recon.prompt_injector import detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "chat_session_id": "c3533794-15bc-492e-bde7-b094bedcc931",
            "prompt": "hello",
        }, ensure_ascii=False)
        new_body, field, has_ph = detect_and_inject_chat_id_placeholder(body)
        assert field == "chat_session_id"
        assert has_ph is True
        data = json.loads(new_body)
        assert data["chat_session_id"] == "{CHAT_ID}"

    def test_deepseek_chat_session_id_empty(self):
        """DeepSeek body with empty chat_session_id should get {CHAT_ID}."""
        from recon.prompt_injector import detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "chat_session_id": "",
            "prompt": "hello",
        }, ensure_ascii=False)
        new_body, field, has_ph = detect_and_inject_chat_id_placeholder(body)
        assert field == "chat_session_id"
        assert has_ph is True
        data = json.loads(new_body)
        assert data["chat_session_id"] == "{CHAT_ID}"

    def test_qwen_session_id_non_empty(self):
        """Qwen body with non-empty session_id should get {CHAT_ID}."""
        from recon.prompt_injector import detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "session_id": "4701629fe58943de95c63828bf64177c",
            "messages": [{"content": "hello"}],
        }, ensure_ascii=False)
        new_body, field, has_ph = detect_and_inject_chat_id_placeholder(body)
        assert field == "session_id"
        assert has_ph is True

    def test_qwen_req_id_non_empty(self):
        """Qwen body with non-empty req_id should get {CHAT_ID}."""
        from recon.prompt_injector import detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "req_id": "9938efd64807421d82af66ff5c676dbe",
            "session_id": "4701629fe58943de95c63828bf64177c",
        }, ensure_ascii=False)
        new_body, field, has_ph = detect_and_inject_chat_id_placeholder(body)
        # req_id should be detected first (appears first in JSON)
        assert field == "req_id"
        assert has_ph is True

    def test_request_txt_chat_id_empty(self):
        """request.txt body with empty ChatId should get {CHAT_ID}."""
        from recon.prompt_injector import detect_and_inject_chat_id_placeholder

        body = json.dumps({
            "ChatId": "",
            "Prompt": "test",
        }, ensure_ascii=False)
        new_body, field, has_ph = detect_and_inject_chat_id_placeholder(body)
        assert field == "ChatId"
        assert has_ph is True
        data = json.loads(new_body)
        assert data["ChatId"] == "{CHAT_ID}"

    def test_no_chat_id_field(self):
        """Body without chat ID fields should remain unchanged."""
        from recon.prompt_injector import detect_and_inject_chat_id_placeholder

        body = json.dumps({"prompt": "hello"}, ensure_ascii=False)
        new_body, field, has_ph = detect_and_inject_chat_id_placeholder(body)
        assert field is None
        assert has_ph is False
        assert new_body == body


class TestApiClassifier:
    """Test API endpoint category detection."""

    def test_chat_api_path(self):
        from recon.api_classifier import detect_api_category

        assert detect_api_category("/api/chat", "") == "chat"
        assert detect_api_category("/api/v1/completions", "") == "chat"
        assert detect_api_category("/v1/messages", "") == "chat"

    def test_metadata_api_path(self):
        from recon.api_classifier import detect_api_category

        assert detect_api_category("/api/models", "") == "metadata"
        assert detect_api_category("/api/v1/model/list", "") == "metadata"
        assert detect_api_category("/health", "") == "metadata"

    def test_api_category_by_body(self):
        from recon.api_classifier import detect_api_category

        # Body with prompt field -> chat
        body = json.dumps({"prompt": "hello"})
        assert detect_api_category("/api/unknown", body) == "chat"

        # Empty body with GET -> metadata
        assert detect_api_category("/api/data", "") == "metadata"


class TestFingerprint:
    """Test AI framework fingerprint extraction."""

    def test_extract_from_response_headers(self):
        from recon.fingerprint import extract_ai_framework_fingerprint

        response = "HTTP/1.1 200 OK\r\nx-vllm-test: value\r\n\r\nbody"
        fw, cat = extract_ai_framework_fingerprint(response)
        assert fw == "vllm"
        assert cat == "ai-runtime"

    def test_extract_from_title(self):
        from recon.fingerprint import extract_ai_framework_fingerprint

        response = "HTTP/1.1 200 OK\r\n\r\n<html><title>Open WebUI</title></html>"
        fw, cat = extract_ai_framework_fingerprint(response)
        assert fw == "open-webui"
        assert cat == "ai-frontend"

    def test_no_match(self):
        from recon.fingerprint import extract_ai_framework_fingerprint

        response = "HTTP/1.1 200 OK\r\n\r\nplain text"
        fw, cat = extract_ai_framework_fingerprint(response)
        assert fw is None
        assert cat is None

    def test_extract_sdk_from_request_headers(self):
        from recon.fingerprint import extract_ai_sdk_from_request_headers

        headers = {"anthropic-version": "2023-06-01"}
        fw, cat = extract_ai_sdk_from_request_headers(headers)
        assert fw == "anthropic"
        assert cat == "ai-sdk-client"

        headers = {"api-key": "xxx"}
        fw, cat = extract_ai_sdk_from_request_headers(headers)
        assert fw == "azure-openai"


class TestTargetFingerprint:
    """Test TargetFingerprint dataclass."""

    def test_default_values(self):
        from recon.burp_parser import TargetFingerprint

        fp = TargetFingerprint()
        assert fp.framework == "Unknown"
        assert fp.api_path == ""
        assert fp.capabilities == []

    def test_getitem_setitem(self):
        from recon.burp_parser import TargetFingerprint

        fp = TargetFingerprint()
        fp["custom_key"] = "value"
        assert fp["custom_key"] == "value"
        assert fp.extra["custom_key"] == "value"

    def test_to_dict_filters_empty(self):
        from recon.burp_parser import TargetFingerprint

        fp = TargetFingerprint(framework="Next.js", api_path="/chat")
        d = fp.to_dict()
        assert "framework" in d
        assert "api_path" in d
        assert "capabilities" not in d  # Empty list filtered out
