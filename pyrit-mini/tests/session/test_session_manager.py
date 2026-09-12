# -*- coding: utf-8 -*-
"""tests/test_session_manager.py - SessionStateManager unit tests"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from strike.session import SessionConfig, SessionStateManager
from strike.session.extraction import SessionExtractor
from strike.session.injection import SessionInjector


class MockResponse:
    """Mock HTTP response object"""

    def __init__(self, text: str, headers: dict | None = None) -> None:
        self.text = text
        self.content = text.encode() if text else b""
        self.headers = headers or {}


class TestSessionStateManager:
    """SessionStateManager core functionality tests"""

    def test_init_default_config(self) -> None:
        """Test default config initialization"""
        manager = SessionStateManager()
        assert manager._config is not None
        assert isinstance(manager._config, SessionConfig)
        assert not manager.is_active

    def test_activate_deactivate(self) -> None:
        """Test activate/deactivate"""
        manager = SessionStateManager()
        assert not manager.is_active
        manager.activate()
        assert manager.is_active
        manager.deactivate()
        assert not manager.is_active

    def test_extract_from_response_json_path(self) -> None:
        """Test JSON path extraction from response"""
        manager = SessionStateManager()
        manager.activate()

        response_text = json.dumps({"response": "Hello!", "session_id": "abc-123-def-456"})

        response = MockResponse(response_text)
        extracted = manager.extract_from_response(response)
        assert "session_id" in extracted
        assert extracted["session_id"] == "abc-123-def-456"

    def test_extract_inactive_returns_empty(self) -> None:
        """Test inactive manager returns empty"""
        manager = SessionStateManager()
        response = MockResponse('{"session_id": "xyz"}')
        extracted = manager.extract_from_response(response)
        assert extracted == {}

    def test_inject_into_request_body(self) -> None:
        """Test body injection"""
        manager = SessionStateManager()
        manager.activate()
        manager._current_state = {"session_id": "test-session-123"}

        request = (
            'POST /api/chat HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{"message": "hello"}'
        )

        result = manager.inject_into_request(request)
        assert "test-session-123" in result

    def test_inject_inactive_returns_original(self) -> None:
        """Test inactive manager returns original request"""
        manager = SessionStateManager()
        request = "POST /api/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{}"
        result = manager.inject_into_request(request)
        assert result == request

    def test_snapshot_restore(self) -> None:
        """Test snapshot and restore"""
        manager = SessionStateManager()
        manager.activate()
        response = MockResponse('{"session_id": "snap-test-123"}')
        manager.extract_from_response(response)

        snapshot = manager.snapshot()
        manager._current_state = {"session_id": "modified"}
        manager.restore(snapshot)
        assert manager.current_state.get("session_id") == "snap-test-123"

    def test_reset(self) -> None:
        """Test reset"""
        manager = SessionStateManager()
        manager.activate()
        manager.extract_from_response('{"session_id": "will-be-cleared"}')
        manager.reset()
        assert manager.current_state == {}
        assert manager.turn_count == 0

    def test_create_callback_wrapper(self) -> None:
        """Test callback wrapper creation"""
        manager = SessionStateManager()
        manager.activate()

        def original_callback(response):
            return "parsed"

        wrapped = manager.create_callback_wrapper(original_callback)
        assert callable(wrapped)
        assert "session_aware" in getattr(wrapped, "__name__", "")

    def test_callback_wrapper_executes_extraction(self) -> None:
        """Test wrapped callback performs extraction"""
        manager = SessionStateManager()
        manager.activate()

        original_called = []

        def original_callback(response):
            original_called.append(True)
            return "parsed"

        wrapped = manager.create_callback_wrapper(original_callback)

        mock_response = MagicMock()
        mock_response.text = '{"session_id": "from-callback-789"}'
        mock_response.content = b'{"session_id": "from-callback-789"}'
        mock_response.headers = {}

        result = wrapped(mock_response)
        assert result == "parsed"
        assert len(original_called) == 1
        assert manager.current_state.get("session_id") == "from-callback-789"


class TestSessionConfig:
    """SessionConfig tests"""

    def test_default_config(self) -> None:
        """Test default config"""
        config = SessionConfig.default_config()
        assert len(config.extraction_rules) > 0
        assert len(config.injection_rules) > 0
        assert config.validation.enabled

    def test_config_serialization(self) -> None:
        """Test config serialization roundtrip"""
        config = SessionConfig.default_config()
        data = config.to_dict()
        assert "extraction_rules" in data
        assert "injection_rules" in data
        restored = SessionConfig.from_dict(data)
        assert len(restored.extraction_rules) == len(config.extraction_rules)


class TestExtractorInjectorIntegration:
    """Extractor-Injector integration tests"""

    def test_extract_then_inject(self) -> None:
        """Test full extract-inject flow"""
        config = SessionConfig.default_config()
        extractor = SessionExtractor(config.extraction_rules)
        injector = SessionInjector(config.injection_rules)

        response = json.dumps({"response": "Hello from agent", "session_id": "flow-test-session-001"})

        tokens = extractor.extract_all(response)
        assert tokens.get("session_id") == "flow-test-session-001"

        request = (
            'POST /api/chat HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"message": "test"}'
        )

        result = injector.inject(request, tokens)
        assert "flow-test-session-001" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
