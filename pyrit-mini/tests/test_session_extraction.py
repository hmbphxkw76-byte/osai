# -*- coding: utf-8 -*-
"""tests/test_session_extraction.py - SessionExtractor unit tests"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from strike.session.extraction import SessionExtractor
from strike.session.session_config import ExtractionRule


class TestSessionExtractor:
    """SessionExtractor functionality tests"""

    def test_json_path_extraction(self) -> None:
        """Test JSONPath extraction"""
        rule = ExtractionRule(
            name="session_id",
            primary={"method": "json_path", "path": "$.session_id"},
        )
        extractor = SessionExtractor([rule])

        response = json.dumps({"session_id": "test-123", "data": "value"})
        result = extractor.extract_all(response)

        assert result["session_id"] == "test-123"

    def test_json_path_nested(self) -> None:
        """Test nested JSONPath extraction"""
        rule = ExtractionRule(
            name="token",
            primary={"method": "json_path", "path": "$.data.session.token"},
        )
        extractor = SessionExtractor([rule])

        response = json.dumps({
            "data": {"session": {"token": "nested-token-456"}}
        })
        result = extractor.extract_all(response)

        assert result["token"] == "nested-token-456"

    def test_regex_extraction(self) -> None:
        """Test regex extraction"""
        rule = ExtractionRule(
            name="session_id",
            primary={"method": "regex", "pattern": r'"session_id"\s*:\s*"([^"]+)"'},
        )
        extractor = SessionExtractor([rule])

        response = '{"session_id": "regex-789", "other": "data"}'
        result = extractor.extract_all(response)

        assert result["session_id"] == "regex-789"

    def test_header_extraction(self) -> None:
        """Test header extraction"""
        rule = ExtractionRule(
            name="session_id",
            primary={"method": "header", "name": "X-Session-Id"},
        )
        extractor = SessionExtractor([rule])

        headers = {"X-Session-Id": "header-session-001", "Content-Type": "application/json"}
        result = extractor.extract_all("", response_headers=headers)

        assert result["session_id"] == "header-session-001"

    def test_cookie_extraction(self) -> None:
        """Test cookie extraction"""
        rule = ExtractionRule(
            name="session_id",
            primary={"method": "cookie", "name": "sid"},
        )
        extractor = SessionExtractor([rule])

        cookies = {"sid": "cookie-session-002", "other": "value"}
        result = extractor.extract_all("", response_cookies=cookies)

        assert result["session_id"] == "cookie-session-002"

    def test_fallback_chain(self) -> None:
        """Test fallback chain when primary fails"""
        rule = ExtractionRule(
            name="session_id",
            primary={"method": "json_path", "path": "$.nonexistent"},
            fallbacks=[
                {"method": "regex", "pattern": r'"sessionId"\s*:\s*"([^"]+)"'},
            ],
        )
        extractor = SessionExtractor([rule])

        response = '{"sessionId": "fallback-success-123"}'
        result = extractor.extract_all(response)

        assert result["session_id"] == "fallback-success-123"

    def test_multiple_rules(self) -> None:
        """Test multiple extraction rules"""
        rules = [
            ExtractionRule(
                name="session_id",
                primary={"method": "json_path", "path": "$.session_id"},
            ),
            ExtractionRule(
                name="csrf_token",
                primary={"method": "json_path", "path": "$.csrf"},
            ),
        ]
        extractor = SessionExtractor(rules)

        response = json.dumps({
            "session_id": "multi-001",
            "csrf": "csrf-002"
        })
        result = extractor.extract_all(response)

        assert result["session_id"] == "multi-001"
        assert result["csrf_token"] == "csrf-002"

    def test_empty_response(self) -> None:
        """Test empty response returns empty dict"""
        rule = ExtractionRule(
            name="session_id",
            primary={"method": "json_path", "path": "$.session_id"},
        )
        extractor = SessionExtractor([rule])

        result = extractor.extract_all("")
        assert result == {}

    def test_invalid_json(self) -> None:
        """Test invalid JSON returns empty dict"""
        rule = ExtractionRule(
            name="session_id",
            primary={"method": "json_path", "path": "$.session_id"},
        )
        extractor = SessionExtractor([rule])

        result = extractor.extract_all("not valid json {{{")
        assert result == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
