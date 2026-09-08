# -*- coding: utf-8 -*-
"""tests/test_session_injection.py - SessionInjector unit tests"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from strike.session.injection import SessionInjector
from strike.session.session_config import InjectionRule, InjectionTarget


class TestSessionInjector:
    """SessionInjector functionality tests"""

    def test_inject_body(self) -> None:
        """Test body injection"""
        rule = InjectionRule(
            name="session_id",
            target=InjectionTarget.BODY,
            field="session_id",
        )
        injector = SessionInjector([rule])

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"message": "hello"}'
        )

        tokens = {"session_id": "inject-body-001"}
        result = injector.inject(request, tokens)

        assert "inject-body-001" in result
        assert "session_id" in result

    def test_inject_header(self) -> None:
        """Test header injection"""
        rule = InjectionRule(
            name="session_id",
            target=InjectionTarget.HEADER,
            field="X-Session-Id",
        )
        injector = SessionInjector([rule])

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"message": "hello"}'
        )

        tokens = {"session_id": "inject-header-002"}
        result = injector.inject(request, tokens)

        assert "X-Session-Id: inject-header-002" in result

    def test_inject_query(self) -> None:
        """Test query parameter injection"""
        rule = InjectionRule(
            name="session_id",
            target=InjectionTarget.QUERY,
            field="sid",
        )
        injector = SessionInjector([rule])

        request = (
            "GET /api/data HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
        )

        tokens = {"session_id": "inject-query-003"}
        result = injector.inject(request, tokens)

        assert "sid=inject-query-003" in result

    def test_inject_cookie(self) -> None:
        """Test cookie injection"""
        rule = InjectionRule(
            name="session_id",
            target=InjectionTarget.COOKIE,
            field="sid",
        )
        injector = SessionInjector([rule])

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{}'
        )

        tokens = {"session_id": "inject-cookie-004"}
        result = injector.inject(request, tokens)

        assert "sid=inject-cookie-004" in result

    def test_inject_missing_token_skipped(self) -> None:
        """Test missing token is skipped"""
        rule = InjectionRule(
            name="session_id",
            target=InjectionTarget.BODY,
            field="session_id",
        )
        injector = SessionInjector([rule])

        request = "POST /api/chat HTTP/1.1\r\nHost: example.com\r\n\r\n{}"

        # Empty tokens
        result = injector.inject(request, {})
        assert result == request

    def test_inject_multiple_rules(self) -> None:
        """Test multiple injection rules"""
        rules = [
            InjectionRule(
                name="session_id",
                target=InjectionTarget.BODY,
                field="session_id",
            ),
            InjectionRule(
                name="session_id",
                target=InjectionTarget.HEADER,
                field="X-Session-Id",
            ),
        ]
        injector = SessionInjector(rules)

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"message": "hello"}'
        )

        tokens = {"session_id": "multi-inject-005"}
        result = injector.inject(request, tokens)

        assert "multi-inject-005" in result
        assert "X-Session-Id" in result

    def test_inject_with_template(self) -> None:
        """Test custom template injection"""
        rule = InjectionRule(
            name="token",
            target=InjectionTarget.HEADER,
            field="Authorization",
            template="Bearer {value}",
        )
        injector = SessionInjector([rule])

        request = (
            "POST /api/data HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
        )

        tokens = {"token": "my-token-123"}
        result = injector.inject(request, tokens)

        assert "Authorization: Bearer my-token-123" in result

    def test_inject_preserves_existing_body(self) -> None:
        """Test injection preserves existing body content"""
        rule = InjectionRule(
            name="session_id",
            target=InjectionTarget.BODY,
            field="session_id",
        )
        injector = SessionInjector([rule])

        request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"message": "hello", "user": "test"}'
        )

        tokens = {"session_id": "preserve-006"}
        result = injector.inject(request, tokens)

        assert "preserve-006" in result
        assert "hello" in result
        assert "test" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
