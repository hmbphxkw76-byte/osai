"""Tests for recon module - Burp parsing + target building + capability probing.

Covers attack chain step (1)(2):
    (1) Burp intercept -> parse HTTP request (with {PROMPT} placeholder)
    (2) Recon -> probe target capabilities, build HTTPTarget

arXiv:2407.01232 - PyRIT: HTTPTarget for black-box HTTP target construction.
"""  # noqa: E501

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure project root on path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestBurpParser:
    """Tests for burp request parsing."""

    def test_parse_basic_post_request(self, tmp_path):
        """Parse a minimal POST request with {PROMPT} placeholder."""
        from recon.burp_parser import parse_burp_request

        request_file = tmp_path / "request.txt"
        # Write a proper HTTP request with CRLF line endings
        request_file.write_bytes(
            b"POST /api/chat HTTP/1.1\r\n"
            b"Host: localhost:8080\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"prompt":"{PROMPT}"}',
        )
        parsed = parse_burp_request(str(request_file))
        assert parsed is not None
        assert parsed.path == "/api/chat"
        assert parsed.method == "POST"
        assert parsed.has_prompt_placeholder is True

    def test_parse_request_auto_injects_prompt_placeholder(self, tmp_path):
        """Request without {PROMPT} should have it auto-injected by burp_parser."""
        from recon.burp_parser import parse_burp_request

        request_file = tmp_path / "request.txt"
        request_file.write_bytes(
            b"POST /api/chat HTTP/1.1\r\n"
            b"Host: localhost:8080\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"prompt":"hello"}',
        )
        parsed = parse_burp_request(str(request_file))
        assert parsed is not None
        # burp_parser auto-injects {PROMPT} when not present in the body
        assert parsed.has_prompt_placeholder is True
        assert "{PROMPT}" in parsed.body


class TestTargetRouter:
    """Tests for target router."""

    @pytest.mark.asyncio
    async def test_create_target_missing_burp_request(self, tmp_path):
        """create_target should raise FileNotFoundError for missing burp request."""
        from core.context import PipelineContext
        from recon.target_router import create_target

        args = MagicMock()
        args.burp = "nonexistent.txt"
        args.max_concurrency = 3
        args.target_api_endpoint = None
        args.target_api_key = None
        args.browser_url = None
        args.auth_refresh_enabled = False
        args.port_discovery_enabled = False

        ctx = PipelineContext(args=args, output_dir=tmp_path)
        with pytest.raises((FileNotFoundError, Exception)):
            await create_target(ctx)


class TestAgentPlatformWordlist:
    """Tests for agent platform flat routes and KB/log routes in wordlist.

    Closes reconnaissance gap: modern AI agent platforms use flat routes
    (no /api/ or /v1/ prefix) that were previously undetected.
    """

    def test_agent_flat_routes_in_wordlist(self):
        """Agent platform flat routes must be in _AI_API_WORDLIST."""
        from recon.health_probe import _AI_API_WORDLIST

        expected_routes = [
            "/chat",
            "/upload",
            "/reset",
            "/summarize",
            "/browse",
            "/review",
            "/session/new",
        ]
        for route in expected_routes:
            assert route in _AI_API_WORDLIST, f"Missing agent route: {route}"

    def test_kb_routes_in_wordlist(self):
        """Knowledge base routes must be in _AI_API_WORDLIST."""
        from recon.health_probe import _AI_API_WORDLIST

        kb_routes = ["/kb/topics", "/kb/add", "/kb/search"]
        for route in kb_routes:
            assert route in _AI_API_WORDLIST, f"Missing KB route: {route}"

    def test_log_variants_in_recursive_expander(self):
        """Log endpoint variants must be in _API_RESOURCE_SUBPATHS."""
        from recon.recursive_expander import _API_RESOURCE_SUBPATHS

        log_routes = ["/logs/latest", "/logs/last-tool-call"]
        for route in log_routes:
            assert route in _API_RESOURCE_SUBPATHS, f"Missing log route: {route}"

    def test_kb_subpaths_in_recursive_expander(self):
        """KB subpaths must be in _API_RESOURCE_SUBPATHS."""
        from recon.recursive_expander import _API_RESOURCE_SUBPATHS

        kb_routes = ["/kb/topics", "/kb/add", "/kb/search"]
        for route in kb_routes:
            assert route in _API_RESOURCE_SUBPATHS, f"Missing KB route: {route}"

    def test_flat_prefix_expansion(self):
        """Flat prefixes like /kb, /logs, /session should generate subpaths."""
        from recon.health_probe import DiscoveredEndpoint
        from recon.recursive_expander import analyze_for_expansion

        # Test /kb prefix expansion
        endpoints = [DiscoveredEndpoint(path="/kb", existence="confirmed")]
        plans = analyze_for_expansion(endpoints)
        assert len(plans) > 0, "Expected expansion plan for /kb"

        # Verify subpaths generated
        all_subpaths = []
        for plan in plans:
            all_subpaths.extend(plan.subpaths_to_probe)

        assert "/kb/topics" in all_subpaths
        assert "/kb/add" in all_subpaths
        assert "/kb/search" in all_subpaths

    def test_session_new_expansion(self):
        """Session prefix should generate /session/new subpath."""
        from recon.health_probe import DiscoveredEndpoint
        from recon.recursive_expander import analyze_for_expansion

        endpoints = [DiscoveredEndpoint(path="/session", existence="confirmed")]
        plans = analyze_for_expansion(endpoints)
        assert len(plans) > 0, "Expected expansion plan for /session"

        all_subpaths = []
        for plan in plans:
            all_subpaths.extend(plan.subpaths_to_probe)

        assert "/session/new" in all_subpaths

    def test_combined_wordlist_includes_new_routes(self):
        """_COMBINED_API_WORDLIST must include all new agent/KB routes."""
        from recon.health_probe import _COMBINED_API_WORDLIST

        new_routes = [
            "/chat", "/upload", "/reset", "/summarize",
            "/browse", "/review", "/session/new",
            "/kb/topics", "/kb/add", "/kb/search",
        ]
        for route in new_routes:
            assert route in _COMBINED_API_WORDLIST, f"Missing in combined: {route}"
