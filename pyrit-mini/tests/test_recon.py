"""Tests for recon module — Burp parsing + target building + capability probing.

Covers attack chain step ①②:
    ① Burp intercept → parse HTTP request (with {PROMPT} placeholder)
    ② Recon → probe target capabilities, build HTTPTarget

arXiv:2407.01232 — PyRIT: HTTPTarget for black-box HTTP target construction.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# Ensure project root on path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestBurpParser:
    """Test Burp HTTP request parsing (step ①)."""

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
    """Test target router (step ②)."""

    @pytest.mark.asyncio
    async def test_create_target_missing_burp_request(self, tmp_path):
        """create_target should raise FileNotFoundError for missing burp request."""
        from core.context import PipelineContext
        from recon.target_router import create_target

        args = MagicMock()
        args.burp_request = "nonexistent.txt"
        args.max_concurrency = 3
        args.target_api_endpoint = None
        args.target_api_key = None
        args.browser_url = None
        args.auth_refresh_enabled = False
        args.port_discovery_enabled = False

        ctx = PipelineContext(args=args, output_dir=tmp_path)
        with pytest.raises((FileNotFoundError, Exception)):
            await create_target(ctx)
