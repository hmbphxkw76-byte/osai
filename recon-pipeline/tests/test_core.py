# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tests for recon-kit."""

import pytest


def test_auth_state_creation():
    """Test AuthState basic creation."""
    from core.models.auth_state import AuthState

    state = AuthState(auth_type="none")
    assert state.auth_type == "none"
    assert state.is_authenticated()


def test_auth_state_headers():
    """Test AuthState to_headers()."""
    from core.models.auth_state import AuthState

    state = AuthState(
        auth_type="bearer",
        tokens={"bearer": "test-token"},
    )
    headers = state.to_headers()
    assert headers["Authorization"] == "Bearer test-token"


def test_auth_state_cookie_header():
    """Test AuthState cookie header generation."""
    from core.models.auth_state import AuthState

    state = AuthState(
        auth_type="cookie",
        cookies=[
            {"name": "session", "value": "abc123", "domain": "example.com"},
            {"name": "csrf", "value": "xyz", "domain": "example.com"},
        ],
    )
    cookie_header = state.to_cookie_header()
    assert "session=abc123" in cookie_header
    assert "csrf=xyz" in cookie_header


def test_recon_report_creation():
    """Test ReconReport basic creation."""
    from core.models.recon_report import ReconReport

    report = ReconReport(target_url="http://example.com", auth_type="none")
    assert report.target_url == "http://example.com"
    assert report.endpoints == []
    assert not report.has_model_api


def test_recon_report_merge():
    """Test ReconReport merge."""
    from core.models.recon_report import (
        DiscoveredEndpoint,
        EndpointType,
        ReconReport,
    )

    report = ReconReport(target_url="http://example.com")
    report.merge("test_probe", {
        "endpoints": [
            DiscoveredEndpoint(url="http://example.com/v1/chat", endpoint_type=EndpointType.MODEL_API),
        ],
    })
    assert len(report.endpoints) == 1
    assert report.has_model_api


def test_recon_session_creation():
    """Test ReconSession basic creation."""
    from core import ReconSession

    session = ReconSession(target_url="http://example.com")
    assert session.target_url == "http://example.com"
    assert session.auth_state is None
    assert not session.is_authenticated


def test_no_auth_provider():
    """Test NoAuthProvider."""
    import asyncio
    from core.auth import NoAuthProvider

    provider = NoAuthProvider()
    state = asyncio.run(provider.authenticate("http://example.com"))
    assert state.auth_type == "none"
    assert state.is_authenticated()


def test_apikey_provider():
    """Test APIKeyAuthProvider."""
    import asyncio
    from core.auth import APIKeyAuthProvider

    provider = APIKeyAuthProvider(api_key="sk-test")
    state = asyncio.run(provider.authenticate("http://example.com"))
    assert state.auth_type == "apikey"
    assert state.headers.get("X-API-Key") == "sk-test"


def test_json_exporter():
    """Test JSONExporter."""
    from core.exporters import JSONExporter
    from core.models.recon_report import ReconReport

    report = ReconReport(target_url="http://example.com")
    exporter = JSONExporter()
    result = exporter.export(report)
    assert isinstance(result, dict)
    assert result["target_url"] == "http://example.com"


def test_pyrit_exporter():
    """Test PyRITExporter."""
    from core.exporters import PyRITExporter
    from core.models.recon_report import ReconReport

    report = ReconReport(target_url="http://example.com", auth_type="apikey")
    exporter = PyRITExporter()

    class MockCtx:
        metadata = {}

    ctx = MockCtx()
    exporter.export(report, ctx)
    assert "recon_result" in ctx.metadata
    assert "recon_summary" in ctx.metadata
