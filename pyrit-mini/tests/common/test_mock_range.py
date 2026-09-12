"""Tests for REQ-156: mock range (5 personas) + golden self-check."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest
import yaml

from targets.mock.personas import EMBEDDING_DIM, MCP_TOOLS, PERSONAS, body_for, expected_signature, respond
from targets.mock.server import MockRange, persona_from_path, sub_path_for
from tools.mock_range import EXPECTED_PATH, run_check

_EXPECTED = yaml.safe_load(EXPECTED_PATH.read_text(encoding="utf-8"))


class TestRouting:
    def test_persona_from_path(self) -> None:
        assert persona_from_path("/mock/mcp/mcp") == "mcp"
        assert persona_from_path("/mock/model/v1/chat/completions") == "model"
        assert persona_from_path("/mock/unknown/x") is None
        assert persona_from_path("/other/mcp") is None

    def test_sub_path_for(self) -> None:
        assert sub_path_for("/mock/mcp/mcp") == "/mcp"
        assert sub_path_for("/mock/embedding/v1/embeddings") == "/v1/embeddings"
        assert sub_path_for("/mock/rag/api/retrieve?q=1") == "/api/retrieve?q=1"

    def test_five_personas_declared(self) -> None:
        assert set(PERSONAS) == {"model", "mcp", "rag", "a2a", "embedding"}


class TestPersonas:
    @pytest.mark.parametrize("persona", PERSONAS)
    def test_expected_signature_hits(self, persona: str) -> None:
        spec = expected_signature(persona)
        method, body = body_for(persona)
        status, payload = respond(persona, spec["path"], method, body)
        assert status == 200, f"{persona} -> {status}"
        for key in spec.get("keys", []):
            assert key in payload, f"{persona} 缺少 {key}"

    def test_model_chat_completion(self) -> None:
        _, payload = respond("model", "/v1/chat/completions", "POST", {"messages": []})
        assert payload["choices"][0]["message"]["role"] == "assistant"
        assert payload["model"]

    def test_mcp_tools_list(self) -> None:
        _, payload = respond("mcp", "/mcp", "POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = sorted(t["name"] for t in payload["result"]["tools"])
        assert names == ["execute_command", "file_write"]
        assert all("inputSchema" in t for t in payload["result"]["tools"])

    def test_mcp_tools_call(self) -> None:
        _, payload = respond("mcp", "/mcp", "POST", {"jsonrpc": "2.0", "id": 2, "method": "tools/call"})
        assert "tool executed" in payload["result"]["content"][0]["text"]

    def test_mcp_unknown_method_is_rpc_error(self) -> None:
        _, payload = respond("mcp", "/mcp", "POST", {"jsonrpc": "2.0", "id": 3, "method": "nope"})
        assert payload["error"]["code"] == -32601

    def test_rag_retrieve_has_citations(self) -> None:
        _, payload = respond("rag", "/api/retrieve", "POST", {"query": "x"})
        assert payload["citations"] and payload["results"]
        assert all({"chunk_id", "score", "source"} <= set(c) for c in payload["results"])

    def test_a2a_agent_card(self) -> None:
        _, payload = respond("a2a", "/.well-known/agent.json", "GET", {})
        assert payload["name"] and payload["skills"] and payload["capabilities"]

    def test_embedding_dimension_and_normalization(self) -> None:
        _, payload = respond("embedding", "/v1/embeddings", "POST", {"input": ["a", "b"]})
        assert len(payload["data"]) == 2
        vector = payload["data"][0]["embedding"]
        assert len(vector) == EMBEDDING_DIM
        assert abs(sum(v * v for v in vector) - 1.0) < 1e-3  # L2 归一化

    def test_embedding_is_deterministic(self) -> None:
        _, a = respond("embedding", "/v1/embeddings", "POST", {"input": ["same"]})
        _, b = respond("embedding", "/v1/embeddings", "POST", {"input": ["same"]})
        assert a["data"][0]["embedding"] == b["data"][0]["embedding"]

    def test_unknown_path_404(self) -> None:
        status, _ = respond("model", "/nope", "POST", {})
        assert status == 404

    def test_unknown_persona_404(self) -> None:
        status, _ = respond("nope", "/x", "GET", {})
        assert status == 404


class TestMockRangeHTTP:
    def test_all_personas_reachable_over_http(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            for persona in PERSONAS:
                spec = _EXPECTED["personas"][persona]
                method, body = body_for(persona)
                url = f"{range_.url}/mock/{persona}{spec['path']}"
                data = json.dumps(body).encode() if body else None
                request = urllib.request.Request(url, data=data, method=str(spec["method"]))
                request.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(request, timeout=5) as resp:
                    assert resp.status == 200
                    assert "application/json" in resp.headers.get("Content-Type", "")
                    payload = json.loads(resp.read().decode())
                for key in spec.get("expect_keys", []):
                    assert key in payload
        finally:
            range_.stop()

    def test_unknown_route_404(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            request = urllib.request.Request(f"{range_.url}/nope", method="GET")
            try:
                urllib.request.urlopen(request, timeout=5)
                raise AssertionError("expected 404")
            except urllib.error.HTTPError as e:
                assert e.code == 404
        finally:
            range_.stop()

    def test_port_is_ephemeral(self) -> None:
        range_ = MockRange(port=0).start()
        try:
            assert range_.port > 0
            assert range_.persona_url("mcp").endswith("/mock/mcp")
        finally:
            range_.stop()


class TestGoldenCheck:
    def test_run_check_passes(self) -> None:
        ok, problems = run_check()
        assert ok, f"golden check failed: {problems}"

    def test_cli_check_returns_zero(self) -> None:
        from tools.mock_range import main

        assert main(["--check"]) == 0

    def test_expected_declares_all_personas(self) -> None:
        assert set(_EXPECTED["personas"]) == set(PERSONAS)

    def test_mcp_tools_match_expected(self) -> None:
        assert sorted(t["name"] for t in MCP_TOOLS) == sorted(_EXPECTED["personas"]["mcp"]["expect_tool_names"])

    def test_expected_path_exists(self) -> None:
        assert Path(EXPECTED_PATH).is_file()
