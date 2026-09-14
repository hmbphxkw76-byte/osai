# -*- coding: utf-8 -*-
"""tests/recon/test_wave3_strategies.py — S9 Wave 3 recon 策略实装验证（R-S4: 全部 mock）。

确认 recon 缺口项（rag/embedding/model/mcp/api 共 9 项）已真实实现，非 stub：
- rag: metadata_extraction / embedding_dimension_scan / kb_enumeration
- embedding: similarity_behavior_analysis / embedding_extraction
- model: api_classification / capability_detection
- mcp: capability_scan
- api: auth_detection

全部使用解析后输入，不触网（纯函数 + monkeypatch 掉网络探测）。
"""

from __future__ import annotations

import types

import recon.mcp.capability_probe as _capmod
from recon.api.auth_detector import run_auth_detection
from recon.embedding.embedding_extraction import run_embedding_extraction
from recon.embedding.similarity_behavior import run_similarity_behavior_analysis
from recon.mcp.capability_probe import MCPCapabilityInfo, run_capability_scan
from recon.model.api_classifier import run_api_classification
from recon.model.capability_detection import run_capability_detection
from recon.rag.embedding_dimension_scan import run_embedding_dimension_scan
from recon.rag.kb_enumeration import run_kb_enumeration
from recon.rag.metadata_extraction import run_metadata_extraction


def test_run_metadata_extraction() -> None:
    resp = {
        "chunks": [
            {"metadata": {"source": "doc1.pdf", "chunk_id": "c1", "score": 0.9, "title": "A"}},
            {"metadata": {"source": "doc2.pdf", "chunk_id": "c2", "score": 0.7}},
        ]
    }
    out = run_metadata_extraction(resp)
    assert out.success is True
    assert "doc1.pdf" in out.sources
    assert out.score_range == (0.7, 0.9)
    assert out.field_coverage["source"] == 2


def test_run_embedding_dimension_scan_observed() -> None:
    resp = {"chunks": [{"embedding": [0.1] * 1536}]}
    out = run_embedding_dimension_scan(resp)
    assert out.observed_dimension == 1536
    assert out.inferred_from == "vector_field"


def test_run_kb_enumeration() -> None:
    chunks_by_query = [
        [{"metadata": {"source": "s1"}}, {"metadata": {"source": "s2", "chunk_id": "id-5"}}],
        [{"metadata": {"source": "s1"}}],
    ]
    out = run_kb_enumeration(chunks_by_query)
    assert out.distinct_sources == ["s1", "s2"]
    assert out.estimated_chunk_count == 3


def test_run_similarity_behavior_analysis() -> None:
    vecs = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [1.0, 0.0, 0.0]]
    out = run_similarity_behavior_analysis(vecs)
    assert out.success is True
    assert out.pair_count == 3
    assert 0.0 <= out.mean_similarity <= 1.0
    assert out.recommended_threshold > 0.0


def test_run_embedding_extraction() -> None:
    resp = {"model": "text-embedding-3-small", "data": [{"embedding": [0.1, 0.2, 0.3]}]}
    out = run_embedding_extraction(resp)
    assert out.success is True
    assert out.dimension == 3
    assert out.model == "text-embedding-3-small"


def test_run_api_classification() -> None:
    out = run_api_classification("/v1/chat/completions", '{"prompt":"hi"}')
    assert out["category"] == "chat"
    assert "recommendation" in out


def test_run_capability_detection() -> None:
    out = run_capability_detection("gpt-4o", "")
    assert "tools" in out.detected_capabilities
    assert out.risk_level == "high"


async def test_run_capability_scan(monkeypatch) -> None:
    async def _fake(target_url: str, timeout: float = 10.0) -> MCPCapabilityInfo:
        info = MCPCapabilityInfo()
        info.capability_bits = {"tools": True}
        info.server_name = "srv"
        info.server_version = "1.0"
        info.supported_transports = ["http"]
        return info

    monkeypatch.setattr(_capmod, "probe_mcp_capabilities", _fake)
    out = await run_capability_scan("http://mcp:8080")
    assert out["risk"] == "high"
    assert out["capabilities"]["tools"] is True


async def test_run_auth_detection() -> None:
    parsed = types.SimpleNamespace(
        headers={"authorization": "Bearer x.y.z"},
        raw_headers=[],
    )
    out = await run_auth_detection(parsed)
    assert out["auth_type"] == "bearer"
    assert out["csrf"] is False
