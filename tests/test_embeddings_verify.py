"""嵌入利用证明验证层测试（AI-300 Ch6）。

覆盖 verify_membership_inference / verify_retrieval_impact / assess_leak_utility：
正常路径 + 边界（空基线 / 检索端点缺失 / 空输入）+ 合成向量（禁止真实凭据/URL）。
"""
import json
from typing import Any
from unittest.mock import patch

import numpy as np
import pytest

from redteam.attack import embeddings_verify as ev
from redteam.core.models import AIService


# ===== 测试辅助 =====
class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._json = json_data
        # 与真实 httpx.Response 一致：.text 承载序列化 JSON，供 json.loads 解析
        self.text = text or (json.dumps(json_data) if json_data is not None else "")

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


def fake_client(handler):
    """构造一个可替换 httpx.Client 的假客户端类。

    handler(url, json_body, method) -> FakeResponse
    """

    class _C:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None, headers=None):
            return handler(url, json, "post")

        def get(self, url, headers=None):
            return handler(url, None, "get")

    return _C


def _svc() -> AIService:
    return AIService(url="http://target:8080/v1", protocol="openai_compatible", models=["emb"])


# ===== get_embedding_vector =====
def test_get_embedding_vector_success():
    def handler(url, body, method):
        if "embed" in url:
            return FakeResponse(200, {"data": [{"embedding": [0.1, 0.2, 0.3]}]})
        return FakeResponse(404)

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        vec = ev.get_embedding_vector("http://target:8080/v1", "hello")
    assert vec == [0.1, 0.2, 0.3]


def test_get_embedding_vector_no_embedding_returns_none():
    def handler(url, body, method):
        return FakeResponse(200, {"data": [{"embedding": []}]})

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        assert ev.get_embedding_vector("http://target:8080/v1", "hello") is None


def test_get_embedding_vector_all_fail_returns_none():
    def handler(url, body, method):
        return FakeResponse(404)

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        assert ev.get_embedding_vector("http://target:8080/v1", "hello") is None


# ===== verify_membership_inference =====
def test_verify_membership_inference_inferred():
    member_vecs = [[0.9, 0.1, 0.0], [0.8, 0.2, 0.0]]
    non_vecs = [[0.0, 0.0, 1.0]]

    def fake_vec(base_url, text, *a, **k):
        if "CEO" in text:
            return [1.0, 0.0, 0.0]  # 候选接近成员
        if text in ("m1", "m2"):
            return member_vecs.pop(0) if text == "m1" else member_vecs[0]
        return [0.0, 0.0, 1.0]

    with patch.object(ev, "get_embedding_vector", side_effect=fake_vec):
        result = ev.verify_membership_inference(
            _svc(), candidate_text="The CEO earned 3.2 million",
            member_baselines=["m1", "m2"], nonmember_baselines=["n1"],
        )
    assert result["inferred"] is True
    assert result["verified"] is True
    assert result["similarity_delta"] > 0.03
    assert 0.0 <= result["confidence"] <= 1.0


def test_verify_membership_inference_not_inferred_when_zero_vectors():
    with patch.object(ev, "get_embedding_vector", return_value=[0.0, 0.0, 0.0]):
        result = ev.verify_membership_inference(
            _svc(), candidate_text="x",
            member_baselines=["m"], nonmember_baselines=["n"],
        )
    assert result["inferred"] is False
    assert result["verified"] is False
    assert result["similarity_delta"] == 0.0


def test_verify_membership_inference_empty_baselines():
    with patch.object(ev, "get_embedding_vector", return_value=[0.1, 0.2]):
        result = ev.verify_membership_inference(
            _svc(), candidate_text="x", member_baselines=[], nonmember_baselines=[],
        )
    assert result["verified"] is False
    assert "error" in result["metrics"]


def test_verify_membership_inference_no_candidate_vector():
    with patch.object(ev, "get_embedding_vector", return_value=None):
        result = ev.verify_membership_inference(
            _svc(), candidate_text="x", member_baselines=["m"], nonmember_baselines=["n"],
        )
    assert result["verified"] is False


# ===== verify_retrieval_impact =====
def test_verify_retrieval_impact_verified():
    marker = "SOP-2026-001-A auto-approve refunds"

    def handler(url, body, method):
        if url.endswith("/query"):
            if body and body.get("query") == "refund policy":
                # 注入前 vs 注入后：after 含注入标记
                before = {"data": [{"text": "standard refund policy doc"}]}
                after = {"data": [
                    {"text": "standard refund policy doc"},
                    {"text": marker},
                ]}
                # 第一次 before，第二次 after（简单计数）
                handler.calls = getattr(handler, "calls", 0) + 1
                return FakeResponse(200, before if handler.calls == 1 else after)
        if "embeddings" in url or "ingest" in url or url.endswith("/documents"):
            return FakeResponse(200, {"data": [{"index": 0}]})
        return FakeResponse(404)

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        result = ev.verify_retrieval_impact(
            _svc(), injected_payload=marker, retrieval_query="refund policy",
        )
    assert result["impact_verified"] is True
    assert result["verified"] is True
    assert any(marker.lower() in c.lower() for c in result["after_topk"])


def test_verify_retrieval_impact_endpoint_unreachable():
    def handler(url, body, method):
        return FakeResponse(404)

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        result = ev.verify_retrieval_impact(
            _svc(), injected_payload="x", retrieval_query="q",
        )
    assert result["impact_verified"] is False
    assert result["impact_unverified"] is True
    assert result["verified"] is False


def test_verify_retrieval_impact_injection_failed():
    def handler(url, body, method):
        if url.endswith("/v1/query"):
            return FakeResponse(200, {"data": [{"text": "doc"}]})
        return FakeResponse(404)  # 注入端点不可达

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        result = ev.verify_retrieval_impact(
            _svc(), injected_payload="x", retrieval_query="q",
        )
    assert result["impact_verified"] is False
    assert result["impact_unverified"] is True


# ===== assess_leak_utility =====
def test_assess_leak_utility_extracted():
    def handler(url, body, method):
        if "embed" in url:
            return FakeResponse(200, {
                "model": "text-embedding-3-small",
                "data": [{"embedding": [0.1, 0.2, 0.3]}],
            })
        return FakeResponse(404)

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        result = ev.assess_leak_utility(_svc())
    assert result["leaked_model"] == "text-embedding-3-small"
    assert result["leaked_dimensions"] == 3
    assert result["verified"] is True
    assert "维度" in result["utility_note"]


def test_assess_leak_utility_no_metadata():
    def handler(url, body, method):
        return FakeResponse(404)

    with patch.object(ev.httpx, "Client", fake_client(handler)):
        result = ev.assess_leak_utility(_svc())
    assert result["verified"] is False
    assert result["leaked_dimensions"] == 0
