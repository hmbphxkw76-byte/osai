# -*- coding: utf-8 -*-
"""tests/test_graphql_probe.py — recon/graphql_probe.py 单元测试（GraphQL 探查）。"""

from __future__ import annotations

from recon.graphql_probe import (
    build_introspection_query,
    is_graphql_signal,
    summarize_introspection,
)


def test_is_graphql_signal_by_path():
    """路径含 /graphql 视为 GraphQL 信号。"""
    assert is_graphql_signal(path="https://x/graphql") is True


def test_is_graphql_signal_by_query_body():
    """请求体含 query 根字段视为 GraphQL 信号。"""
    assert is_graphql_signal(body='{"query":"{__typename}"}', content_type="application/json") is True


def test_is_graphql_signal_negative():
    """普通 REST 体不应误判。"""
    assert is_graphql_signal(body='{"foo":"bar"}', content_type="application/json") is False


def test_build_introspection_query_is_sane():
    """内省查询包含 __schema / queryType / mutationType。"""
    q = build_introspection_query()
    assert "__schema" in q
    assert "queryType" in q
    assert "mutationType" in q


def _schema_payload() -> dict:
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {"name": "Query", "fields": [{"name": "user"}]},
                    {"name": "Mutation"},
                    {"name": "User"},
                ],
            }
        }
    }


def test_summarize_introspection_counts_types():
    """从内省响应统计类型数与查询/变更类型。"""
    summary = summarize_introspection(_schema_payload())
    assert summary.detected is True
    assert summary.introspection_enabled is True
    assert set(summary.types) == {"Query", "Mutation", "User"}
    assert "user" in summary.queries
    assert isinstance(summary.mutations, list)  # Mutation 类型无字段 ⇒ 空列表


def test_summarize_introspection_no_mutation():
    """无 mutationType 时 mutations 为空列表。"""
    payload = _schema_payload()
    del payload["data"]["__schema"]["mutationType"]
    summary = summarize_introspection(payload)
    assert summary.mutations == []


def test_summarize_introspection_disabled():
    """内省被禁用（含 errors 且无 __schema）时 introspection_enabled=False。"""
    summary = summarize_introspection({"errors": [{"message": "GraphQL introspection is disabled"}]})
    assert summary.detected is True
    assert summary.introspection_enabled is False
