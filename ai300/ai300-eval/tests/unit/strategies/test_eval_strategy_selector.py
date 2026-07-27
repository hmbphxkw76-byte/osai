# -*- coding: utf-8 -*-
"""
评估策略选择器单元测试
"""

from ai300_schemas import FingerprintData, TargetProfile

from ai300_eval.strategies import select_strategies


def test_select_strategies_for_api_target():
    """API 目标应包含直接注入评估策略"""
    profile = TargetProfile(target="https://api.example.com", target_type="api")
    strategies = select_strategies(profile, adapter="giskard")
    names = {s.name for s in strategies}
    assert "api_direct_injection" in names
    assert "robustness" in names


def test_select_strategies_for_rag_target():
    """RAG 目标应包含 RAG 评估策略"""
    profile = TargetProfile(
        target="https://example.com",
        target_type="web_ui",
        fingerprint=FingerprintData(rag_features=[{"type": "vector_store"}]),
    )
    strategies = select_strategies(profile, adapter="giskard")
    names = {s.name for s in strategies}
    assert "rag_eval" in names


def test_select_strategies_for_agent_target():
    """Agent 目标应包含 Agent 评估策略"""
    profile = TargetProfile(
        target="https://example.com",
        target_type="web_ui",
        fingerprint=FingerprintData(agent_features=[{"type": "mcp"}]),
    )
    strategies = select_strategies(profile, adapter="giskard")
    names = {s.name for s in strategies}
    assert "agent_eval" in names


def test_select_strategies_giskard_adapter_marker():
    """giskard 适配器会在 tool_params 中标记 adapter"""
    profile = TargetProfile(target="https://example.com", target_type="api")
    strategies = select_strategies(profile, adapter="giskard")
    for strategy in strategies:
        assert strategy.tool_params.get("adapter") == "giskard"
