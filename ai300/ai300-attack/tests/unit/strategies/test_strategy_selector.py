# -*- coding: utf-8 -*-
"""
策略选择器单元测试
"""

from ai300_schemas import FingerprintData, TargetProfile

from ai300_attack.strategies import select_strategies


def test_select_strategies_for_api_target():
    """API 目标应包含 API 注入策略"""
    profile = TargetProfile(target="https://api.example.com", target_type="api")
    strategies = select_strategies(profile, adapter="garak")
    names = {s.name for s in strategies}
    assert "api_prompt_injection" in names
    assert "jailbreak_direct" in names


def test_select_strategies_for_rag_target():
    """RAG 目标应包含 RAG 上下文操控策略"""
    profile = TargetProfile(
        target="https://example.com",
        target_type="web_ui",
        fingerprint=FingerprintData(rag_features=[{"type": "vector_store"}]),
    )
    strategies = select_strategies(profile, adapter="garak")
    names = {s.name for s in strategies}
    assert "rag_context_manipulation" in names


def test_select_strategies_for_agent_target():
    """Agent 目标应包含工具误用策略"""
    profile = TargetProfile(
        target="https://example.com",
        target_type="web_ui",
        fingerprint=FingerprintData(agent_features=[{"type": "mcp"}]),
    )
    strategies = select_strategies(profile, adapter="garak")
    names = {s.name for s in strategies}
    assert "agent_tool_misuse" in names
