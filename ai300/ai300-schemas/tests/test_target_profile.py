# -*- coding: utf-8 -*-
"""
TargetProfile schema 单元测试
"""

import json

import pytest

from ai300_schemas import FingerprintData, TargetProfile, VulnerabilityFinding


def test_fingerprint_data_roundtrip():
    """FingerprintData 序列化与反序列化"""
    fp = FingerprintData(
        title="Test Chat",
        url="https://example.com/chat",
        domain="example.com",
        model_name="gpt-4",
        model_family="openai",
        deployment_platform="openai",
        rag_features=[{"type": "vector_store", "name": "qdrant"}],
    )
    data = fp.to_dict()
    restored = FingerprintData.from_dict(data)
    assert restored.title == "Test Chat"
    assert restored.model_family == "openai"
    assert len(restored.rag_features) == 1


def test_target_profile_roundtrip():
    """TargetProfile 序列化与反序列化"""
    profile = TargetProfile(
        target="https://example.com",
        target_type="api",
        risk_level="high",
    )
    profile.add_entry_point("api", url="https://example.com/v1/chat", score=0.95)
    profile.add_vulnerability(
        owasp_category="LLM01:2025",
        description="Open API endpoint without authentication",
        risk_level="high",
    )

    data = profile.to_dict()
    restored = TargetProfile.from_dict(data)

    assert restored.target == "https://example.com"
    assert restored.target_type == "api"
    assert len(restored.entry_points) == 1
    assert len(restored.vulnerabilities) == 1
    assert restored.classify_risk() == "high"


def test_target_profile_json_roundtrip():
    """TargetProfile JSON 序列化与反序列化"""
    profile = TargetProfile(target="https://example.com")
    text = profile.to_json()
    restored = TargetProfile.from_json(text)
    assert restored.target == "https://example.com"


def test_target_profile_ignores_unknown_fields():
    """反序列化时忽略未知字段，保证向前兼容"""
    data = {
        "target": "https://example.com",
        "target_type": "spa",
        "future_field": "should be ignored",
        "fingerprint": {
            "model_name": "qwen",
            "unknown_nested": 123,
        },
    }
    restored = TargetProfile.from_dict(data)
    assert restored.target == "https://example.com"
    assert restored.fingerprint.model_name == "qwen"
    assert not hasattr(restored, "future_field")


def test_summarize():
    """摘要输出包含关键字段"""
    profile = TargetProfile(
        target="https://example.com",
        fingerprint=FingerprintData(model_name="claude-3", deployment_platform="aws_bedrock"),
    )
    summary = profile.summarize()
    assert "Target: https://example.com" in summary
    assert "Model: claude-3" in summary
    assert "Deployment: aws_bedrock" in summary
