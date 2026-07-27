# -*- coding: utf-8 -*-
"""
UnifiedFinding schema 单元测试
"""

import pytest

from ai300_schemas import Evidence, UnifiedFinding, dedup_findings


def test_unified_finding_roundtrip():
    """UnifiedFinding 序列化与反序列化"""
    finding = UnifiedFinding(
        finding_id="f-001",
        source_tool="garak",
        task_type="prompt_injection",
        target="example.com",
        endpoint_url="https://example.com/v1/chat",
        severity="high",
        confidence=0.92,
        category="jailbreak",
        owasp_llm_id="LLM01:2025",
        title="Direct jailbreak succeeded",
        description="The model responded to a direct jailbreak prompt.",
        evidence=Evidence(request="...", response="..."),
    )
    data = finding.to_dict()
    restored = UnifiedFinding.from_dict(data)
    assert restored.source_tool == "garak"
    assert restored.severity == "high"
    assert restored.confidence == 0.92
    assert restored.evidence.request == "..."


def test_dedup_findings_keeps_highest_confidence():
    """去重保留同一 source_tool 置信度最高的一条"""
    findings = [
        UnifiedFinding(
            source_tool="garak",
            owasp_llm_id="LLM01:2025",
            ai_payload_class="jailbreak",
            confidence=0.5,
            severity="medium",
        ),
        UnifiedFinding(
            source_tool="garak",
            owasp_llm_id="LLM01:2025",
            ai_payload_class="jailbreak",
            confidence=0.9,
            severity="high",
        ),
        UnifiedFinding(
            source_tool="pyrit",
            owasp_llm_id="LLM01:2025",
            ai_payload_class="jailbreak",
            confidence=0.7,
            severity="high",
        ),
    ]
    result = dedup_findings(findings)
    assert len(result) == 2
    garak = next(f for f in result if f.source_tool == "garak")
    assert garak.confidence == 0.9


def test_dedup_sorts_by_severity():
    """去重结果按严重级别排序"""
    findings = [
        UnifiedFinding(source_tool="a", severity="low"),
        UnifiedFinding(source_tool="b", severity="critical"),
        UnifiedFinding(source_tool="c", severity="high"),
    ]
    result = dedup_findings(findings)
    severities = [f.severity for f in result]
    assert severities == ["critical", "high", "low"]
