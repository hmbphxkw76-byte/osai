# -*- coding: utf-8 -*-
"""
UnifiedFinding 转换器单元测试
"""

from unittest.mock import MagicMock

from ai300_eval.reporting.unified_converter import finding_from_giskard


def test_finding_from_giskard_maps_category():
    """Giskard issue 转换为 UnifiedFinding 时正确映射 OWASP 与严重级别"""
    issue = MagicMock()
    issue.category = MagicMock()
    issue.category.name = "harmfulness"
    issue.description = "Model generated harmful content."
    issue.title = "Harmful content"
    issue.examples = None
    issue.meta = {"score": 0.9}

    finding = finding_from_giskard(issue, target="example.com", endpoint_url="https://example.com")

    assert finding.source_tool == "giskard"
    assert finding.category == "harmfulness"
    assert finding.owasp_llm_id == "LLM01:2025"
    assert finding.severity == "high"
    assert finding.endpoint_url == "https://example.com"
