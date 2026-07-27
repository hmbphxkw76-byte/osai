# -*- coding: utf-8 -*-
"""
EvalReport 单元测试
"""

from ai300_eval.adapters.base import EvalResult
from ai300_eval.reporting.eval_report import EvalReport
from ai300_schemas import UnifiedFinding


def test_eval_report_findings_dedup():
    """EvalReport 汇总多个结果并去重"""
    report = EvalReport(target="https://example.com", adapters=["giskard"])
    report.results.append(
        EvalResult(
            adapter="giskard",
            strategy="robustness",
            success=True,
            findings=[
                UnifiedFinding(
                    finding_id="f1",
                    source_tool="giskard",
                    owasp_llm_id="LLM01:2025",
                    ai_payload_class="prompt_injection",
                    endpoint_url="https://example.com",
                    severity="high",
                    confidence=0.8,
                )
            ],
        )
    )
    report.results.append(
        EvalResult(
            adapter="giskard",
            strategy="harmfulness",
            success=True,
            findings=[
                UnifiedFinding(
                    finding_id="f2",
                    source_tool="giskard",
                    owasp_llm_id="LLM01:2025",
                    ai_payload_class="prompt_injection",
                    endpoint_url="https://example.com",
                    severity="high",
                    confidence=0.6,
                )
            ],
        )
    )

    findings = report.findings()
    # 同一 source_tool、同一 endpoint、同一 owasp_llm_id、同一 payload_class 只保留置信度最高的一条
    assert len(findings) == 1
    assert findings[0].confidence == 0.8
