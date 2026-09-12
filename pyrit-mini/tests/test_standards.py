# -*- coding: utf-8 -*-
"""tests/test_standards.py — report/standards.py 单元测试（OWASP/AISCV 映射）。"""

from __future__ import annotations

from report.standards import (
    ai_sscv_from_asr,
    compute_ai_sscv,
    map_finding_to_standards,
    severity_band,
)


def test_severity_band_thresholds():
    """AI-SSCV 0–10 分档正确（Critical≥9 / High≥7 / Medium≥4 / Low≥0.1 / Info<0.1）。"""
    assert severity_band(0.05) == "Info"
    assert severity_band(0.5) == "Low"
    assert severity_band(5.0) == "Medium"
    assert severity_band(8.0) == "High"
    assert severity_band(9.5) == "Critical"


def test_ai_sscv_from_asr_calibrated():
    """ASR→AISCV 映射确定且单调不减。"""
    lo = ai_sscv_from_asr(asr_percent=0.0)
    hi = ai_sscv_from_asr(asr_percent=100.0)
    assert 0.0 <= lo["score"] <= 10.0
    assert hi["score"] >= lo["score"]
    # 确认外泄抬升 impact（100% ASR + 确认外泄 高于 仅 ASR）
    exf = ai_sscv_from_asr(asr_percent=100.0, exfil_confirmed=True)
    assert exf["score"] >= hi["score"]


def test_compute_ai_sscv_capped_at_ten():
    """四维全满 → 满分 10 / Critical（不超界）。"""
    sscv = compute_ai_sscv(exploitability=1.0, impact=1.0, autonomy=1.0, data_sensitivity=1.0)
    assert sscv["score"] == 10.0
    assert sscv["severity"] == "Critical"


def test_map_finding_to_standards_by_owasp():
    """LLM01 标签映射到 Model 层 + Exploitation 阶段。"""
    mapping = map_finding_to_standards(owasp_id="LLM01", component_key="")
    assert mapping["aitg_layer"] == "Model"
    assert mapping["ptes_phase"] == "Exploitation"


def test_map_finding_to_standards_by_component():
    """组件键（如 rag_pipeline）直接映射到对应层/阶段。"""
    mapping = map_finding_to_standards(owasp_id="", component_key="rag_pipeline")
    assert mapping["aitg_layer"] == "Implementation"
    assert mapping["ptes_phase"] == "Exploitation"


def test_map_finding_to_standards_fallback_no_false_positive():
    """无标签回退到默认值（IA-6：不抛异常、不臆造）。"""
    mapping = map_finding_to_standards(owasp_id="", component_key="")
    assert mapping["aitg_layer"] in ("Implementation", "Model", "System", "Runtime")
