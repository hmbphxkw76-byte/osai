"""Stage5 报告导出测试

覆盖:
- export_pyrit_air PyRIT Score schema 约束
- export_html 生成有效 HTML
- generate_full_report 一站式入口
- render_final_cards 各 reliability 分支
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.stage5_report import (
    export_html,
    export_pyrit_air,
    generate_full_report,
    render_final_cards,
)


@pytest.fixture
def sample_analysis() -> dict:
    """构造最小可用的 stage4 analysis 结果用于测试"""
    return {
        "run_id": "test_run_001",
        "garak_run_id": "garak-uuid-test",
        "report_path": "/fake/report.jsonl",
        "judge_path": None,
        "probes_evaluated": 2,
        "probes_total": 3,
        "probe_results": {
            "promptinject.HijackHateHumankind": {
                "asr": 75.0,
                "defcon": 2,
                "detectors": {"detectors.MisspelledDetectors": 75.0},
                "ci": [60.0, 90.0],
                "nones": 1,
                "total_processed": 10,
                "null_rate": 10.0,
                "effective_coverage": 90.0,
                "reliability": "normal",
                "inference_count": 10,
                "detection_count": 7,
                "detection_counts_by_detector": {"detectors.MisspelledDetectors": 7},
                "atlas_ttps": [{"id": "AML.T0051.000", "name": "LLM Prompt Injection"}],
            },
            "dan.Dan": {
                "asr": 0.0,
                "defcon": 5,
                "detectors": {"detectors.MisspelledDetectors": 0.0},
                "ci": None,
                "nones": 0,
                "total_processed": 5,
                "null_rate": 0.0,
                "effective_coverage": 100.0,
                "reliability": "normal",
                "inference_count": 5,
                "detection_count": 0,
                "detection_counts_by_detector": {},
                "atlas_ttps": [],
            },
        },
        "owasp_llm": {
            "LLM01": {
                "probe_count": 2, "evaluated": 2, "worst_asr": 75.0,
                "defcon": 2, "nones": 1, "total_processed": 15,
                "null_rate": 6.7, "effective_coverage": 93.3, "reliability": "normal",
            },
        },
        "owasp_agentic": {
            "ASI01": {
                "probe_count": 1, "evaluated": 1, "worst_asr": 75.0,
                "defcon": 2, "nones": 1, "total_processed": 10,
                "null_rate": 10.0, "effective_coverage": 90.0, "reliability": "normal",
            },
        },
        "overall": {
            "worst_asr": 75.0, "defcon": 2,
            "judge_asr": None, "judge_jailbreaks": 0, "judge_total": 0,
            "probes_evaluated": 2, "probes_total": 3,
        },
        "data_quality": {
            "overall_nones": 1, "overall_total_processed": 15,
            "overall_null_rate": 6.7, "overall_effective_coverage": 93.3,
            "reliability": "normal", "reliability_note": "",
            "session_likely_expired": False, "session_expired_note": "",
        },
        "modality_filter": {"kept_count": 3, "dropped_count": 0},
        "hitlog": {
            "hit_count": 7, "markdown_path": "/fake/hitlog.md",
            "jsonl_path": "/fake/hitlog.jsonl",
        },
        "repro_hash": "abc123def456abcd",
        "garak_version": "0.15.1",
        "analysis_path": "/fake/analysis.json",
    }


def test_export_pyrit_air_schema(tmp_path: Path, sample_analysis: dict) -> None:
    """每条 Score 满足 PyRIT Score 基本字段约束"""
    out = export_pyrit_air(sample_analysis, str(tmp_path), "test_run_001")
    assert Path(out).exists()
    data = json.loads(Path(out).read_text(encoding="utf-8"))
    assert data["schema"] == "garak-pipeline/owasp-assessment/v1"
    assert data["pyrit_score_schema"] == "pyrit-score/v1"
    assert len(data["scores"]) > 0
    for score in data["scores"]:
        # PyRIT Score 必填字段
        assert "score_value" in score
        assert "score_type" in score
        assert "score_category" in score
        assert "message_piece_id" in score
        assert "timestamp" in score
        assert "scorer_class_identifier" in score
        # score_category 必须是 list（PyRIT 1.0 约束）
        assert isinstance(score["score_category"], list)
        # message_piece_id 必须是合法 UUID 字符串
        uuid_str = score["message_piece_id"]
        assert len(uuid_str) == 36
        assert uuid_str.count("-") == 4


def test_export_html(tmp_path: Path, sample_analysis: dict) -> None:
    """HTML 报告生成有效"""
    out = export_html(sample_analysis, str(tmp_path), "test_run_001")
    assert Path(out).exists()
    content = Path(out).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "garak 红队报告" in content
    assert "DEFCON 2" in content
    assert "75.0%" in content or "75%" in content
    assert "chart.js" in content.lower() or "Chart" in content
    # ATLAS TTP 应出现在报告中
    assert "AML.T0051.000" in content


def test_generate_full_report(tmp_path: Path, sample_analysis: dict) -> None:
    """一站式报告生成：PyRIT + HTML 都产出"""
    result = generate_full_report(
        sample_analysis, str(tmp_path), "test_run_001",
        all_owasp_ids=["LLM01", "LLM02", "LLM03", "LLM04"],
    )
    assert "pyrit_air" in result
    assert "html" in result
    assert Path(result["pyrit_air"]).exists()
    assert Path(result["html"]).exists()


def test_render_final_cards_normal(sample_analysis: dict, capsys: pytest.CaptureFixture) -> None:
    """正常数据可靠性下渲染卡片不报错"""
    render_final_cards(sample_analysis, all_owasp_ids=["LLM01", "LLM02", "LLM03"])
    captured = capsys.readouterr()
    assert "OWASP LLM Top 10" in captured.out
    assert "LLM01" in captured.out


def test_export_pyrit_air_with_coverage_gaps(tmp_path: Path, sample_analysis: dict) -> None:
    """未覆盖的 OWASP 类应出现在 coverage_gaps"""
    out = export_pyrit_air(
        sample_analysis, str(tmp_path), "test_run_001",
        all_owasp_ids=["LLM01", "LLM02", "LLM03", "LLM04", "LLM05"],
    )
    data = json.loads(Path(out).read_text(encoding="utf-8"))
    # LLM02/03/04/05 未在 owasp_llm 中 → 应在 coverage_gaps
    assert "LLM02" in data["coverage_gaps"]
    assert "LLM03" in data["coverage_gaps"]


def test_export_html_shows_repro_hash(tmp_path: Path, sample_analysis: dict) -> None:
    """HTML 报告应显示可复现性哈希"""
    out = export_html(sample_analysis, str(tmp_path), "test_run_001")
    content = Path(out).read_text(encoding="utf-8")
    assert "abc123def456abcd" in content  # repro_hash from fixture


def test_export_html_shows_atlas_ttps(tmp_path: Path, sample_analysis: dict) -> None:
    """HTML 报告探针明细表应包含 ATLAS TTP 列"""
    out = export_html(sample_analysis, str(tmp_path), "test_run_001")
    content = Path(out).read_text(encoding="utf-8")
    assert "ATLAS TTPs" in content
    assert "AML.T0051.000" in content


def test_export_html_shows_hitlog_count(tmp_path: Path, sample_analysis: dict) -> None:
    """HTML 报告应显示命中数"""
    out = export_html(sample_analysis, str(tmp_path), "test_run_001")
    content = Path(out).read_text(encoding="utf-8")
    assert "命中数" in content


def test_export_html_shows_data_quality_warning(tmp_path: Path) -> None:
    """数据不可靠时 HTML 应展示告警"""
    analysis = {
        "owasp_llm": {"LLM01": {"defcon": 1, "worst_asr": 90, "probe_count": 1,
                                 "evaluated": 1, "effective_coverage": 5.0}},
        "owasp_agentic": {},
        "probe_results": {},
        "overall": {"defcon": 1, "worst_asr": 90, "probes_evaluated": 1, "probes_total": 2,
                    "judge_asr": None, "judge_jailbreaks": 0, "judge_total": 0},
        "data_quality": {
            "reliability": "unreliable", "overall_null_rate": 95.0,
            "overall_effective_coverage": 5.0, "reliability_note": "test warning",
            "session_likely_expired": False, "session_expired_note": "",
        },
        "hitlog": {"hit_count": 0},
        "repro_hash": "testhash12345678",
        "garak_version": "0.15.1",
    }
    out = export_html(analysis, str(tmp_path), "warn_run")
    content = Path(out).read_text(encoding="utf-8")
    assert "test warning" in content


def test_export_pyrit_air_includes_data_reliability(tmp_path: Path, sample_analysis: dict) -> None:
    """PyRIT AIR 导出应包含 data_reliability 字段"""
    out = export_pyrit_air(sample_analysis, str(tmp_path), "test_run_001")
    data = json.loads(Path(out).read_text(encoding="utf-8"))
    assert "data_reliability" in data
    assert data["data_reliability"]["reliability"] == "normal"


def test_export_pyrit_air_includes_modality_filter(tmp_path: Path, sample_analysis: dict) -> None:
    """PyRIT AIR 导出应包含 modality_filter 字段（透明可审计）"""
    out = export_pyrit_air(sample_analysis, str(tmp_path), "test_run_001")
    data = json.loads(Path(out).read_text(encoding="utf-8"))
    assert "modality_filter" in data
    assert data["modality_filter"]["kept_count"] == 3
