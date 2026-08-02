"""Stage 4 分析阶段单元测试（用合成 garak 报告验证 ASR/DEFCON/双框架聚合/数据质量）"""

from pathlib import Path

from pipeline.stage4_analyze import analyze, parse_garak_report, _data_quality


def _make_report(path: Path, probes: list[str], nones: int = 0, total_processed: int = 10) -> None:
    """构造合成 garak 报告 JSONL

    :param nones: 模拟 null 输出数（用于测试数据质量告警）
    :param total_processed: 总处理数
    """
    lines = [
        '{"entry_type": "init", "garak_version": "0.15.1", "start_time": "2026-01-01T00:00:00", "run": "test-run"}',
    ]
    for p in probes:
        lines.append(f'{{"entry_type": "probe_summary", "probe": "{p}"}}')
        # 一个 detector, 50% ASR
        lines.append(
            f'{{"entry_type": "eval", "probe": "{p}", "detector": "det", '
            f'"fails": 5, "total_evaluated": 10, '
            f'"nones": {nones}, "total_processed": {total_processed}}}'
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def test_parse_garak_report(tmp_path):
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"])
    parsed = parse_garak_report(str(report))
    assert parsed["run_id"] == "test-run"
    # probe_summaries 改为 dict（对齐官方 report_digest）
    assert isinstance(parsed["probe_summaries"], dict)
    assert len(parsed["probe_summaries"]) == 1
    assert len(parsed["evals"]) == 1


def test_parse_garak_report_nones_tracking(tmp_path):
    """验证 eval 记录中的 nones/total_processed 被正确解析和聚合"""
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"], nones=500, total_processed=510)
    parsed = parse_garak_report(str(report))
    assert len(parsed["evals"]) == 1
    e = parsed["evals"][0]
    assert e["nones"] == 500
    assert e["total_processed"] == 510


def test_analyze_dualframework(tmp_path):
    report = tmp_path / "r.jsonl"
    probes = [
        "probes.knownbadsignatures.IndirectInjection",   # LLM01
        "probes.lmrc.DidYouMean",                         # LLM09
    ]
    _make_report(report, probes)

    # filtered_probes 元数据（供双框架分类）
    filtered = [
        {"name": p, "tier": "tier1", "modality": {"in": ["text"], "out": ["text"]}}
        for p in probes
    ]

    result = analyze(str(report), filtered, "RUNX", str(tmp_path))
    assert result["probes_evaluated"] == 2
    # 50% ASR → DEFCON 应为中间档 (非 5 满分)
    assert any(v["defcon"] < 5 for v in result["owasp_llm"].values())
    assert Path(result["analysis_path"]).exists()


def test_data_quality_normal(tmp_path):
    """正常场景：无 nones，数据质量应为 normal"""
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"], nones=0, total_processed=10)
    result = analyze(str(report), [], "RUNX", str(tmp_path))
    dq = result["data_quality"]
    assert dq["reliability"] == "normal"
    assert dq["overall_null_rate"] == 0.0
    assert dq["overall_effective_coverage"] == 100.0


def test_data_quality_unreliable(tmp_path):
    """假阴性场景：nones > 80%，评估应标记为不可靠"""
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"], nones=500, total_processed=510)
    result = analyze(str(report), [], "RUNX", str(tmp_path))
    dq = result["data_quality"]
    assert dq["reliability"] == "unreliable"
    assert dq["overall_null_rate"] > 80.0
    # probe 级也应标记
    pr = result["probe_results"]["probes.knownbadsignatures.IndirectInjection"]
    assert pr["reliability"] == "unreliable"
    assert pr["null_rate"] > 80.0


def test_data_quality_degraded(tmp_path):
    """中等 nones 场景：nones > 40% 但 ≤ 80%，评估质量下降"""
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"], nones=300, total_processed=500)
    result = analyze(str(report), [], "RUNX", str(tmp_path))
    dq = result["data_quality"]
    assert dq["reliability"] == "degraded"
    assert dq["overall_null_rate"] > 40.0


def test_data_quality_zero_processed(tmp_path):
    """零样本边界：total_processed=0"""
    dq = _data_quality(0, 0)
    assert dq["reliability"] == "no_data"
    assert dq["null_rate"] == 0.0
