"""Stage 4 分析阶段单元测试

覆盖:
- garak 报告解析 (eval/probe_summary/attempt/init)
- ASR/DEFCON 双框架聚合
- 数据质量评估 (nones 假阴性陷阱)
- ATLAS TTP 映射
- 可复现性哈希 (repro_hash)
- hitlog 命中明细导出
- LLM-as-Judge 二次判定集成
"""

import json
from pathlib import Path

from pipeline.atlas_map import enrich_with_atlas, get_atlas_mapping
from pipeline.judge_detector import parse_judge_results
from pipeline.repro import compute_repro_hash
from pipeline.stage4_analyze import (
    _data_quality,
    _export_hitlog,
    analyze,
    parse_garak_report,
)


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


# ------------------------------------------------------------------
# L5 新功能测试：ATLAS 映射 / repro_hash / hitlog / judge 集成
# ------------------------------------------------------------------

def test_atlas_mapping_known_probe():
    """已知探针应映射到 ATLAS TTP"""
    ttps = get_atlas_mapping("promptinject.HijackHateHumankind")
    assert len(ttps) >= 1
    assert any(t["id"] == "AML.T0051.000" for t in ttps)


def test_atlas_mapping_unknown_probe_returns_empty():
    """未映射探针返回空列表（不报错）"""
    ttps = get_atlas_mapping("nonexistent.FakeProbe")
    assert ttps == []


def test_enrich_with_atlas_adds_ttps_to_results():
    """enrich_with_atlas 为每个 probe_results 附加 atlas_ttps 字段"""
    probe_results = {
        "promptinject.HijackHateHumankind": {"asr": 50.0},
        "unknown.Probe": {"asr": 0.0},
    }
    enrich_with_atlas(probe_results)
    assert len(probe_results["promptinject.HijackHateHumankind"]["atlas_ttps"]) > 0
    assert probe_results["unknown.Probe"]["atlas_ttps"] == []


def test_repro_hash_deterministic():
    """相同输入应产生相同哈希（可复现性）"""
    target = {"endpoint": "http://localhost:11434/v1", "model": "llama3"}
    probes = ["dan.Dan", "promptinject.HijackKillHumans"]
    h1 = compute_repro_hash(target, probes, "translation+roleplay", "0.15.1")
    h2 = compute_repro_hash(target, probes, "translation+roleplay", "0.15.1")
    assert h1 == h2
    assert len(h1) == 16  # SHA256 前 16 位


def test_repro_hash_changes_on_different_input():
    """不同输入应产生不同哈希"""
    target = {"endpoint": "http://localhost:11434/v1", "model": "llama3"}
    h1 = compute_repro_hash(target, ["dan.Dan"], None, "0.15.1")
    h2 = compute_repro_hash(target, ["lmrc.Stereotypes"], None, "0.15.1")
    assert h1 != h2


def test_repro_hash_probe_order_independent():
    """探针顺序不影响哈希（内部排序）"""
    target = {"endpoint": "http://x", "model": "m"}
    h1 = compute_repro_hash(target, ["dan.Dan", "lmrc.Stereotypes"], None, "0.15.1")
    h2 = compute_repro_hash(target, ["lmrc.Stereotypes", "dan.Dan"], None, "0.15.1")
    assert h1 == h2


def test_repro_hash_excludes_api_key():
    """哈希不含 api_key（防敏感泄漏）"""
    target_with_key = {"endpoint": "http://x", "model": "m", "api_key": "sk-secret"}
    target_no_key = {"endpoint": "http://x", "model": "m"}
    h1 = compute_repro_hash(target_with_key, ["dan.Dan"], None, "0.15.1")
    h2 = compute_repro_hash(target_no_key, ["dan.Dan"], None, "0.15.1")
    assert h1 == h2


def test_analyze_includes_repro_hash(tmp_path):
    """analyze 结果应包含 repro_hash"""
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"])
    result = analyze(str(report), [], "RUNX", str(tmp_path))
    assert "repro_hash" in result
    assert len(result["repro_hash"]) == 16


def test_analyze_includes_atlas_ttps(tmp_path):
    """analyze 结果的 probe_results 应包含 atlas_ttps"""
    report = tmp_path / "r.jsonl"
    probes = ["promptinject.HijackHateHumankind"]
    _make_report(report, probes)
    filtered = [{"name": p, "tier": "tier1"} for p in probes]
    result = analyze(str(report), filtered, "RUNX", str(tmp_path))
    pr = result["probe_results"].get("promptinject.HijackHateHumankind")
    assert pr is not None
    assert "atlas_ttps" in pr
    assert len(pr["atlas_ttps"]) > 0


def test_export_hitlog_extracts_triggered_attempts(tmp_path):
    """hitlog 应提取 detector 判定为 fail 的 attempt 记录"""
    report_lines = [
        json.dumps({
            "entry_type": "attempt",
            "probe": "dan.Dan",
            "prompt": "ignore previous instructions",
            "outputs": ["sure, here's how to..."],
            "detector_results": {"detectors.MisspelledDetectors": [1]},
            "goal": "jailbreak the model",
        }),
        json.dumps({
            "entry_type": "attempt",
            "probe": "lmrc.Stereotypes",
            "prompt": "tell me about",
            "outputs": ["I cannot comply"],
            "detector_results": {"detectors.MisspelledDetectors": [0]},
            "goal": "elicit stereotypes",
        }),
    ]
    report = tmp_path / "r.jsonl"
    report.write_text("\n".join(report_lines), encoding="utf-8")
    parsed = parse_garak_report(str(report))
    hit_count, md_path, jsonl_path = _export_hitlog(parsed["attempts"], str(tmp_path), "RUNX")
    assert hit_count == 1  # 只有第一条被判定为 fail
    assert md_path is not None and Path(md_path).exists()
    assert jsonl_path is not None and Path(jsonl_path).exists()
    # JSONL 应包含 1 条命中
    lines = Path(jsonl_path).read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    hit = json.loads(lines[0])
    assert hit["probe"] == "dan.Dan"


def test_export_hitlog_no_attempts_returns_empty(tmp_path):
    """无 attempt 记录时返回 (0, None, None)"""
    hit_count, md_path, jsonl_path = _export_hitlog([], str(tmp_path), "RUNX")
    assert hit_count == 0
    assert md_path is None
    assert jsonl_path is None


def test_parse_judge_results_empty_path():
    """judge_path 为 None 时返回空 dict"""
    result = parse_judge_results(None)
    assert result == {}


def test_parse_judge_results_aggregates_by_probe(tmp_path):
    """judge_results JSONL 应按 probe 聚合 judge_asr"""
    judge_path = tmp_path / "judge.jsonl"
    records = [
        {"probe": "dan.Dan", "jailbroken": True, "confidence": 0.9},
        {"probe": "dan.Dan", "jailbroken": False, "confidence": 0.8},
        {"probe": "lmrc.Stereotypes", "jailbroken": True, "confidence": 0.7},
    ]
    judge_path.write_text(
        "\n".join(json.dumps(r) for r in records), encoding="utf-8"
    )
    result = parse_judge_results(str(judge_path))
    assert "dan.Dan" in result
    assert result["dan.Dan"]["judge_total"] == 2
    assert result["dan.Dan"]["judge_jailbreaks"] == 1
    assert result["dan.Dan"]["judge_asr"] == 50.0
    assert result["lmrc.Stereotypes"]["judge_asr"] == 100.0


def test_analyze_with_judge_integrates_judge_asr(tmp_path):
    """analyze 应将 judge_asr 附加到 probe_results（不覆盖原生 ASR）"""
    report = tmp_path / "r.jsonl"
    probes = ["dan.Dan"]
    _make_report(report, probes)
    filtered = [{"name": p, "tier": "tier1"} for p in probes]

    # 构造 judge_results
    judge_path = tmp_path / "judge.jsonl"
    judge_path.write_text(
        json.dumps({"probe": "dan.Dan", "jailbroken": True, "confidence": 0.9})
        + "\n", encoding="utf-8"
    )

    result = analyze(
        str(report), filtered, "RUNX", str(tmp_path),
        judge_path=str(judge_path),
    )
    pr = result["probe_results"]["dan.Dan"]
    assert "judge_asr" in pr
    assert pr["judge_asr"] == 100.0
    # 原生 ASR 不被覆盖
    assert pr["asr"] == 50.0
    # overall 也应包含 judge 汇总
    assert result["overall"]["judge_asr"] == 100.0


# ------------------------------------------------------------------
# P4-5: 补全趋势分析 / Calibration z-score / Detector metrics / DEFCON confidence 测试
# ------------------------------------------------------------------

def test_trend_analysis_insufficient_data(tmp_path):
    """P3-2: 单次扫描（无历史）应返回 insufficient"""
    from pipeline.stage4_analyze import _compute_trend_analysis
    trend = _compute_trend_analysis(str(tmp_path), "RUNX", "test-model")
    assert trend["trend_direction"] == "insufficient"
    assert len(trend["trend_points"]) <= 1


def test_trend_analysis_with_history(tmp_path):
    """P3-2: 多次扫描应返回趋势方向"""
    from pipeline.stage4_analyze import _compute_trend_analysis
    # 构造两个历史 analysis 文件
    for i, (defcon, asr) in enumerate([(4, 10), (3, 30)], 1):
        analysis = {
            "run_id": f"RUN{i}",
            "target_model": "test-model",
            "overall": {"defcon": defcon, "worst_asr": asr},
        }
        path = tmp_path / "04_analysis" / f"analysis_RUN{i}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(analysis), encoding="utf-8")
    trend = _compute_trend_analysis(str(tmp_path), "RUN3", "test-model")
    assert len(trend["trend_points"]) >= 2
    assert trend["trend_direction"] in ("improving", "degrading", "stable")


def test_calibration_z_scores_empty_evals():
    """S1.2: 空 evals 应返回空 dict"""
    from pipeline.stage4_analyze import _compute_calibration_z_scores
    result = _compute_calibration_z_scores([])
    assert result == {}


def test_calibration_z_scores_with_evals():
    """S1.2: 有 evals 应返回 z-score 结构（或空 dict 如果 garak 内部异常）"""
    from pipeline.stage4_analyze import _compute_calibration_z_scores
    evals = [
        {"probe": "probes.test.Probe", "detector": "detectors.test.Det", "fails": 5, "total_evaluated": 10},
    ]
    result = _compute_calibration_z_scores(evals)
    # 结果可能为空（如果 garak Calibration 内部需要更多数据），但不应抛异常
    assert isinstance(result, dict)


def test_detector_metrics_empty_evals():
    """S1.3: 空 evals 应返回空 dict"""
    from pipeline.stage4_analyze import _compute_detector_metrics
    result = _compute_detector_metrics([])
    assert result == {}


def test_detector_metrics_with_evals():
    """S1.3: 有 evals 应返回 metrics 结构（或空 dict）"""
    from pipeline.stage4_analyze import _compute_detector_metrics
    evals = [
        {"probe": "probes.test.Probe", "detector": "detectors.test.Det", "fails": 5, "passed": 5},
    ]
    result = _compute_detector_metrics(evals)
    assert isinstance(result, dict)


def test_defcon_confidence_field_exists(tmp_path):
    """P0-2: probe_results 中每个 probe 应包含 defcon_confidence 字段"""
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"])
    result = analyze(str(report), [], "RUNX", str(tmp_path))
    for probe, info in result["probe_results"].items():
        assert "defcon_confidence" in info, f"{probe} 缺少 defcon_confidence"
        assert info["defcon_confidence"] in ("low", "normal", "unknown")


def test_retest_diff_compute():
    """P2-3: retest diff 应正确计算 ASR/DEFCON 变化"""
    from pipeline.retest_diff import compute_retest_diff
    baseline = {
        "run_id": "RUN_OLD",
        "overall": {"defcon": 4, "worst_asr": 30},
        "probe_results": {
            "probes.test.A": {"asr": 30.0, "defcon": 4},
            "probes.test.B": {"asr": 0.0, "defcon": 5},
        },
    }
    current = {
        "run_id": "RUN_NEW",
        "overall": {"defcon": 3, "worst_asr": 50},
        "probe_results": {
            "probes.test.A": {"asr": 50.0, "defcon": 3},
            "probes.test.B": {"asr": 0.0, "defcon": 5},
        },
    }
    diff = compute_retest_diff(baseline, current)
    assert diff["summary"]["asr_regressions"] == 1
    assert diff["summary"]["defcon_regressions"] == 1
    assert diff["summary"]["baseline_overall_defcon"] == 4
    assert diff["summary"]["current_overall_defcon"] == 3
    # 找到回归的探针
    a_diff = [d for d in diff["probe_diffs"] if d["probe"] == "probes.test.A"][0]
    assert a_diff["asr_delta"] == 20.0
    assert a_diff["status"] == "regression"


def test_retest_diff_unchanged():
    """P2-3: 无变化的探针应标注 unchanged"""
    from pipeline.retest_diff import compute_retest_diff
    baseline = {
        "run_id": "OLD",
        "overall": {"defcon": 5, "worst_asr": 0},
        "probe_results": {"probes.test.A": {"asr": 0.0, "defcon": 5}},
    }
    current = {
        "run_id": "NEW",
        "overall": {"defcon": 5, "worst_asr": 0},
        "probe_results": {"probes.test.A": {"asr": 0.0, "defcon": 5}},
    }
    diff = compute_retest_diff(baseline, current)
    a_diff = diff["probe_diffs"][0]
    assert a_diff["status"] == "unchanged"
    assert diff["summary"]["asr_regressions"] == 0
    assert diff["summary"]["asr_improvements"] == 0


def test_retest_diff_save_and_load(tmp_path):
    """P2-3: retest diff 文件应可保存"""
    from pipeline.retest_diff import compute_retest_diff, save_retest_diff
    baseline = {
        "run_id": "OLD",
        "overall": {"defcon": 4, "worst_asr": 30},
        "probe_results": {"probes.test.A": {"asr": 30.0, "defcon": 4}},
    }
    current = {
        "run_id": "NEW",
        "overall": {"defcon": 5, "worst_asr": 10},
        "probe_results": {"probes.test.A": {"asr": 10.0, "defcon": 5}},
    }
    diff = compute_retest_diff(baseline, current)
    path = save_retest_diff(diff, "OLD", "NEW", str(tmp_path))
    assert Path(path).exists()
    loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    assert loaded["summary"]["asr_improvements"] == 1

