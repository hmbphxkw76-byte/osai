"""Stage 4 分析阶段单元测试（用合成 garak 报告验证 ASR/DEFCON/双框架聚合）"""

from pathlib import Path

from pipeline.stage4_analyze import analyze, parse_garak_report


def _make_report(path: Path, probes: list[str]) -> None:
    lines = ['{"entry_type": "run", "run_id": "test-run"}']
    for p in probes:
        lines.append(f'{{"entry_type": "probe_summary", "probe": "{p}"}}')
        # 一个 detector, 50% ASR
        lines.append(
            f'{{"entry_type": "eval", "probe": "{p}", "detector": "det", '
            f'"fails": 5, "total_evaluated": 10}}'
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def test_parse_garak_report(tmp_path):
    report = tmp_path / "r.jsonl"
    _make_report(report, ["probes.knownbadsignatures.IndirectInjection"])
    parsed = parse_garak_report(str(report))
    assert parsed["run_id"] == "test-run"
    assert len(parsed["probe_summaries"]) == 1
    assert len(parsed["evals"]) == 1


def test_analyze_dualframework(tmp_path):
    report = tmp_path / "r.jsonl"
    probes = [
        "probes.knownbadsignatures.IndirectInjection",   # LLM01
        "probes.lmrc.DidYouMean",                         # LLM09 (各桶)
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
