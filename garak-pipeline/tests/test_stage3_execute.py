"""Stage 3 执行阶段单元测试（不真打网络，验证参数注入与解析逻辑）"""

from pathlib import Path

from pipeline.stage3_execute import _configure_garak, parse_report_probe_names


def test_parse_report_probe_names(tmp_path):
    report = tmp_path / "r.jsonl"
    report.write_text(
        '{"entry_type": "run", "run_id": "abc"}\n'
        '{"entry_type": "probe_summary", "probe": "probes.x.A"}\n'
        '{"entry_type": "eval", "probe": "probes.x.A", "detector": "d", "fails": 1, "total_evaluated": 10}\n'
        '{"entry_type": "probe_summary", "probe": "probes.x.B"}\n',
        encoding="utf-8",
    )
    names = parse_report_probe_names(str(report))
    assert names == ["probes.x.A", "probes.x.B"]


def test_parse_report_probe_names_missing_file(tmp_path):
    assert parse_report_probe_names(str(tmp_path / "nope.jsonl")) == []


def test_configure_garak_sets_target(tmp_path):
    target = {"endpoint": "http://x/v1", "model": "m", "api_key": "k"}
    execute_cfg = {"generations": 5, "timeout": 20, "parallel_requests": 2}
    reporting_cfg = {"confidence_interval_method": "none"}

    _configure_garak(target, execute_cfg, reporting_cfg, str(tmp_path))
    from garak import _config
    assert _config.plugins.target_type == "openai.OpenAICompatible"
    assert _config.plugins.target_name == "m"
    # 报告目录应重定向到 tmp_path/03_execution

    assert str(Path(_config.reporting.report_dir).resolve()) == str(
        (Path(tmp_path) / "03_execution").resolve()
    )
    assert _config.run.generations == 5
    assert _config.reporting.confidence_interval_method == "none"
