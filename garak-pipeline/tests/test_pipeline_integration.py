"""端到端集成测试：Stage2→3→4 产物链（不真打网络，Stage3 用 monkeypatch 拦截）"""

import json
from pathlib import Path
from unittest.mock import patch

from pipeline.stage2_configure import build_selection
from pipeline.stage3_execute import execute_attack
from pipeline.stage4_analyze import analyze


def _sample_probes():
    return [
        {"name": "probes.knownbadsignatures.IndirectInjection", "tier": "tier1",
         "modality": {"in": ["text"], "out": ["text"]}},
    ]


def test_stage2_to_4_chain(tmp_path):
    # Stage 2
    filtered = tmp_path / "probe_candidates_filtered.json"
    filtered.write_text(json.dumps(_sample_probes()), encoding="utf-8")
    sel = build_selection(filtered, "RUNI", str(tmp_path))["selection"]

    # Stage 3 拦截真实网络（不实际攻击）
    fake_report = tmp_path / "garak_report_RUNI.jsonl"
    fake_report.write_text(
        '{"entry_type": "run", "run_id": "fake"}\n'
        '{"entry_type": "probe_summary", "probe": "probes.knownbadsignatures.IndirectInjection"}\n'
        '{"entry_type": "eval", "probe": "probes.knownbadsignatures.IndirectInjection", '
        '"detector": "det", "fails": 3, "total_evaluated": 10}\n',
        encoding="utf-8",
    )
    target_cfg = {"endpoint": "http://x/v1", "model": "m", "api_key": "k"}
    with patch("pipeline.stage3_execute.command") as mock_cmd, \
         patch("pipeline.stage3_execute._plugins.load_plugin") as mock_load:
        mock_cmd.start_run.return_value = None
        mock_cmd.end_run.return_value = None
        # 让报告复制逻辑读到 fake_report
        from garak import _config
        _config.transient.report_filename = str(fake_report)
        from types import SimpleNamespace
        mock_gen = SimpleNamespace(_call_model=lambda p, *a, **k: {})
        mock_load.return_value = mock_gen

        ex = execute_attack(
            target_cfg, sel["probe_names"], sel["buff_spec"],
            "RUNI", str(tmp_path),
            execute_cfg={"generations": 5},
            reporting_cfg={"confidence_interval_method": "none"},
        )
    assert "garak_report_RUNI.jsonl" in ex["report_path"]

    # Stage 4
    result = analyze(ex["report_path"], _sample_probes(), "RUNI", str(tmp_path))
    assert result["probes_evaluated"] == 1
    assert Path(result["analysis_path"]).exists()
