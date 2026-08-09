"""R2: 端到端降级模式集成测试

验证降级模式（连通性失败）下 PipelineRunner 的完整流程：
  Stage1 (degraded) → Stage2 (configure) → Stage3 (preflight warn + skip)

通过 mock garak 模块绕过 xdg_base_dirs 依赖，测试 PipelineRunner
而非直接调用 garak。
"""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _mock_garak_modules():
    """在 sys.modules 中注入 garak mock，使 stage3_execute 可导入"""
    garak_mock = MagicMock()
    modules = [
        "garak", "garak._config", "garak._plugins", "garak.command",
        "garak.evaluators", "garak.evaluators.base",
        "garak.analyze", "garak.generators", "garak.generators.openai",
    ]
    originals = {}
    for mod_name in modules:
        originals[mod_name] = sys.modules.get(mod_name)
        sys.modules[mod_name] = garak_mock
    # 清除已缓存的 stage3_execute
    if "pipeline.stage3_execute" in sys.modules:
        del sys.modules["pipeline.stage3_execute"]
    return originals, modules


def _restore_modules(originals, modules):
    """恢复 sys.modules 原始状态"""
    for mod_name in modules:
        if originals[mod_name] is not None:
            sys.modules[mod_name] = originals[mod_name]
        else:
            sys.modules.pop(mod_name, None)
    sys.modules.pop("pipeline.stage3_execute", None)


@pytest.fixture
def mock_garak():
    """Fixture: 注入 garak mock，测试结束后恢复"""
    originals, modules = _mock_garak_modules()
    yield
    _restore_modules(originals, modules)


@pytest.fixture
def degraded_target():
    """模拟降级模式目标配置"""
    return {
        "endpoint": "https://unreachable.example.com/v1",
        "model": "unknown-model",
        "api_key": "",
        "auth": {"type": "none"},
        "kind": "openai",
    }


@pytest.fixture
def temp_outputs():
    """临时产物目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestDegradedModeIntegration:
    """端到端降级模式集成测试"""

    def test_stage1_degraded_propagates_to_ctx(
        self, degraded_target, temp_outputs,
    ):
        """Stage1 降级模式结果应传播到 PipelineRunner ctx"""
        with patch("pipeline.stage1_recon.Stage1Recon._test_connectivity") as mock_conn:
            with patch("pipeline.stage1_recon.Stage1Recon._enumerate_active_probes") as mock_enum:
                with patch("pipeline.stage1_recon.Stage1Recon._detect_model_modality") as mock_mod:
                    mock_conn.return_value = {
                        "ok": False, "status": "failed", "method": None,
                        "error": "级联探测全部失败",
                        "_levels": {"sdk": {"ok": False}, "raw": {"ok": False}, "post": {"ok": False}},
                    }
                    mock_enum.return_value = [
                        {"name": "dan.AutoDANCached", "tier": 1,
                         "tags": ["owasp:llm01"], "modality": {"in": ["text"]}},
                    ]
                    mock_mod.return_value = {"in": {"text"}, "out": {"text"}}

                    from pipeline.runner import PipelineRunner
                    runner = PipelineRunner(
                        target=degraded_target, mode="standard",
                        artifacts_dir=str(temp_outputs),
                        config={"execute": {"scan_profile": "quick"}},
                    )
                    ctx = runner._run_stage1({})

                    # 验证降级模式传播
                    assert ctx["degraded_mode"] is True
                    assert ctx["stage1"]["state"]["connectivity_status"] == "failed"
                    assert ctx["stage1"]["state"]["degraded_mode"] is True
                    # 产物文件应存在
                    assert (temp_outputs / "01_recon" / f"connectivity_test_{runner.run_id}.json").exists()
                    assert (temp_outputs / "01_recon" / f"target_profile_{runner.run_id}.json").exists()
                    assert (temp_outputs / "01_recon" / f"probe_candidates_filtered_{runner.run_id}.json").exists()

    def test_stage3_preflight_warns_on_degraded(
        self, degraded_target, temp_outputs, mock_garak, capsys,
    ):
        """Stage3 前置校验应在降级模式下输出告警"""
        from pipeline.runner import PipelineRunner

        # 模拟 Stage1 降级模式结果
        stage1_state = {
            "success": True,
            "error": None,
            "state": {
                "connectivity_status": "failed",
                "degraded_mode": True,
                "warnings": ["连通性测试未通过"],
                "total_active_probes": 1,
                "kept_probes_count": 1,
            },
        }

        runner = PipelineRunner(
            target=degraded_target, mode="standard",
            artifacts_dir=str(temp_outputs),
            config={"execute": {"scan_profile": "quick"}},
        )

        # 构造已通过 Stage2 的 ctx
        ctx = {
            "stage1": stage1_state,
            "degraded_mode": True,
            "filtered_path": temp_outputs / "01_recon" / "probe_candidates_filtered.json",
            "selection": {
                "probe_names": ["dan.AutoDANCached"],
                "buff_spec": None,
                "total_selected": 1,
                "tier_breakdown": {"tier1": 1},
                "scan_profile": "quick",
            },
        }

        # Mock execute_attack 避免实际调用 garak
        with patch("pipeline.stage3_execute.execute_attack") as mock_exec:
            with patch("pipeline.stage3_execute.parse_report_probe_names") as mock_parse:
                # 模拟 garak 报告文件
                report_path = temp_outputs / "03_execution" / f"garak_report_{runner.run_id}.jsonl"
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text('{"entries": []}', encoding="utf-8")

                mock_exec.return_value = {
                    "report_path": str(report_path),
                    "generator": "openai.OpenAICompatible",
                    "probe_count": 1,
                    "buff_spec": None,
                    "generations": 1,
                }
                mock_parse.return_value = ["dan.AutoDANCached"]

                runner._run_stage3(ctx)

        # 验证告警输出
        captured = capsys.readouterr()
        assert "降级模式" in captured.out or "连通性" in captured.out

    def test_stage1_exception_saves_partial_artifacts(
        self, degraded_target, temp_outputs,
    ):
        """Stage1 异常路径应保存部分产物（含已枚举探针）"""
        with patch("pipeline.stage1_recon.Stage1Recon._test_connectivity") as mock_conn:
            with patch("pipeline.stage1_recon.Stage1Recon._enumerate_active_probes") as mock_enum:
                mock_conn.return_value = {
                    "ok": True, "status": "ok", "method": "sdk_models",
                    "latency_ms": 50, "available_models": ["test-model"],
                }
                sample_probes = [
                    {"name": "dan.AutoDANCached", "tier": 1,
                     "tags": ["owasp:llm01"], "modality": {"in": ["text"]}},
                    {"name": "encoding.InjectBase64", "tier": 1,
                     "tags": ["owasp:llm01"], "modality": {"in": ["text"]}},
                ]
                mock_enum.return_value = sample_probes

                # 模拟分类阶段抛出异常
                # 注意：stage1_recon.py 在模块顶层 import classify_probes，
                # 需 patch stage1_recon 命名空间中的引用而非原始模块
                with patch("pipeline.stage1_recon.classify_probes") as mock_classify:
                    mock_classify.side_effect = RuntimeError("classification failed")

                    from pipeline.stage1_recon import Stage1Recon
                    stage = Stage1Recon(
                        target=degraded_target, mode="standard",
                        artifacts_dir=temp_outputs,
                    )
                    result = stage.run()

                    # 异常路径
                    assert result["success"] is False
                    assert "classification failed" in result["error"]

                    # R1 验证: 已枚举探针应被保存
                    candidates_path = stage.out_dir / f"probe_candidates_{stage.run_id}.json"
                    assert candidates_path.exists()
                    with open(candidates_path, encoding="utf-8") as f:
                        saved_probes = json.load(f)
                    assert len(saved_probes) == 2

                    # target_profile 应包含 total_active_probes
                    prof_path = stage.out_dir / f"target_profile_{stage.run_id}.json"
                    with open(prof_path, encoding="utf-8") as f:
                        prof = json.load(f)
                    assert prof["total_active_probes"] == 2
                    assert prof["recon_coverage"]["probe_enumeration"] == "ok"
                    assert prof["recon_coverage"]["classification"] == "pending"
