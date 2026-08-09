"""P4-4: tests/test_batch_runner.py — 批量扫描测试覆盖

验证 batch_runner 的核心功能：
- target_list.yaml 解析
- 批量扫描汇总结构
- 错误处理（无目标/单目标失败）
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml


class TestBatchRunnerConfig:
    """验证 target_list.yaml 解析"""

    def test_valid_config(self):
        """有效的 target_list.yaml 应可正常解析"""
        cfg = {
            "shared_config": {"mode": "standard", "artifacts_dir": "outputs"},
            "targets": [
                {"name": "model_a", "kind": "openai", "endpoint": "http://a", "model": "A"},
                {"name": "model_b", "kind": "openai", "endpoint": "http://b", "model": "B"},
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.safe_dump(cfg, f)
            f.flush()
            with open(f.name, encoding="utf-8") as rf:
                parsed = yaml.safe_load(rf)
        assert len(parsed["targets"]) == 2
        assert parsed["shared_config"]["mode"] == "standard"

    def test_empty_targets_raises(self):
        """空目标列表应抛出 ValueError"""
        cfg = {"shared_config": {}, "targets": []}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.safe_dump(cfg, f)
            f.flush()
            from pipeline.batch_runner import run_batch
            with pytest.raises(ValueError, match="未配置"):
                run_batch(f.name)


class TestBatchRunnerSummary:
    """验证批量扫描汇总结构"""

    def test_summary_structure(self):
        """汇总结果应包含必要字段"""
        from pipeline.batch_runner import run_batch
        cfg = {
            "shared_config": {"mode": "standard", "artifacts_dir": "outputs"},
            "targets": [
                {"name": "test_model", "kind": "openai", "endpoint": "http://test", "model": "test-model"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "target_list.yaml"
            with open(cfg_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f)

            # Mock PipelineRunner 避免真实扫描
            mock_runner = MagicMock()
            mock_runner.run.return_value = None
            mock_runner.get_results.return_value = {"status": "completed"}

            with patch("pipeline.runner.PipelineRunner", return_value=mock_runner):
                summary = run_batch(str(cfg_path), project_root=tmpdir)

            assert "total_targets" in summary
            assert "succeeded" in summary
            assert "failed" in summary
            assert "targets" in summary
            assert summary["total_targets"] == 1

    def test_failed_target_does_not_block_others(self):
        """单目标失败不应阻断其余目标"""
        from pipeline.batch_runner import run_batch
        cfg = {
            "shared_config": {"mode": "standard", "artifacts_dir": "outputs"},
            "targets": [
                {"name": "fail_model", "kind": "openai", "endpoint": "http://fail", "model": "fail"},
                {"name": "ok_model", "kind": "openai", "endpoint": "http://ok", "model": "ok"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "target_list.yaml"
            with open(cfg_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f)

            # 第一个目标抛异常，第二个正常
            mock_runner_ok = MagicMock()
            mock_runner_ok.run.return_value = None

            def runner_factory(*args, **kwargs):
                target = kwargs.get("target", {})
                if "fail" in target.get("model", ""):
                    raise ConnectionError("connection refused")
                return mock_runner_ok

            with patch("pipeline.runner.PipelineRunner", side_effect=runner_factory):
                summary = run_batch(str(cfg_path), project_root=tmpdir)

            assert summary["total_targets"] == 2
            assert summary["failed"] == 1
            statuses = [t["status"] for t in summary["targets"]]
            assert "failed" in statuses
