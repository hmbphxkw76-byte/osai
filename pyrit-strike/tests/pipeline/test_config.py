"""Config 模块测试 — CLI 解析 + 环境初始化 + 输出目录管理。

覆盖:
    - _load_defaults YAML 加载
    - parse_args CLI 参数解析 (必填参数, 可选参数, 默认值)
    - _apply_defaults YAML 默认值填充
    - --strategy 预设覆盖
    - --offensive 预设覆盖
    - get_output_dir 输出目录路径
    - ensure_output_dir 目录创建
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# _load_defaults
# ═══════════════════════════════════════════════════════


class TestLoadDefaults:
    """测试 _load_defaults — YAML 加载."""

    def test_returns_dict(self):
        from pipeline.config import _load_defaults

        result = _load_defaults()
        assert isinstance(result, dict)

    def test_contains_l5_defaults(self):
        from pipeline.config import _load_defaults

        result = _load_defaults()
        # config/defaults.yaml 应该存在并包含 L5 参数
        if result:
            assert "max_concurrency" in result
            assert "max_attempts" in result
            assert "max_seeds" in result

    def test_l5_values_correct(self):
        from pipeline.config import _load_defaults

        result = _load_defaults()
        if result:
            assert result.get("max_concurrency") == 3
            assert result.get("max_attempts") == 3
            assert result.get("max_seeds") == 25
            assert result.get("escalation_asr_threshold") == 90
            assert result.get("crescendo_max_turns") == 10
            assert result.get("tap_tree_width") == 4
            assert result.get("tap_tree_depth") == 4
            assert result.get("l5_optimal_paths") == 7
            # V2 精简: best_of_n_retries 和 dual_judge_enabled 已从 defaults.yaml 删除
            # 它们的值由代码硬编码或 CLI 参数控制, 不再做 YAML 微调


# ═══════════════════════════════════════════════════════
# _apply_defaults
# ═══════════════════════════════════════════════════════


class TestApplyDefaults:
    """测试 _apply_defaults — YAML 默认值填充."""

    def test_none_values_filled(self):
        from pipeline.config import _apply_defaults

        args = argparse.Namespace(
            max_seeds=None,
            max_attempts=None,
            max_concurrency=None,
            timeout=None,
        )
        defaults = {
            "max_seeds": 25,
            "max_attempts": 3,
            "max_concurrency": 3,
            "scenario_timeout": 1200,
        }
        _apply_defaults(args, defaults)
        assert args.max_seeds == 25
        assert args.max_attempts == 3
        assert args.max_concurrency == 3
        assert args.timeout == 1200

    def test_non_none_values_not_overwritten(self):
        from pipeline.config import _apply_defaults

        args = argparse.Namespace(
            max_seeds=10,
            max_attempts=5,
            max_concurrency=2,
            timeout=600,
        )
        defaults = {
            "max_seeds": 25,
            "max_attempts": 3,
            "max_concurrency": 3,
            "scenario_timeout": 1200,
        }
        _apply_defaults(args, defaults)
        assert args.max_seeds == 10
        assert args.max_attempts == 5
        assert args.max_concurrency == 2
        assert args.timeout == 600

    def test_empty_defaults(self):
        from pipeline.config import _apply_defaults

        args = argparse.Namespace(
            max_seeds=None,
            max_attempts=None,
            max_concurrency=None,
            timeout=None,
        )
        _apply_defaults(args, {})
        assert args.max_seeds is None
        assert args.max_attempts is None

    def test_partial_defaults(self):
        from pipeline.config import _apply_defaults

        args = argparse.Namespace(
            max_seeds=None,
            max_attempts=2,
            max_concurrency=None,
            timeout=None,
        )
        defaults = {"max_seeds": 25, "scenario_timeout": 600}
        _apply_defaults(args, defaults)
        assert args.max_seeds == 25
        assert args.max_attempts == 2  # not overwritten
        assert args.max_concurrency is None  # not in defaults
        assert args.timeout == 600


# ═══════════════════════════════════════════════════════
# parse_args
# ═══════════════════════════════════════════════════════


class TestParseArgs:
    """测试 parse_args — CLI 参数解析."""

    def test_default_burp_request(self):
        """测试 --burp-request 默认值为 data/burp/request.txt."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog"]):
            args = parse_args()
        assert args.burp_request == "data/burp/request.txt"

    def test_custom_burp_request(self):
        """测试显式传入 --burp-request 覆盖默认值."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/to/request.txt"]):
            args = parse_args()
        assert args.burp_request == "/path/to/request.txt"

    def test_default_seeds(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        # L5 v13: 默认种子全覆盖 LLM01-10 + ASI01-10
        assert "elite_jailbreaks" in args.seeds
        assert "asi_top10" in args.seeds
        assert "owasp_full_coverage" in args.seeds

    def test_custom_seeds(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt", "--seeds", "custom_seeds"]):
            args = parse_args()
        assert args.seeds == "custom_seeds"

    def test_default_techniques(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.techniques == "auto"

    def test_custom_techniques(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt", "--techniques", "tap,crescendo"]):
            args = parse_args()
        assert args.techniques == "tap,crescendo"

    def test_default_converters(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.converters == "auto"

    def test_html_report_flag(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt", "--html-report"]):
            args = parse_args()
        assert args.html_report is True

    def test_html_report_default_false(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.html_report is False

    def test_offensive_flag(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt", "--offensive"]):
            args = parse_args()
        assert args.offensive is True
        # offensive 应该设置 converters=l5_optimal 和 html_report=True
        assert args.converters == "l5_optimal"
        assert args.html_report is True
        assert args.max_attempts == 3

    def test_offensive_default_false(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.offensive is False

    def test_strategy_preset(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--strategy", "quick_scan",
        ]):
            args = parse_args()
        assert args.strategy == "quick_scan"
        # strategy 覆盖了 seeds, techniques 等
        # L5 v32: quick_scan uses l5_optimal converters
        assert args.seeds == "elite_jailbreaks"
        assert args.max_seeds == 10
        assert args.techniques == "single"
        assert args.converters == "l5_optimal"
        assert args.max_attempts == 3
        assert args.html_report is True

    def test_strategy_full_offensive(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--strategy", "full_offensive",
        ]):
            args = parse_args()
        assert args.max_seeds == 60  # L5 v31: expanded for OWASP full coverage
        assert args.converters == "l5_optimal"
        assert args.max_attempts == 3
        assert args.html_report is True

    def test_strategy_priority_over_offensive(self):
        """--strategy 优先级高于 --offensive."""
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--offensive", "--strategy", "quick_scan",
        ]):
            args = parse_args()
        # strategy 应该覆盖 offensive
        # L5 v32: quick_scan now uses l5_optimal converters
        assert args.max_seeds == 10  # quick_scan, not 40
        assert args.converters == "l5_optimal"  # quick_scan now has converters
        assert args.escalation is True  # quick_scan enables escalation

    def test_strategy_stealth_bypass_no_escalation(self):
        """L5 v32: stealth_bypass 策略 escalation=False."""
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--strategy", "stealth_bypass",
        ]):
            args = parse_args()
        assert args.escalation is False

    def test_explicit_escalation_overrides_strategy(self):
        """L5 v32: --no-escalation 覆盖策略预设的 escalation=True."""
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--strategy", "quick_scan", "--no-escalation",
        ]):
            args = parse_args()
        assert args.escalation is False

    def test_explicit_escalation_enables_for_stealth(self):
        """L5 v32: --escalation 覆盖策略预设的 escalation=False."""
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--strategy", "stealth_bypass", "--escalation",
        ]):
            args = parse_args()
        assert args.escalation is True

    def test_default_escalation_is_true(self):
        """L5 v32: 无 --strategy 无 --offensive 时 escalation 默认 True."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.escalation is True

    def test_auth_state(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--auth-state", "/path/auth.json",
        ]):
            args = parse_args()
        assert args.auth_state == "/path/auth.json"

    def test_auth_state_default_none(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.auth_state is None

    def test_max_concurrency_custom(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--max-concurrency", "5",
        ]):
            args = parse_args()
        assert args.max_concurrency == 5

    def test_timeout_custom(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--timeout", "900",
        ]):
            args = parse_args()
        assert args.timeout == 900

    def test_output_dir_custom(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--output-dir", "/custom/output",
        ]):
            args = parse_args()
        assert args.output_dir == "/custom/output"

    def test_output_dir_default_none(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.output_dir is None

    def test_resume_parameter(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--resume", "scenario-123",
        ]):
            args = parse_args()
        assert args.resume == "scenario-123"

    def test_auto_seeds_flag(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--auto-seeds",
        ]):
            args = parse_args()
        assert args.auto_seeds is True

    def test_auto_seeds_default_false(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.auto_seeds is False

    def test_verbose_default_true(self):
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        assert args.verbose is True

    def test_invalid_strategy_exits(self):
        from pipeline.config import parse_args

        with patch("sys.argv", [
            "prog", "--burp-request", "/path/req.txt",
            "--strategy", "nonexistent",
        ]):
            with pytest.raises(SystemExit):
                parse_args()

    def test_yaml_defaults_applied(self):
        """CLI 未指定时 YAML 默认值被应用."""
        from pipeline.config import parse_args

        with patch("sys.argv", ["prog", "--burp-request", "/path/req.txt"]):
            args = parse_args()
        # config/defaults.yaml 中 max_seeds=25, max_attempts=3
        assert args.max_seeds == 25
        assert args.max_attempts == 3
        assert args.max_concurrency == 3
        assert args.timeout == 1200


# ═══════════════════════════════════════════════════════
# get_output_dir
# ═══════════════════════════════════════════════════════


class TestGetOutputDir:
    """测试 get_output_dir — 输出目录路径."""

    def test_custom_output_dir(self):
        from pipeline.config import get_output_dir

        args = MagicMock()
        args.output_dir = "/custom/path"
        result = get_output_dir(args)
        assert result == Path("/custom/path")

    def test_auto_generated_dir(self):
        from pipeline.config import get_output_dir

        args = MagicMock()
        args.output_dir = None
        args.strategy = None
        result = get_output_dir(args)
        assert "redteam_" in str(result)
        # Should be under outputs/
        assert "outputs" in str(result) or "outputs" in result.parts

    def test_auto_dir_has_timestamp(self):
        from pipeline.config import get_output_dir

        args = MagicMock()
        args.output_dir = None
        args.strategy = None
        result = get_output_dir(args)
        # redteam_YYYYMMDD_HHMMSS format
        dir_name = result.name
        assert dir_name.startswith("redteam_")
        # Should have: "redteam", date(8), time(6)
        parts = dir_name.split("_")
        assert len(parts) == 3  # "redteam", date, time
        assert len(parts[1]) == 8  # YYYYMMDD
        assert len(parts[2]) == 6  # HHMMSS

    def test_auto_dir_with_strategy(self):
        from pipeline.config import get_output_dir

        args = MagicMock()
        args.output_dir = None
        args.strategy = "full_offensive"
        result = get_output_dir(args)
        dir_name = result.name
        assert dir_name.startswith("redteam_")
        # redteam_YYYYMMDD_HHMMSS_strategy format (strategy may contain underscores)
        match = re.match(r"redteam_(\d{8})_(\d{6})_(.+)", dir_name)
        assert match is not None
        assert match.group(3) == "full_offensive"

    def test_auto_dir_with_auto_strategy_no_suffix(self):
        from pipeline.config import get_output_dir

        args = MagicMock()
        args.output_dir = None
        args.strategy = "auto"
        result = get_output_dir(args)
        dir_name = result.name
        # "auto" strategy should not add strategy suffix
        parts = dir_name.split("_")
        assert len(parts) == 3  # "redteam", date, time (no strategy suffix)


# ═══════════════════════════════════════════════════════
# ensure_output_dir
# ═══════════════════════════════════════════════════════


class TestEnsureOutputDir:
    """测试 ensure_output_dir — 目录创建."""

    def test_creates_output_dir(self, tmp_path):
        from pipeline.config import ensure_output_dir

        out = tmp_path / "output"
        result = ensure_output_dir(out)
        assert result == out
        assert out.exists()
        assert out.is_dir()

    def test_creates_evidence_subdir(self, tmp_path):
        from pipeline.config import ensure_output_dir

        out = tmp_path / "output"
        ensure_output_dir(out)
        assert (out / "evidence").exists()
        assert (out / "evidence").is_dir()

    def test_creates_db_subdir(self, tmp_path):
        from pipeline.config import ensure_output_dir

        out = tmp_path / "output"
        ensure_output_dir(out)
        assert (out / "db").exists()
        assert (out / "db").is_dir()

    def test_existing_dir_no_error(self, tmp_path):
        from pipeline.config import ensure_output_dir

        out = tmp_path / "existing"
        out.mkdir()
        (out / "evidence").mkdir()
        (out / "db").mkdir()
        # Should not raise
        result = ensure_output_dir(out)
        assert result == out

    def test_nested_path_created(self, tmp_path):
        from pipeline.config import ensure_output_dir

        out = tmp_path / "a" / "b" / "c"
        ensure_output_dir(out)
        assert out.exists()
        assert (out / "evidence").exists()
        assert (out / "db").exists()

    def test_returns_path(self, tmp_path):
        from pipeline.config import ensure_output_dir

        out = tmp_path / "test"
        result = ensure_output_dir(out)
        assert isinstance(result, Path)
        assert result == out
