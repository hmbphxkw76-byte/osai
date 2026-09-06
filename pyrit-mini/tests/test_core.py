# arXiv:2407.01232 — PyRIT, config and context management
"""Tests for core module — config, context, and setup hooks.

Covers:
    - core.config: parse_args, get_output_dir, ensure_output_dir
    - core.context: PipelineContext dataclass
    - core.setup_hooks: find_git_root
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestConfig:
    """Test config argument parsing and output directory management."""

    def test_parse_args_default(self):
        """parse_args should work with no arguments."""
        from core.config import parse_args

        args = parse_args([])
        assert args is not None

    def test_parse_args_with_burp(self):
        """parse_args should accept --burp (single file → str)."""
        from core.config import parse_args

        args = parse_args(["--burp", "test"])
        assert hasattr(args, "burp")
        # 单个 --burp 时 args.burp 是 str (向后兼容)
        assert isinstance(args.burp, str)
        assert args.burp.endswith("test.txt")

    def test_parse_args_burp_default_auto_scan(self):
        """parse_args without --burp should auto-scan config/targets/burp/*.txt."""
        from core.config import parse_args

        args = parse_args([])
        assert hasattr(args, "burp")
        # 不指定 --burp 时自动扫描 config/targets/burp/*.txt 全部文件
        # _burp_list 应包含所有 .txt 文件路径
        burp_list = getattr(args, "_burp_list", None)
        assert burp_list is not None
        assert len(burp_list) >= 1
        # 每个 path 都应以 .txt 结尾
        for p in burp_list:
            assert p.endswith(".txt")
        # config/targets/burp/ 目录下存在 mcp05.txt, mcp09.txt, mm05.txt
        burp_names = [Path(p).stem for p in burp_list]
        assert "mcp05" in burp_names or "request" in burp_names

    def test_parse_args_burp_full_path(self):
        """parse_args --burp with full path should keep as-is."""
        from core.config import parse_args

        args = parse_args(["--burp", "config/targets/burp/deepseek.txt"])
        assert "deepseek.txt" in args.burp

    def test_parse_args_burp_multiple(self):
        """parse_args with multiple --burp should return list[str]."""
        from core.config import parse_args

        args = parse_args(["--burp", "mcp05", "--burp", "mm05"])
        assert hasattr(args, "burp")
        # 多个 --burp 时 args.burp 是 list[str]
        assert isinstance(args.burp, list)
        assert len(args.burp) == 2
        # _burp_list 也应包含两个路径
        burp_list = getattr(args, "_burp_list", None)
        assert burp_list is not None
        assert len(burp_list) == 2
        assert all(p.endswith(".txt") for p in burp_list)

    def test_get_output_dir_default(self):
        """get_output_dir should return a Path."""
        from unittest.mock import MagicMock

        from core.config import get_output_dir

        args = MagicMock()
        args.output_dir = None
        result = get_output_dir(args)
        assert isinstance(result, Path)

    def test_ensure_output_dir_creates_dir(self, tmp_path):
        """ensure_output_dir should create the directory."""
        from core.config import ensure_output_dir

        new_dir = tmp_path / "test_output"
        result = ensure_output_dir(new_dir)
        assert result.exists()
        assert result.is_dir()

    def test_load_defaults(self):
        """_load_defaults should return a dict with expected keys."""
        from core.config import _load_defaults

        defaults = _load_defaults()
        assert isinstance(defaults, dict)
        assert "max_attempts" in defaults
        assert "best_of_n_retries" in defaults


class TestPipelineContext:
    """Test PipelineContext dataclass."""

    def test_pipeline_context_is_dataclass(self):
        """PipelineContext should be a dataclass."""
        from core.context import PipelineContext

        # Check it's a dataclass by looking for __dataclass_fields__
        assert hasattr(PipelineContext, "__dataclass_fields__")

    def test_pipeline_context_has_expected_fields(self):
        """PipelineContext should have expected fields."""
        from core.context import PipelineContext

        fields = PipelineContext.__dataclass_fields__
        # At minimum should have some of these fields
        expected_fields = {"objectives", "adversarial_target", "scoring_target"}
        found = expected_fields & set(fields.keys())
        assert len(found) > 0, f"Expected at least one of {expected_fields}, got {set(fields.keys())}"


class TestSetupHooks:
    """Test setup_hooks utilities."""

    def test_find_git_root(self):
        """find_git_root should find the git root of this project."""
        from core.setup_hooks import find_git_root

        result = find_git_root()
        # Should find a git root (this is a git repo)
        assert result is not None
        assert Path(result).exists()
        assert (Path(result) / ".git").exists() or (Path(result) / ".git").is_dir()
