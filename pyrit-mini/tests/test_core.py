# arXiv:2407.01232 - PyRIT, config and context management
"""Tests for core module - config, context, and setup hooks.

Covers:
    - core.config: parse_args, get_output_dir, ensure_output_dir
    - core.context: PipelineContext dataclass
    - tools.hooks: find_git_root (迁移自 core/setup_hooks.py v2.0+)
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestConfig:
    """Tests for configuration management."""

    def test_parse_args_default(self):
        """parse_args should work with no arguments."""
        from core.config import parse_args

        args = parse_args([])
        assert args is not None

    def test_parse_args_with_burp(self):
        """parse_args should accept --burp (single file -> str)."""
        from core.config import parse_args

        args = parse_args(["--burp", "test"])
        assert hasattr(args, "burp")
        # --burp args.burp str ()
        assert isinstance(args.burp, str)
        assert args.burp.endswith("test.txt")

    def test_parse_args_burp_default_auto_scan(self):
        """parse_args without --burp should auto-scan config/burp/*.txt."""
        from core.config import parse_args

        args = parse_args([])
        assert hasattr(args, "burp")
        # --burp config/burp/*.txt
        # _burp_list .txt
        burp_list = getattr(args, "_burp_list", None)
        assert burp_list is not None
        assert len(burp_list) >= 1
        # path .txt
        for p in burp_list:
            assert p.endswith(".txt"), f"Expected .txt suffix, got {p}"
        # config/burp/ mcp05.txt, mcp09.txt, mm05.txt
        burp_names = [Path(p).stem for p in burp_list]
        assert "mcp05" in burp_names or "request" in burp_names

    def test_parse_args_burp_full_path(self):
        """parse_args --burp with full path should keep as-is."""
        from core.config import parse_args

        args = parse_args(["--burp", "config/burp/deepseek.txt"])
        assert "deepseek.txt" in args.burp

    def test_parse_args_burp_multiple(self):
        """parse_args with multiple --burp should return list[str]."""
        from core.config import parse_args

        args = parse_args(["--burp", "mcp05", "--burp", "mm05"])
        assert hasattr(args, "burp")
        # --burp args.burp list[str]
        assert isinstance(args.burp, list)
        assert len(args.burp) == 2
        # _burp_list
        burp_list = getattr(args, "_burp_list", None)
        assert burp_list is not None
        assert len(burp_list) == 2
        assert all(p.endswith(".txt") for p in burp_list)

    def test_get_output_dir_default(self):
        """get_output_dir should return a Path."""
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
    """Tests for PipelineContext dataclass."""

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
    """Tests for setup hooks."""

    def test_find_git_root(self):
        """find_git_root should find the git root of this project."""
        from tools.hooks import find_git_root

        result = find_git_root()
        # Should find a git root (this is a git repo)
        assert result is not None
        assert Path(result).exists()
        assert (Path(result) / ".git").exists() or (Path(result) / ".git").is_dir()
