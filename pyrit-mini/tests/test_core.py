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

    def test_parse_args_with_burp_request(self):
        """parse_args should accept --burp-request."""
        from core.config import parse_args

        args = parse_args(["--burp-request", "test.burp"])
        assert hasattr(args, "burp_request")

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
