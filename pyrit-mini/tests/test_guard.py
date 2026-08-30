# arXiv:2407.01232 — PyRIT, architecture guard enforcement
"""Tests for core/architecture_guard.py — rule enforcement.

Covers:
    - Guard runs without errors
    - R6 serial stacking detection
    - R5 arXiv citation check
    - R4 L5 parameter baseline
    - R7 hardcoded parameter detection
    - R2 native output check
    - T0 cascade order check
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestArchitectureGuard:
    """Test architecture guard runs and produces zero violations on current codebase."""

    def test_guard_runs_clean(self):
        """Guard should pass with 0 BLOCKING violations on current codebase.

        INFO-level violations (e.g., R9 observability hints) are acceptable —
        only BLOCKING violations indicate a broken architecture contract.
        """
        from core.architecture_guard import ArchitectureGuard, Severity

        guard = ArchitectureGuard(_PROJECT_ROOT)
        violations = guard.check_all()
        blocking = [v for v in violations if v.severity == Severity.BLOCKING]
        assert len(blocking) == 0, (
            f"Expected 0 BLOCKING violations, got {len(blocking)}:\n"
            + "\n".join(f"  [{v.severity.name}] {v.rule} {v.file}:{v.line} — {v.description}" for v in blocking)
        )

    def test_source_files_discovered(self):
        """Guard should discover source files."""
        from core.architecture_guard import ArchitectureGuard

        guard = ArchitectureGuard(_PROJECT_ROOT)
        files = guard.source_files
        assert len(files) > 10, "Should discover more than 10 source files"

    def test_l5_baseline_defined(self):
        """L5 baseline parameters should be defined."""
        from core.architecture_guard import _L5_BASELINE

        assert "max_attempts" in _L5_BASELINE
        assert "best_of_n_retries" in _L5_BASELINE
        assert "post_l1_exit_threshold" in _L5_BASELINE
        assert _L5_BASELINE["best_of_n_retries"] == 5

    def test_hardcoded_param_names_defined(self):
        """Hardcoded parameter names should be defined."""
        from core.architecture_guard import _HARDCODED_PARAM_NAMES

        assert "best_of_n_retries" in _HARDCODED_PARAM_NAMES
        assert "post_l1_exit_threshold" in _HARDCODED_PARAM_NAMES

    def test_forbidden_custom_patterns_defined(self):
        """Forbidden custom class patterns should be defined."""
        from core.architecture_guard import _FORBIDDEN_CUSTOM_PATTERNS

        assert len(_FORBIDDEN_CUSTOM_PATTERNS) > 0

    def test_technique_keywords_defined(self):
        """Technique keywords for arXiv check should be defined."""
        from core.architecture_guard import _TECHNIQUE_KEYWORDS

        assert "Crescendo" in _TECHNIQUE_KEYWORDS
        assert "GCG" in _TECHNIQUE_KEYWORDS
        assert "SkeletonKey" in _TECHNIQUE_KEYWORDS

    def test_arxiv_pattern_matches(self):
        """arXiv pattern should match valid arXiv IDs."""
        from core.architecture_guard import _ARXIV_PATTERN

        assert _ARXIV_PATTERN.search("arXiv:2402.12109")
        assert _ARXIV_PATTERN.search("arXiv:2307.08673")
        # Should be case-insensitive
        assert _ARXIV_PATTERN.search("arxiv:2402.12109")
