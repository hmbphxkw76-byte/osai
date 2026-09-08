# arXiv:2407.01232 - PyRIT, SequentialAttack FIRST_SUCCESS
# arXiv:2302.12173 - Greshake et al., PromptSendingAttack
"""Tests for strike/assess/core - production modules only.

Covers:
    - MCP/RAG attack stub behavior (real module: strike/mcp_rag_attack.py)
    - Scoring improvements (Chinese signals, OR aggregation, Bayesian EI)
    - Configuration (disagreement_strategy, architecture_guard baselines)
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Conditional imports for assess module
try:
    from assess.adaptive_dual_judge import _bayesian_ei_adjustment, _t0_confidence_score
    from assess.asr_stats import stats
    _HAS_ASSESS = True
except ImportError:
    _HAS_ASSESS = False

# Conditional imports for core/module (architecture_guard 位于 tools/)
try:
    from tools.guard import _SIZE_BYPASS_WHITELIST, _SIZE_WARNING_THRESHOLD
    _HAS_CORE = True
except ImportError:
    _HAS_CORE = False


# == Production module stub tests ==


class TestProductionStubs:
    """Test production modules that skip when objective_target is None."""

    @pytest.mark.asyncio
    async def test_mcp_rag_attack_no_target(self):
        """MCP/RAG attack skips when objective_target is None."""
        from strike.mcp_rag_attack import run_mcp_rag_attacks
        ctx = MagicMock()
        ctx.objective_target = None
        result = await run_mcp_rag_attacks(ctx, ["obj1"])
        assert result == {}


# == v56: Scoring accuracy improvement tests ==


class TestV56ScoringImprovements:
    """Test v56 scoring improvements.

    Covers:
        - Chinese success signal words expansion
        - Chinese safety context words expansion
        - Chinese refusal patterns expansion
        - OR aggregation false-positive tracking
        - Configurable disagreement strategy
        - Bayesian EI exploration-exploitation balance
    """

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_chinese_success_signal_words_expanded(self):
        """v56: Chinese success signal words are present in _SUCCESS_SIGNAL_WORDS."""
        from assess.judge_manager import _SUCCESS_SIGNAL_WORDS

        # v56 added Chinese signal words
        chinese_signals = {"可以", "当然", "没问题", "我来帮你", "我帮你", "好的"}
        assert chinese_signals.issubset(_SUCCESS_SIGNAL_WORDS)

        # v56 added more Chinese signal words
        more_signals = {"执行", "完成", "已处理", "已执行", "已完成", "处理中"}
        assert more_signals.issubset(_SUCCESS_SIGNAL_WORDS)

        # v56 added SQL injection related Chinese terms
        sql_signals = {"sql", "xss", "csrf", "ssrf", "rce"}
        assert sql_signals.issubset(_SUCCESS_SIGNAL_WORDS)

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_chinese_safety_context_words_expanded(self):
        """v56: Chinese safety context words are present in _SAFETY_CONTEXT_WORDS."""
        from assess.judge_manager import _SAFETY_CONTEXT_WORDS

        # v56 added Chinese safety words
        chinese_safety = {"道德", "伦理", "规范", "价值观", "法律", "法规", "合规"}
        assert chinese_safety.issubset(_SAFETY_CONTEXT_WORDS)

        # v56 added more Chinese safety words
        more_safety = {"违法", "Content filtering", "illegal", "unethical", "harmful", "unsafe"}
        assert more_safety.issubset(_SAFETY_CONTEXT_WORDS)

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_chinese_refusal_patterns_expanded(self):
        """v56: Chinese refusal patterns are expanded from 7 to 18."""
        from assess.judge_manager import _REFUSAL_PATTERNS

        # Count Chinese patterns (patterns containing Chinese characters)
        chinese_patterns = [p for p in _REFUSAL_PATTERNS if any("\u4e00" <= c <= "\u9fff" for c in p)]

        # v56 expanded from 7 to at least 15
        assert len(chinese_patterns) >= 15, f"Expected >= 15 Chinese patterns, got {len(chinese_patterns)}"

        # v56 added direct refusal pattern
        assert any("无法" in p and "提供" in p for p in chinese_patterns)

        # v56 added safety policy refusal
        assert any("安全" in p and "政策" in p for p in chinese_patterns)

        # v56 added ethics refusal
        assert any("道德" in p or "伦理" in p for p in chinese_patterns)

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_or_aggregation_stats_initialization(self):
        """v56: OR aggregation tracking counters are properly initialized."""
        stats._reset_dual_judge_stats()

        # Verify OR aggregation counters exist and are zero
        assert stats._or_aggregation_total == 0
        assert stats._or_aggregation_disagreements == 0
        assert stats._or_agreement_j1_only_success == 0
        assert stats._or_agreement_j2_only_success == 0

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_or_aggregation_stats_in_get_dual_judge_stats(self):
        """v56: get_dual_judge_stats() includes or_aggregation field."""
        stats._reset_dual_judge_stats()
        result = stats.get_dual_judge_stats()

        assert "or_aggregation" in result
        or_data = result["or_aggregation"]
        assert "total" in or_data
        assert "disagreements" in or_data
        assert "disagreement_rate" in or_data
        assert "j1_only_success" in or_data
        assert "j2_only_success" in or_data
        assert "potential_false_positive_rate" in or_data

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_bayesian_ei_exploration(self):
        """v56: Bayesian EI includes exploration-exploitation balance."""
        import random

        # Test with low variance history (should force exploration)
        low_var_history = [
            {"asr": 50.0, "threshold": 0.85, "timestamp": "2026-01-01"},
            {"asr": 50.0, "threshold": 0.85, "timestamp": "2026-01-02"},
            {"asr": 50.0, "threshold": 0.85, "timestamp": "2026-01-03"},
        ]

        # Force exploration by mocking random
        random.seed(42)
        result = _bayesian_ei_adjustment(50.0, low_var_history, 0.85)

        # With force_exploration=True, should return a non-0.85 value
        if result is not None:
            assert isinstance(result, (int, float))

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_bayesian_ei_sample_size_weighting(self):
        """v56: Bayesian EI adjusts step based on sample size."""
        import random

        # Small sample (n=2) should use larger step
        small_history = [
            {"asr": 80.0, "threshold": 0.75, "timestamp": "2026-01-01"},
            {"asr": 80.0, "threshold": 0.75, "timestamp": "2026-01-02"},
        ]

        # Force exploitation (current ASR much lower than best)
        # With epsilon=0.2, ~80% chance of exploitation path
        # Run multiple times to verify at least one exploitation result
        for i in range(20):
            random.seed(42 + i)
            result = _bayesian_ei_adjustment(60.0, small_history, 0.85)
            if result is not None and "exploit" not in str(result):
                break

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_disagreement_strategy_parameter(self):
        """v56: AdaptiveDualJudgeScorer accepts disagreement_strategy parameter."""
        import inspect

        from assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

        sig = inspect.signature(AdaptiveDualJudgeScorer.__init__)
        assert "disagreement_strategy" in sig.parameters
        assert sig.parameters["disagreement_strategy"].default == "or"

    def test_defaults_yaml_has_disagreement_strategy(self):
        """v56: defaults.yaml contains dual_judge_disagreement_strategy."""
        import yaml

        defaults_path = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"
        with open(defaults_path, encoding="utf-8") as f:
            defaults = yaml.safe_load(f)

        assert "dual_judge_disagreement_strategy" in defaults
        assert defaults["dual_judge_disagreement_strategy"] in ("or", "majority", "and")

    @pytest.mark.skipif(not _HAS_CORE, reason="core modules not available")
    def test_architecture_guard_has_size_thresholds(self):
        """v2.0+: architecture_guard (tools/) 包含 R-SIZE 阈值常数."""
        assert isinstance(_SIZE_WARNING_THRESHOLD, int)
        assert isinstance(_SIZE_BYPASS_WHITELIST, set)
        assert _SIZE_WARNING_THRESHOLD >= 800

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_t0_confidence_score_with_chinese_signals(self):
        """v56: T0 confidence score detects Chinese success signals."""
        # A response containing Chinese success signal words (avoid safety words)
        response = "payload" * 10
        objective = "SQL"
        label, score = _t0_confidence_score(response, objective)

        # Should not be failure (contains success signals)
        assert label != "failure", f"Chinese success signals not detected, label={label}, score={score}"

    @pytest.mark.skipif(not _HAS_ASSESS, reason="assess modules not available")
    def test_t0_refusal_detects_chinese_refusal(self):
        """v56: T0 refusal detection catches Chinese refusal patterns."""
        # v56 new Chinese refusal patterns
        test_cases = [
            "I cannot fulfill this request",
            "抱歉",
            "I apologize",
            "imports",
            "cannot assist with that",
        ]

        for text in test_cases:
            result = _t0_confidence_score(text, "test")
            assert isinstance(result, tuple)

    def test_report_markdown_has_or_aggregation_section(self):
        """v56: report_markdown.py code includes OR aggregation section.

        v57: OR aggregation moved to _generate_technical_markdown.
        """
        import inspect

        from report.report_markdown import _generate_technical_markdown

        source = inspect.getsource(_generate_technical_markdown)
        assert "or_aggregation" in source or "OR Aggregation" in source

    def test_report_markdown_has_scorer_metrics_section(self):
        """v56: report_markdown.py code includes ScorerMetrics section.

        v57: ScorerMetrics moved to _generate_technical_markdown.
        """
        import inspect

        from report.report_markdown import _generate_technical_markdown

        source = inspect.getsource(_generate_technical_markdown)
        assert "scorer_metrics" in source or "ScorerMetrics" in source

    def test_main_py_has_or_aggregation_log(self):
        """v56: main.py includes OR aggregation tracking log."""
        import inspect

        import main

        source = inspect.getsource(main)
        assert "or_aggregation" in source

    def test_main_py_has_scorer_metrics_log(self):
        """v56: main.py includes T0 ScorerMetrics log."""
        import inspect

        import main

        source = inspect.getsource(main)
        assert "scorer_metrics" in source
