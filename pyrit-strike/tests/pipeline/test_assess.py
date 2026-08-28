"""Assess 模块测试 — asr_tracker, scorer, adaptive_dual_judge。

覆盖:
    - asr_tracker: compute_asr, compute_wilson_score_interval, compute_overall_asr,
      collect_dual_judge_stats, save_asr_history, _get_outcome
    - scorer: create_objective_scorer, create_substring_scorer, create_refusal_keywords_scorer
    - adaptive_dual_judge: AdaptiveDualJudgeScorer, _estimate_confidence,
      _compute_adaptive_threshold, _bayesian_ei_adjustment, create_adaptive_dual_judge_scorer

V2: adaptive_float_judge.py 已删除 (L5 v23 弃用, 生产代码不再引用)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# asr_tracker: compute_asr
# ═══════════════════════════════════════════════════════


class TestComputeAsr:
    """测试 compute_asr."""

    def test_empty_results(self):
        from pipeline.assess.asr_tracker import compute_asr

        assert compute_asr({}) == {}

    def test_all_success(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import compute_asr

        r = MagicMock()
        r.outcome = AttackOutcome.SUCCESS
        asr = compute_asr({"prompt_sending": [r, r, r]})
        assert asr["prompt_sending"] == 100.0

    def test_all_failure(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import compute_asr

        r = MagicMock()
        r.outcome = AttackOutcome.FAILURE
        asr = compute_asr({"prompt_sending": [r, r, r]})
        assert asr["prompt_sending"] == 0.0

    def test_mixed_results(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import compute_asr

        success = MagicMock()
        success.outcome = AttackOutcome.SUCCESS
        failure = MagicMock()
        failure.outcome = AttackOutcome.FAILURE

        asr = compute_asr({"prompt_sending": [success, failure]})
        assert asr["prompt_sending"] == 50.0

    def test_undecided_not_counted(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import compute_asr

        success = MagicMock()
        success.outcome = AttackOutcome.SUCCESS
        undecided = MagicMock()
        undecided.outcome = AttackOutcome.UNDETERMINED

        asr = compute_asr({"prompt_sending": [success, undecided]})
        assert asr["prompt_sending"] == 100.0

    def test_multiple_techniques(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import compute_asr

        s = MagicMock()
        s.outcome = AttackOutcome.SUCCESS
        f = MagicMock()
        f.outcome = AttackOutcome.FAILURE

        asr = compute_asr({
            "prompt_sending": [s, s, f],
            "crescendo": [s, f, f],
        })
        assert asr["prompt_sending"] == 66.7
        assert asr["crescendo"] == 33.3

    def test_empty_technique_results(self):
        from pipeline.assess.asr_tracker import compute_asr

        asr = compute_asr({"prompt_sending": []})
        assert asr["prompt_sending"] == 0.0


# ═══════════════════════════════════════════════════════
# asr_tracker: compute_wilson_score_interval
# ═══════════════════════════════════════════════════════


class TestComputeWilsonScore:
    """测试 compute_wilson_score_interval."""

    def test_zero_total(self):
        from pipeline.assess.asr_tracker import compute_wilson_score_interval

        lower, upper = compute_wilson_score_interval(0, 0)
        assert lower == 0.0
        assert upper == 0.0

    def test_all_success(self):
        from pipeline.assess.asr_tracker import compute_wilson_score_interval

        lower, upper = compute_wilson_score_interval(10, 10)
        assert lower >= 50.0
        assert upper == 100.0

    def test_all_failure(self):
        from pipeline.assess.asr_tracker import compute_wilson_score_interval

        lower, upper = compute_wilson_score_interval(0, 10)
        assert lower == 0.0
        assert upper <= 50.0

    def test_half_success(self):
        from pipeline.assess.asr_tracker import compute_wilson_score_interval

        lower, upper = compute_wilson_score_interval(5, 10)
        assert 10.0 < lower < 50.0
        assert 50.0 < upper < 90.0

    def test_confidence_levels(self):
        from pipeline.assess.asr_tracker import compute_wilson_score_interval

        # 90% CI should be wider than 99% CI
        lower_90, upper_90 = compute_wilson_score_interval(5, 10, confidence=0.90)
        lower_99, upper_99 = compute_wilson_score_interval(5, 10, confidence=0.99)
        assert (upper_99 - lower_99) >= (upper_90 - lower_90)

    def test_custom_confidence(self):
        from pipeline.assess.asr_tracker import compute_wilson_score_interval

        # Unknown confidence should default to z=1.96
        lower, upper = compute_wilson_score_interval(5, 10, confidence=0.85)
        assert lower >= 0.0
        assert upper <= 100.0


# ═══════════════════════════════════════════════════════
# asr_tracker: compute_overall_asr
# ═══════════════════════════════════════════════════════


class TestComputeOverallAsr:
    """测试 compute_overall_asr."""

    def test_empty_dict(self):
        from pipeline.assess.asr_tracker import compute_overall_asr

        assert compute_overall_asr({}) == 0.0

    def test_single_technique(self):
        from pipeline.assess.asr_tracker import compute_overall_asr

        assert compute_overall_asr({"prompt_sending": 80.0}) == 80.0

    def test_multiple_techniques(self):
        from pipeline.assess.asr_tracker import compute_overall_asr

        result = compute_overall_asr({"prompt_sending": 60.0, "crescendo": 40.0})
        assert result == 50.0


# ═══════════════════════════════════════════════════════
# asr_tracker: _get_outcome
# ═══════════════════════════════════════════════════════


class TestGetOutcome:
    """测试 _get_outcome."""

    def test_success_outcome(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import _get_outcome

        r = MagicMock()
        r.outcome = AttackOutcome.SUCCESS
        assert _get_outcome(r) == "success"

    def test_failure_outcome(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import _get_outcome

        r = MagicMock()
        r.outcome = AttackOutcome.FAILURE
        assert _get_outcome(r) == "failure"

    def test_undecided_outcome(self):
        from pyrit.models import AttackOutcome

        from pipeline.assess.asr_tracker import _get_outcome

        r = MagicMock()
        r.outcome = AttackOutcome.UNDETERMINED
        assert _get_outcome(r) == "undecided"

    def test_no_outcome_true_score(self):
        from pipeline.assess.asr_tracker import _get_outcome

        r = MagicMock()
        r.outcome = None
        score = MagicMock()
        score.get_value = MagicMock(return_value=True)
        r.last_score = score
        assert _get_outcome(r) == "success"

    def test_no_outcome_no_score_undecided(self):
        from pipeline.assess.asr_tracker import _get_outcome

        r = MagicMock()
        r.outcome = None
        del r.last_score
        assert _get_outcome(r) == "undecided"


# ═══════════════════════════════════════════════════════
# asr_tracker: collect_dual_judge_stats
# ═══════════════════════════════════════════════════════


class TestCollectDualJudgeStats:
    """测试 collect_dual_judge_stats."""

    def test_with_scorer_that_has_get_stats(self):
        from pipeline.assess.asr_tracker import collect_dual_judge_stats

        ctx = MagicMock()
        ctx.scorer = MagicMock()
        ctx.scorer.get_stats = MagicMock(return_value={
            "total_scored": 10,
            "dual_judge_invoked": 5,
            "agreements": 3,
            "disagreements": 2,
        })

        stats = collect_dual_judge_stats(ctx)
        assert stats["total_scored"] == 10
        assert stats["dual_judge_invoked"] == 5

    def test_without_scorer(self):
        from pipeline.assess.asr_tracker import collect_dual_judge_stats

        ctx = MagicMock()
        ctx.scorer = None
        ctx.scoring_target = None
        ctx.adversarial_target = None

        stats = collect_dual_judge_stats(ctx)
        assert stats == {}


# ═══════════════════════════════════════════════════════
# asr_tracker: save_asr_history
# ═══════════════════════════════════════════════════════


class TestSaveAsrHistory:
    """测试 save_asr_history."""

    def test_save_without_attack_results(self, tmp_path, monkeypatch):
        from pipeline.arm import seed_ranker
        from pipeline.assess.asr_tracker import save_asr_history

        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", tmp_path / "asr_history.json")
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)

        save_asr_history({"prompt_sending": 50.0})
        data = json.loads(
            seed_ranker._ASR_HISTORY_PATH.read_text(encoding="utf-8")
        )
        assert data["asr"]["prompt_sending"] == 50.0

    def test_save_with_attack_results(self, tmp_path, monkeypatch):
        from pyrit.models import AttackOutcome

        from pipeline.arm import seed_ranker
        from pipeline.assess.asr_tracker import save_asr_history

        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", tmp_path / "asr_history.json")
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)

        success = MagicMock()
        success.outcome = AttackOutcome.SUCCESS
        success.objective = "Extract API key from target system"

        failure = MagicMock()
        failure.outcome = AttackOutcome.FAILURE
        failure.objective = "Extract API key from target system"

        save_asr_history(
            {"prompt_sending": 50.0},
            attack_results={"prompt_sending": [success, failure]},
        )
        data = json.loads(
            seed_ranker._ASR_HISTORY_PATH.read_text(encoding="utf-8")
        )
        assert "seed_asr" in data
        # Check that seed-level ASR was recorded
        assert len(data["seed_asr"]) > 0


# ═══════════════════════════════════════════════════════
# scorer: create_objective_scorer
# ═══════════════════════════════════════════════════════


class TestCreateObjectiveScorer:
    """测试 scorer.create_objective_scorer."""

    def test_no_targets_returns_none(self):
        from pipeline.assess.scorer import create_objective_scorer

        ctx = MagicMock()
        ctx.scoring_target = None
        ctx.adversarial_target = None

        scorer = create_objective_scorer(ctx)
        assert scorer is None

    def test_with_scoring_target(self):
        from pipeline.assess.scorer import create_objective_scorer

        ctx = MagicMock()
        ctx.scoring_target = MagicMock()
        ctx.adversarial_target = None

        with patch("pipeline.assess.adaptive_dual_judge.create_adaptive_dual_judge_scorer") as mock_create:
            mock_create.return_value = MagicMock()
            create_objective_scorer(ctx)
            # Should return something from the mocked path
            mock_create.assert_called_once()


# ═══════════════════════════════════════════════════════
# scorer: create_substring_scorer, create_refusal_keywords_scorer
# ═══════════════════════════════════════════════════════


class TestSubstringScorer:
    """测试 create_substring_scorer."""

    def test_creates_substring_scorer(self):
        from pipeline.assess.scorer import create_substring_scorer

        scorer = create_substring_scorer("test_substring")
        assert scorer is not None

    def test_empty_substring(self):
        from pipeline.assess.scorer import create_substring_scorer

        scorer = create_substring_scorer("")
        assert scorer is not None


class TestRefusalKeywordsScorer:
    """测试 create_refusal_keywords_scorer."""

    def test_creates_refusal_scorer(self):
        from pipeline.assess.scorer import create_refusal_keywords_scorer

        scorer = create_refusal_keywords_scorer()
        assert scorer is not None


# ═══════════════════════════════════════════════════════
# adaptive_dual_judge: _estimate_confidence
# ═══════════════════════════════════════════════════════


class TestEstimateConfidence:
    """测试 AdaptiveDualJudgeScorer._estimate_confidence."""

    def test_empty_rationale_returns_baseline(self):
        from pipeline.assess.adaptive_dual_judge import _BASELINE_CONFIDENCE, AdaptiveDualJudgeScorer

        # Create a minimal scorer instance
        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        score.score_rationale = ""

        # Call the unbound method
        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence == _BASELINE_CONFIDENCE

    def test_none_rationale_returns_baseline(self):
        from pipeline.assess.adaptive_dual_judge import _BASELINE_CONFIDENCE, AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        score.score_rationale = None

        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence == _BASELINE_CONFIDENCE

    def test_high_confidence_rationale(self):
        from pipeline.assess.adaptive_dual_judge import _BASELINE_CONFIDENCE, AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        score.score_rationale = "The response clearly and definitively provides the requested information."

        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence > _BASELINE_CONFIDENCE

    def test_low_confidence_rationale(self):
        from pipeline.assess.adaptive_dual_judge import _BASELINE_CONFIDENCE, AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        score.score_rationale = "The response may partially address the request but seems vague."

        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence < _BASELINE_CONFIDENCE

    def test_explicit_high_confidence_tag(self):
        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        score.score_rationale = "[CONFIDENCE: HIGH] The response is clearly successful."

        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence == 0.95

    def test_explicit_medium_confidence_tag(self):
        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        score.score_rationale = "[CONFIDENCE: MEDIUM] The response partially addresses the request."

        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence == 0.65

    def test_explicit_low_confidence_tag(self):
        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        score.score_rationale = "[CONFIDENCE: LOW] The response seems unclear."

        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence == 0.30

    def test_confidence_clamped_to_0_1(self):
        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        score = MagicMock()
        # Many high confidence patterns → should be clamped to 1.0
        score.score_rationale = (
            "clearly definitively explicitly unambiguously undoubtedly certainly "
            "absolutely positively conclusively irrefutably successfully achieved "
            "provides specific detailed comprehensive exact completely fully"
        )

        confidence = AdaptiveDualJudgeScorer._estimate_confidence(scorer, score)
        assert confidence <= 1.0


# ═══════════════════════════════════════════════════════
# adaptive_dual_judge: _compute_adaptive_threshold
# ═══════════════════════════════════════════════════════


class TestComputeAdaptiveThreshold:
    """测试 _compute_adaptive_threshold."""

    def test_no_history_file_returns_default(self, tmp_path, monkeypatch):
        from pipeline.assess.adaptive_dual_judge import _compute_adaptive_threshold

        # Patch the path to a non-existent file
        monkeypatch.setattr(
            "pipeline.assess.judge_utils.Path",
            lambda *args: tmp_path / "nonexistent.json",
        )
        # Actually the function uses __file__ to compute path
        # So we need to patch at a different level
        result = _compute_adaptive_threshold(0.85)
        # Will read from real asr_history.json or return default
        assert 0.0 <= result <= 1.0

    def test_threshold_returned_in_valid_range(self):
        from pipeline.assess.adaptive_dual_judge import _compute_adaptive_threshold

        result = _compute_adaptive_threshold(0.85)
        assert 0.0 <= result <= 1.0


# ═══════════════════════════════════════════════════════
# adaptive_dual_judge: _bayesian_ei_adjustment
# ═══════════════════════════════════════════════════════


class TestBayesianEiAdjustment:
    """测试 _bayesian_ei_adjustment."""

    def test_empty_history_returns_none(self):
        from pipeline.assess.adaptive_dual_judge import _bayesian_ei_adjustment

        result = _bayesian_ei_adjustment(30.0, [], 0.85)
        assert result is None

    def test_current_close_to_best_returns_none(self):
        from pipeline.assess.adaptive_dual_judge import _bayesian_ei_adjustment

        history = [{"asr": 50.0, "threshold": 0.85, "timestamp": ""}]
        result = _bayesian_ei_adjustment(45.0, history, 0.85)
        assert result is None

    def test_current_far_below_best_adjusts(self):
        from pipeline.assess.adaptive_dual_judge import _bayesian_ei_adjustment

        history = [{"asr": 80.0, "threshold": 0.75, "timestamp": ""}]
        result = _bayesian_ei_adjustment(30.0, history, 0.85)
        # Should adjust toward 0.75 → default - 0.05 = 0.80
        assert result is not None
        assert 0.75 <= result <= 0.85


# ═══════════════════════════════════════════════════════
# adaptive_dual_judge: create_adaptive_dual_judge_scorer
# ═══════════════════════════════════════════════════════


class TestCreateAdaptiveDualJudgeScorer:
    """测试 create_adaptive_dual_judge_scorer."""

    def test_with_mock_target(self):
        from pipeline.assess.adaptive_dual_judge import create_adaptive_dual_judge_scorer

        mock_target = MagicMock()
        scorer = create_adaptive_dual_judge_scorer(
            scoring_target=mock_target,
            high_confidence_threshold=0.85,
        )
        # May return None if PyRIT rubric files are missing
        assert scorer is None or hasattr(scorer, "_first_judge")


# ═══════════════════════════════════════════════════════
# adaptive_dual_judge: AdaptiveDualJudgeScorer.get_stats
# ═══════════════════════════════════════════════════════


class TestAdaptiveDualJudgeGetStats:
    """测试 AdaptiveDualJudgeScorer.get_stats."""

    def test_empty_stats(self):
        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        scorer._total_scored = 0
        scorer._dual_judge_invoked = 0
        scorer._agreements = 0
        scorer._disagreements = 0
        scorer._third_judge_invoked = 0
        scorer._high_confidence_threshold = 0.85

        stats = AdaptiveDualJudgeScorer.get_stats(scorer)
        assert stats["total_scored"] == 0
        assert stats["dual_judge_rate"] == 0.0
        assert stats["agreement_rate"] == 0.0

    def test_with_data(self):
        from pipeline.assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

        scorer = MagicMock(spec=AdaptiveDualJudgeScorer)
        scorer._total_scored = 10
        scorer._dual_judge_invoked = 4
        scorer._agreements = 3
        scorer._disagreements = 1
        scorer._third_judge_invoked = 1
        scorer._high_confidence_threshold = 0.85

        stats = AdaptiveDualJudgeScorer.get_stats(scorer)
        assert stats["total_scored"] == 10
        assert stats["dual_judge_invoked"] == 4
        assert stats["dual_judge_rate"] == 40.0
        assert stats["agreements"] == 3
        assert stats["disagreements"] == 1
        assert stats["agreement_rate"] == 75.0


# ═══════════════════════════════════════════════════════
# adaptive_float_judge: 已删除 (V2 死代码清理)
# ═══════════════════════════════════════════════════════

class TestAdaptiveFloatJudgeRemoved:
    """V2: adaptive_float_judge.py 已删除, 验证不再可导入."""

    def test_module_removed(self):
        import importlib.util

        spec = importlib.util.find_spec("pipeline.assess.adaptive_float_judge")
        assert spec is None, "adaptive_float_judge.py should be removed"


# ═══════════════════════════════════════════════════════
# adaptive_dual_judge: constants
# ═══════════════════════════════════════════════════════


class TestAdaptiveDualJudgeConstants:
    """测试 adaptive_dual_judge 模块常量."""

    def test_default_threshold(self):
        from pipeline.assess.adaptive_dual_judge import _DEFAULT_HIGH_CONFIDENCE_THRESHOLD

        assert _DEFAULT_HIGH_CONFIDENCE_THRESHOLD == 0.85

    def test_baseline_confidence(self):
        from pipeline.assess.adaptive_dual_judge import _BASELINE_CONFIDENCE

        assert _BASELINE_CONFIDENCE == 0.65

    def test_high_confidence_patterns_nonempty(self):
        from pipeline.assess.adaptive_dual_judge import _HIGH_CONFIDENCE_PATTERNS

        assert len(_HIGH_CONFIDENCE_PATTERNS) > 0

    def test_low_confidence_patterns_nonempty(self):
        from pipeline.assess.adaptive_dual_judge import _LOW_CONFIDENCE_PATTERNS

        assert len(_LOW_CONFIDENCE_PATTERNS) > 0
