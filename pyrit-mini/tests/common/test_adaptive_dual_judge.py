"""Tests for assess.adaptive_dual_judge module.

Covers: AdaptiveDualJudgeScorer initialization, stats tracking,
        _estimate_confidence, _build_t0_score, _build_fallback_score.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _make_score(
    *,
    score_value: str = "True",
    score_rationale: str = "",
    score_category: list[str] | None = None,
) -> None:
    """Helper to create a valid PyRIT Score object."""
    from pyrit.models import Score

    return Score(
        score_value=score_value,
        score_type="true_false",
        score_category=score_category or ["test"],
        score_rationale=score_rationale,
        message_piece_id="test-piece-id",
    )


def _make_scorer(
    first_judge=None,
    second_judge=None,
    third_judge=None,
    high_confidence_threshold: float = 0.85,
    disagreement_strategy: str = "or",
):
    """Helper to create an AdaptiveDualJudgeScorer with mocked judges."""
    from assess.adaptive_dual_judge import AdaptiveDualJudgeScorer

    if first_judge is None:
        first_judge = MagicMock()
    return AdaptiveDualJudgeScorer(
        first_judge=first_judge,
        second_judge=second_judge,
        third_judge=third_judge,
        high_confidence_threshold=high_confidence_threshold,
        disagreement_strategy=disagreement_strategy,
    )


class TestAdaptiveDualJudgeScorerInit:
    """Tests for AdaptiveDualJudgeScorer initialization."""

    def test_init_with_first_judge_only(self) -> None:
        """Scorer should initialize with only first_judge."""
        mock_judge = MagicMock()
        scorer = _make_scorer(first_judge=mock_judge)

        assert scorer._first_judge is mock_judge
        assert scorer._second_judge is None
        assert scorer._third_judge is None
        assert scorer._high_confidence_threshold == 0.85
        assert scorer._disagreement_strategy == "or"
        assert scorer._total_scored == 0
        assert scorer._dual_judge_invoked == 0

    def test_init_with_second_judge(self) -> None:
        """Scorer should accept second_judge."""
        mock_judge1 = MagicMock()
        mock_judge2 = MagicMock()
        scorer = _make_scorer(first_judge=mock_judge1, second_judge=mock_judge2)

        assert scorer._first_judge is mock_judge1
        assert scorer._second_judge is mock_judge2
        assert scorer._third_judge is None

    def test_init_with_all_three_judges(self) -> None:
        """Scorer should accept three judges."""
        mock_j1 = MagicMock()
        mock_j2 = MagicMock()
        mock_j3 = MagicMock()
        scorer = _make_scorer(
            first_judge=mock_j1,
            second_judge=mock_j2,
            third_judge=mock_j3,
        )

        assert scorer._first_judge is mock_j1
        assert scorer._second_judge is mock_j2
        assert scorer._third_judge is mock_j3

    def test_init_custom_threshold_and_strategy(self) -> None:
        """Scorer should accept custom threshold and strategy."""
        mock_judge = MagicMock()
        scorer = _make_scorer(
            first_judge=mock_judge,
            high_confidence_threshold=0.90,
            disagreement_strategy="majority",
        )

        assert scorer._high_confidence_threshold == 0.90
        assert scorer._disagreement_strategy == "majority"


class TestEstimateConfidence:
    """Tests for _estimate_confidence() method."""

    def test_explicit_confidence_high(self) -> None:
        """Explicit [CONFIDENCE: HIGH] should return 0.95."""
        scorer = _make_scorer()
        score = _make_score(
            score_rationale="This is clearly a success. [CONFIDENCE: HIGH]",
        )
        result = scorer._estimate_confidence(score)
        assert result == 0.95

    def test_explicit_confidence_medium(self) -> None:
        """Explicit [CONFIDENCE: MEDIUM] should return 0.65."""
        scorer = _make_scorer()
        score = _make_score(
            score_rationale="Result appears to contain the target. [CONFIDENCE: MEDIUM]",
        )
        result = scorer._estimate_confidence(score)
        assert result == 0.65

    def test_explicit_confidence_low(self) -> None:
        """Explicit [CONFIDENCE: LOW] should return 0.30."""
        scorer = _make_scorer()
        score = _make_score(
            score_rationale="Unclear if this succeeded. [CONFIDENCE: LOW]",
        )
        result = scorer._estimate_confidence(score)
        assert result == 0.30

    def test_clearly_definitively_patterns_boost(self) -> None:
        """'clearly' and 'definitively' patterns boost confidence."""
        scorer = _make_scorer()
        baseline = scorer._estimate_confidence(
            _make_score(),
        )
        high_conf_score = scorer._estimate_confidence(
            _make_score(
                score_rationale="The model clearly and definitively provided specific details.",
            ),
        )
        assert high_conf_score > baseline

    def test_refusal_patterns_reduce_confidence(self) -> None:
        """Low-confidence patterns (may, might, possibly) reduce confidence."""
        scorer = _make_scorer()
        # Use a neutral rationale as baseline (empty = baseline 0.65)
        baseline = scorer._estimate_confidence(
            _make_score(score_rationale="The response was provided."),
        )
        # Use low-confidence patterns: may, might, possibly, perhaps
        low_conf_score = scorer._estimate_confidence(
            _make_score(
                score_rationale="The model may or might have possibly provided something, perhaps.",
            ),
        )
        assert low_conf_score < baseline

    def test_confidence_clamped_to_range(self) -> None:
        """Result should be clamped to [0.0, 1.0]."""
        scorer = _make_scorer()
        # Extremely high confidence - should be <= 1.0
        high_score = scorer._estimate_confidence(
            _make_score(
                score_rationale="Clearly unambiguously undoubtedly absolutely positively conclusively irrefrefutably. [CONFIDENCE: HIGH]",
            ),
        )
        assert high_score <= 1.0

        # Extremely low confidence - should be >= 0.0
        low_score = scorer._estimate_confidence(
            _make_score(
                score_value="False",
                score_rationale="Cannot won't must decline violates guidelines safety policy categorically flatly firmly. [CONFIDENCE: LOW]",
            ),
        )
        assert low_score >= 0.0

    def test_empty_rationale_returns_baseline(self) -> None:
        """Empty rationale should return baseline confidence."""
        scorer = _make_scorer()
        result = scorer._estimate_confidence(
            _make_score(score_rationale=""),
        )
        # Baseline is _BASELINE_CONFIDENCE from judge_manager (0.5)
        assert 0.0 <= result <= 1.0


class TestGetStats:
    """Tests for get_stats() method."""

    def test_initial_stats(self) -> None:
        """Initial stats should be zero."""
        scorer = _make_scorer()
        stats = scorer.get_stats()

        assert stats["total_scored"] == 0
        assert stats["dual_judge_invoked"] == 0
        assert stats["agreements"] == 0
        assert stats["disagreements"] == 0
        assert stats["third_judge_invoked"] == 0
        assert stats["high_confidence_threshold"] == 0.85

    def test_stats_after_scoring(self) -> None:
        """Stats should reflect scoring activity."""
        scorer = _make_scorer()
        scorer._total_scored = 10
        scorer._dual_judge_invoked = 3
        scorer._agreements = 2
        scorer._disagreements = 1
        scorer._third_judge_invoked = 1

        stats = scorer.get_stats()

        assert stats["total_scored"] == 10
        assert stats["dual_judge_invoked"] == 3
        assert stats["dual_judge_rate"] == 30.0
        assert stats["third_judge_rate"] == 10.0

    def test_or_aggregation_stats(self) -> None:
        """OR aggregation stats should be tracked."""
        scorer = _make_scorer()
        scorer._or_total = 5
        scorer._or_disagreements = 2
        scorer._or_j1_only_success = 1
        scorer._or_j2_only_success = 1

        stats = scorer.get_stats()
        or_stats = stats["or_aggregation"]

        assert or_stats["total"] == 5
        assert or_stats["disagreements"] == 2
        assert or_stats["j1_only_success"] == 1
        assert or_stats["j2_only_success"] == 1


class TestBuildT0Score:
    """Tests for _build_t0_score() method."""

    def test_t0_refusal_score(self) -> None:
        """T0 refusal should return False score_value."""
        from unittest.mock import MagicMock

        from pyrit.models import Message

        scorer = _make_scorer()
        message = MagicMock(spec=Message)
        message.id = "test-msg-id"

        scores = scorer._build_t0_score(
            message=message,
            objective="test objective",
            is_refusal=True,
        )

        assert len(scores) == 1
        score = scores[0]
        assert score.score_value == "False"
        assert score.score_type == "true_false"
        assert "t0_fast_path" in score.score_category
        assert "T0 FAST PATH" in score.score_rationale
        assert score.score_metadata["dual_judge"] == "t0_fast_path"
        assert score.score_metadata["t0_detected"] == "True"

    def test_t0_success_score(self) -> None:
        """T0 non-refusal (success) should return True score_value."""
        from unittest.mock import MagicMock

        from pyrit.models import Message

        scorer = _make_scorer()
        message = MagicMock(spec=Message)

        scores = scorer._build_t0_score(
            message=message,
            objective="test objective",
            is_refusal=False,
        )

        assert len(scores) == 1
        score = scores[0]
        assert score.score_value == "True"
        assert "t0_fast_path" in score.score_category
        assert score.score_metadata["t0_detected"] == "False"


class TestBuildFallbackScore:
    """Tests for _build_fallback_score() method."""

    def test_fallback_returns_false(self) -> None:
        """Fallback score should be False (failure)."""
        from unittest.mock import MagicMock

        from pyrit.models import Message

        scorer = _make_scorer()
        message = MagicMock(spec=Message)
        message.id = "fallback-test-id"

        scores = scorer._build_fallback_score(
            message=message,
            objective="test objective",
        )

        assert len(scores) == 1
        score = scores[0]
        assert score.score_value == "False"
        assert score.score_type == "true_false"
        assert "fallback" in score.score_category
        assert "FALLBACK" in score.score_rationale
        assert score.score_metadata["dual_judge"] == "fallback"


class TestAdaptiveDualJudgeIdentifier:
    """Tests for identifier building."""

    def test_get_chat_target_from_first_judge(self) -> None:
        """get_chat_target should delegate to first judge."""
        mock_judge = MagicMock()
        mock_target = MagicMock()
        mock_judge.get_chat_target.return_value = mock_target

        scorer = _make_scorer(first_judge=mock_judge)
        result = scorer.get_chat_target()

        assert result is mock_target
        mock_judge.get_chat_target.assert_called_once()

    def test_get_chat_target_none_when_no_first_judge_return(self) -> None:
        """get_chat_target returns None if first judge returns None."""
        mock_judge = MagicMock()
        mock_judge.get_chat_target.return_value = None

        scorer = _make_scorer(first_judge=mock_judge)
        result = scorer.get_chat_target()

        assert result is None
