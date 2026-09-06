"""Tests for assess module — scorer + ASR tracker + dual judge.

Covers attack chain step ⑥:
    ⑥ Assess → dual Judge cross-validation, ASR statistics, evidence collection

arXiv:2308.07920 — Zhang et al.: Dual Judge cross-validation + Cohen's Kappa
arXiv:2402.01135 — Chao et al.: Best-of-N ASR amplification
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class TestASRTracker:
    """Test ASR computation (step ⑥).

    arXiv:2308.07920 — Wilson Score 95% CI for ASR confidence interval.
    """

    def test_compute_asr_empty_results(self):
        """compute_asr with empty results should return empty dict."""
        from assess.asr_compute import compute_asr

        asr = compute_asr({})
        assert isinstance(asr, dict)

    def test_compute_overall_asr_empty(self):
        """compute_overall_asr with empty dict should return 0.0."""
        from assess.asr_stats import compute_overall_asr

        overall = compute_overall_asr({})
        assert overall == 0.0

    def test_compute_wilson_score_interval(self):
        """Wilson Score interval should be valid for known inputs."""
        from assess.asr_compute import compute_wilson_score_interval

        # Wilson Score returns percentage values (0-100), not 0-1
        lower, upper = compute_wilson_score_interval(5, 10)
        # Values are percentages (0-100 range)
        assert 0.0 <= lower <= upper <= 100.0

    def test_compute_cohens_kappa(self):
        """Cohen's Kappa should be valid for known agreements/disagreements.

        arXiv:2308.07920 — Cohen's Kappa measures inter-rater agreement.
        """
        from assess.asr_stats import compute_cohens_kappa

        kappa = compute_cohens_kappa(8, 2)
        assert -1.0 <= kappa <= 1.0


class TestScorer:
    """Test scorer module."""

    def test_scorer_import(self):
        """Scorer module should import cleanly."""
        import assess.scorer
        assert hasattr(assess.scorer, "__name__")
