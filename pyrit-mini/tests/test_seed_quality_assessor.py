"""Tests for Seed Quality Assessment Engine."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.seed_quality_assessor import (
    SeedPerformanceMetrics,
    SeedQualityAssessor,
    SeedHealthReport,
    assess_seed_library_health,
    _RETIREMENT_THRESHOLD,
    _WARNING_THRESHOLD,
    _MIN_SEED_SAMPLES,
)


class TestSeedPerformanceMetrics(unittest.TestCase):
    """Test SeedPerformanceMetrics dataclass."""

    def test_initial_state(self) -> None:
        m = SeedPerformanceMetrics(seed_hash="abc", category="test", owasp_id="LLM01")
        self.assertEqual(m.total_attempts, 0)
        self.assertEqual(m.average_asr, 0.0)
        self.assertEqual(m.status, "active")

    def test_record_success(self) -> None:
        m = SeedPerformanceMetrics(seed_hash="abc", category="test", owasp_id="LLM01")
        m.record_attempt(True, 100)
        self.assertEqual(m.total_attempts, 1)
        self.assertEqual(m.successful_attacks, 1)
        self.assertEqual(m.average_asr, 1.0)
        self.assertGreater(m.total_token_cost, 0)

    def test_record_failure(self) -> None:
        m = SeedPerformanceMetrics(seed_hash="abc", category="test", owasp_id="LLM01")
        m.record_attempt(False, 50)
        self.assertEqual(m.total_attempts, 1)
        self.assertEqual(m.successful_attacks, 0)
        self.assertEqual(m.average_asr, 0.0)

    def test_should_retire_below_threshold(self) -> None:
        m = SeedPerformanceMetrics(seed_hash="abc", category="test", owasp_id="LLM01")
        for _ in range(_MIN_SEED_SAMPLES):
            m.record_attempt(False)
        self.assertTrue(m.should_retire)

    def test_should_not_retire_with_few_samples(self) -> None:
        m = SeedPerformanceMetrics(seed_hash="abc", category="test", owasp_id="LLM01")
        for _ in range(_MIN_SEED_SAMPLES - 1):
            m.record_attempt(False)
        self.assertFalse(m.should_retire)

    def test_needs_review_warning_threshold(self) -> None:
        m = SeedPerformanceMetrics(seed_hash="abc", category="test", owasp_id="LLM01")
        # Add enough samples to exceed _MIN_SEED_SAMPLES
        for _ in range(_MIN_SEED_SAMPLES):
            m.record_attempt(False)
        # Should need review (ASR < WARNING_THRESHOLD)
        self.assertTrue(m.needs_review)

    def test_well_performing_seed_healthy(self) -> None:
        m = SeedPerformanceMetrics(seed_hash="abc", category="test", owasp_id="LLM01")
        for _ in range(_MIN_SEED_SAMPLES):
            m.record_attempt(True)
        self.assertFalse(m.should_retire)
        self.assertFalse(m.needs_review)


class TestSeedQualityAssessor(unittest.TestCase):
    """Test SeedQualityAssessor class."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.history_path = os.path.join(self.tmpdir, "test_history.json")
        self.assessor = SeedQualityAssessor(self.history_path)

    def tearDown(self) -> None:
        # Clean up all files in tmpdir
        if os.path.exists(self.tmpdir):
            for f in os.listdir(self.tmpdir):
                file_path = os.path.join(self.tmpdir, f)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            os.rmdir(self.tmpdir)

    def test_record_and_retrieve(self) -> None:
        self.assessor.record_result("seed_abc", True, 100, "injection", "LLM01")
        self.assertIn("seed_abc", self.assessor._metrics_cache)

    def test_generate_health_report(self) -> None:
        self.assessor.record_result("seed_1", True, 100, "injection", "LLM01")
        self.assessor.record_result("seed_2", False, 50, "injection", "LLM01")
        report = self.assessor.generate_health_report()
        self.assertEqual(report.total_seeds, 2)

    def test_retire_underperforming(self) -> None:
        # Add a seed with very low ASR
        for _ in range(_MIN_SEED_SAMPLES + 5):
            self.assessor.record_result("bad_seed", False, 10, "injection", "LLM01")

        # Verify seed needs retirement
        to_retire = self.assessor.get_seeds_for_retirement()
        self.assertGreater(len(to_retire), 0)

        # After calling retire, status should be retired
        self.assessor.retire_underperforming()
        metrics = self.assessor._metrics_cache["bad_seed"]
        self.assertEqual(metrics.status, "retired")

    def test_get_seeds_for_retirement(self) -> None:
        for _ in range(_MIN_SEED_SAMPLES + 5):
            self.assessor.record_result("bad_seed", False, 10, "injection", "LLM01")
        self.assessor.retire_underperforming()
        to_retire = self.assessor.get_seeds_for_retirement()
        self.assertGreater(len(to_retire), 0)

    def test_export_report_to_json(self) -> None:
        self.assessor.record_result("seed_1", True, 100, "injection", "LLM01")
        output_path = os.path.join(self.tmpdir, "test_report.json")
        result = self.assessor.export_report_to_json(output_path)
        self.assertTrue(os.path.exists(result))

        with open(result, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("summary", data)
        self.assertIn("category_coverage", data)

    def test_save_and_load_history(self) -> None:
        self.assessor.record_result("seed_1", True, 100, "injection", "LLM01")
        self.assessor.save_history()
        self.assertTrue(os.path.exists(self.history_path))

        # Create new assessor that loads from file
        new_assessor = SeedQualityAssessor(self.history_path)
        self.assertIn("seed_1", new_assessor._metrics_cache)

    def test_recommendations_for_missing_categories(self) -> None:
        # Only add LLM01 seeds
        self.assessor.record_result("seed_1", True, 100, "injection", "LLM01")
        report = self.assessor.generate_health_report()

        # Should recommend adding missing categories
        has_critical_rec = any("CRITICAL" in r or "HIGH" in r for r in report.recommendations)
        self.assertTrue(has_critical_rec)

    def test_load_corrupt_history(self) -> None:
        """Should handle corrupt history file gracefully."""
        with open(self.history_path, "w", encoding="utf-8") as f:
            f.write("{corrupt json")
        assessor = SeedQualityAssessor(self.history_path)
        self.assertEqual(len(assessor._metrics_cache), 0)


class TestLibraryHealthCheck(unittest.TestCase):
    """Test the assess_seed_library_health convenience function."""

    def test_returns_dict_with_expected_keys(self) -> None:
        result = assess_seed_library_health()
        expected_keys = {
            "total_seeds", "active", "warning", "retired", "overall_asr", "recommendations"
        }
        self.assertTrue(expected_keys.issubset(set(result.keys())))


if __name__ == "__main__":
    unittest.main()
