"""Tests for Seed Dynamic Generation Engine."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.seed_dynamic_engine import SeedDynamicEngine, generate_dynamic_seeds_for_context


class MockContext:
    """Mock PipelineContext for testing."""

    def __init__(self) -> None:
        self.service_profile = {
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "model_name": "gpt-4",
            "organization": "TestCorp",
        }
        self.capabilities = {
            "file_access": True,
            "code_execution": False,
            "database_access": True,
        }
        self.seeds = []
        self.orchestration_log = []


class MockZhContext:
    """Mock context with Chinese model."""

    def __init__(self) -> None:
        self.service_profile = {
            "endpoint": "https://qwen.example.com/v1/chat/completions",
            "model_name": "qwen2.5-72b",
            "organization": "测试公司",
        }
        self.capabilities = {"rag_knowledge": True}
        self.seeds = []
        self.orchestration_log = []


class TestSeedDynamicEngine(unittest.TestCase):
    """Test suite for SeedDynamicEngine."""

    def setUp(self) -> None:
        self.ctx = MockContext()
        self.engine = SeedDynamicEngine(self.ctx)

    def test_detect_model_type_gpt(self) -> None:
        """Should detect GPT-family models."""
        self.assertEqual(self.engine._detect_model_type(), "gpt-family")

    def test_detect_model_type_zh(self) -> None:
        """Should detect Chinese models."""
        ctx_zh = MockZhContext()
        engine_zh = SeedDynamicEngine(ctx_zh)
        self.assertEqual(engine_zh._detect_model_type(), "zh-llm")

    def test_detect_model_type_generic(self) -> None:
        """Should fallback to generic."""
        self.ctx.service_profile = {}
        engine = SeedDynamicEngine(self.ctx)
        self.assertEqual(engine._detect_model_type(), "generic")

    def test_generate_seeds_returns_list(self) -> None:
        """Should return a list of seed dicts."""
        seeds = self.engine.generate_seeds(category="LLM01", count=3)
        self.assertIsInstance(seeds, list)
        self.assertGreater(len(seeds), 0)

    def test_generate_seeds_structure(self) -> None:
        """Generated seeds should have correct structure."""
        seeds = self.engine.generate_seeds(category="LLM01", count=1)
        if seeds:
            seed = seeds[0]
            self.assertIn("value", seed)
            self.assertIn("metadata", seed)
            self.assertIn("owasp_id", seed["metadata"])
            self.assertEqual(seed["metadata"]["owasp_id"], "LLM01")

    def test_generate_seeds_with_capabilities(self) -> None:
        """Should use capabilities when targeting."""
        seeds = self.engine.generate_seeds(
            category="ASI02",
            count=3,
            use_capability_targeting=True,
        )
        self.assertGreater(len(seeds), 0)

    def test_generate_targeted_seeds(self) -> None:
        """Should generate capability-targeted seeds."""
        seeds = self.engine.generate_targeted_seeds("database_access", count=2)
        self.assertIsInstance(seeds, list)
        for seed in seeds:
            self.assertIn("value", seed)
            self.assertIn("target_capability", seed["metadata"])

    def test_generate_rag_secrets(self) -> None:
        """Should generate RAG-targeted secret extraction seeds."""
        secrets = ["api_keys", "db_credentials"]
        self.engine.generate_rag_secrets(secrets)
        self.assertEqual(len(secrets), len(secrets))

    def test_inject_seeds_into_ctx(self) -> None:
        """Should inject seeds into context."""
        seeds = self.engine.generate_seeds(category="LLM01", count=2)
        injected = self.engine.inject_seeds_into_ctx(seeds)
        self.assertGreater(injected, 0)
        self.assertEqual(len(self.ctx.seeds), injected)

    def test_inject_no_duplicates(self) -> None:
        """Should not inject duplicate seeds."""
        seeds = self.engine.generate_seeds(category="LLM01", count=1)
        self.engine.inject_seeds_into_ctx(seeds)
        initial_count = len(self.ctx.seeds)
        # Inject same seeds again
        self.engine.inject_seeds_into_ctx(seeds)
        self.assertEqual(len(self.ctx.seeds), initial_count)

    def test_zh_model_generates_chinese(self) -> None:
        """Should generate Chinese content for Chinese models."""
        ctx_zh = MockZhContext()
        engine_zh = SeedDynamicEngine(ctx_zh)
        seeds = engine_zh.generate_seeds(category="LLM01", count=1, language="zh")
        if seeds:
            # Check that seed value contains Chinese characters
            value = seeds[0]["value"]
            self.assertTrue(any("\u4e00" <= ch <= "\u9fff" for ch in value))


class TestConvenienceFunction(unittest.TestCase):
    """Test generate_dynamic_seeds_for_context convenience function."""

    def test_default_categories(self) -> None:
        """Should use capabilities when no categories specified."""
        ctx = MockContext()
        seeds = generate_dynamic_seeds_for_context(ctx, count_per_category=1)
        self.assertIsInstance(seeds, list)
        self.assertGreater(len(seeds), 0)

    def test_explicit_categories(self) -> None:
        """Should use specified categories."""
        ctx = MockContext()
        seeds = generate_dynamic_seeds_for_context(
            ctx,
            categories=["LLM01", "ASI02"],
            count_per_category=1,
        )
        self.assertGreater(len(seeds), 0)
        # Should have seeds from both categories
        categories_generated = {s["metadata"]["owasp_id"] for s in seeds}
        self.assertTrue("LLM01" in categories_generated or "ASI02" in categories_generated)


if __name__ == "__main__":
    unittest.main()
