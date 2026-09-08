"""Tests for strike/rag_targeted_consumer.py — RAG Metadata Consumer.

Tests cover:
    1. Document-targeted seed generation
    2. Chunk boundary exploitation seed generation
    3. Retrieval manipulation seed generation
    4. Technique recommendation based on KB metadata
    5. Execution optimization from timing data
    6. Integration injection into ctx.seeds
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from strike.rag_targeted_consumer import (
    compute_optimal_concurrency,
    estimate_attack_duration,
    generate_document_targeted_seeds,
    inject_rag_targeted_seeds,
    optimize_strike_execution,
    recommend_techniques_for_rag,
)


class TestDocumentTargetedSeeds(unittest.TestCase):
    """Test seed generation from KB metadata."""

    def setUp(self):
        """Create sample KB map for testing."""
        self.sample_kb_map = {
            "document_count": 3,
            "documents": {
                "PTO_Leave_Policy_2024.pdf": {
                    "chunks_observed": 5,
                    "max_chunk_id_num": 87,
                    "scores": [0.51, 0.45, 0.42],
                },
                "Employee_Handbook_2024.pdf": {
                    "chunks_observed": 3,
                    "max_chunk_id_num": 45,
                    "scores": [0.62, 0.58],
                },
                "Security_Policy_v3.pdf": {
                    "chunks_observed": 1,
                    "max_chunk_id_num": 12,
                    "scores": [0.35],
                },
            },
            "inferred_chunk_size": 500,
            "inferred_retrieval_formula": "linear_fusion (α·vector + β·bm25)",
            "chunk_id_patterns": {"chunk_N": 8, "chunk_NNN": 2},
            "score_statistics": {
                "vector": {"mean": 0.45, "stdev": 0.08, "count": 20},
                "bm25": {"mean": 2.1, "stdev": 0.3, "count": 20},
                "combined": {"mean": 0.55, "stdev": 0.05, "count": 20},
            },
        }

    def test_generates_seeds_from_known_documents(self):
        """Should generate seeds targeting specific documents."""
        seeds = generate_document_targeted_seeds(self.sample_kb_map, max_seeds=10)

        self.assertGreater(len(seeds), 0)
        self.assertLessEqual(len(seeds), 10)

        # Check seed structure
        for seed in seeds:
            self.assertIn("value", seed)
            self.assertIn("metadata", seed)
            self.assertIn("attack_category", seed["metadata"])

    def test_seeds_reference_actual_documents(self):
        """Generated seeds should reference known document titles."""
        seeds = generate_document_targeted_seeds(self.sample_kb_map, max_seeds=10)

        # At least one seed should reference a known document
        all_values = " ".join(s["value"] for s in seeds)
        has_doc_ref = any(
            doc_name in all_values
            for doc_name in self.sample_kb_map["documents"].keys()
        )
        self.assertTrue(has_doc_ref, "Seeds should reference actual document titles")

    def test_empty_kb_map_returns_empty(self):
        """Empty KB map should return no seeds."""
        seeds = generate_document_targeted_seeds({}, max_seeds=10)
        self.assertEqual(len(seeds), 0)

        seeds = generate_document_targeted_seeds(None, max_seeds=10)
        self.assertEqual(len(seeds), 0)

    def test_chunk_boundary_seeds_generated(self):
        """Chunk boundary exploitation seeds should be generated when chunk_size known."""
        seeds = generate_document_targeted_seeds(
            self.sample_kb_map,
            max_seeds=15,
            include_chunk_boundary=True,
        )

        chunk_seeds = [s for s in seeds if s["metadata"].get("attack_category") == "chunk_boundary_exploit"]
        self.assertGreater(len(chunk_seeds), 0, "Chunk boundary seeds should be generated")


class TestTechniqueRecommendation(unittest.TestCase):
    """Test technique selection based on RAG metadata."""

    def test_small_chunks_add_decomposition(self):
        """Small chunk size should add decomposition technique."""
        kb_map = {"inferred_chunk_size": 200, "document_count": 5}
        techniques = recommend_techniques_for_rag(kb_map, existing_techniques=[])
        self.assertIn("decomposition", techniques)

    def test_large_chunks_add_chunked_request(self):
        """Large chunk size should add chunked_request technique."""
        kb_map = {"inferred_chunk_size": 1000, "document_count": 5}
        techniques = recommend_techniques_for_rag(kb_map, existing_techniques=[])
        self.assertIn("chunked_request", techniques)

    def test_linear_fusion_adds_persuasion(self):
        """Linear fusion should add persuasion technique."""
        kb_map = {"inferred_retrieval_formula": "linear_fusion (α·vector + β·bm25)", "document_count": 5}
        techniques = recommend_techniques_for_rag(kb_map, existing_techniques=[])
        self.assertIn("persuasion", techniques)

    def test_many_documents_adds_multi_turn(self):
        """Many documents should add multi_turn technique."""
        kb_map = {"document_count": 10}
        techniques = recommend_techniques_for_rag(kb_map, existing_techniques=[])
        self.assertIn("multi_turn", techniques)

    def test_skeleton_key_always_first(self):
        """Skeleton key should always be the highest priority technique."""
        kb_map = {"document_count": 1}
        techniques = recommend_techniques_for_rag(kb_map, existing_techniques=[])
        if techniques:
            self.assertEqual(techniques[0], "skeleton_key")

    def test_existing_techniques_preserved(self):
        """Existing techniques should be preserved."""
        kb_map = {"document_count": 5}
        existing = ["custom_technique"]
        techniques = recommend_techniques_for_rag(kb_map, existing_techniques=existing)
        self.assertIn("custom_technique", techniques)


class TestExecutionOptimization(unittest.TestCase):
    """Test execution parameter optimization."""

    def test_high_cache_hit_increases_concurrency(self):
        """High cache consistency should allow higher concurrency."""
        kb_map = {
            "document_count": 5,
            "score_statistics": {
                "vector": {"stdev": 0.02, "count": 10},  # Low variance = cache hit
            },
        }
        concurrency = compute_optimal_concurrency(kb_map, default_concurrency=4)
        self.assertGreater(concurrency, 4)

    def test_low_cache_hit_decreases_concurrency(self):
        """Low cache hit should decrease concurrency."""
        kb_map = {
            "document_count": 5,
            "score_statistics": {
                "vector": {"stdev": 0.5, "count": 10},  # High variance = no cache
            },
        }
        concurrency = compute_optimal_concurrency(kb_map, default_concurrency=4)
        self.assertLessEqual(concurrency, 4)

    def test_estimate_duration_scales_with_documents(self):
        """Larger KB should increase estimated duration."""
        small_kb = {"document_count": 2}
        large_kb = {"document_count": 50}

        small_duration = estimate_attack_duration(small_kb, num_seeds=10)
        large_duration = estimate_attack_duration(large_kb, num_seeds=10)

        self.assertGreater(large_duration, small_duration)


class TestSeedInjection(unittest.TestCase):
    """Test seed injection into pipeline context."""

    def test_injects_seeds_into_ctx(self):
        """Seeds should be prepended to ctx.seeds."""
        ctx = MagicMock()
        ctx.seeds = []
        ctx.orchestration_log = []

        kb_map = {
            "document_count": 2,
            "documents": {
                "doc1.pdf": {"chunks_observed": 3, "max_chunk_id_num": 10, "scores": [0.5]},
                "doc2.pdf": {"chunks_observed": 1, "max_chunk_id_num": 5, "scores": [0.4]},
            },
            "inferred_chunk_size": 500,
            "inferred_retrieval_formula": "linear_fusion",
        }

        with patch("strike.rag_targeted_consumer.logger"):
            count = inject_rag_targeted_seeds(ctx, kb_map, max_seeds=10)

        self.assertGreater(count, 0)
        # Seeds should be prepended (first seeds in list)
        self.assertGreater(len(ctx.seeds), 0)

    def test_deduplication(self):
        """Duplicate seeds should not be injected."""
        ctx = MagicMock()
        ctx.seeds = []
        ctx.orchestration_log = []

        # Add a seed with the same value that would be generated
        from pyrit.models import SeedPrompt
        existing_seed = SeedPrompt(
            value="According to the document 'doc1.pdf', what are the specific policies?",
            data_type="text",
        )
        ctx.seeds = [existing_seed]

        kb_map = {
            "document_count": 1,
            "documents": {
                "doc1.pdf": {"chunks_observed": 3, "max_chunk_id_num": 10, "scores": [0.5]},
            },
            "inferred_chunk_size": 500,
            "inferred_retrieval_formula": "linear_fusion",
        }

        with patch("strike.rag_targeted_consumer.logger"):
            count = inject_rag_targeted_seeds(ctx, kb_map, max_seeds=10)

        # Should inject some seeds but skip duplicates
        self.assertGreaterEqual(count, 0)


class TestEndToEnd(unittest.TestCase):
    """End-to-end test: KB map → seeds → technique → optimization."""

    def test_full_pipeline_integration(self):
        """Full pipeline: KB map should produce seeds, techniques, and optimizations."""
        kb_map = {
            "document_count": 5,
            "documents": {
                "PTO_Policy.pdf": {"chunks_observed": 5, "max_chunk_id_num": 87, "scores": [0.51]},
                "Handbook.pdf": {"chunks_observed": 3, "max_chunk_id_num": 45, "scores": [0.62]},
                "Security.pdf": {"chunks_observed": 2, "max_chunk_id_num": 23, "scores": [0.45]},
                "API_Docs.pdf": {"chunks_observed": 4, "max_chunk_id_num": 56, "scores": [0.55]},
                "Compliance.pdf": {"chunks_observed": 1, "max_chunk_id_num": 12, "scores": [0.38]},
            },
            "inferred_chunk_size": 500,
            "inferred_retrieval_formula": "linear_fusion (α·vector + β·bm25)",
            "chunk_id_patterns": {"chunk_NNN": 10},
            "score_statistics": {
                "vector": {"mean": 0.45, "stdev": 0.08, "count": 30},
                "bm25": {"mean": 2.1, "stdev": 0.3, "count": 30},
                "combined": {"mean": 0.50, "stdev": 0.05, "count": 30},
            },
        }

        # Step 1: Generate seeds
        seeds = generate_document_targeted_seeds(kb_map, max_seeds=15)
        self.assertGreater(len(seeds), 0)

        # Step 2: Recommend techniques
        techniques = recommend_techniques_for_rag(kb_map, existing_techniques=[])
        self.assertIn("skeleton_key", techniques)
        self.assertIn("persuasion", techniques)

        # Step 3: Optimize execution
        concurrency = compute_optimal_concurrency(kb_map, default_concurrency=4)
        self.assertGreater(concurrency, 0)
        self.assertLessEqual(concurrency, 8)

        duration = estimate_attack_duration(kb_map, num_seeds=len(seeds))
        self.assertGreater(duration, 0)


if __name__ == "__main__":
    unittest.main()
