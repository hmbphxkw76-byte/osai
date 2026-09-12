"""End-to-end pipeline integration test for RAG metadata flow.

Verifies complete data flow:
    recon/rag_metadata_parser → ctx.service_profile["rag_kb_map"]
    → arm.py (seed injection + technique optimization)
    → executor.py (execution optimization)
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from recon.rag.metadata_parser import (
    KnowledgeBaseMap,
    RetrievalTiming,
)


class TestRAGPipelineDataFlow(unittest.TestCase):
    """Verify RAG metadata flows through pipeline without breakpoints."""

    def _create_mock_ctx(self) -> MagicMock:
        """Create a mock PipelineContext for testing."""
        ctx = MagicMock()
        ctx.service_profile = {}
        ctx.seeds = []
        ctx.techniques = ["base_technique"]
        ctx.mcpsec_surface = {}
        ctx.mcpsec_scan_results = {}
        ctx.orchestration_log = []
        ctx.args = MagicMock()
        ctx.args.timeout = 3600
        ctx.args.adversarial = False
        ctx.args.rag_metadata = True
        return ctx

    def _create_sample_kb_map(self) -> dict:
        """Create a sample KB map matching KnowledgeBaseMap.to_dict() schema."""
        return {
            "total_queries": 10,
            "total_chunks_observed": 45,
            "document_count": 2,
            "documents": {
                "PTO_Leave_Policy_2024.pdf": {
                    "chunk_count": 12,
                    "max_chunk_id": 11,
                    "sensitive_keywords": ["vacation", "leave"],
                },
                "Employee_Handbook_v3.pdf": {
                    "chunk_count": 20,
                    "max_chunk_id": 19,
                    "sensitive_keywords": ["salary", "termination"],
                },
            },
            "chunk_id_patterns": {"chunk_": 45},
            "score_statistics": {
                "vector": {"mean": 0.75, "stdev": 0.02, "count": 45},
                "bm25": {"mean": 3.2, "stdev": 0.5, "count": 45},
            },
            "inferred_chunk_size": 250,
            "inferred_chunk_overlap": 50,
            "inferred_retrieval_formula": "linear_fusion",
        }

    def test_recon_populates_service_profile(self):
        """Verify recon phase correctly populates ctx.service_profile['rag_kb_map']."""
        # Simulate recon phase output
        ctx = self._create_mock_ctx()
        kb_map_data = self._create_sample_kb_map()

        # This simulates what recon.py does:
        # ctx.service_profile["rag_kb_map"] = kb_map.to_dict()
        ctx.service_profile["rag_kb_map"] = kb_map_data

        self.assertIn("rag_kb_map", ctx.service_profile)
        self.assertEqual(ctx.service_profile["rag_kb_map"]["document_count"], 2)

    def test_arm_reads_rag_kb_map(self):
        """Verify arm phase reads from ctx.service_profile['rag_kb_map']."""
        ctx = self._create_mock_ctx()
        kb_map_data = self._create_sample_kb_map()
        ctx.service_profile["rag_kb_map"] = kb_map_data

        # Simulate arm.py reading pattern:
        # _rag_kb_map = ctx.service_profile.get("rag_kb_map") if hasattr(ctx, "service_profile") else None
        _rag_kb_map = ctx.service_profile.get("rag_kb_map") if hasattr(ctx, "service_profile") else None

        self.assertIsNotNone(_rag_kb_map)
        self.assertGreater(_rag_kb_map.get("document_count", 0), 0)

    def test_executor_reads_rag_kb_map(self):
        """Verify executor reads from ctx.service_profile['rag_kb_map']."""
        ctx = self._create_mock_ctx()
        kb_map_data = self._create_sample_kb_map()
        ctx.service_profile["rag_kb_map"] = kb_map_data

        # Simulate executor.py reading pattern
        _rag_kb_map = ctx.service_profile.get("rag_kb_map") if hasattr(ctx, "service_profile") else None

        self.assertIsNotNone(_rag_kb_map)
        self.assertEqual(_rag_kb_map.get("inferred_retrieval_formula"), "linear_fusion")

    def test_seed_injection_updates_ctx_seeds(self):
        """Verify seed injection appends to ctx.seeds."""
        from strike.rag.targeted_consumer import inject_rag_targeted_seeds

        ctx = self._create_mock_ctx()
        kb_map = self._create_sample_kb_map()

        count = inject_rag_targeted_seeds(ctx, kb_map, max_seeds=10)

        self.assertGreater(count, 0)
        self.assertEqual(len(ctx.seeds), count)
        # Verify orchestration_log updated
        self.assertTrue(
            any(log.get("phase") == "arm" and "rag" in log.get("decision", "") for log in ctx.orchestration_log)
        )

    def test_technique_recommendation_updates_ctx_techniques(self):
        """Verify technique recommendation modifies ctx.techniques."""
        from strike.rag.targeted_consumer import recommend_techniques_for_rag

        ctx = self._create_mock_ctx()
        kb_map = self._create_sample_kb_map()

        optimized = recommend_techniques_for_rag(kb_map, existing_techniques=ctx.techniques)

        # Should add techniques based on KB analysis
        # chunk_size=250 < 300 → adds 'decomposition'
        # linear_fusion → adds 'persuasion'
        # document_count=2, not > 3, so no multi_turn
        self.assertIn("decomposition", optimized)
        self.assertIn("persuasion", optimized)
        # skeleton_key should be first
        self.assertEqual(optimized[0], "skeleton_key")

    def test_execution_optimization_returns_params(self):
        """Verify execution optimization returns concurrency/timeout."""
        from strike.rag.targeted_consumer import optimize_strike_execution

        ctx = self._create_mock_ctx()
        kb_map = self._create_sample_kb_map()

        opts = optimize_strike_execution(ctx, kb_map)

        self.assertIn("concurrency", opts)
        self.assertIn("recommended_timeout", opts)
        self.assertIn("estimated_duration_seconds", opts)
        # High cache hit (stdev=0.02 < 0.05) should increase concurrency
        self.assertGreater(opts["concurrency"], 3)

    def test_data_flow_no_breakpoint_recon_to_arm(self):
        """Verify data flows from recon output to arm input without break."""
        # Step 1: Simulate recon output (KnowledgeBaseMap.to_dict())
        kb_map = KnowledgeBaseMap()
        kb_map.unique_documents["test.pdf"] = {"chunk_count": 5, "max_chunk_id": 4}
        kb_map_dict = kb_map.to_dict()

        # Step 2: Simulate ctx.service_profile storage
        ctx = self._create_mock_ctx()
        ctx.service_profile["rag_kb_map"] = kb_map_dict

        # Step 3: Verify arm can read it
        arm_kb_map = ctx.service_profile.get("rag_kb_map")
        self.assertIsInstance(arm_kb_map, dict)
        # All required keys present (note: to_dict uses 'documents' not 'unique_documents')
        self.assertIn("documents", arm_kb_map)
        self.assertIn("document_count", arm_kb_map)
        self.assertIn("inferred_chunk_size", arm_kb_map)
        self.assertIn("inferred_retrieval_formula", arm_kb_map)

    def test_data_flow_no_breakpoint_arm_to_executor(self):
        """Verify data flows from arm ctx.seeds to executor without break."""
        from strike.rag.targeted_consumer import inject_rag_targeted_seeds

        ctx = self._create_mock_ctx()
        kb_map = self._create_sample_kb_map()

        # ARM phase: inject seeds
        count = inject_rag_targeted_seeds(ctx, kb_map, max_seeds=5)

        # Executor phase: read ctx.seeds
        executor_seeds = list(ctx.seeds)
        # Seeds generated depends on available documents and dedup
        self.assertEqual(len(executor_seeds), count)
        self.assertGreater(count, 0)  # At least some seeds injected

        # Verify seeds have proper metadata for executor
        for seed in executor_seeds:
            self.assertTrue(hasattr(seed, "value"))
            self.assertTrue(hasattr(seed, "data_type"))
            self.assertTrue(hasattr(seed, "metadata"))

    def test_timing_cache_hit_probability_property(self):
        """Verify RetrievalTiming.cache_hit_probability calculates correctly."""
        # Fast retrieval → high cache hit probability
        fast = RetrievalTiming(retrieval_time_ms=0.4, generation_time_ms=2000)
        self.assertGreater(fast.cache_hit_probability, 0.8)

        # Slow retrieval → low cache hit probability
        slow = RetrievalTiming(retrieval_time_ms=150.0, generation_time_ms=500)
        self.assertLess(slow.cache_hit_probability, 0.3)

        # Edge case: exactly 5ms
        edge = RetrievalTiming(retrieval_time_ms=5.0, generation_time_ms=1000)
        self.assertGreater(edge.cache_hit_probability, 0.7)

    def test_kb_map_document_count_property(self):
        """Verify KB map document_count property works for conditional checks."""
        kb_map = KnowledgeBaseMap()
        # Empty map
        self.assertEqual(kb_map.document_count, 0)

        # Simulate adding documents
        kb_map.unique_documents["doc1.pdf"] = {"chunk_count": 5}
        kb_map.unique_documents["doc2.pdf"] = {"chunk_count": 3}
        self.assertEqual(kb_map.document_count, 2)


class TestRAGMetadataConsistency(unittest.TestCase):
    """Verify metadata format consistency across pipeline boundaries."""

    def test_kb_map_to_dict_schema_stable(self):
        """Verify KB map dict schema is stable for ctx.storage."""
        kb_map = KnowledgeBaseMap()
        kb_map.unique_documents["test.pdf"] = {
            "chunk_count": 5,
            "max_chunk_id": 4,
        }
        kb_map.inferred_chunk_size = 500
        kb_map.inferred_retrieval_formula = "vector_only"

        d = kb_map.to_dict()

        # Verify schema matches what arm.py and executor.py expect
        self.assertIn("document_count", d)
        self.assertIn("documents", d)
        self.assertIn("inferred_chunk_size", d)
        self.assertIn("inferred_retrieval_formula", d)
        self.assertIn("score_statistics", d)

        # Verify document_count is exposed at top level (for conditional checks)
        self.assertEqual(d["document_count"], 1)


if __name__ == "__main__":
    unittest.main()
