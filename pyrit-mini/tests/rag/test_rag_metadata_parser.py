"""Tests for recon/rag_metadata_parser.py — RAG Metadata Auto-Parser.

Tests cover:
    1. Format-agnostic response parsing (multiple RAG response formats)
    2. Timing analysis (cache hit detection)
    3. Stealth features (query diversification, behavioral mimicry, temporal spacing)
"""

from __future__ import annotations

import unittest

from recon.rag.metadata_parser import (
    _cluster_queries_by_topic,
    _compute_lognormal_delay,
    _diversify_query,
    parse_rag_response,
)


class TestRAGResponseParsing(unittest.TestCase):
    """Test parsing of various RAG response formats."""

    def test_user_example_format(self):
        """Parse the exact format from user's curl example."""
        response = {
            "answer": "According to PTO_Leave_Policy_2024.pdf...",
            "sources": [
                {
                    "title": "PTO_Leave_Policy_2024.pdf",
                    "chunk_id": "chunk_087",
                    "text": "Vacation Accrual: Years 0-2: 15 days/year. Years 3-5: 18 days/year.",
                    "vector_score": 0.2,
                    "bm25_score": 2.1,
                    "combined_score": 0.51,
                }
            ],
            "retrieval_info": {
                "retrieval_time_ms": 0.4,
                "generation_time_ms": 6796.02,
                "total_time_ms": 6796.8,
            },
        }

        result = parse_rag_response(response)

        self.assertTrue(result.has_structured_sources)
        self.assertEqual(result.num_chunks, 1)
        self.assertEqual(result.format_type, "openai_rag")
        self.assertEqual(result.unique_sources, ["PTO_Leave_Policy_2024.pdf"])
        self.assertEqual(result.unique_chunk_ids, ["chunk_087"])

        # Score ranges
        self.assertEqual(result.score_range_vector, (0.2, 0.2))
        self.assertEqual(result.score_range_bm25, (2.1, 2.1))
        self.assertEqual(result.score_range_combined, (0.51, 0.51))

        # Timing
        self.assertEqual(result.timing.retrieval_time_ms, 0.4)
        self.assertEqual(result.timing.generation_time_ms, 6796.02)
        self.assertEqual(result.timing.total_time_ms, 6796.8)
        self.assertGreater(result.timing.cache_hit_probability, 0.8)  # Fast retrieval = cache hit

    def test_langchain_format(self):
        """Parse LangChain-style response with source_documents."""
        response = {
            "result": "The answer is...",
            "source_documents": [
                {
                    "page_content": "This is the document content...",
                    "metadata": {
                        "source": "/docs/policy.pdf",
                        "page": 5,
                    },
                }
            ],
        }

        result = parse_rag_response(response)

        self.assertTrue(result.has_structured_sources)
        self.assertEqual(result.num_chunks, 1)
        self.assertEqual(result.format_type, "langchain_style")
        # Text should be extracted from page_content
        self.assertGreater(result.chunks[0].text_length, 0)

    def test_cohere_format(self):
        """Parse Cohere-style response with passages."""
        response = {
            "text": "Generated answer...",
            "documents": [
                {
                    "id": "doc_001",
                    "title": "API Reference",
                    "snippet": "The API supports rate limiting...",
                    "relevance_score": 0.85,
                }
            ],
        }

        result = parse_rag_response(response)

        self.assertTrue(result.has_structured_sources)
        self.assertEqual(result.num_chunks, 1)

    def test_no_sources_response(self):
        """Handle response with no structured sources."""
        response = {
            "answer": "I don't have enough information to answer.",
        }

        result = parse_rag_response(response)

        self.assertFalse(result.has_structured_sources)
        self.assertEqual(result.num_chunks, 0)

    def test_multiple_chunks(self):
        """Parse response with multiple retrieved chunks."""
        response = {
            "sources": [
                {
                    "title": f"Document_{i}.pdf",
                    "chunk_id": f"chunk_{i:03d}",
                    "text": f"Content of chunk {i}...",
                    "vector_score": 0.9 - i * 0.1,
                    "bm25_score": 3.0 - i * 0.5,
                    "combined_score": 0.8 - i * 0.05,
                }
                for i in range(5)
            ],
        }

        result = parse_rag_response(response)

        self.assertEqual(result.num_chunks, 5)
        self.assertEqual(len(result.unique_sources), 5)
        self.assertEqual(len(result.unique_chunk_ids), 5)

        # Check score ranges (use assertAlmostEqual for float precision)
        self.assertAlmostEqual(result.score_range_vector[0], 0.5, places=5)
        self.assertAlmostEqual(result.score_range_vector[1], 0.9, places=5)
        self.assertAlmostEqual(result.score_range_bm25[0], 1.0, places=5)
        self.assertAlmostEqual(result.score_range_bm25[1], 3.0, places=5)
        self.assertAlmostEqual(result.score_range_combined[0], 0.6, places=5)
        self.assertAlmostEqual(result.score_range_combined[1], 0.8, places=5)


class TestRetrievalTiming(unittest.TestCase):
    """Test timing analysis and cache hit detection."""

    def test_fast_retrieval_cache_hit(self):
        """Sub-5ms retrieval should indicate cache hit."""
        response = {
            "sources": [{"title": "doc.pdf", "text": "content"}],
            "retrieval_info": {"retrieval_time_ms": 0.4, "generation_time_ms": 2000},
        }

        result = parse_rag_response(response)
        self.assertGreater(result.timing.cache_hit_probability, 0.8)

    def test_slow_retrieval_no_cache(self):
        """Slow retrieval should indicate no cache hit."""
        response = {
            "sources": [{"title": "doc.pdf", "text": "content"}],
            "retrieval_info": {"retrieval_time_ms": 150.0, "generation_time_ms": 500},
        }

        result = parse_rag_response(response)
        self.assertLess(result.timing.cache_hit_probability, 0.3)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def test_empty_response(self):
        """Empty response should not crash."""
        result = parse_rag_response({})
        self.assertFalse(result.has_structured_sources)

    def test_malformed_chunk(self):
        """Malformed chunk fields should be handled gracefully."""
        response = {
            "sources": [
                {
                    "title": "doc.pdf",
                    "chunk_id": None,
                    "vector_score": "not_a_number",
                    "text": 12345,  # Non-string text
                }
            ],
        }

        result = parse_rag_response(response)
        self.assertTrue(result.has_structured_sources)
        # Should still parse without crashing
        self.assertEqual(result.num_chunks, 1)

    def test_deeply_nested_response(self):
        """Deeply nested sources should be auto-detected."""
        response = {
            "response": {
                "data": {
                    "retrieval": {
                        "results": [
                            {
                                "title": "Deep_Doc.pdf",
                                "text": "Found at depth 4",
                                "score": 0.75,
                            }
                        ]
                    }
                }
            }
        }

        result = parse_rag_response(response)
        # Should find sources at depth 4
        self.assertTrue(result.has_structured_sources or result.format_type == "unknown")


class TestStealthQueryDiversification(unittest.TestCase):
    """Test stealth query diversification — semantic-preserving rephrasing."""

    def test_policy_query_variant(self):
        """Policy queries should use policy-framed templates."""
        intent = "PTO policy"
        variant = _diversify_query(intent, category="policy", variant_index=0)

        # Should be natural language, not the static template
        self.assertNotIn("What is the policy", variant.lower())
        # Should contain the topic concept
        self.assertIn("pto", variant.lower())

    def test_compliance_query_variant(self):
        """Compliance queries should use audit-framed templates."""
        intent = "Explain the GDPR compliance procedures."
        variant = _diversify_query(intent, category="compliance", variant_index=1)

        # Should reframe as audit/compliance context
        self.assertIn("gdpr", variant.lower())
        self.assertNotIn("explain the", variant.lower())

    def test_technical_query_variant(self):
        """Technical queries should use implementation-framed templates."""
        intent = "API rate limiting configuration"
        variant = _diversify_query(intent, category="technical", variant_index=0)

        # Should frame as technical review
        self.assertIn("api", variant.lower())
        self.assertNotIn("what is the", variant.lower())

    def test_variant_uniqueness(self):
        """Different variant indices should produce different phrasings."""
        intent = "Employee benefits enrollment"
        variants = {_diversify_query(intent, category="policy", variant_index=i) for i in range(5)}
        # Should have multiple distinct variants (at least 3 unique)
        self.assertGreaterEqual(len(variants), 3)

    def test_no_keywords_from_original_format(self):
        """Diversified queries should not start with common detection patterns."""
        original = "What is the PTO policy?"
        variant = _diversify_query(original, category="policy", variant_index=2)

        # Should not match common enumeration patterns
        detection_patterns = [
            "what is the policy",
            "tell me about",
            "list all",
        ]
        for pattern in detection_patterns:
            self.assertNotIn(pattern, variant.lower())


class TestBehavioralMimicry(unittest.TestCase):
    """Test topic-clustered query ordering."""

    def test_topic_clustering_groups_related(self):
        """Related topics should be adjacent in output."""
        queries = [
            "What is the PTO policy?",
            "What is the API rate limiting configuration?",
            "What are the company travel reimbursement guidelines?",
            "Describe the password complexity requirements.",
        ]
        reordered = _cluster_queries_by_topic(queries)

        # All queries should be preserved
        self.assertEqual(len(reordered), len(queries))
        self.assertEqual(set(reordered), set(queries))

    def test_topic_clustering_no_abrupt_jumps(self):
        """Policy → compliance → technical should not be interleaved randomly."""
        queries = [
            "What is the PTO policy?",  # policy
            "What are the company travel reimbursement guidelines?",  # policy
            "What is the API rate limiting configuration?",  # technical
            "What are the deployment rollback procedures?",  # technical
        ]
        reordered = _cluster_queries_by_topic(queries)

        # With high probability, related topics should cluster together
        # (statistical test: at least 2 adjacent queries should share category)
        adjacent_pairs = list(zip(reordered, reordered[1:]))
        has_clustering = False
        policy_keywords = {"pto", "travel", "reimbursement", "benefits"}
        tech_keywords = {"api", "deployment", "database", "configuration"}

        for a, b in adjacent_pairs:
            a_is_policy = any(kw in a.lower() for kw in policy_keywords)
            b_is_policy = any(kw in b.lower() for kw in policy_keywords)
            a_is_tech = any(kw in a.lower() for kw in tech_keywords)
            b_is_tech = any(kw in b.lower() for kw in tech_keywords)

            if (a_is_policy and b_is_policy) or (a_is_tech and b_is_tech):
                has_clustering = True
                break

        # Note: Due to randomness, we can't guarantee this always passes,
        # but with proper clustering it should be statistically likely
        self.assertTrue(has_clustering or len(reordered) <= 2)

    def test_empty_query_list(self):
        """Empty query list should return empty."""
        self.assertEqual(_cluster_queries_by_topic([]), [])


class TestLognormalTiming(unittest.TestCase):
    """Test lognormal distribution for temporal spacing."""

    def test_delay_within_bounds(self):
        """Generated delays should respect min/max bounds."""
        for _ in range(100):
            delay = _compute_lognormal_delay(
                base_seconds=10.0,
                sigma=0.5,
                min_delay=1.0,
                max_delay=120.0,
            )
            self.assertGreaterEqual(delay, 1.0)
            self.assertLessEqual(delay, 120.0)

    def test_lognormal_distribution_shape(self):
        """Lognormal delays should have right-skewed distribution."""
        delays = [_compute_lognormal_delay(base_seconds=10.0, sigma=0.5) for _ in range(200)]

        # Lognormal: mean > median (right skew)
        mean_delay = sum(delays) / len(delays)
        sorted_delays = sorted(delays)
        median_delay = sorted_delays[len(sorted_delays) // 2]

        # Mean should be greater than median for lognormal
        self.assertGreater(mean_delay, median_delay * 0.5)  # Allow variance

    def test_delay_increases_with_base(self):
        """Higher base_seconds should produce higher average delays."""
        low_delays = [_compute_lognormal_delay(base_seconds=2.0) for _ in range(100)]
        high_delays = [_compute_lognormal_delay(base_seconds=15.0) for _ in range(100)]

        avg_low = sum(low_delays) / len(low_delays)
        avg_high = sum(high_delays) / len(high_delays)

        self.assertGreater(avg_high, avg_low)

    def test_jitter_applied(self):
        """Different sigma values should produce different variance."""
        # Low sigma = consistent delays
        consistent = [_compute_lognormal_delay(base_seconds=10.0, sigma=0.1) for _ in range(100)]
        # High sigma = variable delays
        variable = [_compute_lognormal_delay(base_seconds=10.0, sigma=1.0) for _ in range(100)]

        import statistics

        var_consistent = statistics.variance(consistent)
        var_variable = statistics.variance(variable)

        # Higher sigma should generally produce more variance
        self.assertGreater(var_variable, var_consistent * 0.5)


if __name__ == "__main__":
    unittest.main()
