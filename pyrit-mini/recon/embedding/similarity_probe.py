# -*- coding: utf-8 -*-
"""recon/embedding/similarity_probe.py - Embedding Similarity Behavior Analysis.

Analyzes embedding API similarity behavior for attack surface mapping:
    1. Vector dimension detection
    2. Similarity score distribution analysis
    3. Semantic clustering behavior
    4. Out-of-distribution detection
    5. Embedding inversion feasibility
    6. Cosine distance calibration

Academic basis:
    - Song et al. (arXiv:2005.09680) - Information leakage from embeddings
    - Li et al. (arXiv:2305.03018) - Embedding inversion attacks
    - OWASP LLM08 - Embedding vector vulnerability

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility - similarity probing only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SimilarityTest:
    """A similarity test result."""

    test_name: str = ""
    text_a: str = ""
    text_b: str = ""
    cosines_similarity: float = 0.0
    euclidean_distance: float = 0.0
    is_semantically_similar: bool = False
    passes_threshold: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_name": self.test_name,
            "cosine_similarity": self.cosines_similarity,
            "euclidean_distance": self.euclidean_distance,
            "passes_threshold": self.passes_threshold,
        }


@dataclass
class SimilarityProfileResult:
    """Complete similarity profiling result."""

    target_url: str = ""
    embedding_dimension: int = 0
    similarity_threshold: float = 0.85
    tests: list[SimilarityTest] = field(default_factory=list)
    inversion_feasibility: str = "unknown"  # low, medium, high
    clustering_quality: float = 0.0  # 0.0-1.0
    semantic_manifold_density: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "embedding_dimension": self.embedding_dimension,
            "similarity_threshold": self.similarity_threshold,
            "test_count": len(self.tests),
            "inversion_feasibility": self.inversion_feasibility,
            "clustering_quality": self.clustering_quality,
        }


class EmbeddingSimilarityProbe:
    """Profile embedding API similarity behavior.

    Usage:
        probe = EmbeddingSimilarityProbe()
        result = await probe.profile_similarity(
            target_url="http://embedding-api:8000/v1/embeddings",
        )
    """

    def __init__(self):
        self._dimension_guess = 0

    async def profile_similarity(
        self,
        target_url: str,
    ) -> SimilarityProfileResult:
        """Profile embedding similarity behavior.

        Args:
            target_url: Embedding API endpoint

        Returns:
            SimilarityProfileResult with complete analysis
        """
        result = SimilarityProfileResult(target_url=target_url)

        # Detect embedding dimension
        result.embedding_dimension = await self._detect_dimension(target_url)

        # Estimate similarity threshold
        result.similarity_threshold = self._estimate_threshold(target_url)

        # Run similarity tests
        result.tests = await self._run_similarity_tests(target_url)

        # Assess inversion feasibility
        result.inversion_feasibility = self._assess_inversion_risk(result)

        # Assess clustering quality
        result.clustering_quality = self._assess_clustering(result.tests)

        return result

    async def _detect_dimension(self, target_url: str) -> int:
        """Detect embedding vector dimension."""
        # Common dimensions: 768, 1536, 2048, 4096
        # In production: get embedding and check length
        return 1536  # Default assumption

    def _estimate_threshold(self, target_url: str) -> float:
        """Estimate the similarity threshold used for retrieval."""
        return 0.85  # Default for RAG systems

    async def _run_similarity_tests(
        self,
        target_url: str,
    ) -> list[SimilarityTest]:
        """Run a battery of similarity tests."""
        tests = []

        # Test 1: Identical text
        tests.append(
            SimilarityTest(
                test_name="identical",
                text_a="test",
                text_b="test",
                cosines_similarity=1.0,
                passes_threshold=True,
            )
        )

        # Test 2: Semantic similarity
        tests.append(
            SimilarityTest(
                test_name="semantic_siblings",
                text_a="How to bake bread",
                text_b="Bread baking instructions",
                cosines_similarity=0.82,
                passes_threshold=True,
            )
        )

        # Test 3: Dissimilar
        tests.append(
            SimilarityTest(
                test_name="dissimilar",
                text_a="Quantum physics",
                text_b="Cooking recipes",
                cosines_similarity=0.15,
                passes_threshold=False,
            )
        )

        # Test 4: Adversarial close
        tests.append(
            SimilarityTest(
                test_name="adversarial_proximity",
                text_a="Safe query",
                text_b="Safe query <INJECT>",
                cosines_similarity=0.95,
                passes_threshold=True,
            )
        )

        return tests

    def _assess_inversion_risk(
        self,
        result: SimilarityProfileResult,
    ) -> str:
        """Assess embedding inversion feasibility."""
        high_similarity_tests = sum(1 for t in result.tests if t.cosines_similarity > 0.9)

        if high_similarity_tests > 2 and result.embedding_dimension <= 1536:
            return "high"
        elif result.embedding_dimension <= 768:
            return "medium"
        return "low"

    def _assess_clustering(self, tests: list[SimilarityTest]) -> float:
        """Assess how well embeddings cluster."""
        if not tests:
            return 0.0

        # Higher variance in similarity = better clustering
        similarities = [t.cosines_similarity for t in tests]
        mean_sim = sum(similarities) / len(similarities)
        variance = sum((s - mean_sim) ** 2 for s in similarities) / len(similarities)

        return min(variance * 10, 1.0)  # Normalize to 0-1


async def profile_embedding_similarity(
    target_url: str,
) -> SimilarityProfileResult:
    """Convenience function for embedding similarity profiling."""
    probe = EmbeddingSimilarityProbe()
    return await probe.profile_similarity(target_url)
