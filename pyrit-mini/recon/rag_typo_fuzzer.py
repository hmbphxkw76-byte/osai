"""RAG Typo Fuzzer — Query rewriting and fuzzy matching capability detection.

Tests whether a RAG system has query rewriting/spell-check capabilities by
sending intentionally misspelled variants and measuring retrieval degradation.

Academic basis:
    - Zou et al. (arXiv:2406.04245) — PoisonedRAG: BM25 poisoning via keyword matching
    - Kandpal et al. (arXiv:2308.14032) — Training data extraction via chunk enumeration
    - Greshake et al. (arXiv:2302.12173) — Indirect prompt injection via retrieval manipulation

Attack vectors detected:
    1. Query rewriting absence — typo causes zero retrieval (e.g., "vaycation dayz rulez" → sources: [])
    2. BM25 dominance — typo affects bm25_score but not vector_score
    3. Fuzzy matching threshold — max edit distance tolerated
    4. PoisonedRAG vulnerability — if typo variants still hit same chunk, BM25 poisoning works

Constitution compliance:
    - R-IMPORT-1: Uses aiohttp (not httpx)
    - R-SIZE: < 400 lines (slim attacker-focused module)
    - R-H3: Single-file module, complements rag_metadata_parser.py

Data contract:
    Integrates with rag_metadata_parser.parse_rag_response() for format-agnostic
    response parsing, ensuring consistent data structures across the RAG recon pipeline.

Typo generation strategies (ranked by real-world frequency):
    1. Keyboard adjacency (QWERTY neighbor substitution)
    2. Character deletion (omitted letter)
    3. Character insertion (extra letter)
    4. Adjacent character swap (transposition)
    5. Phonetic substitution (e.g., 'ph' → 'f', 'c' → 'k')
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from dataclasses import dataclass, field
from typing import Any

import aiohttp

# Re-export data structures from rag_metadata_parser for consistency
from recon.rag_metadata_parser import (
    RAGResponseMetadata,
    parse_rag_response,
)

logger = logging.getLogger(__name__)

# ====================================================================
# Section 1: QWERTY Keyboard Adjacency Map
# ====================================================================

_QWERTY_ADJACENT: dict[str, str] = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx",
    "e": "wrd", "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb",
    "i": "ujko", "j": "huiknm", "k": "jiolm", "l": "kop",
    "m": "njk", "n": "bhjm", "o": "iklp", "p": "ol",
    "q": "wa", "r": "edft", "s": "wedxza", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc",
    "y": "tghu", "z": "asx",
}

# Common phonetic substitutions (English)
# Note: using list of tuples to avoid duplicate keys (F601)
_PHONETIC_MAP: list[tuple[str, str]] = [
    ("ph", "f"),
    ("f", "ph"),
    ("ck", "k"),
    ("c", "k"),
    ("s", "z"),
    ("z", "s"),
    ("x", "ks"),
    ("ks", "x"),
    ("ee", "ea"),
    ("ea", "ee"),
    ("oo", "u"),
    ("tion", "shun"),
    ("ight", "ite"),
]


# ====================================================================
# Section 2: Data Structures — Typo Fuzzing Results
# ====================================================================


@dataclass
class TypoVariantResult:
    """Result of a single typo variant test.

    Attacker value:
        original_query: Baseline query that retrieves successfully
        typo_query: The misspelled variant
        strategy: Which typo strategy was used
        retrieval_degradation: Ratio of chunk loss (0.0 = no loss, 1.0 = total loss)
        same_chunks: Whether the same chunks are retrieved despite typo
        bm25_impact: How bm25_score changed (None if not comparable)
    """
    original_query: str = ""
    typo_query: str = ""
    strategy: str = ""  # keyboard, deletion, insertion, swap, phonetic
    original_chunks: int = 0
    typo_chunks: int = 0
    retrieval_degradation: float = 0.0  # 0.0 = same, 1.0 = total loss
    same_source_retrieved: bool = False
    bm25_impact: float | None = None  # score delta

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_query": self.original_query,
            "typo_query": self.typo_query,
            "strategy": self.strategy,
            "original_chunks": self.original_chunks,
            "typo_chunks": self.typo_chunks,
            "retrieval_degradation": round(self.retrieval_degradation, 3),
            "same_source_retrieved": self.same_source_retrieved,
            "bm25_impact": round(self.bm25_impact, 4) if self.bm25_impact is not None else None,
        }


@dataclass
class TypoFuzzingReport:
    """Complete typo fuzzing report for a RAG endpoint.

    Attacker value:
        total_tests: Number of typo variants tested
        query_rewriting_detected: Whether system has spell-check/rewriting
        max_edit_distance_tolerated: Maximum edit distance system handles
        vulnerable_to_bm25_poisoning: Whether typo variants hit same chunks
        per_strategy_breakdown: Results grouped by typo strategy
    """
    total_tests: int = 0
    query_rewriting_detected: bool = False
    max_edit_distance_tolerated: int = 0
    vulnerable_to_bm25_poisoning: bool = False
    results: list[TypoVariantResult] = field(default_factory=list)

    @property
    def failure_rate(self) -> float:
        """Ratio of typo variants that lost retrieval."""
        if not self.results:
            return 0.0
        failed = sum(1 for r in self.results if r.retrieval_degradation > 0.5)
        return failed / len(self.results)

    @property
    def has_rag(self) -> bool:
        """True if any retrieval was observed across tests."""
        return any(r.original_chunks > 0 for r in self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tests": self.total_tests,
            "query_rewriting_detected": self.query_rewriting_detected,
            "max_edit_distance_tolerated": self.max_edit_distance_tolerated,
            "vulnerable_to_bm25_poisoning": self.vulnerable_to_bm25_poisoning,
            "failure_rate": round(self.failure_rate, 3),
            "results": [r.to_dict() for r in self.results[:50]],  # Limit storage
        }


# ====================================================================
# Section 3: Typo Generation Strategies
# ====================================================================


def _keyboard_adjacent_typo(word: str) -> str | None:
    """Replace one character with QWERTY neighbor.

    Example: "vacation" → "vaycation" (a→y), "days" → "dayz" (s→z)
    """
    if len(word) < 2:
        return None
    candidates = []
    for i, ch in enumerate(word.lower()):
        if ch in _QWERTY_ADJACENT:
            for neighbor in _QWERTY_ADJACENT[ch]:
                candidates.append((i, neighbor))
    if not candidates:
        return None
    # Pick a random character position (prefer middle of word for realism)
    mid = len(word) // 2
    candidates.sort(key=lambda x: abs(x[0] - mid))
    idx, replacement = candidates[0]
    result = list(word)
    # Preserve original case
    if word[idx].isupper():
        replacement = replacement.upper()
    result[idx] = replacement
    return "".join(result)


def _deletion_typo(word: str) -> str | None:
    """Delete one character from word.

    Example: "policy" → "plicy"
    """
    if len(word) < 3:
        return None
    idx = random.randint(1, len(word) - 2)  # Avoid first/last char
    return word[:idx] + word[idx + 1:]


def _insertion_typo(word: str) -> str | None:
    """Insert a random character.

    Example: "vacation" → "vacastion" (insert 's')
    """
    idx = random.randint(1, len(word) - 1)
    chars = "abcdefghijklmnopqrstuvwxyz"
    new_char = random.choice(chars)
    return word[:idx] + new_char + word[idx:]


def _swap_typo(word: str) -> str | None:
    """Swap two adjacent characters.

    Example: "vacation" → "vacatoin" (swap i,o)
    """
    if len(word) < 3:
        return None
    idx = random.randint(0, len(word) - 2)
    result = list(word)
    result[idx], result[idx + 1] = result[idx + 1], result[idx]
    return "".join(result)


def _phonetic_typo(word: str) -> str | None:
    """Apply phonetic substitution.

    Example: "phone" → "fone", "graph" → "graf"
    """
    word_lower = word.lower()
    for pattern, replacement in _PHONETIC_MAP:
        if pattern in word_lower:
            # Find position of pattern
            pos = word_lower.find(pattern)
            # Apply substitution preserving case of first char
            if pos == 0 and word[0].isupper():
                replacement = replacement.upper()
            # Replace only first occurrence
            return word[:pos] + replacement + word[pos + len(pattern):]
    return None


# Strategy registry (ordered by STR fingerprint likelihood)
_TYPO_STRATEGIES = [
    ("keyboard", _keyboard_adjacent_typo),
    ("swap", _swap_typo),
    ("deletion", _deletion_typo),
    ("insertion", _insertion_typo),
    ("phonetic", _phonetic_typo),
]


def generate_typo_variants(query: str, max_variants: int = 5) -> list[tuple[str, str]]:
    """Generate typo variants for a query.

    Extracts key words from query (length >= 4) and applies typo strategies.
    Returns list of (typo_query, strategy) tuples.

    Strategy:
        1. Tokenize query into words
        2. Filter words with length >= 4 (skip short/common words)
        3. Apply each strategy to most promising word candidates
        4. Deduplicate results
    """
    # Extract candidate words (length >= 4, alphabetic)
    words = re.findall(r"[a-zA-Z]{4,}", query)
    if not words:
        return []

    variants: list[tuple[str, str]] = []
    seen: set[str] = set()

    # Try each strategy on each candidate word
    for word in words:
        for strategy_name, strategy_fn in _TYPO_STRATEGIES:
            try:
                typo_word = strategy_fn(word)
                if typo_word and typo_word != word:
                    # Reconstruct full query with typo
                    typo_query = query.replace(word, typo_word, 1)
                    if typo_query not in seen and typo_query != query:
                        variants.append((typo_query, strategy_name))
                        seen.add(typo_query)
                        if len(variants) >= max_variants:
                            return variants
            except Exception:
                continue

    return variants


# ====================================================================
# Section 4: Fuzzing Execution Engine
# ====================================================================


async def _send_and_parse_safe(
    session: aiohttp.ClientSession,
    base_url: str,
    parsed_request: Any,
    query: str,
    api_key: str | None = None,
) -> RAGResponseMetadata | None:
    """Send query to RAG endpoint and parse response (format-agnostic).

    Reuses parse_rag_response from rag_metadata_parser for consistent
    data structure handling across the RAG recon pipeline.
    """
    headers: dict[str, str] = {}
    if hasattr(parsed_request, "raw_headers"):
        for key, value in parsed_request.raw_headers:
            if key.lower() not in ("content-length", "host"):
                headers[key] = value
    headers["Content-Type"] = "application/json"

    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # Build probe body from template
    body = _build_probe_body(parsed_request, query)
    url = f"{base_url}{getattr(parsed_request, 'path', '/v1/chat/completions')}"

    from recon.config_loader import get_tls_verify as _get_tls_verify_from_config
    tls_verify = _get_tls_verify_from_config()

    try:
        async with session.post(
            url,
            data=body,
            headers=headers,
            ssl=tls_verify,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            if resp.status != 200:
                return None
            response_text = await resp.text()
            try:
                response_data = json.loads(response_text)
            except json.JSONDecodeError:
                return None

            # Use format-agnostic parser from rag_metadata_parser
            return parse_rag_response(response_data)

    except asyncio.TimeoutError:
        return None
    except Exception as e:
        logger.debug("Typo fuzz probe failed: %s", e)
        return None


def _build_probe_body(parsed_request: Any, prompt: str) -> str:
    """Build probe body from template or default to OpenAI format."""
    if hasattr(parsed_request, "body") and parsed_request.body:
        if "{PROMPT}" in parsed_request.body:
            return parsed_request.body.replace("{PROMPT}", prompt)
    return json.dumps({
        "model": "test",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500,
        "temperature": 0,
    })


def _compute_degradation(
    original: RAGResponseMetadata,
    typo: RAGResponseMetadata,
) -> tuple[float, bool, float | None]:
    """Compute retrieval degradation between original and typo response.

    Returns:
        (degradation_ratio, same_source_retrieved, bm25_score_delta)
        degradation_ratio: 0.0 = same retrieval, 1.0 = total loss
        same_source_retrieved: True if same source titles appear in both
        bm25_score_delta: Change in bm25 score (None if not comparable)
    """
    if original.num_chunks == 0:
        return (0.0, False, None)

    degradation = 1.0 - (typo.num_chunks / original.num_chunks)
    degradation = max(0.0, min(1.0, degradation))

    # Check if same sources retrieved
    orig_sources = set(original.unique_sources)
    typo_sources = set(typo.unique_sources)
    same_source = bool(orig_sources & typo_sources)

    # Compute bm25 impact (average score delta)
    bm25_delta = None
    orig_bm25_scores = [c.bm25_score for c in original.chunks if c.bm25_score is not None]
    typo_bm25_scores = [c.bm25_score for c in typo.chunks if c.bm25_score is not None]
    if orig_bm25_scores and typo_bm25_scores:
        bm25_delta = sum(typo_bm25_scores) / len(typo_bm25_scores) - sum(orig_bm25_scores) / len(orig_bm25_scores)

    return (degradation, same_source, bm25_delta)


# ====================================================================
# Section 5: High-Level Orchestrator — Complete Typo Fuzzing Pipeline
# ====================================================================


async def run_typo_fuzzing(
    parsed_request: Any,
    *,
    use_tls: bool = True,
    api_key: str | None = None,
    max_concurrent: int = 2,
    test_queries: list[str] | None = None,
    variants_per_query: int = 3,
) -> TypoFuzzingReport:
    """Run complete typo fuzzing pipeline against RAG endpoint.

    This is the MAIN ENTRY POINT for typo fuzzing.
    Orchestrates: query selection → typo generation → parallel probing → result aggregation.

    Args:
        parsed_request: Parsed HTTP request template
        use_tls: Whether to use HTTPS
        api_key: Optional API key
        max_concurrent: Max concurrent requests (stealth bound)
        test_queries: Custom queries to test (overrides default set)
        variants_per_query: Max typo variants per query

    Returns:
        TypoFuzzingReport with complete fuzzy matching capability assessment

    Academic basis:
        - Query rewriting detection via controlled typo injection
        - BM25 poisoning vulnerability via keyword variant retrieval

    Data flow consistency:
        Uses parse_rag_response() from rag_metadata_parser for format-agnostic
        parsing, ensuring identical data structures as the main KB mapper.
    """
    import time
    start_time = time.time()

    # Default test queries (same domain as _KB_MAPPING_QUERIES in rag_metadata_parser)
    if test_queries is None:
        test_queries = [
            "What is the PTO policy?",
            "What are the password complexity requirements?",
            "Describe the API rate limiting configuration?",
        ]

    # Setup HTTP
    host = getattr(parsed_request, "host", "")
    if not host:
        return TypoFuzzingReport()

    base_url = f"{'https' if use_tls else 'http'}://{host}"
    connector = aiohttp.TCPConnector(limit=max_concurrent)
    timeout = aiohttp.ClientTimeout(total=120)
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    report = TypoFuzzingReport()

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=default_headers,
    ) as session:

        sem = asyncio.Semaphore(max_concurrent)

        async def _probe_one(query: str) -> RAGResponseMetadata | None:
            async with sem:
                return await _send_and_parse_safe(session, base_url, parsed_request, query, api_key)

        # Phase 1: Probe original queries (baseline)
        original_results: dict[str, RAGResponseMetadata | None] = {}
        probe_tasks = [_probe_one(q) for q in test_queries]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        for query, result in zip(test_queries, probe_results):
            if isinstance(result, Exception):
                original_results[query] = None
            else:
                original_results[query] = result

        # Phase 2: Generate typo variants and probe
        typo_tasks: list[tuple[str, str, str]] = []  # (original_query, typo_query, strategy)
        for query in test_queries:
            variants = generate_typo_variants(query, max_variants=variants_per_query)
            for typo_query, strategy in variants:
                typo_tasks.append((query, typo_query, strategy))

        if not typo_tasks:
            logger.warning("Typo fuzzer: no variants generated")
            return report

        # Probe typo variants
        sem2 = asyncio.Semaphore(max_concurrent)
        async def _probe_typo(task: tuple[str, str, str]) -> tuple[str, str, str, RAGResponseMetadata | None]:
            async with sem2:
                orig, typo, strat = task
                result = await _send_and_parse_safe(session, base_url, parsed_request, typo, api_key)
                return (orig, typo, strat, result)

        typo_probe_tasks = [_probe_typo(t) for t in typo_tasks]
        typo_probe_results = await asyncio.gather(*typo_probe_tasks, return_exceptions=True)

        # Phase 3: Compute degradation
        for result in typo_probe_results:
            if isinstance(result, Exception):
                report.total_tests += 1
                continue
            orig_query, typo_query, strategy, typo_metadata = result
            report.total_tests += 1

            original_metadata = original_results.get(orig_query)
            if original_metadata is None or typo_metadata is None:
                continue

            degradation, same_source, bm25_delta = _compute_degradation(
                original_metadata, typo_metadata,
            )

            variant_result = TypoVariantResult(
                original_query=orig_query,
                typo_query=typo_query,
                strategy=strategy,
                original_chunks=original_metadata.num_chunks,
                typo_chunks=typo_metadata.num_chunks,
                retrieval_degradation=degradation,
                same_source_retrieved=same_source,
                bm25_impact=bm25_delta,
            )
            report.results.append(variant_result)

    # Phase 4: Aggregate findings
    if report.results:
        # Query rewriting detection: if degradation < 0.3 for most tests
        low_degradation = sum(1 for r in report.results if r.retrieval_degradation < 0.3)
        report.query_rewriting_detected = low_degradation > len(report.results) * 0.5

        # Max edit distance tolerated (simplified: assume keyboard/swap = dist 1)
        tolerated_tests = [r for r in report.results if r.retrieval_degradation < 0.5]
        if tolerated_tests:
            report.max_edit_distance_tolerated = 1  # All strategies are edit distance 1

        # BM25 poisoning vulnerability: typo still retrieves same source
        same_source_retrievals = [r for r in report.results if r.same_source_retrieved and r.original_chunks > 0]
        report.vulnerable_to_bm25_poisoning = len(same_source_retrievals) > 0

    duration = round(time.time() - start_time, 2)
    logger.info(
        "Typo fuzzing: tests=%d, rewriting=%s, bm25_poisoning=%s, failure_rate=%.2f, %.2fs",
        report.total_tests,
        report.query_rewriting_detected,
        report.vulnerable_to_bm25_poisoning,
        report.failure_rate,
        duration,
    )

    return report
