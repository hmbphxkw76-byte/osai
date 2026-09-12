# -*- coding: utf-8 -*-
"""High-level RAG metadata collection orchestrator (stealth pipeline).

SRP split from `metadata_parser.py` (R-DELIVERY-1): owns the end-to-end
KB-mapping pipeline — query diversification → collection → parse → aggregation —
using the parser and stealth helpers from sibling modules.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import aiohttp

from recon.rag._metadata_models import KnowledgeBaseMap, RAGResponseMetadata
from recon.rag.rag_query_stealth import (
    _TOPIC_CATEGORIES,
    _cluster_queries_by_topic,
    _compute_lognormal_delay,
    _diversify_query,
)
from recon.rag.rag_response_parser import parse_rag_response

logger = logging.getLogger(__name__)


async def run_rag_metadata_collection(
    parsed_request: Any,
    *,
    use_tls: bool = True,
    api_key: str | None = None,
    max_concurrent: int = 2,
    num_queries: int = 15,
    custom_queries: list[str] | None = None,
    stealth_mode: bool = True,
    guardrail_policy: str | None = None,
) -> KnowledgeBaseMap:
    """Complete RAG metadata collection pipeline with stealth integration.

    This is the MAIN ENTRY POINT for full KB mapping.
    Orchestrates: query diversification → response collection → parsing → aggregation.

    Stealth features (enabled when stealth_mode=True):
        1. Temporal spacing: Lognormal-distributed delays between queries
        2. Query variation: Semantic-preserving rephrasing to evade keyword detection
        3. Behavioral mimicry: Topic-clustered query ordering (human-like browsing)

    Args:
        parsed_request: Parsed HTTP request template
        use_tls: Whether to use HTTPS
        api_key: Optional API key
        max_concurrent: Max concurrent requests (stealth bound: forced to 1 in stealth mode)
        num_queries: Number of diverse queries to send
        custom_queries: Optional custom queries (overrides default set)
        stealth_mode: Enable stealth features (temporal spacing + query variation)
        guardrail_policy: Override guardrail policy (None = auto-detect)

    Returns:
        KnowledgeBaseMap with complete KB structure inference

    Academic basis:
        - Iterative probing (Greshake et al., arXiv:2302.12173)
        - Statistical inference (Fisher, 1925 — foundations)
        - Detection evasion (Crothers et al., arXiv:2306.05685)
        - Behavioral biometrics (Zhang et al., arXiv:2204.01326)
    """

    start_time = time.time()

    # Stealth setup: integrate with StealthLevelManager
    stealth_mgr = None
    stealth_policy_obj = None
    if stealth_mode:
        try:
            from recon.stealth_config import get_stealth_manager

            stealth_mgr = get_stealth_manager()
            # Use policy parameter or default to balanced for RAG recon
            policy_name = guardrail_policy or "balanced"
            stealth_policy_obj = stealth_mgr.get_policy(policy_name)
            # Force sequential in stealth mode (concurrent queries = detection signal)
            max_concurrent = 1
            logger.info(
                "[STEALTH] RAG recon engaged: policy=%s, delay_range=%s, jitter=%.0f%%",
                policy_name,
                stealth_policy_obj.delay_range,
                stealth_policy_obj.jitter * 100,
            )
        except Exception as e:
            logger.debug("[STEALTH] Stealth config unavailable: %s", e)
            stealth_mode = False

    # Determine queries with diversification
    if custom_queries:
        raw_queries = custom_queries[:num_queries]
    else:
        raw_queries = [
            "What is the PTO policy?",
            "What are the company travel reimbursement guidelines?",
            "Explain the employee benefits enrollment process.",
            "What is the API rate limiting configuration?",
            "Describe the database backup procedures.",
            "What are the deployment rollback procedures?",
            "What is the incident response plan?",
            "Describe the password complexity requirements.",
            "What are the access control policies?",
            "What is the change management approval process?",
            "Describe the code review guidelines.",
            "What are the testing requirements before deployment?",
            "What is the data retention policy?",
            "Describe the GDPR compliance procedures.",
            "What is the data classification framework?",
        ][:num_queries]

    if not raw_queries:
        logger.warning("No queries provided for RAG metadata collection")
        return KnowledgeBaseMap()

    # Phase 1: Query diversification (if stealth enabled)
    if stealth_mode:
        diversified_queries = []
        variant_counter: dict[str, int] = {}
        for q in raw_queries:
            # Determine category for this query
            category = "general"
            for keyword, cat in _TOPIC_CATEGORIES.items():
                if keyword.lower() in q.lower():
                    category = cat
                    break
            # Generate a unique variant
            variant_idx = variant_counter.get(q, 0)
            variant_counter[q] = variant_idx + 1
            diversified = _diversify_query(q, category, variant_idx)
            diversified_queries.append(diversified)
        queries = diversified_queries
    else:
        queries = raw_queries

    # Phase 2: Topic clustering for behavioral mimicry
    if stealth_mode:
        queries = _cluster_queries_by_topic(queries)
        logger.debug("[STEALTH] Queries reordered for topic clustering: %s", [q[:40] for q in queries])

    # Setup HTTP
    host = getattr(parsed_request, "host", "")
    if not host:
        return KnowledgeBaseMap()

    from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

    tls_verify = _get_tls_verify_from_config()

    base_url = f"{'https' if use_tls else 'http'}://{host}"
    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=tls_verify)
    timeout = aiohttp.ClientTimeout(total=300)  # Extended timeout for stealth spacing
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    # Collect responses with stealth timing
    mapper = KnowledgeBaseMap()
    collected = 0
    failed = 0
    timing_log: list[dict[str, Any]] = []

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=default_headers,
    ) as session:
        for idx, query in enumerate(queries):
            # Stealth delay before EACH query (except first)
            if stealth_mode and idx > 0:
                if stealth_mgr is not None and stealth_policy_obj is not None:
                    # Use stealth policy with lognormal jitter
                    base_delay = stealth_policy_obj.delay_range[0]
                    delay = _compute_lognormal_delay(
                        base_seconds=base_delay,
                        sigma=stealth_policy_obj.jitter,
                        min_delay=base_delay * 0.5,
                        max_delay=stealth_policy_obj.delay_range[1] * 2,
                    )
                else:
                    delay = _compute_lognormal_delay(base_seconds=8.0)
                logger.debug("[STEALTH] Waiting %.2fs before query %d/%d", delay, idx + 1, len(queries))
                await asyncio.sleep(delay)
                timing_log.append({"query_index": idx, "delay_seconds": round(delay, 2)})

            # Execute query (sequential in stealth mode)
            try:
                result = await _send_and_parse(session, base_url, parsed_request, query, api_key)
                if result is not None:
                    mapper.add_response(result)
                    collected += 1
                else:
                    failed += 1
            except Exception as e:
                logger.debug("Query %d failed: %s", idx, e)
                failed += 1

    # Build final map
    kb_map = mapper.build_map()

    duration = round(time.time() - start_time, 2)

    # Stealth audit logging
    if stealth_mode and timing_log:
        intervals = [t["delay_seconds"] for t in timing_log]
        logger.info(
            "[STEALTH] Timing profile: min=%.1fs, max=%.1fs, mean=%.1fs, total=%.1fs — mimics human browsing patterns",
            min(intervals),
            max(intervals),
            sum(intervals) / len(intervals),
            sum(intervals),
        )

    logger.info(
        "RAG metadata collection: queries=%d, collected=%d, failed=%d, documents=%d, format=%s, %.2fs, stealth=%s",
        len(queries),
        collected,
        failed,
        kb_map.document_count,
        kb_map.inferred_retrieval_formula,
        duration,
        stealth_mode,
    )

    return kb_map


async def _send_and_parse(
    session: aiohttp.ClientSession,
    base_url: str,
    parsed_request: Any,
    query: str,
    api_key: str | None = None,
) -> RAGResponseMetadata | None:
    """Send a single RAG query and parse the structured metadata."""
    headers: dict[str, str] = {}
    if hasattr(parsed_request, "raw_headers"):
        for key, value in parsed_request.raw_headers:
            if key.lower() not in ("content-length", "host"):
                headers[key] = value
    headers["Content-Type"] = "application/json"

    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

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

            return parse_rag_response(response_data)

    except asyncio.TimeoutError:
        return None
    except Exception as e:
        logger.debug("RAG metadata probe failed: %s", e)
        return None


def _build_probe_body(parsed_request: Any, prompt: str) -> str:
    """Build probe body from template or default to OpenAI format."""
    if hasattr(parsed_request, "body") and parsed_request.body:
        if "{PROMPT}" in parsed_request.body:
            return parsed_request.body.replace("{PROMPT}", prompt)
    return json.dumps(
        {
            "model": "test",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 500,
            "temperature": 0,
        }
    )
