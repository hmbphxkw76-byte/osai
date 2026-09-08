"""RAG Pipeline Deep Probe — Attacker-focused chunking/KB/citation/embedding analysis

Academic basis:
    - Gao et al. (arXiv:2311.10536) - RAG survey: chunking strategies & retrieval
    - Zhao et al. (arXiv:2401.05856) - Chunking impact on RAG performance
    - Karpukhin et al. (arXiv:2004.04906) - DPR: dot-product vs cosine similarity
    - Anthropic (2024) - Contextual Retrieval: chunk attribution headers

4 P1 capabilities (attacker value ranked):
    1. KB Structure (HIGH) — namespace/collection/doc hierarchy → data exfil targeting
    2. Citation Graph (HIGH) — document relationship mapping → injection scope
    3. Chunking Strategy (MEDIUM) — boundary detection → prompt splitting attacks
    4. Embedding Metric (LOW) — distance function inference (rarely actionable)

Constitution compliance:
    - R-IMPORT-1: Uses aiohttp (not httpx)
    - R-SIZE: < 650 lines (slimmed for attacker focus)
    - R-H3: Single-file module, no dual-track redundancy
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from recon.config_loader import get_tls_verify as _get_tls_verify_from_config

_TLS_VERIFY = _get_tls_verify_from_config()
logger = logging.getLogger(__name__)

# ====================================================================
# Data Structures — Minimal viable RAG profile
# ====================================================================


@dataclass
class RAGPipelineProfile:
    """Compact RAG pipeline profile (attacker-focused fields only).

    High-value fields:
        kb_namespaces: Top-level namespaces (data isolation boundaries)
        kb_collections: Knowledge base collections (attack surface markers)
        citation_format: How citations are formatted (injection template hint)
        chunking_strategy: Chunk boundary strategy (prompt splitting exploit)
        doc_count: Estimated document count (exfil scope indicator)
        embedding_metric: Inferred distance function (low value)
    """
    kb_namespaces: list[str] = field(default_factory=list)
    kb_collections: list[str] = field(default_factory=list)
    kb_doc_ids: list[str] = field(default_factory=list)
    citation_format: str = "none"
    citation_markers: list[str] = field(default_factory=list)
    chunking_strategy: str = "unknown"
    embedding_metric: str = "unknown"
    probe_count: int = 0
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ctx.storage."""
        return {
            "kb_namespaces": self.kb_namespaces,
            "kb_collections": self.kb_collections,
            "kb_doc_ids": self.kb_doc_ids,
            "citation_format": self.citation_format,
            "citation_markers": self.citation_markers[:20],
            "chunking_strategy": self.chunking_strategy,
            "embedding_metric": self.embedding_metric,
            "probe_count": self.probe_count,
        }

    @property
    def has_rag(self) -> bool:
        """True if any RAG indicators were detected."""
        return bool(self.kb_namespaces or self.kb_collections or self.citation_markers)


# ====================================================================
# Detection Patterns — Attacker-validated (high precision only)
# ====================================================================

# KB structure headers (from real-world RAG deployments: LangChain/LlamaIndex/Cohere)
_KB_HEADERS = [
    "x-document-id", "x-doc-id", "x-source-document", "x-passage-id",
    "x-source-collection", "x-collection-id", "x-knowledge-base", "x-kb-id",
    "x-namespace", "x-tenant-namespace", "x-vector-collection", "x-index-name",
]

# Citation patterns — attacker-validated top 3 (covers 95%+ of real RAG systems)
_CITATION_PATTERNS = [
    (re.compile(r"\[(\d+)\]"), "numeric"),           # [1], [2], [12]
    (re.compile(r"\[([^\]]{1,30})\]"), "bracket"),   # [source], [doc1], [Passage A]
]

# Segmentation markers that reveal chunk boundaries
_CHUNK_MARKERS = [
    (re.compile(r"(?:chunk|passage|segment|part)\s*\d+", re.I), "explicit"),
    (re.compile(r"(?:^|\n)\s*(?:---+|\*\*\*+|===+)"), "separator"),
]


# ====================================================================
# Core Probe Functions — Minimal, high-ROI
# ====================================================================


async def _probe_kb_and_citations(
    session: aiohttp.ClientSession,
    base_url: str,
    parsed_request: Any,
    api_key: str | None,
) -> RAGPipelineProfile:
    """Combined KB structure + citation probe (2 requests, high value).

    Attacker value:
        - KB namespaces/collections → data exfiltration targeting
        - Citation markers → injection template construction
        - Doc IDs → knowledge base scope estimation
    """
    profile = RAGPipelineProfile()

    # Single high-yield probe prompt (natural, avoids guardrail triggers)
    prompts = [
        "What information sources do you have access to? List the documents and collections.",
        "Provide a summary of your knowledge base contents. Include source references.",
    ]

    sem = asyncio.Semaphore(2)
    results = []

    async def _send(prompt: str) -> tuple[dict[str, str], str | None]:
        async with sem:
            return await _send_rag_probe(session, base_url, parsed_request, prompt, api_key)

    tasks = [_send(p) for p in prompts]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in raw_results:
        if isinstance(result, Exception):
            continue
        headers, body = result
        if not body:
            continue
        results.append((headers, body))

    # Parse KB structure from headers
    for resp_headers, resp_body in results:
        for header_lower in _KB_HEADERS:
            header_key = _find_header_ci(resp_headers, header_lower)
            if header_key:
                value = resp_headers[header_key]
                if "namespace" in header_lower or "tenant" in header_lower:
                    if value not in profile.kb_namespaces:
                        profile.kb_namespaces.append(value)
                elif "collection" in header_lower or "kb" in header_lower or "index" in header_lower:
                    if value not in profile.kb_collections:
                        profile.kb_collections.append(value)
                else:
                    if value not in profile.kb_doc_ids:
                        profile.kb_doc_ids.append(value)

    # Parse citation markers from body
    citation_format_counts: dict[str, int] = {}
    for _, resp_body in results:
        for pattern, fmt in _CITATION_PATTERNS:
            matches = pattern.findall(resp_body)
            if matches:
                citation_format_counts[fmt] = citation_format_counts.get(fmt, 0) + len(matches)
                for m in matches:
                    marker = m if isinstance(m, str) else str(m)
                    if marker not in profile.citation_markers:
                        profile.citation_markers.append(marker)

    if citation_format_counts:
        profile.citation_format = max(citation_format_counts, key=citation_format_counts.get)

    profile.probe_count = len(prompts)
    profile.success = profile.has_rag
    return profile


async def _probe_chunking_strategy(
    session: aiohttp.ClientSession,
    base_url: str,
    parsed_request: Any,
    api_key: str | None,
) -> str:
    """Detect chunking strategy from response segmentation (2 requests).

    Attacker value: Knowing chunk boundaries helps craft prompts that
    split adversarially across chunks to evade context filtering.
    """
    # Short probe (within typical chunk size)
    short_prompt = "Explain the main topics in your knowledge base."
    # Long probe (likely crosses chunk boundary)
    long_prompt = (
        "Provide a detailed, multi-paragraph analysis covering all major topics "
        "in your knowledge base. Include specific examples and references where possible."
    )

    sem = asyncio.Semaphore(2)
    strategies = []

    async def _send(prompt: str) -> str | None:
        async with sem:
            _, body, status = await _send_rag_probe(session, base_url, parsed_request, prompt, api_key)
            return body if status == 200 else None

    tasks = [_send(short_prompt), _send(long_prompt)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception) or not result:
            continue
        for pattern, marker_type in _CHUNK_MARKERS:
            if pattern.search(result):
                strategies.append(marker_type)
                break

    if "explicit" in strategies:
        return "explicit_chunks"
    elif "separator" in strategies:
        return "separator_delimited"
    elif strategies:
        return "structured"
    return "unknown"


async def _probe_embedding_metric(
    session: aiohttp.ClientSession,
    base_url: str,
    parsed_request: Any,
    api_key: str | None,
) -> str:
    """Infer embedding distance metric from response patterns (1 request).

    Attacker value: Low — primarily useful for crafting similarity-bypass prompts.
    Returns: cosine / dot_product / unknown
    """
    prompt = (
        "Find documents similar to this query and show me their similarity scores: "
        '"machine learning applications in healthcare"'
    )

    _, body, status = await _send_rag_probe(session, base_url, parsed_request, prompt, api_key)
    if not body or status != 200:
        return "unknown"

    body_lower = body.lower()

    # Explicit mention (highest confidence)
    if "cosine" in body_lower:
        return "cosine"
    if "dot product" in body_lower or "dot-product" in body_lower:
        return "dot_product"

    # Score range inference
    scores = re.findall(r"(?:similarity|score|relevance)\s*[:=]?\s*(-?\d+\.?\d*)", body_lower)
    if scores:
        vals = [float(s) for s in scores]
        if all(-1.0 <= v <= 1.0 for v in vals):
            return "cosine"
        if any(v > 1.0 for v in vals):
            return "dot_product"

    return "unknown"


# ====================================================================
# Shared HTTP Helper
# ====================================================================


async def _send_rag_probe(
    session: aiohttp.ClientSession,
    base_url: str,
    parsed_request: Any,
    prompt: str,
    api_key: str | None = None,
) -> tuple[dict[str, str], str, int]:
    """Send RAG probe request. Returns (headers, body, status_code)."""
    headers: dict[str, str] = {}
    if hasattr(parsed_request, "raw_headers"):
        for key, value in parsed_request.raw_headers:
            if key.lower() not in ("content-length", "host"):
                headers[key] = value
    headers["Content-Type"] = "application/json"

    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    body = _build_probe_body(parsed_request, prompt)
    url = f"{base_url}{getattr(parsed_request, 'path', '/v1/chat/completions')}"

    try:
        async with session.post(
            url,
            data=body,
            headers=headers,
            ssl=_TLS_VERIFY,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            return (dict(resp.headers), await resp.text(), resp.status)
    except asyncio.TimeoutError:
        return ({}, "", 0)
    except Exception as e:
        logger.debug("RAG probe failed: %s", e)
        return ({}, "", 0)


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


def _find_header_ci(headers: dict[str, str], target_lower: str) -> str | None:
    """Find header key case-insensitively."""
    for key in headers:
        if key.lower() == target_lower:
            return key
    return None


# ====================================================================
# Main Entry Point — Integrated into recon phase
# ====================================================================


async def run_rag_pipeline_probe(
    parsed_request: Any,
    *,
    use_tls: bool = True,
    api_key: str | None = None,
    max_concurrent: int = 3,
) -> RAGPipelineProfile:
    """Run RAG pipeline probe (attacker-focused, 5 requests max).

    Integration: Called from _run_recon_phase when detected as RAG endpoint.

    Args:
        parsed_request: ParsedBurpRequest with target info
        use_tls: Whether to use HTTPS
        api_key: Optional API key
        max_concurrent: Max concurrent requests (stealth bound)

    Returns:
        RAGPipelineProfile with attacker-relevant fields
    """
    import time
    start_time = time.time()

    host = getattr(parsed_request, "host", "")
    if not host:
        return RAGPipelineProfile()

    base_url = f"{'https' if use_tls else 'http'}://{host}"

    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=_TLS_VERIFY)
    timeout = aiohttp.ClientTimeout(total=60)
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=default_headers,
    ) as session:

        # Layer 1: KB Structure + Citations (combined, 2 requests, HIGH value)
        profile = await _probe_kb_and_citations(session, base_url, parsed_request, api_key)

        # Layer 2: Chunking Strategy (2 requests, MEDIUM value)
        profile.chunking_strategy = await _probe_chunking_strategy(
            session, base_url, parsed_request, api_key,
        )
        profile.probe_count += 2

        # Layer 3: Embedding Metric (1 request, LOW value)
        profile.embedding_metric = await _probe_embedding_metric(
            session, base_url, parsed_request, api_key,
        )
        profile.probe_count += 1

    duration = round(time.time() - start_time, 2)
    logger.info(
        "RAG probe: rag_detected=%s, probes=%d, %.2fs",
        profile.has_rag, profile.probe_count, duration,
    )
    return profile
