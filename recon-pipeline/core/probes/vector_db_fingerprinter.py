# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Vector database fingerprinting — identify RAG backend vector DB types.

After NetworkInterceptor discovers RAG API endpoints, further probe
vector database fingerprints:
  1. URL path fingerprint: /vectors, /collections, /index -> Pinecone / Weaviate / Chroma / Qdrant
  2. Response body fingerprint: specific JSON fields (namespace, collection_name, distance, etc.)
  3. Response header fingerprint: Server, X-Powered-By, etc.
  4. Active confirmation reads: GET known endpoints to confirm DB type (NEW)

Identification enables:
  - Generating unauthorized access attack recommendations for specific vector DBs
  - Mapping to OWASP LLM08 (Vector and Embedding Weaknesses)

Academic basis:
  - OWASP Top 10 for LLM Applications 2025: LLM08 Vector and Embedding Weaknesses
  - MITRE ATT&CK T1580: Cloud Infrastructure Discovery
  - PoisonedRAG (arXiv:2402.07867): vector DB is a key attack surface
  - Reference: RedAmon _confirm_vector_dbs() + AI_VECTOR_DB_READS
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from core.probes.ai_signal_catalog import AI_VECTOR_DB_READS
from core.probes.recon_result import DiscoveredEndpoint, EndpointType

logger = logging.getLogger(__name__)


class VectorDBType(str, Enum):
    """向量数据库类型。."""

    PINECONE = "pinecone"
    WEAVIATE = "weaviate"
    CHROMA = "chroma"
    QDRANT = "qdrant"
    MILVUS = "milvus"
    REDIS_VECTOR = "redis_vector"
    PGVECTOR = "pgvector"
    UNKNOWN = "unknown"


@dataclass
class VectorDBFingerprint:
    """向量数据库指纹识别结果.

    Attributes:
        db_type: 识别到的向量库类型。
        endpoint_url: 关联的端点 URL。
        confidence: 置信度 (0.0-1.0)。
        evidence: 识别证据列表。
        unauthorized_access_likely: 是否可能存在未授权访问。
    """

    db_type: VectorDBType = VectorDBType.UNKNOWN
    endpoint_url: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    unauthorized_access_likely: bool = False

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。."""
        return {
            "db_type": self.db_type.value,
            "endpoint_url": self.endpoint_url,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "unauthorized_access_likely": self.unauthorized_access_likely,
        }


# ── 指纹规则 ──
# 每条规则: (URL 正则, 响应体关键词列表, 响应头关键词, 向量库类型, 置信度)
_FINGERPRINT_RULES: list[tuple[re.Pattern[str], list[str], list[str], VectorDBType, float]] = [
    # Pinecone
    (
        re.compile(r"pinecone\.io|/vectors|/namespaces|/index\.(?:describe|list)", re.IGNORECASE),
        ["namespace", "vector_count", "dimension", "metric"],
        ["pinecone"],
        VectorDBType.PINECONE,
        0.85,
    ),
    # Weaviate
    (
        re.compile(r"weaviate|/v1/(?:objects|schema|graphql|batch)", re.IGNORECASE),
        ["deprecation_length", "class_name", "vector_weights", "where_filter"],
        ["weaviate"],
        VectorDBType.WEAVIATE,
        0.85,
    ),
    # Chroma
    (
        re.compile(r"chroma|/api/v1/(?:collections|embeddings|heartbeat)", re.IGNORECASE),
        ["collection_name", "embedding_function", "hnsw:space", "metadata"],
        ["chroma"],
        VectorDBType.CHROMA,
        0.80,
    ),
    # Qdrant
    (
        re.compile(r"qdrant|/collections/\w+/(?:points|search)|/points/(?:search|scroll)", re.IGNORECASE),
        ["payload", "vector", "score", "collection_name", "distance"],
        ["qdrant"],
        VectorDBType.QDRANT,
        0.85,
    ),
    # Milvus
    (
        re.compile(r"milvus|/v2/(?:vector|collection|partition)|zilliz", re.IGNORECASE),
        ["collection_name", "field_name", "index_type", "metric_type"],
        ["milvus"],
        VectorDBType.MILVUS,
        0.80,
    ),
    # Redis Vector
    (
        re.compile(r"redis.*vector|/ft\.info|/ft\.search|rediSearch", re.IGNORECASE),
        ["index_name", "num_docs", "attributes", "gc_stats"],
        ["redis"],
        VectorDBType.REDIS_VECTOR,
        0.75,
    ),
    # pgvector
    (
        re.compile(r"pgvector|/rpc/(?:query|search).*embedding|extension=vector", re.IGNORECASE),
        ["embedding", "cosine_distance", "vector"],
        ["postgresql", "nginx"],
        VectorDBType.PGVECTOR,
        0.65,
    ),
]


class VectorDBFingerprinter:
    """Vector database fingerprinting.

    Analyzes RAG API endpoints discovered by NetworkInterceptor,
    identifies backend vector database types.

    Supports both passive fingerprinting (URL/body/header patterns)
    and active confirmation reads (GET known endpoints).

    Usage::
        fingerprinter = VectorDBFingerprinter()
        fingerprints = fingerprinter.fingerprint(endpoints)
        # With active confirmation:
        fingerprints = await fingerprinter.fingerprint_async(endpoints, auth_headers)
        for fp in fingerprints:
            print(f"{fp.db_type}: {fp.endpoint_url} (conf={fp.confidence})")
    """

    def fingerprint(
        self,
        endpoints: list[DiscoveredEndpoint],
    ) -> list[VectorDBFingerprint]:
        """Fingerprint all RAG API endpoints (passive only).

        Args:
            endpoints: Endpoints discovered by NetworkInterceptor.

        Returns:
            List of identified VectorDBFingerprint (only successfully identified).
        """
        fingerprints: list[VectorDBFingerprint] = []

        for endpoint in endpoints:
            # Only analyze RAG API and unknown POST endpoints
            if endpoint.endpoint_type not in (EndpointType.RAG_API, EndpointType.UNKNOWN):
                continue

            for tech_name, reads in AI_VECTOR_DB_READS.items():
                if any(path in endpoint.url for path, _ in reads):
                    logger.info(
                        "VectorDBFingerprinter: candidate vector DB pattern %s at %s",
                        tech_name, endpoint.url,
                    )

            fp = self._fingerprint_single(endpoint)
            if fp and fp.db_type != VectorDBType.UNKNOWN:
                fingerprints.append(fp)

        logger.info(
            "VectorDBFingerprinter: identified %d vector DB endpoints "
            "from %d total endpoints",
            len(fingerprints), len(endpoints),
        )
        return fingerprints

    async def fingerprint_async(
        self,
        endpoints: list[DiscoveredEndpoint],
        auth_headers: dict[str, str] | None = None,
        active_timeout: float = 10.0,
    ) -> list[VectorDBFingerprint]:
        """Fingerprint with active confirmation reads (async).

        Args:
            endpoints: Endpoints discovered by NetworkInterceptor.
            auth_headers: Optional auth headers for active requests.
            active_timeout: Timeout for active confirmation requests.

        Returns:
            List of identified VectorDBFingerprint.
        """
        # First, passive fingerprinting
        fingerprints = self.fingerprint(endpoints)

        # Then, active confirmation for each identified type
        async with httpx.AsyncClient(timeout=active_timeout, verify=False) as client:
            for fp in fingerprints:
                confirmed = await self._confirm_read(
                    client, fp.endpoint_url, fp.db_type, auth_headers or {},
                )
                if confirmed:
                    fp.confidence = min(fp.confidence + 0.15, 1.0)
                    fp.evidence.append("Active GET confirmation successful")
                else:
                    fp.confidence = max(fp.confidence - 0.1, 0.3)

        return fingerprints

    async def _confirm_read(
        self,
        client: httpx.AsyncClient,
        endpoint_url: str,
        db_type: VectorDBType,
        headers: dict[str, str],
    ) -> bool:
        """Actively confirm a vector DB endpoint by GET request.

        Args:
            client: httpx async client.
            endpoint_url: Base endpoint URL.
            db_type: Suspected vector DB type.
            headers: Auth headers.

        Returns:
            True if confirmed, False otherwise.
        """
        db_key = db_type.value
        if db_key not in AI_VECTOR_DB_READS:
            return False

        confirm_endpoints = AI_VECTOR_DB_READS[db_key]

        from urllib.parse import urlparse
        parsed = urlparse(endpoint_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path, expected_substring in confirm_endpoints:
            url = f"{base.rstrip('/')}{path}"
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if expected_substring.lower() in body or expected_substring == "200":
                        logger.info(
                            "VectorDBFingerprinter: confirmed %s via %s (200 + '%s')",
                            db_type.value, url, expected_substring,
                        )
                        return True
            except (httpx.RequestError, asyncio.TimeoutError):
                pass

        return False

    def _fingerprint_single(
        self, endpoint: DiscoveredEndpoint
    ) -> VectorDBFingerprint | None:
        """对单个端点进行指纹识别。."""
        url = endpoint.url
        body_preview = endpoint.response_body_preview or ""
        content_type = endpoint.content_type or ""
        _ = content_type  # 保留供未来使用
        request_headers = endpoint.request_headers or {}

        evidence: list[str] = []

        for url_pattern, body_keywords, header_keywords, db_type, base_confidence in _FINGERPRINT_RULES:
            confidence = 0.0
            evidence.clear()

            # URL 匹配
            if url_pattern.search(url):
                confidence += base_confidence * 0.5
                evidence.append(f"URL matches pattern: {url_pattern.pattern}")

            # 响应体关键词匹配
            body_lower = body_preview.lower()
            body_matches = sum(1 for kw in body_keywords if kw.lower() in body_lower)
            if body_matches > 0:
                confidence += base_confidence * 0.3 * (body_matches / len(body_keywords))
                matched_kws = [kw for kw in body_keywords if kw.lower() in body_lower]
                evidence.append(f"Response body keywords: {matched_kws}")

            # 请求头/响应头关键词匹配
            header_text = " ".join(f"{k}:{v}" for k, v in request_headers.items()).lower()
            header_matches = sum(1 for kw in header_keywords if kw.lower() in header_text)
            if header_matches > 0:
                confidence += base_confidence * 0.2 * (header_matches / max(len(header_keywords), 1))
                matched_hdrs = [kw for kw in header_keywords if kw.lower() in header_text]
                evidence.append(f"Header keywords: {matched_hdrs}")

            if confidence >= 0.3:
                # 检查是否可能存在未授权访问
                unauthorized = self._check_unauthorized_access(endpoint)
                return VectorDBFingerprint(
                    db_type=db_type,
                    endpoint_url=url,
                    confidence=min(confidence, 1.0),
                    evidence=evidence,
                    unauthorized_access_likely=unauthorized,
                )

        return None

    @staticmethod
    def _check_unauthorized_access(endpoint: DiscoveredEndpoint) -> bool:
        """检查端点是否可能存在未授权访问.

        判据:
          - HTTP 200 但无 Authorization 头 → 可能未授权
          - HTTP 401/403 → 有认证保护 (非未授权)
          - 无认证头但响应成功 → 未授权可能性高
        """
        # 有认证头 → 有保护
        has_auth = any(
            k.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token")
            for k in endpoint.request_headers
        )
        if has_auth:
            return False

        # HTTP 200 且无认证头 → 可能未授权
        if endpoint.status_code == 200:
            return True

        # 401/403 → 有保护
        if endpoint.status_code in (401, 403):
            return False

        # 其他状态码 → 不确定
        return False

    @staticmethod
    def get_owasp_mapping(db_type: VectorDBType) -> list[str]:
        """将向量库类型映射到 OWASP LLM 类别.

        Args:
            db_type: 向量库类型。

        Returns:
            关联的 OWASP LLM ID 列表。
        """
        # 所有向量库都关联 LLM08
        owasp_ids = ["LLM08"]

        # Pinecone/Weaviate 等云服务也可能涉及 LLM02 (敏感信息)
        if db_type in (VectorDBType.PINECONE, VectorDBType.WEAVIATE):
            owasp_ids.append("LLM02")

        return owasp_ids