"""向量数据库端点探测（AI-300 Ch5: Exploiting RAG Pipelines）。

实现 AI-300 课程中的向量数据库侦察技术：
  - Qdrant / Chroma / Weaviate / Pinecone / Milvus / pgvector 端点探测
  - 未认证端点识别
  - 集合/命名空间枚举

对齐 OWASP LLM Top 10: LLM08 (Vector Database Weaknesses)
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

_VECTOR_DB_PATHS: list[tuple[str, str, str]] = [
    ("/collections", "qdrant", "GET"),
    ("/collections", "chroma", "GET"),
    ("/v1/objects", "weaviate", "GET"),
    ("/describe_index_stats", "pinecone", "POST"),
    ("/v2/vectordb/collections", "milvus", "GET"),
    ("/v1/collections", "qdrant", "GET"),
    ("/api/v1/collections", "chroma", "GET"),
    ("/v1/schema", "weaviate", "GET"),
    ("/v1/vector/collections", "milvus", "GET"),
]


def probe_vector_dbs(
    base_url: str,
    auth: Any | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """探测向量数据库端点（AI-300 Ch5.1）。"""
    results: list[dict[str, Any]] = []
    headers = auth.to_header_dict() if auth else {}

    for path, db_type, method in _VECTOR_DB_PATHS:
        url = urljoin(base_url, path)
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                if method == "GET":
                    r = client.get(url, headers=headers)
                else:
                    r = client.post(url, headers=headers, json={})

                if r.status_code in (200, 201, 401, 403):
                    results.append({
                        "url": url,
                        "db_type": db_type,
                        "status": r.status_code,
                        "body_preview": r.text[:500],
                    })
        except Exception:
            pass

    return results


__all__ = [
    "probe_vector_dbs",
    "_VECTOR_DB_PATHS",
]