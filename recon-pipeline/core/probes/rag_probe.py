# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""RAGProbe: RAG 系统侦察探针。.

职责:
  1. 从 NetworkInterceptor 结果中筛选 RAG_API + FILE_UPLOAD 端点
  2. 委托 VectorDBFingerprinter 识别向量数据库类型
  3. 检测未授权访问风险

对齐 DESIGN.md 六类探针架构:
  - 输入: auth_state + browser_page
  - 产出: endpoints (RAG_API) + vector_db_fingerprints
  - 浏览器需求: True

学术依据:
  - OWASP LLM08: Vector and Embedding Weaknesses
  - OWASP LLM04: Data Poisoning — RAG 知识库是投毒目标

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.models.recon_report import DiscoveredEndpoint, EndpointType
from core.probes.base import ReconProbe
from core.probes.vector_db_fingerprinter import (
    VectorDBFingerprint,
    VectorDBFingerprinter,
)

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class RAGProbe(ReconProbe):
    """RAG 系统侦察探针。.

    从已发现的端点中筛选 RAG 相关端点,
    执行向量数据库指纹识别和未授权访问检测。

    用法::
        probe = RAGProbe()
        result = await probe.probe(session)
        # result["endpoints"] → RAG API 端点列表
        # result["vector_db_fingerprints"] → 向量库指纹
    """

    def __init__(self) -> None:
        self._fingerprinter = VectorDBFingerprinter()

    @property
    def name(self) -> str:
        return "RAGProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """执行 RAG 探针。.

        Args:
            session: 侦察会话。

        Returns:
            包含 rag_endpoints 和 vector_db_fingerprints 的结果字典。
        """
        rag_endpoints = [
            e for e in session.report.endpoints
            if e.endpoint_type in (EndpointType.RAG_API, EndpointType.FILE_UPLOAD, EndpointType.EMBEDDING_API)
        ]

        fingerprints: list[VectorDBFingerprint] = []
        if rag_endpoints:
            fingerprints = self._fingerprinter.fingerprint(rag_endpoints)

        logger.info(
            f"RAGProbe: {len(rag_endpoints)} RAG endpoints, "
            f"{len(fingerprints)} vector DB fingerprints"
        )

        return {
            "endpoints": rag_endpoints,
            "vector_db_fingerprints": [fp.to_dict() for fp in fingerprints],
        }
