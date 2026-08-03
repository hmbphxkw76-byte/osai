# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""EmbeddingProbe: 嵌入向量端点侦察探针。.

职责:
  1. 从 NetworkInterceptor 结果中筛选 EMBEDDING_API 端点
  2. 提取嵌入维度、模型信息
  3. 检测未授权访问风险

对齐 DESIGN.md 六类探针架构:
  - 输入: auth_state (HTTP headers)
  - 产出: endpoints (EMBEDDING_API)
  - 浏览器需求: True

学术依据:
  - OWASP LLM08: Vector and Embedding Weaknesses
  - MITRE ATT&CK T1580: Cloud Infrastructure Discovery

> **日期**: 2026-8-3
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from core.models.recon_report import DiscoveredEndpoint, EndpointType
from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class EmbeddingProbe(ReconProbe):
    """嵌入向量端点侦察探针。.

    从已发现的端点中筛选 Embedding API 端点,
    提取嵌入维度和模型信息。

    用法::
        probe = EmbeddingProbe()
        result = await probe.probe(session)
        # result["endpoints"] → Embedding API 端点列表
        # result["embedding_info"] → 嵌入维度/模型信息
    """

    @property
    def name(self) -> str:
        return "EmbeddingProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """执行 Embedding 探针。.

        Args:
            session: 侦察会话。

        Returns:
            包含 embedding_endpoints 和 embedding_info 的结果字典。
        """
        embedding_endpoints = [
            e for e in session.report.endpoints
            if e.endpoint_type == EndpointType.EMBEDDING_API
        ]

        info: list[dict[str, Any]] = []
        for ep in embedding_endpoints:
            ep_info = self._analyze_embedding_endpoint(ep)
            if ep_info:
                info.append(ep_info)

        logger.info(
            f"EmbeddingProbe: {len(embedding_endpoints)} embedding endpoints, "
            f"{len(info)} analyzed"
        )

        return {
            "endpoints": embedding_endpoints,
            "embedding_info": info,
        }

    @staticmethod
    def _analyze_embedding_endpoint(endpoint: DiscoveredEndpoint) -> dict[str, Any] | None:
        """分析单个 Embedding 端点。."""
        body = endpoint.response_body_preview or ""
        if not body:
            return None

        result: dict[str, Any] = {
            "url": endpoint.url,
            "dimension": None,
            "model": None,
            "usage_info": None,
        }

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return result

        # 提取维度
        if "data" in data and isinstance(data["data"], list) and data["data"]:
            embedding = data["data"][0].get("embedding", [])
            if isinstance(embedding, list):
                result["dimension"] = len(embedding)

        # 提取模型信息
        result["model"] = data.get("model")

        # 提取用量信息
        result["usage_info"] = data.get("usage")

        return result
