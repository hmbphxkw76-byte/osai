# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""端点分类器 — 将发现的 URL 分类为 API 端点类型。.

基于 URL 路径模式、HTTP 方法和 Content-Type,
将发现的端点分类为 Model API / RAG API / Agent Tool API 等。

分类规则基于 OWASP Top 10 for LLMs 2025 攻击面对应的 API 模式:
  - Model API: LLM 推理端点 (LLM01/LLM02/LLM07/LLM10)
  - RAG API: 检索增强生成端点 (LLM08)
  - Agent Tool API: Agent 工具调用端点 (LLM01 间接注入 / LLM06 过度代理)
  - File Upload: 文件上传端点 (LLM04 数据投毒 / LLM08 知识库投毒)

> **日期**: 2026-8-2
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from core.probes.recon_result import EndpointType

logger = logging.getLogger(__name__)

# ── 端点分类规则 (按优先级排序) ──
# 每条规则: (编译后的正则, 匹配的端点类型, 描述)
_CLASSIFICATION_RULES: list[tuple[re.Pattern[str], EndpointType, str]] = [
    # Model API — LLM 推理端点
    (
        re.compile(r"/v1/chat/completions", re.IGNORECASE),
        EndpointType.MODEL_API,
        "OpenAI 兼容聊天补全端点",
    ),
    (
        re.compile(r"/v1/responses", re.IGNORECASE),
        EndpointType.MODEL_API,
        "OpenAI Responses API (o1/o3)",
    ),
    (
        re.compile(r"/v1/completions", re.IGNORECASE),
        EndpointType.MODEL_API,
        "OpenAI 补全端点",
    ),
    (
        re.compile(r"/api/(chat|completion|generate|inference)", re.IGNORECASE),
        EndpointType.MODEL_API,
        "自定义 LLM 推理端点",
    ),
    (
        re.compile(r"/(openai|anthropic|llama|gemini|mistral)/", re.IGNORECASE),
        EndpointType.MODEL_API,
        "LLM 供应商端点",
    ),

    # RAG API — 检索/嵌入/向量端点
    (
        re.compile(r"/api/(search|retrieve|query)", re.IGNORECASE),
        EndpointType.RAG_API,
        "RAG 检索端点",
    ),
    (
        re.compile(r"/api/embeddings?", re.IGNORECASE),
        EndpointType.RAG_API,
        "向量嵌入端点",
    ),
    (
        re.compile(r"/api/(vector|index|collection)", re.IGNORECASE),
        EndpointType.RAG_API,
        "向量数据库端点",
    ),
    (
        re.compile(r"/(rag|retrieval|knowledge[-_]base)/", re.IGNORECASE),
        EndpointType.RAG_API,
        "RAG 系统端点",
    ),
    (
        re.compile(r"/api/(upload[-_]?document|ingest|import)", re.IGNORECASE),
        EndpointType.RAG_API,
        "知识库导入端点",
    ),

    # Agent Tool API — 工具调用端点
    (
        re.compile(r"/api/(tools?|functions?|actions?)", re.IGNORECASE),
        EndpointType.AGENT_TOOL_API,
        "Agent 工具调用端点",
    ),
    (
        re.compile(r"/(fetch|browse|navigate|crawl)", re.IGNORECASE),
        EndpointType.AGENT_TOOL_API,
        "网页获取工具端点 (XPIA 注入面)",
    ),
    (
        re.compile(r"/api/(execute|run|invoke)", re.IGNORECASE),
        EndpointType.AGENT_TOOL_API,
        "Agent 执行端点 (LLM06 过度代理)",
    ),
    (
        re.compile(r"/(copilot|assistant|agent)/", re.IGNORECASE),
        EndpointType.AGENT_TOOL_API,
        "Copilot/Assistant 端点",
    ),

    # Auth API — 认证端点
    (
        re.compile(r"/oauth", re.IGNORECASE),
        EndpointType.AUTH_API,
        "OAuth 认证端点",
    ),
    (
        re.compile(r"/(token|auth|login|signin|sso|idp)", re.IGNORECASE),
        EndpointType.AUTH_API,
        "认证端点",
    ),

    # File Upload — 文件上传端点
    (
        re.compile(r"/api/(upload|files?|attachment)", re.IGNORECASE),
        EndpointType.FILE_UPLOAD,
        "文件上传端点",
    ),
    (
        re.compile(r"/(upload|files?|media)/", re.IGNORECASE),
        EndpointType.FILE_UPLOAD,
        "文件上传端点",
    ),
]


class EndpointClassifier:
    """端点分类器。.

    将发现的 URL 分类为 API 端点类型,
    基于 URL 路径模式、HTTP 方法和 Content-Type。

    用法::
        classifier = EndpointClassifier()
        endpoint_type = classifier.classify(
            url="https://example.com/v1/chat/completions",
            method="POST",
            content_type="application/json",
        )
    """

    def classify(
        self,
        url: str,
        method: str = "GET",
        content_type: str = "",
    ) -> EndpointType:
        """分类端点。.

        Args:
            url: 端点 URL。
            method: HTTP 方法。
            content_type: 响应 Content-Type。

        Returns:
            EndpointType 分类结果。
        """
        # 1. URL 路径模式匹配 (最高优先级)
        for pattern, endpoint_type, _desc in _CLASSIFICATION_RULES:
            if pattern.search(url):
                logger.debug(
                    f"EndpointClassifier: {url} → {endpoint_type.value} "
                    f"(rule: {pattern.pattern})"
                )
                return endpoint_type

        # 2. POST + multipart → 文件上传
        if method.upper() == "POST" and "multipart" in content_type.lower():
            logger.debug(f"EndpointClassifier: {url} → file_upload (multipart POST)")
            return EndpointType.FILE_UPLOAD

        # 3. POST + JSON → 可能是 Model API 或 RAG API
        if method.upper() == "POST" and "json" in content_type.lower():
            # 检查路径是否包含 LLM 相关关键词
            path = urlparse(url).path.lower()
            if any(kw in path for kw in ("chat", "completion", "generate", "infer")):
                logger.debug(f"EndpointClassifier: {url} → model_api (POST JSON + chat keyword)")
                return EndpointType.MODEL_API
            if any(kw in path for kw in ("search", "retrieve", "embed", "query")):
                logger.debug(f"EndpointClassifier: {url} → rag_api (POST JSON + search keyword)")
                return EndpointType.RAG_API

        # 4. 无法分类
        return EndpointType.UNKNOWN

    @staticmethod
    def get_owasp_mapping(endpoint_type: EndpointType) -> list[str]:
        """将端点类型映射到 OWASP LLM 类别。.

        Args:
            endpoint_type: 端点类型。

        Returns:
            关联的 OWASP LLM ID 列表。
        """
        mapping: dict[EndpointType, list[str]] = {
            EndpointType.MODEL_API: ["LLM01", "LLM02", "LLM07", "LLM10"],
            EndpointType.RAG_API: ["LLM01", "LLM08"],
            EndpointType.AGENT_TOOL_API: ["LLM01", "LLM06"],
            EndpointType.AUTH_API: [],
            EndpointType.FILE_UPLOAD: ["LLM04", "LLM08"],
            EndpointType.UNKNOWN: [],
        }
        return mapping.get(endpoint_type, [])