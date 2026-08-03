# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""端点分类器 — 将发现的 URL 分类为 API 端点类型。.

基于 URL 路径模式、HTTP 方法和 Content-Type,
将发现的端点分类为 Model API / RAG API / Agent Tool API / MCP Server 等。

分类规则基于 OWASP Top 10 for LLMs 2025 攻击面对应的 API 模式:
  - Model API: LLM 推理端点 (LLM01/LLM02/LLM07/LLM10)
  - RAG API: 检索增强生成端点 (LLM08)
  - Agent Tool API: Agent 工具调用端点 (LLM01 间接注入 / LLM06 过度代理)
  - MCP Server: Model Context Protocol 端点 (LLM01/LLM06/LLM07)
  - Embedding API: 嵌入向量端点 (LLM08)
  - File Upload: 文件上传端点 (LLM04 数据投毒 / LLM08 知识库投毒)

> **日期**: 2026-8-3
> **变更**: 新增 MCP Server 和 Embedding API 端点分类规则。
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from core.probes.ai_signal_catalog import AI_PATH_PATTERNS
from core.probes.recon_result import EndpointType

logger = logging.getLogger(__name__)


def _endpoint_type_for_interface(interface_type: str) -> EndpointType:
    if interface_type == "mcp":
        return EndpointType.MCP_SERVER
    if interface_type == "sse-stream":
        return EndpointType.MCP_SERVER
    if interface_type == "rag":
        return EndpointType.RAG_API
    if interface_type == "vector-db":
        return EndpointType.RAG_API
    if interface_type == "agent-tool":
        return EndpointType.AGENT_TOOL_API
    if interface_type == "upload":
        return EndpointType.FILE_UPLOAD
    if interface_type == "llm-embedding":
        return EndpointType.EMBEDDING_API
    if interface_type == "llm-graphql":
        return EndpointType.MODEL_API
    if interface_type.startswith("llm"):
        return EndpointType.MODEL_API
    return EndpointType.UNKNOWN


# ── 端点分类规则 (按优先级排序) ──
# 每条规则: (编译后的正则, 匹配的端点类型, 描述)
_CLASSIFICATION_RULES: list[tuple[re.Pattern[str], EndpointType, str]] = [
    *[
        (pattern, _endpoint_type_for_interface(interface_type), f"AI signal catalog: {interface_type}")
        for pattern, interface_type in AI_PATH_PATTERNS
    ],
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

    # MCP Server — Model Context Protocol 端点
    (
        re.compile(r"/mcp/(?:message|sse|stream)", re.IGNORECASE),
        EndpointType.MCP_SERVER,
        "MCP 消息端点 (SSE/Streamable HTTP)",
    ),
    (
        re.compile(r"/sse", re.IGNORECASE),
        EndpointType.MCP_SERVER,
        "MCP SSE 端点 (Server-Sent Events)",
    ),
    (
        re.compile(r"/jsonrpc", re.IGNORECASE),
        EndpointType.MCP_SERVER,
        "JSON-RPC 端点 (MCP 兼容)",
    ),
    (
        re.compile(r"/.well-known/mcp", re.IGNORECASE),
        EndpointType.MCP_SERVER,
        "MCP 服务发现端点",
    ),
    (
        re.compile(r"/mcp-server", re.IGNORECASE),
        EndpointType.MCP_SERVER,
        "MCP Server 端点",
    ),

    # Embedding API — 专用嵌入端点 (独立于 RAG)
    (
        re.compile(r"/v1/embeddings", re.IGNORECASE),
        EndpointType.EMBEDDING_API,
        "OpenAI 兼容嵌入端点",
    ),
    (
        re.compile(r"/api/(?:embed|embedding|encode|vectorize)", re.IGNORECASE),
        EndpointType.EMBEDDING_API,
        "自定义嵌入端点",
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
        response_body: str = "",
    ) -> EndpointType:
        """分类端点。.

        Args:
            url: 端点 URL。
            method: HTTP 方法。
            content_type: 响应 Content-Type。
            response_body: 响应体文本 (用于 MCP JSON-RPC 检测)。

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

        # 2. 响应体 MCP JSON-RPC 检测
        if response_body and self._is_mcp_jsonrpc(response_body):
            logger.debug(f"EndpointClassifier: {url} → mcp_server (JSON-RPC response body)")
            return EndpointType.MCP_SERVER

        # 3. POST + multipart → 文件上传
        if method.upper() == "POST" and "multipart" in content_type.lower():
            logger.debug(f"EndpointClassifier: {url} → file_upload (multipart POST)")
            return EndpointType.FILE_UPLOAD

        # 4. POST + JSON → 可能是 Model API / RAG API / MCP
        if method.upper() == "POST" and "json" in content_type.lower():
            path = urlparse(url).path.lower()
            if any(kw in path for kw in ("chat", "completion", "generate", "infer")):
                logger.debug(f"EndpointClassifier: {url} → model_api (POST JSON + chat keyword)")
                return EndpointType.MODEL_API
            if any(kw in path for kw in ("search", "retrieve", "embed", "query")):
                logger.debug(f"EndpointClassifier: {url} → rag_api (POST JSON + search keyword)")
                return EndpointType.RAG_API
            if any(kw in path for kw in ("mcp", "jsonrpc", "rpc")):
                logger.debug(f"EndpointClassifier: {url} → mcp_server (POST JSON + mcp keyword)")
                return EndpointType.MCP_SERVER

        # 5. SSE Content-Type → MCP Server
        if "text/event-stream" in content_type.lower():
            logger.debug(f"EndpointClassifier: {url} → mcp_server (SSE content-type)")
            return EndpointType.MCP_SERVER

        # 6. 无法分类
        return EndpointType.UNKNOWN

    @staticmethod
    def _is_mcp_jsonrpc(body: str) -> bool:
        """检测响应体是否为 MCP JSON-RPC 格式。.

        MCP JSON-RPC 特征: {"jsonrpc": "2.0", "id": ..., "result": {"tools": [...]}}
        """
        if '"jsonrpc"' not in body:
            return False
        # 检查是否包含 MCP 特有字段
        mcp_markers = ('"tools"', '"resources"', '"prompts"', '"serverInfo"', '"capabilities"')
        return any(marker in body for marker in mcp_markers)

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
            EndpointType.MCP_SERVER: ["LLM01", "LLM06", "LLM07"],
            EndpointType.EMBEDDING_API: ["LLM08"],
            EndpointType.AUTH_API: [],
            EndpointType.FILE_UPLOAD: ["LLM04", "LLM08"],
            EndpointType.UNKNOWN: [],
        }
        return mapping.get(endpoint_type, [])