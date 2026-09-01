"""attack_surface_classifier.py — 基于 HTTP 内容的攻击面分类器.

扩展静态 Burp 文件名分析, 基于 HTTP 内容进行更深层的攻击面识别.

理论依据:
  - Wappalyzer/WhatWeb 技术指纹识别方法论
  - NIST SP 800-115 §2.3: 基于调查的技术识别
  - OWASP WSTG (Web Security Testing Guide) §4.2: 应用技术识别

设计原则:
  1. 被动分析优先: 不发送额外请求
  2. 保守分类: 置信度低时回退到默认类型
  3. 可解释性: 每个分类结果附带证据

分类结果对齐:
  - MCP Server: 基于 OpenAI MCP 规范的特征 (路径、端点、response schema)
  - RAG System: 基于 RAG API 常见模式 (search, retrieve, documents)
  - Agent System: 基于 Agent 工具调用模式 (tools, actions, workflow)
  - Standard LLM API: 默认分类 (OpenAI-compatible)

注意: 本分类器仅做初步筛选, 最终决策仍需人工确认.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ClassificationResult:
    """攻击面分类结果."""

    attack_surface: str
    confidence: float  # 0.0 ~ 1.0
    evidence: list[str] = field(default_factory=list)
    sub_type: str | None = None  # 更细粒度的子类型


# ──────────────────────────────────────────────
# 检测规则 (基于实证研究)
# ──────────────────────────────────────────────
# MCP Protocol Indicators (来自 OpenAI MCP 规范 + 实际部署)
MCP_INDICATORS: dict[str, list[str]] = {
    "path_patterns": [
        r"/mcp/?$",
        r"/mcp/v\d+",
        r"/api/mcp",
        r"/mcp-api",
        r"/sse",  # Server-Sent Events (MCP streaming)
        r"/api/v1/mcp",
        r"/mcp",  # 通用 MCP 路径匹配 (如 /api/labs/MCP_05/chat)
    ],
    "header_indicators": [
        "mcp-session-id",
        "mcp-protocol-version",
        "x-mcp-",
    ],
    "response_fields": [
        "jsonrpc",
        "tools",
        "resources",
        "prompts",
    ],
    "path_keywords": [
        "/tools/",
        "/resources/",
        "/prompts/",
        "/api/tools",
    ],
}

# RAG System Indicators
RAG_INDICATORS: dict[str, list[str]] = {
    "path_patterns": [
        r"/search",
        r"/retrieve",
        r"/query",
        r"/documents?",
        r"/knowledge",
        r"/vector",
        r"/embeddings?",
        r"/rag",
        r"/semantic",
    ],
    "header_indicators": [
        "x-document-id",
        "x-retrieval",
    ],
    "response_fields": [
        "documents",
        "passages",
        "chunks",
        "results",
        "retrieved_context",
        "relevance_score",
        "vector_match",
    ],
    "path_keywords": [
        "/search",
        "/retrieve",
        "/query",
        "/documents",
        "/knowledge-base",
    ],
}

# Agent System Indicators
AGENT_INDICATORS: dict[str, list[str]] = {
    "path_patterns": [
        r"/agent",
        r"/agents/",
        r"/workflow",
        r"/execute",
        r"/run",
        r"/task",
        r"/action",
        r"/invoke",
        r"/function",
        r"/call",
    ],
    "header_indicators": [
        "x-agent-id",
        "x-session-id",
        "x-workflow",
    ],
    "response_fields": [
        "tool_calls",
        "function_call",
        "action",
        "result",
        "status",
        "intermediate_steps",
        "chain_of_thought",
        "reasoning",
    ],
    "path_keywords": [
        "/agent/",
        "/agents/",
        "/workflow/",
        "/tools/",
        "/actions/",
        "/execute/",
    ],
}


def classify_http_content(
    http_request: str | None = None,
    http_response: str | None = None,
    url: str | None = None,
) -> ClassificationResult:
    """基于 HTTP 内容分析攻击面类型.

    被动分析 HTTP 请求/响应内容, 识别目标系统的攻击面类型.

    Args:
        http_request: HTTP 请求原始内容 (可选)
        http_response: HTTP 响应原始内容 (可选)
        url: 请求 URL (可选, 若未提供则从 http_request 提取)

    Returns:
        ClassificationResult: 攻击面分类结果
    """
    if not any([http_request, http_response, url]):
        return ClassificationResult(
            attack_surface="standard_llm_api",
            confidence=0.0,
            evidence=["No HTTP content provided"],
        )

    # Auto-extract URL from http_request first line if not provided
    if url is None and http_request:
        url = _extract_url_from_burp(http_request)

    scores: dict[str, float] = {
        "mcp_server": 0.0,
        "rag_system": 0.0,
        "multi_agent_system": 0.0,
    }
    evidence: dict[str, list[str]] = {
        "mcp_server": [],
        "rag_system": [],
        "multi_agent_system": [],
    }

    # ① URL 分析 (最高权重)
    if url:
        url_lower = url.lower()
        _score_url_indicators(url_lower, scores, evidence)

    # ② Request Headers 分析
    if http_request:
        _score_headers(http_request, scores, evidence)

    # ③ Request Body 分析
    if http_request:
        _score_body(http_request, scores, evidence)

    # ④ Response Body 分析
    if http_response:
        _score_response(http_response, scores, evidence)

    # 选择最高分类型
    max_score = max(scores.values())
    if max_score == 0:
        return ClassificationResult(
            attack_surface="standard_llm_api",
            confidence=0.5,
            evidence=["No specific indicators detected"],
        )

    max_surface = max(scores, key=scores.get)
    confidence = min(max_score / 10.0, 1.0)  # 归一化到 0~1

    return ClassificationResult(
        attack_surface=max_surface,
        confidence=confidence,
        evidence=evidence.get(max_surface, []),
        sub_type=_determine_sub_type(max_score, max_surface),
    )


def _score_url_indicators(
    url: str,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> None:
    """URL 路径指标评分.

    权重: 每个匹配 +3 (强指标)
    """
    # MCP 检测
    for pattern in MCP_INDICATORS["path_patterns"]:
        if re.search(pattern, url, re.IGNORECASE):
            scores["mcp_server"] += 3.0
            evidence["mcp_server"].append(f"URL pattern match: {pattern}")

    # RAG 检测
    for pattern in RAG_INDICATORS["path_patterns"]:
        if re.search(pattern, url, re.IGNORECASE):
            scores["rag_system"] += 3.0
            evidence["rag_system"].append(f"URL pattern match: {pattern}")

    # Agent 检测
    for pattern in AGENT_INDICATORS["path_patterns"]:
        if re.search(pattern, url, re.IGNORECASE):
            scores["multi_agent_system"] += 3.0
            evidence["multi_agent_system"].append(f"URL pattern match: {pattern}")


def _score_headers(
    http_request: str,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> None:
    """HTTP 请求头指标评分.

    权重: 每个匹配 +2 (中等指标)
    """
    headers_lower = http_request.lower()

    # MCP Header 检测
    for header in MCP_INDICATORS["header_indicators"]:
        if header in headers_lower:
            scores["mcp_server"] += 2.0
            evidence["mcp_server"].append(f"Header indicator: {header}")

    # Agent Header 检测
    for header in AGENT_INDICATORS["header_indicators"]:
        if header in headers_lower:
            scores["multi_agent_system"] += 2.0
            evidence["multi_agent_system"].append(f"Header indicator: {header}")


def _score_body(
    http_request: str,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> None:
    """HTTP 请求体指标评分.

    权重: 每个匹配 +1.5 (弱指标, 但多条可累积)
    """
    body_lower = http_request.lower()

    # JSON-RPC 检测 (MCP 协议)
    if "jsonrpc" in body_lower:
        scores["mcp_server"] += 2.5
        evidence["mcp_server"].append("JSON-RPC protocol detected")

    # RAG 语义搜索特征
    if any(kw in body_lower for kw in ["query", "documents", "retrieval"]):
        scores["rag_system"] += 1.5
        evidence["rag_system"].append("RAG-like terms in body")

    # Agent 工具调用特征
    if "tool_calls" in body_lower or "function_call" in body_lower:
        scores["multi_agent_system"] += 2.0
        evidence["multi_agent_system"].append("Agent tool call pattern")


def _score_response(
    http_response: str,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> None:
    """HTTP 响应体指标评分.

    权重: 每个匹配 +2 (中等指标, 响应结构更能反映后端类型)
    """
    resp_lower = http_response.lower()

    # MCP JSON-RPC Response
    if "jsonrpc" in resp_lower and "tools" in resp_lower:
        scores["mcp_server"] += 4.0
        evidence["mcp_server"].append("MCP JSON-RPC response with tools")

    # MCP SSE Response (Server-Sent Events format, common in MCP deployments)
    # 特征: MCP_CALL + server: + tool: pattern
    if "mcp_call" in resp_lower:
        scores["mcp_server"] += 3.0
        evidence["mcp_server"].append("MCP SSE response with MCP_CALL event")
    if "server:" in resp_lower and "tool:" in resp_lower:
        scores["mcp_server"] += 2.0
        evidence["mcp_server"].append("MCP server/tool pattern in response")

    # event: meta with lab_id indicating MCP lab
    if "event: meta" in resp_lower and "lab_id" in resp_lower:
        scores["mcp_server"] += 1.0
        evidence["mcp_server"].append("SSE event:meta pattern (MCP streaming)")

    # RAG Response Structure
    if any(f in resp_lower for f in RAG_INDICATORS["response_fields"]):
        count = sum(1 for f in RAG_INDICATORS["response_fields"] if f in resp_lower)
        scores["rag_system"] += count * 1.5
        evidence["rag_system"].append(f"RAG response fields detected ({count})")

    # Agent Response Structure
    if any(f in resp_lower for f in AGENT_INDICATORS["response_fields"]):
        count = sum(1 for f in AGENT_INDICATORS["response_fields"] if f in resp_lower)
        scores["multi_agent_system"] += count * 1.5
        evidence["multi_agent_system"].append(f"Agent response fields detected ({count})")


def _determine_sub_type(score: float, surface: str) -> str | None:
    """根据分数确定子类型."""
    if score >= 8:
        return "high_confidence"
    elif score >= 5:
        return "medium_confidence"
    elif score >= 3:
        return "low_confidence"
    return None


# ──────────────────────────────────────────────
# Burp 文件联合分类器 (文件名 + 内容)
# ──────────────────────────────────────────────
def classify_burp_file(
    burp_file_path: str | None = None,
    burp_content: str | None = None,
    burp_profile_name: str | None = None,
) -> ClassificationResult:
    """Burp 配置文件完整分类 (文件名 + 内容).

    整合:
      1. 基于文件名的快速分类 (from AssetMapper)
      2. 基于 HTTP 内容的深度分类

    Args:
        burp_file_path: Burp 文件路径 (可选)
        burp_content: Burp 文件原始内容 (可选)
        burp_profile_name: Burp 配置文件名 (可选)

    Returns:
        ClassificationResult: 完整分类结果
    """
    from data.asset_mapper import get_default_mapper

    # Phase 1: 文件名分类 (快速)
    mapper = get_default_mapper()
    if burp_profile_name:
        filename_surface = mapper.classify_attack_surface(burp_profile_name)
    else:
        filename_surface = "standard_llm_api"

    # Phase 2: 内容分类 (深度)
    if burp_content:
        content_result = classify_http_content(
            http_request=burp_content,
            url=_extract_url_from_burp(burp_content),
        )
    elif burp_file_path:
        try:
            content_raw = open(burp_file_path, encoding="utf-8", errors="ignore").read()
            content_result = classify_http_content(
                http_request=content_raw,
                url=_extract_url_from_burp(content_raw),
            )
        except Exception as e:
            logger.warning("Failed to read burp file %s: %s", burp_file_path, e)
            content_result = None
    else:
        content_result = None

    # 决策融合
    if content_result is None or content_result.confidence < 0.3:
        # 内容分类置信度低, 回退到文件名分类
        return ClassificationResult(
            attack_surface=filename_surface,
            confidence=0.5 if content_result is None else content_result.confidence,
            evidence=["File-name based classification (content confidence too low)"],
        )

    # 两者一致: 置信度高
    if content_result.attack_surface == filename_surface:
        return ClassificationResult(
            attack_surface=content_result.attack_surface,
            confidence=min(content_result.confidence + 0.2, 1.0),
            evidence=["File-name + content agreement"] + content_result.evidence,
        )

    # 两者不一致: 选择置信度更高的
    if content_result.confidence >= 0.6:
        return ClassificationResult(
            attack_surface=content_result.attack_surface,
            confidence=content_result.confidence - 0.1,  # 轻微惩罚不一致
            evidence=["Content-based (filename disagreed)"] + content_result.evidence,
        )

    return ClassificationResult(
        attack_surface=filename_surface,
        confidence=0.4,
        evidence=[f"File-name fallback (content suggested {content_result.attack_surface})"],
    )


def _extract_url_from_burp(content: str) -> str | None:
    """从 Burp HTTP 内容中提取 URL."""
    # 简单解析: 第一行通常是 "METHOD /path HTTP/1.1"
    first_line = content.split("\n", 1)[0].strip()
    parts = first_line.split()
    if len(parts) >= 2:
        return parts[1]
    return None


# ──────────────────────────────────────────────
# 全局实例
# ──────────────────────────────────────────────
_default_classifier = None


def get_default_classifier():
    """获取全局默认分类器."""
    global _default_classifier
    if _default_classifier is None:
        def _default_classifier():
            return None  # placeholder
    return _default_classifier


def quick_classify(burp_profile_name: str, burp_dir: str | None = None) -> ClassificationResult:
    """快速分类接口 (Burp 文件名 → 攻击面类型).

    Args:
        burp_profile_name: Burp 配置文件名 (如 "mcp05")
        burp_dir: data/burp 目录路径 (可选)

    Returns:
        ClassificationResult
    """
    if burp_dir:
        burp_path = f"{burp_dir}/{burp_profile_name}.txt"
        return classify_burp_file(burp_file_path=burp_path, burp_profile_name=burp_profile_name)

    # 仅文件名分类
    from data.asset_mapper import get_default_mapper
    mapper = get_default_mapper()
    surface = mapper.classify_attack_surface(burp_profile_name)
    return ClassificationResult(
        attack_surface=surface,
        confidence=0.6,
        evidence=[f"File-name based: {burp_profile_name}"],
    )
