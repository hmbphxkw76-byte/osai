"""recon/attack_surface_classifier.py - HTTP .

Extend Burp ,  HTTP Layer.

:
    v61 imports data/attack_surface_classifier.py ,  D-13 :
    ,  recon/ Layer.

:
  - Wappalyzer/WhatWeb 
  - NIST SP 800-115 Sec2.3: 
  - OWASP WSTG (Web Security Testing Guide) Sec4.2: 

:
  1. : 
  2. : 
  3. : converter(s)

:
  - MCP Server:  OpenAI MCP  (response schema)
  - RAG System:  RAG API  (search, retrieve, documents)
  - Agent System:  Agent  (tools, actions, workflow)
  - Standard LLM API:  (OpenAI-compatible)

: , Confirmation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ClassificationResult:
 """."""

    attack_surface: str
    confidence: float  # 0.0 ~ 1.0
    evidence: list[str] = field(default_factory=list)
    sub_type: str | None = None  # 


# ==============================================
# ()
# ==============================================
# MCP Protocol Indicators ( OpenAI MCP + )
MCP_INDICATORS: dict[str, list[str]] = {
    "path_patterns": [
        r"/mcp/?$",
        r"/mcp/v\d+",
        r"/api/mcp",
        r"/mcp-api",
        r"/sse",  # Server-Sent Events (MCP streaming)
        r"/api/v1/mcp",
        r"/mcp",  # MCP ( /api/labs/MCP_05/chat)
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
 """ HTTP .

     HTTP /, .

    Args:
        http_request: HTTP  ()
        http_response: HTTP  ()
        url:  URL (, imports http_request )

    Returns:
        ClassificationResult: 
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

 # (1) URL ()
    if url:
        url_lower = url.lower()
        _score_url_indicators(url_lower, scores, evidence)

 # (2) Request Headers 
    if http_request:
        _score_headers(http_request, scores, evidence)

 # (3) Request Body 
    if http_request:
        _score_body(http_request, scores, evidence)

 # (4) Response Body 
    if http_response:
        _score_response(http_response, scores, evidence)

 # 
    max_score = max(scores.values())
    if max_score == 0:
        return ClassificationResult(
            attack_surface="standard_llm_api",
            confidence=0.5,
            evidence=["No specific indicators detected"],
        )

    max_surface = max(scores, key=scores.get)
    confidence = min(max_score / 10.0, 1.0)  # 0~1

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
 """URL .

    : converter(s) +3 ()
 """
 # MCP 
    for pattern in MCP_INDICATORS["path_patterns"]:
        if re.search(pattern, url, re.IGNORECASE):
            scores["mcp_server"] += 3.0
            evidence["mcp_server"].append(f"URL pattern match: {pattern}")

 # RAG 
    for pattern in RAG_INDICATORS["path_patterns"]:
        if re.search(pattern, url, re.IGNORECASE):
            scores["rag_system"] += 3.0
            evidence["rag_system"].append(f"URL pattern match: {pattern}")

 # Agent 
    for pattern in AGENT_INDICATORS["path_patterns"]:
        if re.search(pattern, url, re.IGNORECASE):
            scores["multi_agent_system"] += 3.0
            evidence["multi_agent_system"].append(f"URL pattern match: {pattern}")


def _score_headers(
    http_request: str,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> None:
 """HTTP .

    : converter(s) +2 ()
 """
    headers_lower = http_request.lower()

 # MCP Header 
    for header in MCP_INDICATORS["header_indicators"]:
        if header in headers_lower:
            scores["mcp_server"] += 2.0
            evidence["mcp_server"].append(f"Header indicator: {header}")

 # Agent Header 
    for header in AGENT_INDICATORS["header_indicators"]:
        if header in headers_lower:
            scores["multi_agent_system"] += 2.0
            evidence["multi_agent_system"].append(f"Header indicator: {header}")


def _score_body(
    http_request: str,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> None:
 """HTTP .

    : converter(s) +1.5 (, )
 """
    body_lower = http_request.lower()

 # JSON-RPC (MCP )
    if "jsonrpc" in body_lower:
        scores["mcp_server"] += 2.5
        evidence["mcp_server"].append("JSON-RPC protocol detected")

 # RAG 
    if any(kw in body_lower for kw in ["query", "documents", "retrieval"]):
        scores["rag_system"] += 1.5
        evidence["rag_system"].append("RAG-like terms in body")

 # Agent 
    if "tool_calls" in body_lower or "function_call" in body_lower:
        scores["multi_agent_system"] += 2.0
        evidence["multi_agent_system"].append("Agent tool call pattern")


def _score_response(
    http_response: str,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
) -> None:
 """HTTP .

    : converter(s) +2 (, )
 """
    resp_lower = http_response.lower()

 # MCP JSON-RPC Response
    if "jsonrpc" in resp_lower and "tools" in resp_lower:
        scores["mcp_server"] += 4.0
        evidence["mcp_server"].append("MCP JSON-RPC response with tools")

 # MCP SSE Response (Server-Sent Events format, common in MCP deployments)
 # : MCP_CALL + server: + tool: pattern
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
 """."""
    if score >= 8:
        return "high_confidence"
    elif score >= 5:
        return "medium_confidence"
    elif score >= 3:
        return "low_confidence"
    return None


# ==============================================
# Burp ( + )
# ==============================================
def classify_burp_file(
    burp_file_path: str | None = None,
    burp_content: str | None = None,
    burp_profile_name: str | None = None,
) -> ClassificationResult:
 """Burp ( + ).

    :
      1.  (from AssetMapper)
      2.  HTTP 

    Args:
        burp_file_path: Burp  ()
        burp_content: Burp  ()
        burp_profile_name: Burp  ()

    Returns:
        ClassificationResult: 
 """
    from core.asset_mapper import get_default_mapper

 # Phase 1: ()
    mapper = get_default_mapper()
    if burp_profile_name:
        filename_surface = mapper.classify_attack_surface(burp_profile_name)
    else:
        filename_surface = "standard_llm_api"

 # Phase 2: ()
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

 # 
    if content_result is None or content_result.confidence < 0.3:
 # , 
        return ClassificationResult(
            attack_surface=filename_surface,
            confidence=0.5 if content_result is None else content_result.confidence,
            evidence=["File-name based classification (content confidence too low)"],
        )

 # : 
    if content_result.attack_surface == filename_surface:
        return ClassificationResult(
            attack_surface=content_result.attack_surface,
            confidence=min(content_result.confidence + 0.2, 1.0),
            evidence=["File-name + content agreement"] + content_result.evidence,
        )

 # : 
    if content_result.confidence >= 0.6:
        return ClassificationResult(
            attack_surface=content_result.attack_surface,
            confidence=content_result.confidence - 0.1,  # 
            evidence=["Content-based (filename disagreed)"] + content_result.evidence,
        )

    return ClassificationResult(
        attack_surface=filename_surface,
        confidence=0.4,
        evidence=[f"File-name fallback (content suggested {content_result.attack_surface})"],
    )


def _extract_url_from_burp(content: str) -> str | None:
 """imports Burp HTTP URL."""
 # : "METHOD /path HTTP/1.1"
    first_line = content.split("\n", 1)[0].strip()
    parts = first_line.split()
    if len(parts) >= 2:
        return parts[1]
    return None


# ==============================================
# 
# ==============================================


def get_default_classifier():
 """ ( classify_http_content ).

    Returns:
         (classify_http_content)
 """
    return classify_http_content


def quick_classify(burp_profile_name: str, burp_dir: str | None = None) -> ClassificationResult:
 """ (Burp -> ).

    Args:
        burp_profile_name: Burp  ( "mcp05")
        burp_dir: config/burp  (, v61 )

    Returns:
        ClassificationResult
 """
    if burp_dir:
        burp_path = f"{burp_dir}/{burp_profile_name}.txt"
        return classify_burp_file(burp_file_path=burp_path, burp_profile_name=burp_profile_name)

 # 
    from core.asset_mapper import get_default_mapper
    mapper = get_default_mapper()
    surface = mapper.classify_attack_surface(burp_profile_name)
    return ClassificationResult(
        attack_surface=surface,
        confidence=0.6,
        evidence=[f"File-name based: {burp_profile_name}"],
    )
