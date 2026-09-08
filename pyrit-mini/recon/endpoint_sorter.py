# arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection ()
# arXiv:2406.12609 - Lattner et al., Parallel multi-strategy scoring
# arXiv:2407.01232 - PyRIT, framework foundation
# arXiv:2309.00212 - NIST SP 800-115 Sec2.3 - Technical reconnaissance
"""Endpoint + Attack Surface Classification - endpoint priority sorting

Merged from:
    - recon/endpoint_sorter.py (priority sorting based on capabilities)
    - recon/attack_surface_classifier.py (HTTP-based surface classification)

Attack surface classification now part of endpoint sorting pipeline.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from recon.burp_parser import parse_burp_request

logger = logging.getLogger(__name__)

# == ==
# Academic basis: Greshake et al. (arXiv:2302.12173) Sec4 -
# MCP/function_calling > RAG > workflow > memory/multi_tenant > a2a > chat
# , endpoint
_CAPABILITY_PRIORITY: dict[str, int] = {
    "mcp": 100,
    "mcp_protocol": 100,
    "function_calling": 90,
    "tool_hijack": 85,
    "rag": 80,
    "embedding_rag": 78,
    "embedding": 75,
    "workflow": 70,
    "memory": 60,
    "multi_tenant": 55,
    "session_auth": 50,
    "a2a_protocol": 45,
    "a2a": 45,
    "multi_agent": 40,
    "agent": 30,
    "code_execution": 25,
    "web_search": 20,
    # ( chat)
}

# ()
_DEFAULT_PRIORITY = 10

# == Burp ==
# Burp Response
# capability_detector.py / capability_probe.py ,
# ,
_CAPABILITY_SIGNAL_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "mcp": [
        re.compile(r'"(?:jsonrpc|mcp_server|server_name|protocol_version)"\s*[:=]', re.IGNORECASE),
        re.compile(r'"tool_call_id"', re.IGNORECASE),
        re.compile(r'"tool_result"', re.IGNORECASE),
        re.compile(r'MCP_CALL', re.IGNORECASE),
        re.compile(r'"selected_server"', re.IGNORECASE),
        re.compile(r'"mcp_telemetry"', re.IGNORECASE),
    ],
    "function_calling": [
        re.compile(r'"(?:function_call|tool_calls|tool_call_id)"', re.IGNORECASE),
        re.compile(r'"function"\s*:\s*\{', re.IGNORECASE),
        re.compile(r'"name"\s*:\s*".*?".*?"arguments"', re.IGNORECASE | re.DOTALL),
    ],
    "rag": [
        re.compile(r'"(?:retrieved_documents|source_documents|context)"\s*:\s*\[', re.IGNORECASE),
        re.compile(r'"(?:references|citations|chunks)"\s*[:=]', re.IGNORECASE),
        re.compile(r'"(?:similarity_score|relevance_score)"\s*[:=]', re.IGNORECASE),
    ],
    "embedding": [
        re.compile(r'"(?:embedding|vector)"\s*:\s*\[', re.IGNORECASE),
        re.compile(r'"(?:similarity|index|collection)"\s*[:=]', re.IGNORECASE),
    ],
    "workflow": [
        re.compile(r'(?:workflow|pipeline|step[\s_]*\d)', re.IGNORECASE),
        re.compile(r'"(?:phase|step|stage)"\s*[:=]', re.IGNORECASE),
    ],
    "memory": [
        re.compile(r'(?:remember|memory|stored.*?conversation)', re.IGNORECASE),
    ],
    "multi_tenant": [
        re.compile(r'(?:tenant|organization|workspace|org_id)', re.IGNORECASE),
    ],
    "a2a_protocol": [
        re.compile(r'(?:agent.?to.?agent|a2a|agent_card|agent.?skill)', re.IGNORECASE),
    ],
    "multi_agent": [
        re.compile(r'"(?:agents|delegated|coordinator|sub.?agent|team)"\s*[:=]', re.IGNORECASE),
    ],
    "agent": [
        re.compile(r'(?:tool|function|agent|assistant)', re.IGNORECASE),
    ],
    "code_execution": [
        re.compile(r'(?:python|sandbox|code.?execution|exec)', re.IGNORECASE),
    ],
    "web_search": [
        re.compile(r'(?:web.?search|online.?search|search.?results)', re.IGNORECASE),
    ],
    "session_auth": [
        re.compile(r'(?:cookie|bearer|jwt|session.?id|auth)', re.IGNORECASE),
    ],
}

def _detect_capabilities_from_burp(burp_path: str) -> set[str]:
    """imports Burp (0 )

    :  Burp  (Request + Response),

    ,  LLM

    Academic basis: Greshake et al. (arXiv:2302.12173) Sec4 -
      ,
      converter(s) (probe_active_capabilities +
      deep_probe_capabilities)

    Args:
        burp_path: Burp

    Returns:
         ( {"mcp", "function_calling", "session_auth"})
    """
    try:
        parsed = parse_burp_request(burp_path)
    except Exception as e:
        logger.warning("Failed to pre-parse %s for sorting: %s", burp_path, e)
        return set()

 # : Response + path + fingerprint
 # Burp Response SSE ,
    raw_text = ""
    try:
        raw = Path(burp_path).read_text(encoding="utf-8", errors="replace")
        raw_text = raw
    except Exception:
        pass

 # path ()
    path_text = parsed.path.lower()
 # fingerprint
    fp_capabilities = parsed.target_fingerprint.get("capabilities", "")
    fp_text = fp_capabilities.lower()

 #
    match_text = f"{raw_text}\n{path_text}\n{fp_text}"

    detected: set[str] = set()

    for cap_name, patterns in _CAPABILITY_SIGNAL_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(match_text):
                detected.add(cap_name)
                break  # converter(s)converter(s)

 # ()
    if "/mcp" in path_text or "mcp" in path_text:
        detected.add("mcp")
    if "/rag" in path_text or "/knowledge" in path_text or "/retriev" in path_text:
        detected.add("rag")
    if "/agent" in path_text or "/tool" in path_text:
        detected.add("agent")
    if "/workflow" in path_text or "/pipeline" in path_text:
        detected.add("workflow")

 # fingerprint app_type
    app_type = parsed.target_fingerprint.get("app_type", "").lower()
    if "agent" in app_type:
        detected.add("agent")
    if "rag" in app_type:
        detected.add("rag")

    return detected

def _compute_priority_score(capabilities: set[str]) -> int:
    """ endpoint

    Academic basis: Greshake et al. (arXiv:2302.12173) Sec4 + Lattner et al. (arXiv:2406.12609)
      all endpoint ,
       endpoint

    Args:
        capabilities:

    Returns:
         (0-100),
    """
    if not capabilities:
        return _DEFAULT_PRIORITY

    scores = [
        _CAPABILITY_PRIORITY.get(cap, 0)
        for cap in capabilities
    ]
    return max(scores) if scores else _DEFAULT_PRIORITY

def sort_endpoints_by_priority(burp_list: list[str]) -> list[dict[str, Any]]:
    """converter(s) Burp endpoint

    Academic basis:
        - Greshake et al. (arXiv:2302.12173) - converter(s) +
        - Lattner et al. (arXiv:2406.12609) -

    :
        1. converter(s) burp  (0 )
        2. imports Burp  ()
        3. : MCP > function_calling > RAG > workflow > chat
        4.  endpoint  ()

    Args:
        burp_list: Burp

    Returns:
         endpoint , :
            - burp_path:
            - burp_name:  (stem)
            - priority_score:
            - capabilities:
            - original_index:  ()
    """
    endpoint_infos: list[dict[str, Any]] = []

    for idx, burp_path in enumerate(burp_list):
        burp_name = Path(burp_path).stem
        capabilities = _detect_capabilities_from_burp(burp_path)
        priority_score = _compute_priority_score(capabilities)

        endpoint_infos.append({
            "burp_path": burp_path,
            "burp_name": burp_name,
            "priority_score": priority_score,
            "capabilities": capabilities,
            "original_index": idx,
        })

        logger.info(
            "Endpoint priority: %s - score=%d, capabilities=%s",
            burp_name,
            priority_score,
            sorted(capabilities) if capabilities else ["(none)"],
        )

 # : , ()
    endpoint_infos.sort(
        key=lambda e: (-e["priority_score"], e["burp_name"]),
    )

 #
    if len(endpoint_infos) > 1:
        logger.info(
            "Endpoint attack order (priority-sorted): %s",
            " -> ".join(
                f"{e['burp_name']}(p={e['priority_score']})"
                for e in endpoint_infos
            ),
        )

    return endpoint_infos

def sort_burp_list_by_priority(burp_list: list[str]) -> list[str]:
    """ Burp ,

     sort_endpoints_by_priority ,  main.py

    Args:
        burp_list: Burp

    Returns:

    """
    endpoint_infos = sort_endpoints_by_priority(burp_list)
    return [e["burp_path"] for e in endpoint_infos]

# ====================================================================
# Attack Surface Classification (merged from attack_surface_classifier.py)
# ====================================================================


@dataclass
class ClassificationResult:
    """Attack surface classification result."""

    attack_surface: str
    confidence: float  # 0.0 ~ 1.0
    evidence: list[str] = field(default_factory=list)
    sub_type: str | None = None  # high_confidence / medium / low

# MCP Protocol Indicators
_MCP_INDICATORS: dict[str, list[str]] = {
    "path_patterns": [
        r"/mcp/?$", r"/mcp/v\d+", r"/api/mcp", r"/mcp-api",
        r"/sse", r"/api/v1/mcp",
    ],
    "header_indicators": ["mcp-session-id", "mcp-protocol-version", "x-mcp-"],
    "response_fields": ["jsonrpc", "tools", "resources", "prompts"],
}

# RAG System Indicators
_RAG_INDICATORS: dict[str, list[str]] = {
    "path_patterns": [
        r"/search", r"/retrieve", r"/query", r"/documents?",
        r"/knowledge", r"/vector", r"/embeddings?", r"/rag", r"/semantic",
    ],
    "header_indicators": ["x-document-id", "x-retrieval"],
    "response_fields": [
        "documents", "passages", "chunks", "results",
        "retrieved_context", "relevance_score", "vector_match",
    ],
}

# Agent System Indicators
_AGENT_INDICATORS: dict[str, list[str]] = {
    "path_patterns": [
        r"/agent", r"/agents/", r"/workflow", r"/execute", r"/run",
        r"/task", r"/action", r"/invoke", r"/function", r"/call",
    ],
    "header_indicators": ["x-agent-id", "x-session-id", "x-workflow"],
    "response_fields": [
        "tool_calls", "function_call", "action", "result", "status",
        "intermediate_steps", "chain_of_thought", "reasoning",
    ],
}

def classify_http_content(
    http_request: str | None = None,
    http_response: str | None = None,
    url: str | None = None,
) -> ClassificationResult:
    """Classify attack surface from HTTP request/response.

    Args:
        http_request: Raw HTTP request
        http_response: Raw HTTP response
        url: Target URL

    Returns:
        ClassificationResult with attack surface type
    """
    if not any([http_request, http_response, url]):
        return ClassificationResult(
            attack_surface="standard_llm_api",
            confidence=0.0,
            evidence=["No HTTP content provided"],
        )

    if url is None and http_request:
        url = _extract_url_from_http(http_request)

    scores: dict[str, float] = {"mcp_server": 0.0, "rag_system": 0.0, "multi_agent_system": 0.0}
    evidence: dict[str, list[str]] = {"mcp_server": [], "rag_system": [], "multi_agent_system": []}

    # Score URL patterns
    if url:
        for pattern in _MCP_INDICATORS["path_patterns"]:
            if re.search(pattern, url, re.IGNORECASE):
                scores["mcp_server"] += 3.0
                evidence["mcp_server"].append(f"URL: {pattern}")
        for pattern in _RAG_INDICATORS["path_patterns"]:
            if re.search(pattern, url, re.IGNORECASE):
                scores["rag_system"] += 3.0
                evidence["rag_system"].append(f"URL: {pattern}")
        for pattern in _AGENT_INDICATORS["path_patterns"]:
            if re.search(pattern, url, re.IGNORECASE):
                scores["multi_agent_system"] += 3.0
                evidence["multi_agent_system"].append(f"URL: {pattern}")

    # Score headers and body from request
    if http_request:
        req_lower = http_request.lower()
        for header in _MCP_INDICATORS["header_indicators"]:
            if header in req_lower:
                scores["mcp_server"] += 2.0
                evidence["mcp_server"].append(f"Header: {header}")
        for header in _AGENT_INDICATORS["header_indicators"]:
            if header in req_lower:
                scores["multi_agent_system"] += 2.0
                evidence["multi_agent_system"].append(f"Header: {header}")

        # Body scoring
        if "jsonrpc" in req_lower:
            scores["mcp_server"] += 2.5
            evidence["mcp_server"].append("JSON-RPC protocol")
        if "tool_calls" in req_lower or "function_call" in req_lower:
            scores["multi_agent_system"] += 2.0
            evidence["multi_agent_system"].append("Agent tool call pattern")

    # Score response
    if http_response:
        resp_lower = http_response.lower()
        if "jsonrpc" in resp_lower and "tools" in resp_lower:
            scores["mcp_server"] += 4.0
            evidence["mcp_server"].append("MCP JSON-RPC response with tools")
        if any(f in resp_lower for f in _RAG_INDICATORS["response_fields"]):
            count = sum(1 for f in _RAG_INDICATORS["response_fields"] if f in resp_lower)
            scores["rag_system"] += count * 1.5
            evidence["rag_system"].append(f"RAG fields: {count}")
        if any(f in resp_lower for f in _AGENT_INDICATORS["response_fields"]):
            count = sum(1 for f in _AGENT_INDICATORS["response_fields"] if f in resp_lower)
            scores["multi_agent_system"] += count * 1.5
            evidence["multi_agent_system"].append(f"Agent fields: {count}")

    # Return result
    max_score = max(scores.values())
    if max_score == 0:
        return ClassificationResult(
            attack_surface="standard_llm_api",
            confidence=0.5,
            evidence=["No specific indicators detected"],
        )

    max_surface = max(scores, key=scores.get)
    confidence = min(max_score / 10.0, 1.0)
    sub_type = "high_confidence" if max_score >= 8 else ("medium_confidence" if max_score >= 5 else ("low_confidence" if max_score >= 3 else None))

    return ClassificationResult(
        attack_surface=max_surface,
        confidence=confidence,
        evidence=evidence.get(max_surface, []),
        sub_type=sub_type,
    )

def _extract_url_from_http(content: str) -> str | None:
    """Extract URL from HTTP request first line."""
    first_line = content.split("\n", 1)[0].strip()
    parts = first_line.split()
    if len(parts) >= 2:
        return parts[1]
    return None


