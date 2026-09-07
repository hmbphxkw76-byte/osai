""" +  — SSOT (Single Source of Truth).

 confidence_scorer.py, i18n_keywords.py, capability_detector.py 
converter(s) recon  ``score_capability`` 
``match_capability_i18n`` , 

Academic basis:
    - Greshake et al. (arXiv:2302.12173) §4 — 
      , 
    - Zheng et al. (arXiv:2306.05685) §4.3 — :
      """" 20-40%
    - Mazeika et al. (arXiv:2402.04249, HarmBench) §3.2 — 
      , 
    - Bayesian Inference —  P(capability | evidence)
      , 
    - PyRIT SequentialAttack (arXiv:2407.01232) §3.3 — 
      , 

:
    HIGH   (>= 0.8):  (JSON schema, tool list, MCP protocol)
    MEDIUM (0.4-0.8): 
    LOW    (< 0.4): 

 (i18n):
    converter(s),
     OR , 
     (case-insensitive),
     ()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ==============================================================
#  — 
# ==============================================================

_CAPABILITY_KEYWORDS_I18N: dict[str, dict[str, list[str]]] = {
    "agent": {
        "en": [
            "i have access to tools",
            "i can use tools",
            "function_call",
            "tool_call",
            "i am an agent",
            "as an ai assistant",
            "i can help you with",
            "my capabilities include",
            "i have access to functions",
            "available tools",
            "i can execute",
        ],
        "zh": [
            "",
            "",
            "",
            "",
            "converter(s)ai",
            "converter(s)",
            "",
            "",
            "",
            "",
            "converter(s)agent",
            "converter(s)",
            "",
            "",
        ],
    },
    "rag": {
        "en": [
            "based on the retrieved",
            "knowledge base",
            "from the documents",
            "according to the context",
            "retrieved information",
            "search results show",
            "from my knowledge",
            "based on available data",
            "reference document",
            "source material",
        ],
        "zh": [
            "",
            "",
            "imports",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "imports",
            "",
            "",
            "",
        ],
    },
    "mcp": {
        "en": [
            "model context protocol",
            "mcp server",
            "mcp tool",
            "protocol server",
            "i'm connected to",
            "connected tools",
            "server-side tools",
        ],
        "zh": [
            "",
            "mcp",
            "mcp",
            "mcp",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "embedding": {
        "en": [
            "embedding",
            "vector search",
            "semantic search",
            "similarity search",
            "vector database",
            "nearest neighbor",
        ],
        "zh": [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "multi_agent": {
        "en": [
            "multiple agents",
            "collaborate with",
            "delegate to",
            "i work with other",
            "team of agents",
            "multi-agent",
            "coordinator",
        ],
        "zh": [
            "converter(s)agent",
            "converter(s)",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "code_execution": {
        "en": [
            "i can execute code",
            "code interpreter",
            "python execution",
            "run code",
            "sandbox",
            "i can write and run",
            "code execution",
        ],
        "zh": [
            "",
            "",
            "python",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "web_search": {
        "en": [
            "i can search",
            "web search",
            "search the web",
            "online search",
            "internet search",
            "browsing",
        ],
        "zh": [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    # ==  ==
    "function_calling": {
        "en": [
            "function",
            "tool",
            "call",
            "schema",
            "parameter",
            "openapi",
            "endpoint",
            "api",
            "method",
        ],
        "zh": [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "memory": {
        "en": [
            "memory",
            "remember",
            "previous",
            "history",
            "session",
            "persistent",
            "stored",
            "context",
        ],
        "zh": [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "workflow": {
        "en": [
            "workflow",
            "pipeline",
            "step",
            "chain",
            "sequence",
            "orchestrat",
            "flow",
            "process",
        ],
        "zh": [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "multi_tenant": {
        "en": [
            "tenant",
            "organization",
            "org",
            "workspace",
            "namespace",
            "account",
            "project",
        ],
        "zh": [
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "session_auth": {
        "en": [
            "session",
            "token",
            "cookie",
            "bearer",
            "jwt",
            "auth",
            "login",
            "user",
        ],
        "zh": [
            "",
            "",
            "cookie",
            "bearer",
            "jwt",
            "",
            "",
            "",
        ],
    },
    "mcp_protocol": {
        "en": [
            "mcp",
            "model context protocol",
            "server",
            "tool",
            "resource",
            "prompt",
        ],
        "zh": [
            "mcp",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "a2a_protocol": {
        "en": [
            "a2a",
            "agent-to-agent",
            "agent card",
            "json-rpc",
            "well-known",
            "inter-agent",
            "orchestrat",
            "delegate",
            "skill",
            "task lifecycle",
            "multi-agent",
        ],
        "zh": [
            "a2a",
            "agent",
            "",
            "agent",
            "",
            "json-rpc",
            "well-known",
            "agent",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    "embedding_rag": {
        "en": [
            "embedding",
            "vector",
            "rag",
            "retrieval",
            "similarity",
            "index",
            "collection",
            "knowledge base",
            "semantic search",
        ],
        "zh": [
            "",
            "",
            "rag",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
}


# ==============================================================
# i18n 
# ==============================================================


def match_capability_i18n(
    response_text: str,
    capability: str,
) -> bool:
    """ — 

    Academic basis:
        - Greshake et al. (arXiv:2302.12173) §4 — 
        - Zheng et al. (arXiv:2306.05685) §4.3 — 
        - , 

    Args:
        response_text: 
        capability:  (agent/rag/mcp/embedding/multi_agent/...)

    Returns:
        True  ()
    """
    keywords = _CAPABILITY_KEYWORDS_I18N.get(capability, {})
    if not keywords:
        return False

    text_lower = response_text.lower()

    #  ()
    for kw in keywords.get("en", []):
        if kw in text_lower:
            return True

    #  (case-insensitive,  "AI" )
    for kw in keywords.get("zh", []):
        if kw in text_lower:
            return True

    return False


def get_i18n_keywords(capability: str) -> dict[str, list[str]]:
    """

    Args:
        capability: 

    Returns:
        {"en": [...], "zh": [...]} 
    """
    return _CAPABILITY_KEYWORDS_I18N.get(capability, {"en": [], "zh": []})


def get_all_capability_names() -> list[str]:
    """all

    Returns:
        
    """
    return list(_CAPABILITY_KEYWORDS_I18N.keys())


# ==============================================================
#  —  HIGH 
# ==============================================================

# JSON  ( [{"type": "function", "function": {...}}])
_TOOL_JSON_PATTERN = re.compile(
    r'\[\s*\{?\s*"?(?:type|name|function|description|parameters)"?\s*:',
    re.IGNORECASE,
)

# MCP JSON-RPC  ( {"jsonrpc": "2.0", "result": {...}})
_MCP_JSONRPC_PATTERN = re.compile(
    r'"jsonrpc"\s*:\s*"2\.0"',
    re.IGNORECASE,
)

# OpenAI function_call  ( "function_call": {"name": "..."}  tool_calls)
_FUNCTION_CALL_PATTERN = re.compile(
    r'"(?:function_call|tool_calls|function|tools)"\s*:',
    re.IGNORECASE,
)

# Agent Card  ( {"capabilities": [...], "skills": [...]})
_AGENT_CARD_PATTERN = re.compile(
    r'"(?:capabilities|skills|endpoints|agent)"\s*:\s*\[',
    re.IGNORECASE,
)

# RAG  ( [1], [src1], (source: xxx))
_RAG_CITATION_PATTERN = re.compile(
    r'\[(?:\d+|src\d*|ref\d*|source|doc)\]',
    re.IGNORECASE,
)

# Embedding/Vector  ( {"vector": [...], "embedding": [...]})
_EMBEDDING_PATTERN = re.compile(
    r'"(?:embedding|vector|similarity|index|collection)"\s*[:=]',
    re.IGNORECASE,
)

# Multi-agent  ( {"agents": [...]}, "delegated to", "coordinator")
_MULTI_AGENT_PATTERN = re.compile(
    r'"(?:agents|delegated|coordinator|sub.?agent|team)"\s*[:=]',
    re.IGNORECASE,
)

#  → 

# MCP tool list / server  (: capability_detector.py  mcp_structural_patterns)
_MCP_STRUCTURAL_PATTERN = re.compile(
    r'"(?:tools|resource_uris|mcp_server|server_name|protocol_version|tool_call_id|tool_result)"'
    r'\s*[:=]\s*(?:\[|"|\{)',
    re.IGNORECASE,
)

# Agent function_call / tool_calls  (: capability_detector.py  agent_structural_patterns)
_AGENT_STRUCTURAL_PATTERN = re.compile(
    r'"(?:function_call|tool_calls|tool_call_id)"|'
    r'"function"\s*:\s*\{|'
    r'"name"\s*:\s*".*?"\s*,\s*"arguments"',
    re.IGNORECASE,
)

# RAG  (: capability_detector.py  rag_structural_patterns)
_RAG_STRUCTURAL_PATTERN = re.compile(
    r'"(?:retrieved_documents|source_documents|references|citations|chunks|similarity_score|relevance_score)"|'
    r'"context"\s*:\s*\[',
    re.IGNORECASE,
)

# Embedding  (: capability_detector.py  embedding_structural_patterns)
_EMBEDDING_STRUCTURAL_PATTERN = re.compile(
    r'"(?:embedding|vector|scores)"\s*:\s*\[|"similarity"\s*:\s*[\d.]',
    re.IGNORECASE,
)

_STRUCTURED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "agent": [_TOOL_JSON_PATTERN, _FUNCTION_CALL_PATTERN, _AGENT_CARD_PATTERN, _AGENT_STRUCTURAL_PATTERN],
    "rag": [_RAG_CITATION_PATTERN, _RAG_STRUCTURAL_PATTERN],
    "mcp": [_MCP_JSONRPC_PATTERN, _MCP_STRUCTURAL_PATTERN],
    "embedding": [_EMBEDDING_PATTERN, _EMBEDDING_STRUCTURAL_PATTERN],
    "multi_agent": [_MULTI_AGENT_PATTERN],
    # 
    "function_calling": [_FUNCTION_CALL_PATTERN, _TOOL_JSON_PATTERN, _AGENT_STRUCTURAL_PATTERN],
    "mcp_protocol": [_MCP_JSONRPC_PATTERN, _MCP_STRUCTURAL_PATTERN],
    "embedding_rag": [_EMBEDDING_PATTERN, _RAG_CITATION_PATTERN, _EMBEDDING_STRUCTURAL_PATTERN, _RAG_STRUCTURAL_PATTERN],
    "a2a_protocol": [_AGENT_CARD_PATTERN],
}

#  —  > 
_SOURCE_WEIGHTS: dict[str, float] = {
    "passive": 1.0,
    "active": 1.5,
    "deep": 2.0,
}

# 
_HIGH_THRESHOLD = 0.8
_MEDIUM_THRESHOLD = 0.4


@dataclass
class CapabilityResult:
    """

    :
        name:  (agent/rag/mcp/embedding/multi_agent/...)
        detected: 
        confidence:  [0.0, 1.0]
        level:  ("high" / "medium" / "low")
        evidence:  ()
        source:  ("passive" / "active" / "deep")
    """

    name: str
    detected: bool = False
    confidence: float = 0.0
    level: str = "low"
    evidence: list[str] = field(default_factory=list)
    source: str = "passive"

    def __post_init__(self) -> None:
        """ level"""
        self.level = _confidence_to_level(self.confidence)


def _confidence_to_level(score: float) -> str:
    """ → """
    if score >= _HIGH_THRESHOLD:
        return "high"
    if score >= _MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def score_capability(
    response_text: str,
    capability: str,
    *,
    source: str = "passive",
) -> CapabilityResult:
    """converter(s)

     (Bayesian ):
        base_score = 0.0
        +  ( OR ): +0.3 per match (max 0.6)
        +  (JSON regex): +0.4 per match (max 0.8)
        + : × source_weight (passive=1.0, active=1.5, deep=2.0)
        = final_score (clamped to [0.0, 1.0])

    :
        score >= 0.8 → "high" ()
        0.4 <= score < 0.8 → "medium" (Confirmation)
        score < 0.4 → "low" (,  "possible")

    Args:
        response_text: 
        capability: 
        source:  (passive/active/deep)

    Returns:
        CapabilityResult 
    """
    evidence: list[str] = []
    score = 0.0

    # == 1.  (i18n) ==
    if match_capability_i18n(response_text, capability):
        score += 0.3
        evidence.append("keyword_match_i18n")

    # , 
    keywords = get_i18n_keywords(capability)
    text_lower = response_text.lower()

    en_matches = sum(1 for kw in keywords.get("en", []) if kw in text_lower)
    zh_matches = sum(1 for kw in keywords.get("zh", []) if kw in response_text)
    total_keyword_matches = en_matches + zh_matches

    #  (max 0.6)
    if total_keyword_matches > 1:
        bonus = min(0.3, 0.1 * (total_keyword_matches - 1))
        score += bonus
        evidence.append(
            f"keyword_matches={total_keyword_matches} (en={en_matches}, zh={zh_matches})"
        )

    # == 2.  ==
    patterns = _STRUCTURED_PATTERNS.get(capability, [])
    for pattern in patterns:
        match = pattern.search(response_text)
        if match:
            score += 0.4
            evidence.append(f"structured_pattern: {pattern.pattern[:50]}")
            break  # 

    # == 3.  ==
    source_weight = _SOURCE_WEIGHTS.get(source, 1.0)
    if source_weight > 1.0:
        score *= source_weight
        evidence.append(f"source_weight={source_weight} ({source})")

    # == 4. Clamp  [0.0, 1.0] ==
    score = max(0.0, min(1.0, score))

    # == 5.  result ==
    # detected  = 0.3 ( "")
    # level : HIGH >= 0.8, MEDIUM >= 0.4, LOW < 0.4
    detected = score >= 0.3

    return CapabilityResult(
        name=capability,
        detected=detected,
        confidence=round(score, 3),
        level=_confidence_to_level(score),
        evidence=evidence,
        source=source,
    )


def aggregate_capabilities(
    results: list[CapabilityResult],
) -> dict[str, CapabilityResult]:
    """ — 

     (passive → active → deep) :
        deep > active > passive
    , 

    Args:
        results: 

    Returns:
        {capability_name: best_result} 
    """
    best: dict[str, CapabilityResult] = {}
    for result in results:
        existing = best.get(result.name)
        if existing is None or result.confidence > existing.confidence:
            best[result.name] = result
        elif result.confidence == existing.confidence:
            # , source 
            if _SOURCE_WEIGHTS.get(result.source, 0) > _SOURCE_WEIGHTS.get(
                existing.source, 0
            ):
                best[result.name] = result
    return best


def filter_by_level(
    capabilities: dict[str, CapabilityResult],
    level: str,
) -> dict[str, CapabilityResult]:
    """

    Args:
        capabilities: 
        level:  ("high" / "medium" / "low")

    Returns:
        
    """
    return {
        name: result
        for name, result in capabilities.items()
        if result.level == level
    }


def get_trigger_recommendations(
    capabilities: dict[str, CapabilityResult],
) -> dict[str, list[str]]:
    """

    :
        HIGH → 
        MEDIUM → Confirmation
        LOW → 

    Returns:
        {
            "immediate": [],   # HIGH , 
            "probe": [],       # MEDIUM , 
            "possible": [],    # LOW ,  "possible"
        }
    """
    recommendations: dict[str, list[str]] = {
        "immediate": [],
        "probe": [],
        "possible": [],
    }
    for name, result in capabilities.items():
        if result.level == "high":
            recommendations["immediate"].append(name)
        elif result.level == "medium":
            recommendations["probe"].append(name)
        else:
            recommendations["possible"].append(name)
    return recommendations


# ==============================================================
# Layer (Multi-Signal Evidence Convergence)
# ==============================================================
# Academic basis:
#   - Chiang et al. (arXiv:2402.04249) — HarmBench: confidently confirmed
#     ,  2 
#   - Abhay et al. (arXiv:2311.04956) — ASR ,  vs 
#      20-30%, Layer
# ——


# 
_MIN_INDEPENDENT_SIGNALS = 2

#  (, )
_EVIDENCE_INDEPENDENCE: dict[str, int] = {
    "keyword_match_i18n": 1,     #  (, )
    "structured_pattern": 2,     #  (, )
    "api_behavior": 3,           # API  (, )
    "behavioral_verification": 4, #  (, )
}


@dataclass
class ConvergenceResult:
    """Layer

    :
        capability: 
        converged:  ( 2 converter(s))
        signal_count: 
        evidence_types: 
        adjusted_confidence: 
        source_level: Layer (S1/S2/S3)
    """
    capability: str
    converged: bool = False
    signal_count: int = 0
    evidence_types: list[str] = field(default_factory=list)
    adjusted_confidence: float = 0.0
    source_level: str = "S1"  # S1=, S2=, S3=


def score_capability_with_convergence(
    capability: str,
    keyword_evidence: bool = False,
    structured_evidence: bool = False,
    api_behavior_evidence: bool = False,
    behavioral_verification_evidence: bool = False,
    text_claim_confidence: float = 0.0,
    behavioral_verify_confidence: float = 0.0,
) -> ConvergenceResult:
    """Layer —  2 converter(s)

     score_capability , Layer,
    Ensureconverter(s)Confirmation ""

    :
        - 1 converter(s): confidence  0.5 (medium, Confirmation)
        - 2 converter(s): confidence  0.8 (high, )
        - 3+ converter(s):  (high, )

    :
        >>> result = score_capability_with_convergence(
        ...     capability="mcp",
        ...     keyword_evidence=True,          # LLM  MCP
        ...     structured_evidence=True,       # JSON-RPC 2.0 
        ...     api_behavior_evidence=True,     # /sse  MCP 
        ...     behavioral_verification_evidence=True,  # tools/list 
        ... )
        >>> assert result.converged  # 4 converter(s) → 

    Args:
        capability: 
        keyword_evidence:  ()
        structured_evidence: 
        api_behavior_evidence:  API 
        behavioral_verification_evidence: 
        text_claim_confidence: Layer (0.0-1.0)
        behavioral_verify_confidence: Layer (0.0-1.0)

    Returns:
        ConvergenceResult 
    """
    result = ConvergenceResult(capability=capability)

    # 
    signals: list[tuple[str, bool, float]] = [
        ("keyword_match_i18n", keyword_evidence, text_claim_confidence * 0.3),
        ("structured_pattern", structured_evidence, 0.5 if structured_evidence else 0.0),
        ("api_behavior", api_behavior_evidence, 0.7 if api_behavior_evidence else 0.0),
        ("behavioral_verification", behavioral_verification_evidence,
         behavioral_verify_confidence if behavioral_verification_evidence else 0.0),
    ]

    active_signals = [(sig_type, conf) for sig_type, active, conf in signals if active]
    result.signal_count = len(active_signals)
    result.evidence_types = [sig_type for sig_type, _ in active_signals]

    if not active_signals:
        result.adjusted_confidence = 0.0
        result.source_level = "S1"
        return result

    # , 
    sorted_signals = sorted(
        active_signals,
        key=lambda x: _EVIDENCE_INDEPENDENCE.get(x[0], 0),
        reverse=True,
    )

    #  confidence
    weighted_sum = 0.0
    weight_total = 0.0
    for sig_type, conf in sorted_signals[:3]:
        weight = _EVIDENCE_INDEPENDENCE.get(sig_type, 1)
        weighted_sum += conf * weight
        weight_total += weight

    base_confidence = weighted_sum / max(1.0, weight_total)

    # 
    if result.signal_count >= _MIN_INDEPENDENT_SIGNALS:
        #  → 
        convergence_bonus = min(0.2, 0.1 * (result.signal_count - 1))
        result.converged = True
        result.adjusted_confidence = min(1.0, base_confidence + convergence_bonus)

        # Layer
        if any(s in result.evidence_types for s in ("behavioral_verification", "api_behavior")):
            result.source_level = "S3"
        elif "structured_pattern" in result.evidence_types:
            result.source_level = "S2"
        else:
            result.source_level = "S1+"
    else:
        #  → 
        result.converged = False
        result.adjusted_confidence = min(0.5, base_confidence)
        result.source_level = "S1"

    return result


def merge_verification_into_capabilities(
    capabilities: dict[str, CapabilityResult],
    behavioral_report: dict[str, Any],
) -> dict[str, CapabilityResult]:
    """

     behavioral_verifier  confidence_scorer :
        -  → confidence  >= HIGH
        -  → confidence  ( false_positive)

    Args:
        capabilities: 
        behavioral_report: behavioral_verifier (to_dict() )

    Returns:
        
    """
    results = dict(capabilities)

    behavioral_results = behavioral_report.get("results", {})

    for cap_name, verify_data in behavioral_results.items():
        behaviorally_verified = verify_data.get("behaviorally_verified", False)
        verify_confidence = verify_data.get("confidence", 0.0)

        existing = results.get(cap_name)

        if behaviorally_verified:
            #  →  HIGH
            updated_confidence = max(
                existing.confidence if existing else 0.0,
                verify_confidence,  #  0.9
            )
            updated_evidence = (existing.evidence if existing else []) + [
                f"behavioral_verification=PASSED (confidence={verify_confidence})"
            ]

            results[cap_name] = CapabilityResult(
                name=cap_name,
                detected=True,
                confidence=round(updated_confidence, 3),
                evidence=updated_evidence,
                source="behavioral",
            )
        else:
            #  → 
            updated_confidence = min(
                existing.confidence if existing else 0.5,
                0.2,  # 
            )
            updated_evidence = (existing.evidence if existing else []) + [
                f"behavioral_verification=FAILED (claimed_text but no behavioral evidence)"
            ]

            results[cap_name] = CapabilityResult(
                name=cap_name,
                detected=updated_confidence >= 0.3,
                confidence=round(updated_confidence, 3),
                level="low",
                evidence=updated_evidence,
                source=existing.source if existing else "passive",
            )

    return results
