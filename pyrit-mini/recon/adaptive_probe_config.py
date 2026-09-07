"""Adaptive Probe Configuration — 

Academic basis:
    - Greshake et al. (arXiv:2302.12173) §5 — 
    - RLFT (Chiang et al. arXiv:2402.04249) — 
    - Perez et al. (arXiv:2202.03286) — InstructGPT : 

:
     "" :
    1.  (paranoid= → )
    2.  ()
    3. API  (SSE > JSON > text)
    4.  (multi_agent > agent > chat)

     = 10
    :
    -  (chat-only): 3-5 
    -  (agent with tools): 8-12 
    -  (multi-agent + MCP + RAG): 15-20 

 (Rule 2: Stealth First):
    Even if "aggressive" ,
     ( max_probes=20)
    , 
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# 
# ====================================================================

# 
_COMPLEXITY_LEVELS = ["simple", "moderate", "complex", "very_complex"]

# 
COMPLEXITY_PROBE_BUDGETS: dict[str, dict[str, int]] = {
    "simple": {
        "budget": 3,
        "parallel": 1,
        "deep_probe_budget": 0,     #  deep probe
        "behavioral_verify_budget": 0,
    },
    "moderate": {
        "budget": 8,
        "parallel": 2,
        "deep_probe_budget": 3,
        "behavioral_verify_budget": 1,
    },
    "complex": {
        "budget": 12,
        "parallel": 3,
        "deep_probe_budget": 6,
        "behavioral_verify_budget": 3,
    },
    "very_complex": {
        "budget": 15,
        "parallel": 5,
        "deep_probe_budget": 8,
        "behavioral_verify_budget": 4,
    },
}

#  → 
_APP_TYPE_COMPLEXITY_OFFSET: dict[str, int] = {
    "chat": 0,
    "agent": 2,
    "mcp": 2,
    "multi_agent": 4,
    "rag": 1,
    "api": 0,
}

#  →  (paranoid )
_GUARDRILL_REDUCTION_FACTOR: dict[str, float] = {
    "none": 1.0,
    "permissive": 1.3,
    "moderate": 1.0,
    "strict": 0.3,  # 
}


# ====================================================================
# 
# ====================================================================


def compute_probe_budget(
    capabilities: dict[str, Any],
    guardrail_severity: str = "none",
    app_type: str = "chat",
    stealth_level: str = "balanced",
) -> dict[str, Any]:
    """

    :
        1. imports
        2. 
        3.  stealth level 
        4. 
        5.  budget = base × capabilities_factor × guardrail_factor × stealth_factor

    :
        >>> budget = compute_probe_budget(
        ...     capabilities={"agent": ..., "mcp": ..., "rag": ...},
        ...     guardrail_severity="strict",
        ...     app_type="multi_agent",
        ...     stealth_level="paranoid",
        ... )
        >>> print(budget)
        {"budget": 3, "parallel": 1, "deep_probe_budget": 0, "behavioral_verify_budget": 0, "complexity_level": "moderate"}

    Args:
        capabilities: 
        guardrail_severity:  (none/permissive/moderate/strict)
        app_type:  (chat/agent/mcp/multi_agent/rag/api)
        stealth_level:  (paranoid/balanced/aggressive)

    Returns:
        :
        {
            "budget": int,                  # 
            "parallel": int,                # 
            "deep_probe_budget": int,       # deep probe  (8 converter(s))
            "behavioral_verify_budget": int, # 
            "complexity_level": str,        # 
            "reasoning": str,               #  ()
        }
    """
    # 1.  ()
    base_complexity = _APP_TYPE_COMPLEXITY_OFFSET.get(app_type, 0)

    # 2. 
    num_capabilities = len(capabilities)
    if num_capabilities <= 1:
        cap_complexity = 0
        complexity_level = "simple"
    elif num_capabilities <= 3:
        cap_complexity = 2
        complexity_level = "moderate"
    elif num_capabilities <= 5:
        cap_complexity = 4
        complexity_level = "complex"
    else:
        cap_complexity = 6
        complexity_level = "very_complex"

    total_complexity = base_complexity + cap_complexity

    # 3. 
    if total_complexity <= 2:
        complexity_level = "simple"
    elif total_complexity <= 4:
        complexity_level = "moderate"
    elif total_complexity <= 7:
        complexity_level = "complex"
    else:
        complexity_level = "very_complex"

    budget_config = COMPLEXITY_PROBE_BUDGETS[complexity_level]

    # 4. 
    guardrail_factor = _GUARDRILL_REDUCTION_FACTOR.get(guardrail_severity, 1.0)

    # 5.  stealth 
    stealth_factors = {
        "paranoid": 0.3,
        "balanced": 1.0,
        "aggressive": 1.5,
    }
    stealth_factor = stealth_factors.get(stealth_level, 1.0)

    # 6.  (,  1)
    budget = max(1, int(budget_config["budget"] * guardrail_factor * stealth_factor))
    parallel = max(1, min(budget_config["parallel"], budget))
    deep_probe = max(0, int(budget_config["deep_probe_budget"] * guardrail_factor * stealth_factor))
    behavioral_verify = max(0, int(budget_config["behavioral_verify_budget"] * guardrail_factor * stealth_factor))

    reasoning_parts = [
        f"app_type={app_type} (+{base_complexity})",
        f"num_capabilities={num_capabilities} (+{cap_complexity})",
        f"complexity_level={complexity_level}",
        f"guardrail={guardrail_severity} (×{guardrail_factor})",
        f"stealth={stealth_level} (×{stealth_factor})",
    ]

    logger.info(
        "Adaptive probe budget: total=%d, parallel=%d, deep=%d, behavioral=%d — %s",
        budget,
        parallel,
        deep_probe,
        behavioral_verify,
        ", ".join(reasoning_parts),
    )

    return {
        "budget": budget,
        "parallel": parallel,
        "deep_probe_budget": deep_probe,
        "behavioral_verify_budget": behavioral_verify,
        "complexity_level": complexity_level,
        "reasoning": "; ".join(reasoning_parts),
    }


def should_run_probe(
    probe_type: str,
    total_used: int,
    budget_config: dict[str, Any],
) -> bool:
    """

    Args:
        probe_type:  ("basic" / "deep" / "behavioral")
        total_used: 
        budget_config: compute_probe_budget 

    Returns:
           
    """
    total_budget = budget_config.get("budget", 5)

    # : 
    if probe_type == "basic":
        return total_used < total_budget

    # Deep probe: 
    if probe_type == "deep":
        deep_budget = budget_config.get("deep_probe_budget", 0)
        return total_used < deep_budget

    # Behavioral verify: 
    if probe_type == "behavioral":
        behavioral_budget = budget_config.get("behavioral_verify_budget", 0)
        return total_used < behavioral_budget

    return False
