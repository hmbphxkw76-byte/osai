"""Adaptive Probe Configuration - Simplified probe budget calculation.

Academic basis:
    - Greshake et al. (arXiv:2302.12173) Sec5 - Adaptive probing
    - RLFT (Chiang et al. arXiv:2402.04249) - Budget-aware exploration

Simplified model (red team focus):
    - Fixed base budgets by complexity level
    - Guardrail-aware reduction (strict = fewer probes)
    - Stealth scaling (paranoid = fewer probes)

    Max budget = 20 (hard ceiling per Rule 2: Stealth First)
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Complexity-based base budgets
_BUDGETS = {
    "simple": {"budget": 3, "parallel": 1, "deep": 0},
    "moderate": {"budget": 8, "parallel": 2, "deep": 3},
    "complex": {"budget": 12, "parallel": 3, "deep": 6},
    "very_complex": {"budget": 15, "parallel": 5, "deep": 8},
}

# App type complexity offsets
_APP_OFFSET = {
    "chat": 0,
    "agent": 2,
    "mcp": 2,
    "multi_agent": 4,
    "rag": 1,
    "api": 0,
}

# Guardrail reduction factors
_GUARDRILL_FACTOR = {
    "none": 1.0,
    "permissive": 1.3,
    "moderate": 1.0,
    "strict": 0.3,
}

# Stealth scaling factors
_STEALTH_FACTOR = {
    "paranoid": 0.3,
    "balanced": 1.0,
    "aggressive": 1.5,
}

# Hard ceiling (Rule 2: Stealth First)
_MAX_BUDGET = 20


def compute_probe_budget(
    capabilities: dict,
    guardrail_severity: str = "none",
    app_type: str = "chat",
    stealth_level: str = "balanced",
) -> dict:
    """Compute adaptive probe budget.

    Args:
        capabilities: Detected capabilities dict
        guardrail_severity: Guardrail severity (none/permissive/moderate/strict)
        app_type: Application type (chat/agent/mcp/multi_agent/rag/api)
        stealth_level: Stealth level (paranoid/balanced/aggressive)

    Returns:
        Dict with budget, parallel, deep, complexity_level, reasoning
    """
    # 1. Base complexity from app type
    base = _APP_OFFSET.get(app_type, 0)

    # 2. Complexity from capability count
    num_caps = len(capabilities)
    if num_caps <= 1:
        cap_add, level = 0, "simple"
    elif num_caps <= 3:
        cap_add, level = 2, "moderate"
    elif num_caps <= 5:
        cap_add, level = 4, "complex"
    else:
        cap_add, level = 6, "very_complex"

    # 3. Determine level
    total = base + cap_add
    if total <= 2:
        level = "simple"
    elif total <= 4:
        level = "moderate"
    elif total <= 7:
        level = "complex"
    else:
        level = "very_complex"

    config = _BUDGETS[level]

    # 4. Apply guardrail and stealth factors
    gf = _GUARDRILL_FACTOR.get(guardrail_severity, 1.0)
    sf = _STEALTH_FACTOR.get(stealth_level, 1.0)

    # 5. Calculate final budget
    budget = max(1, int(config["budget"] * gf * sf))
    parallel = max(1, min(config["parallel"], budget))
    deep = max(0, int(config["deep"] * gf * sf))

    # Hard ceiling
    budget = min(budget, _MAX_BUDGET)
    parallel = min(parallel, _MAX_BUDGET)
    deep = min(deep, _MAX_BUDGET)

    reasoning = (
        f"app={app_type}(+{base}), caps={num_caps}(+{cap_add}), "
        f"level={level}, guardrail={guardrail_severity}(x{gf}), "
        f"stealth={stealth_level}(x{sf})"
    )

    logger.info("Probe budget: total=%d, parallel=%d, deep=%d - %s", budget, parallel, deep, reasoning)

    return {
        "budget": budget,
        "parallel": parallel,
        "deep_probe_budget": deep,
        "complexity_level": level,
        "reasoning": reasoning,
    }
