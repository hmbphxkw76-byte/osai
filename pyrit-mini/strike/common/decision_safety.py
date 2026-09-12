# -*- coding: utf-8 -*-
# arXiv:2407.01232 - PyRIT, Authentication & Authorization Framework
"""decision_safety.py — R-DECIDE-1 Safety Boundary Protection for Decision Engine.

Implements safety boundary checks for the autonomous decision system.
Ensures that all strategy decisions stay within authorized target boundaries.

Academic basis:
    - PyRIT (arXiv:2407.01232): Authentication and authorization framework
    - NIST AI RMF (AI 600-1): AI Risk Management Framework — govern/map/measure/manage
    - OWASP LLM Top 10 (2025): LLM01 Prompt Injection / LLM02 Insecure Output Handling

Constitution compliance:
    - R-DECIDE-1 (BLOCKING): Decisions must not bypass authorized safety boundaries
    - R-S1: Authorized target set must be respected

Data Flow:
    Decision output → check_authorized_target() → ALLOW / BLOCK
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def check_decision_safety_boundary(
    ctx: Any,
    decision_output: dict[str, Any],
) -> tuple[bool, str]:
    """Check if a decision output stays within authorized safety boundaries.

    R-DECIDE-1 compliance: Verifies that:
    1. Target is within authorized scope (ctx.authorized_targets)
    2. Attack type is permitted (not on denylist)
    3. Decision does not bypass critical safety limits

    Args:
        ctx: PipelineContext with authorized_targets and safety config.
        decision_output: Dict from decision function (e.g., determine_bypass_strategy).

    Returns:
        Tuple of (is_safe: bool, reason: str).
        is_safe=True if decision passes all boundary checks.
    """
    # Check 1: Verify target is authorized
    # plan Wave 2.9：PipelineContext 已把 authorized_targets 提升为一等字段，
    # 此处不再恒为 None。范围匹配统一委托 core.context.is_host_authorized（C3：
    # 精确匹配 + 子域匹配只准有一份实现）。
    authorized_targets = getattr(ctx, "authorized_targets", None)
    if authorized_targets:
        from core.context import is_host_authorized, normalize_authorized_targets

        target = decision_output.get("target", "")
        if target and not is_host_authorized(target, normalize_authorized_targets(authorized_targets)):
            return False, f"Target '{target}' not in authorized targets list"

    # Check 2: Verify attack type is permitted
    attack_type = decision_output.get("strategy", "") or decision_output.get("carrier", "")
    forbidden_types = getattr(ctx, "forbidden_attack_types", None)
    if forbidden_types and attack_type in forbidden_types:
        return False, f"Attack type '{attack_type}' is forbidden by policy"

    # Check 3: Verify safety limits (max concurrent attacks)
    max_concurrent = getattr(ctx, "max_concurrent_attacks", None)
    if max_concurrent is not None:
        current_concurrent = getattr(ctx, "current_concurrent_attacks", 0)
        if current_concurrent >= max_concurrent:
            return False, f"Max concurrent attacks ({max_concurrent}) reached"

    # Check 4: Verify budget limits
    budget_limit = getattr(ctx, "safety_budget_limit", None)
    budget_consumed = getattr(ctx, "budget_consumed", {})
    if budget_limit is not None and isinstance(budget_consumed, dict):
        total_consumed = sum(budget_consumed.values()) if budget_consumed else 0
        if total_consumed >= budget_limit:
            return False, f"Safety budget limit ({budget_limit}) exceeded"

    return True, "Decision passes all safety boundary checks"


def validate_decision_payload(
    ctx: Any,
    strategy_name: str,
    objective: str,
) -> tuple[bool, str]:
    """Validate a decision payload before execution.

    Pre-execution safety check for individual attack objectives.
    Ensures that the attack prompt does not contain forbidden operations.

    Args:
        ctx: PipelineContext with safety config.
        strategy_name: Name of the selected strategy.
        objective: The attack objective/prompt.

    Returns:
        Tuple of (is_valid: bool, reason: str).
    """
    # Check for forbidden operations (from config)
    forbidden_ops = getattr(ctx, "forbidden_operations", None)
    if forbidden_ops:
        objective_lower = objective.lower()
        for op in forbidden_ops:
            if op.lower() in objective_lower:
                return False, f"Objective contains forbidden operation: {op}"

    # Check objective length (prevent abuse)
    max_objective_len = getattr(ctx, "max_objective_length", 10000)
    if len(objective) > max_objective_len:
        return False, f"Objective exceeds max length ({len(objective)} > {max_objective_len})"

    return True, "Payload validated"


def get_decision_safety_report(ctx: Any) -> dict[str, Any]:
    """Generate a safety report for all decisions made in current session.

    Args:
        ctx: PipelineContext with decision_log populated.

    Returns:
        Dict with safety statistics and any violations.
    """
    decision_log = getattr(ctx, "decision_log", []) or []
    violations = [d for d in decision_log if not d.get("safety_check_passed", True)]
    authorized_targets = getattr(ctx, "authorized_targets", None)

    return {
        "total_decisions": len(decision_log),
        "violations": len(violations),
        "authorized_targets": authorized_targets,
        "violation_details": violations[:10],  # Limit to 10 for brevity
    }
