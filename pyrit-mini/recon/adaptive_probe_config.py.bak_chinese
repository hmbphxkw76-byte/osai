"""Adaptive Probe Configuration — 按目标复杂度动态分配探测资源。

学术依据:
    - Greshake et al. (arXiv:2302.12173) §5 — 基于目标能力数量的探测深度调整
    - RLFT (Chiang et al. arXiv:2402.04249) — 自适应红队资源分配
    - Perez et al. (arXiv:2202.03286) — InstructGPT 种子库红队: 按复杂度分桶

自适应策略:
    目标 "复杂度" 由多维因素计算:
    1. 护栏级别 (paranoid=高隐蔽需求 → 少探测)
    2. 已检测到的能力数量 (越多越复杂)
    3. API 响应格式复杂度 (SSE > JSON > text)
    4. 目标应用类型 (multi_agent > agent > chat)

    基础探测预算 = 10
    按复杂度调整:
    - 简单目标 (chat-only): 3-5 探测
    - 中等目标 (agent with tools): 8-12 探测
    - 复杂目标 (multi-agent + MCP + RAG): 15-20 探测

设计原则 (Rule 2: Stealth First):
    自适应不等于暴增探测数。即使在 "aggressive" 模式,
    探测数也不会超过宪法上限 (默认 max_probes=20)。
    复杂目标是逐步加探测, 不是上来就满额探测。
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# 复杂度评分与对应探测预算
# ════════════════════════════════════════════════════════════════════

# 复杂度等级
_COMPLEXITY_LEVELS = ["simple", "moderate", "complex", "very_complex"]

# 每个复杂度等级对应探测参数
COMPLEXITY_PROBE_BUDGETS: dict[str, dict[str, int]] = {
    "simple": {
        "budget": 3,
        "parallel": 1,
        "deep_probe_budget": 0,     # 不运行 deep probe
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

# 应用类型 → 复杂度基础偏移
_APP_TYPE_COMPLEXITY_OFFSET: dict[str, int] = {
    "chat": 0,
    "agent": 2,
    "mcp": 2,
    "multi_agent": 4,
    "rag": 1,
    "api": 0,
}

# 护栏等级 → 探测削减系数 (paranoid 模式需严格控制)
_GUARDRILL_REDUCTION_FACTOR: dict[str, float] = {
    "none": 1.0,
    "permissive": 1.3,
    "moderate": 1.0,
    "strict": 0.3,  # 严格护栏大幅削减探测数
}


# ════════════════════════════════════════════════════════════════════
# 主函数
# ════════════════════════════════════════════════════════════════════


def compute_probe_budget(
    capabilities: dict[str, Any],
    guardrail_severity: str = "none",
    app_type: str = "chat",
    stealth_level: str = "balanced",
) -> dict[str, Any]:
    """根据目标特征动态计算探测预算。

    算法:
        1. 从应用类型获取基础复杂度
        2. 按护栏级别调整
        3. 按 stealth level 调整
        4. 按发现的能力数量调整
        5. 最终 budget = base × capabilities_factor × guardrail_factor × stealth_factor

    示例:
        >>> budget = compute_probe_budget(
        ...     capabilities={"agent": ..., "mcp": ..., "rag": ...},
        ...     guardrail_severity="strict",
        ...     app_type="multi_agent",
        ...     stealth_level="paranoid",
        ... )
        >>> print(budget)
        {"budget": 3, "parallel": 1, "deep_probe_budget": 0, "behavioral_verify_budget": 0, "complexity_level": "moderate"}

    Args:
        capabilities: 已检测到能力字典。
        guardrail_severity: 护栏级别 (none/permissive/moderate/strict)。
        app_type: 应用类型 (chat/agent/mcp/multi_agent/rag/api)。
        stealth_level: 隐蔽等级 (paranoid/balanced/aggressive)。

    Returns:
        探测参数字典:
        {
            "budget": int,                  # 总探测预算
            "parallel": int,                # 并行探测数
            "deep_probe_budget": int,       # deep probe 预算 (8 个维度)
            "behavioral_verify_budget": int, # 行为验证预算
            "complexity_level": str,        # 复杂度等级
            "reasoning": str,               # 决策理由 (用于审计)
        }
    """
    # 1. 基础复杂度 (按应用类型)
    base_complexity = _APP_TYPE_COMPLEXITY_OFFSET.get(app_type, 0)

    # 2. 按发现的能力数量调整
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

    # 3. 取对应等级的预算配置
    if total_complexity <= 2:
        complexity_level = "simple"
    elif total_complexity <= 4:
        complexity_level = "moderate"
    elif total_complexity <= 7:
        complexity_level = "complex"
    else:
        complexity_level = "very_complex"

    budget_config = COMPLEXITY_PROBE_BUDGETS[complexity_level]

    # 4. 应用护栏削减
    guardrail_factor = _GUARDRILL_REDUCTION_FACTOR.get(guardrail_severity, 1.0)

    # 5. 应用 stealth 等级调整
    stealth_factors = {
        "paranoid": 0.3,
        "balanced": 1.0,
        "aggressive": 1.5,
    }
    stealth_factor = stealth_factors.get(stealth_level, 1.0)

    # 6. 最终计算 (四舍五入到整数, 至少 1)
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
    """判断是否应该运行特定类型的探测。

    Args:
        probe_type: 探测类型 ("basic" / "deep" / "behavioral")。
        total_used: 已使用的总探测数。
        budget_config: compute_probe_budget 返回的预算字典。

    Returns:
           是否应该继续探测。
    """
    total_budget = budget_config.get("budget", 5)

    # 基础探测: 在总预算内始终允许
    if probe_type == "basic":
        return total_used < total_budget

    # Deep probe: 有独立预算
    if probe_type == "deep":
        deep_budget = budget_config.get("deep_probe_budget", 0)
        return total_used < deep_budget

    # Behavioral verify: 有独立预算
    if probe_type == "behavioral":
        behavioral_budget = budget_config.get("behavioral_verify_budget", 0)
        return total_used < behavioral_budget

    return False
