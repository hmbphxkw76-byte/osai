# -*- coding: utf-8 -*-
"""pair_tap_strategies.py — PAIR & TAP as Independent Attack Strategies.

Implements Prompt Automatic Iterative Refinement (PAIR) and
Tree of Attacks with Pruning (TAP) as standalone strategy options.

Academic basis:
    - Chao et al. (arXiv:2310.08419) PAIR — Black-box jailbreaking via iterative refinement
    - Mehrad et al. (arXiv:2405.17350) TAP — Tree of Attacks with Pruning
    - PyRIT (arXiv:2407.01232): PAIRAttack / TAPAttack native classes

Constitution compliance:
    - R-NATIVE-1: Uses PyRIT native PAIRAttack/TAPAttack
    - R-DECIDE-1: Subject to safety boundary checks

Data Flow:
    Low ASR → select PAIR/TAP → execute iterative attack → re-score
"""

from __future__ import annotations

import logging
from typing import Any

from strike.strategies import pair_params, tap_params
from utils.attack_utils import is_attack_successful

logger = logging.getLogger(__name__)


def determine_pair_tap_strategy(
    ctx: Any,
    current_asr: float,
) -> str | None:
    """Determine if PAIR or TAP should be used based on current ASR.

    Decision logic:
    - ASR < 0.10: Use PAIR (iterative refinement for low-success scenarios)
    - ASR 0.10-0.30: Use TAP (tree-based exploration for moderate scenarios)
    - ASR > 0.30: Not needed (primary strategies sufficient)

    Args:
        ctx: PipelineContext with configuration.
        current_asr: Current attack success rate.

    Returns:
        Strategy name ("pair", "tap") or None if not applicable.
    """
    # Check if PAIR/TAP are enabled
    enable_pair = getattr(ctx, "enable_pair", True)
    enable_tap = getattr(ctx, "enable_tap", True)

    if not enable_pair and not enable_tap:
        return None

    # Decision thresholds
    if current_asr < 0.10 and enable_pair:
        return "pair"
    elif current_asr < 0.30 and enable_tap:
        return "tap"

    return None


async def execute_pair_attack(
    ctx: Any,
    target: Any,
    objective: str,
    max_iterations: int | None = None,
) -> dict[str, Any]:
    """Execute PAIR (Prompt Automatic Iterative Refinement) attack.

    PAIR uses an attacker LLM to iteratively refine jailbreak prompts
    based on target responses.

    Args:
        ctx: PipelineContext.
        target: PyRIT target object.
        objective: Attack objective.
        max_iterations: 迭代精化深度（映射到 PyRIT `tree_depth`）。为 None 时从
            config/defaults.yaml:pair_tree_depth 读取（plan Wave 4.3，
            消除此前 5 / 10 双口径硬编码）。

    Returns:
        Dict with attack results and metadata.
    """
    # plan Wave 4.3：未显式指定时统一取 SSOT，消除 5/10 双口径。
    # P0 修复（2026-09-12）：PyRIT 1.0.1 PAIRAttack 无 `max_iterations` 形参，
    # 其迭代深度即 `tree_depth`；且 `attack_adversarial_config` 为必填。
    if max_iterations is None:
        max_iterations = int(pair_params(getattr(ctx, "args", None))["tree_depth"])
    logger.info("[PAIR] Starting PAIR attack (tree_depth=%d)", max_iterations)

    try:
        from pyrit.executor.attack.multi_turn import PAIRAttack

        from strike.strategies.adversarial import build_native_attack_kwargs

        _kwargs = build_native_attack_kwargs(
            ctx, PAIRAttack, {**pair_params(getattr(ctx, "args", None)), "tree_depth": max_iterations}
        )
        if _kwargs is None:
            logger.warning("[PAIR] PAIRAttack 不可构造：缺少 adversarial_target（I5）")
            return {
                "strategy": "pair",
                "success": False,
                "error": "PAIRAttack unavailable: missing adversarial_target",
            }
        attack = PAIRAttack(
            objective_target=target,
            **_kwargs,
        )

        result = await attack.execute_async(objective=objective)

        success = is_attack_successful(result)
        logger.info("[PAIR] Complete: success=%s", success)

        return {
            "strategy": "pair",
            "success": success,
            "iterations": max_iterations,
            "result": result,
        }

    except ImportError:
        logger.warning("[PAIR] PAIRAttack not available in PyRIT")
        return {
            "strategy": "pair",
            "success": False,
            "error": "PAIRAttack not available",
        }
    except Exception as e:
        logger.error("[PAIR] Execution failed: %s", e)
        return {
            "strategy": "pair",
            "success": False,
            "error": str(e),
        }


async def execute_tap_attack(
    ctx: Any,
    target: Any,
    objective: str,
    width: int | None = None,
    depth: int | None = None,
) -> dict[str, Any]:
    """Execute TAP (Tree of Attacks with Pruning) attack.

    TAP builds a tree of attack prompts, pruning branches that show
    low success probability.

    Args:
        ctx: PipelineContext.
        target: PyRIT target object.
        objective: Attack objective.
        width: Tree width (number of branches per level). 为 None 时从
            config/defaults.yaml:tap_tree_width 读取（plan Wave 4.3）。
        depth: Tree depth (number of levels). 为 None 时从
            config/defaults.yaml:tap_tree_depth 读取（plan Wave 4.3）。

    Returns:
        Dict with attack results and metadata.
    """
    # plan Wave 4.3：未显式指定时统一取 SSOT，消除 3/3/5 与 3/2/3 多口径硬编码
    # P0 修复（2026-09-12）：PyRIT 1.0.1 形参名为 tree_width / tree_depth，
    # 且 `attack_adversarial_config` 为必填；旧调用用 width/depth + attack_strategy
    # 属 0.x API，构造必抛异常 → 被 except 吞掉后静默失败。
    _defaults = tap_params(getattr(ctx, "args", None))
    if width is None:
        width = int(_defaults["tree_width"])
    if depth is None:
        depth = int(_defaults["tree_depth"])
    logger.info("[TAP] Starting TAP attack (tree_width=%d, tree_depth=%d)", width, depth)

    try:
        from pyrit.executor.attack.multi_turn import TAPAttack

        from strike.strategies.adversarial import build_native_attack_kwargs

        _kwargs = build_native_attack_kwargs(
            ctx, TAPAttack, {**_defaults, "tree_width": width, "tree_depth": depth}
        )
        if _kwargs is None:
            logger.warning("[TAP] TAPAttack 不可构造：缺少 adversarial_target（I5）")
            return {
                "strategy": "tap",
                "success": False,
                "error": "TAPAttack unavailable: missing adversarial_target",
            }
        attack = TAPAttack(
            objective_target=target,
            **_kwargs,
        )

        result = await attack.execute_async(objective=objective)

        success = is_attack_successful(result)
        logger.info("[TAP] Complete: success=%s", success)

        return {
            "strategy": "tap",
            "success": success,
            "width": width,
            "depth": depth,
            "result": result,
        }

    except ImportError:
        logger.warning("[TAP] TAPAttack not available in PyRIT")
        return {
            "strategy": "tap",
            "success": False,
            "error": "TAPAttack not available",
        }
    except Exception as e:
        logger.error("[TAP] Execution failed: %s", e)
        return {
            "strategy": "tap",
            "success": False,
            "error": str(e),
        }


def get_pair_tap_recommendation(
    ctx: Any,
    current_asr: float,
    technique_history: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Get PAIR/TAP strategy recommendation with rationale.

    Args:
        ctx: PipelineContext.
        current_asr: Current attack success rate.
        technique_history: Dict mapping technique name to ASR.

    Returns:
        Dict with recommendation and rationale.
    """
    strategy = determine_pair_tap_strategy(ctx, current_asr)

    if strategy is None:
        return {
            "recommended": False,
            "reason": f"Current ASR ({current_asr:.1%}) above PAIR/TAP threshold",
        }

    # plan Wave 4.3：建议参数同样取 SSOT，避免「建议 10 次、实际 5 次」的自相矛盾
    _args = getattr(ctx, "args", None)
    if strategy == "pair":
        return {
            "recommended": True,
            "strategy": "pair",
            "reason": f"Low ASR ({current_asr:.1%}) — PAIR iterative refinement recommended",
            "expected_improvement": "15-30% ASR boost via iterative prompt optimization",
            "parameters": dict(pair_params(_args)),
        }
    else:  # tap
        return {
            "recommended": True,
            "strategy": "tap",
            "reason": f"Moderate ASR ({current_asr:.1%}) — TAP tree exploration recommended",
            "expected_improvement": "10-20% ASR boost via tree-based exploration",
            "parameters": dict(tap_params(_args)),
        }
