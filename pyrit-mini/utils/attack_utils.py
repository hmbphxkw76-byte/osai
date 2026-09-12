# -*- coding: utf-8 -*-
"""utils/attack_utils.py — Attack result processing SSOT (Single Source of Truth).

P2 optimization (2026-09-06):
    Consolidates _is_success from multiple duplicated definitions:
    - utils/display_stages.py
    - strike/executor.py (and strike/_sequential.py)
    - report/evidence_extract.py

P0 enhancement (2026-09-09):
    Also consolidates _is_result_success from:
    - strike/output_filter_bypass.py
    - strike/multimodal_injection.py
    - strike/backdoor_attack.py
    - strike/escalation_runtime.py

This module is the SSOT for determining attack result success.
All attack modules must import from here, not redefine locally.

Academic basis:
    - PyRIT (arXiv:2407.01232): AttackOutcome枚举标准化攻击结果表示

Constitution compliance:
    - R-H3: Prevents dual-track redundancy (single success criteria)
    - C3: SSOT principle for result evaluation
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def is_attack_successful(result: Any) -> bool:
    """Determine if an attack result is successful (SSOT).

    This is the single source of truth for all success criteria.
    Checks (in order):
    1. outcome field (AttackOutcome.SUCCESS / FAILURE)
    2. score_value field (boolean or numeric)
    3. scores list (any scorer returns true)

    Args:
        result: AttackResult or compatible object.

    Returns:
        True if the attack was successful, False otherwise.
    """
    outcome = getattr(result, "outcome", None)
    if outcome:
        outcome_str = str(outcome).lower()
        if "success" in outcome_str:
            return True
        if "failure" in outcome_str or "fail" in outcome_str:
            return False
    score_val = getattr(result, "score_value", None)
    if score_val:
        if isinstance(score_val, str):
            return score_val.lower() in ("true", "1", "success")
        if isinstance(score_val, (int, float)):
            return score_val > 0
    # plan Wave 4.4：`scores` 既可能是 list[Score]（PyRIT 原生）也可能是
    # dict[str, Score]（部分历史模块）。SSOT 必须同时覆盖两种形态，否则各调用点
    # 会各自实现一份 → 又回退成多套口径（R-H3）。
    scores = getattr(result, "scores", None)
    if scores:
        try:
            items = scores.values() if isinstance(scores, dict) else scores
            for s in items:
                sv = getattr(s, "score_value", s) if hasattr(s, "score_value") else s
                if isinstance(sv, (int, float)):
                    if sv > 0:
                        return True
                elif str(sv).lower() in ("true", "1", "success"):
                    return True
        except Exception:
            logger.debug("scores 解析失败，按未成功处理", exc_info=True)
    return False


# Backward compatibility aliases
_is_success = is_attack_successful
_is_result_success = is_attack_successful
