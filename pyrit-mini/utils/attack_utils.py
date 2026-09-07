# -*- coding: utf-8 -*-
""" — SSOT .

P2  (2026-09-06):
     _is_success :
    - utils/display_stages.py
    - strike/executor.py ( strike/_sequential.py)
    - strike/escalation_chain.py (Rule 11 , )
    - report/evidence_extract.py (, )

:
    -  SSOT (Single Source of Truth)
    -  (Rule 11, evidence_extract) 
    - from
"""
from __future__ import annotations

from typing import Any


def _is_success(result: Any) -> bool:
    """ ().

    SSOT , :
    1. outcome  (AttackOutcome.SUCCESS / FAILURE)
    2. score_value  ()
    3. scores  ()

    Args:
        result: AttackResult .

    Returns:
        True , False /.
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
    scores = getattr(result, "scores", None)
    if scores:
        try:
            for s in scores:
                sv = getattr(s, "score_value", "")
                if str(sv).lower() in ("true", "1", "success"):
                    return True
        except Exception:
            pass
    return False
