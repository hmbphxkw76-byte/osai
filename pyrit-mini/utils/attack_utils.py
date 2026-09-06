# -*- coding: utf-8 -*-
"""攻击工具函数 — SSOT 统一封装.

P2 优化 (2026-09-06):
    消除 _is_success 函数在以下位置的重复定义:
    - utils/display_stages.py
    - strike/executor.py (已拆分为 strike/_sequential.py)
    - strike/escalation_chain.py (Rule 11 特殊版本, 保持独立)
    - report/evidence_extract.py (简单版本, 保持独立)

设计决策:
    - 本模块作为攻击判断的 SSOT (Single Source of Truth)
    - 复杂变体 (Rule 11集成, evidence_extract) 保留本地实现
    - 延迟导入避免循环依赖
"""
from __future__ import annotations

from typing import Any


def _is_success(result: Any) -> bool:
    """判断攻击结果是否成功 (用于进度统计和摘要).

    SSOT 实现, 覆盖标准判断路径:
    1. outcome 属性 (AttackOutcome.SUCCESS / FAILURE)
    2. score_value 属性 (单值评分)
    3. scores 属性 (多值评分列表)

    Args:
        result: AttackResult 或兼容对象.

    Returns:
        True 表示攻击成功, False 表示失败/未知.
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
