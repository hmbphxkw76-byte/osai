# -*- coding: utf-8 -*-
"""
AI-300 Framework - Adaptive Early Stopping (P1-6)
基于 ASR、收敛性和预算的自适应早停机制

核心功能：
1. 基于 ASR 置信度调整早停阈值（高 ASR 载荷失败 3 次即停，低 ASR 载荷失败 8 次才停）
2. 基于剩余预算调整激进度（预算充足时多尝试，预算紧张时更激进早停）
3. 基于攻击类型成本调整（多轮攻击成本高，更激进早停）
4. 滑动窗口成功率收敛检测

设计原则：
- 替换原有的固定 max_consecutive_failures=5
- 不影响已有攻击执行逻辑
- 可通过环境变量禁用（AI300_DISABLE_ADAPTIVE_EARLY_STOP=1）

使用方式：
    stopper = AdaptiveEarlyStopper(
        total_payloads=len(plan),
        avg_asr=0.4,
        attack_cost=AttackCost.SINGLE_TURN,
    )
    if stopper.should_stop(consecutive_failures, executed_count, recent_results):
        trigger_early_stop()
"""

from __future__ import annotations

import logging
import os
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AttackCost(Enum):
    """攻击成本级别"""
    SINGLE_TURN = 1      # 单轮攻击（成本低）
    MULTI_TURN = 5        # 多轮攻击（成本中等）
    TREE_SEARCH = 10     # 树搜索攻击（成本高）
    SEQUENTIAL = 8       # 顺序攻击（成本中高）


@dataclass
class EarlyStopDecision:
    """早停决策结果"""
    should_stop: bool
    reason: str
    adaptive_threshold: int
    remaining_budget: int
    convergence_score: float = 0.0


class AdaptiveEarlyStopper:
    """
    自适应早停器 (P1-6)

    基于多维度信号动态调整早停阈值：
    1. ASR 置信度：高 ASR 载荷失败更少次就停（因为预期成功但没成功 = 目标对这类攻击有防护）
    2. 剩余预算：预算充足时更宽容，预算紧张时更激进
    3. 攻击成本：高成本攻击更激进早停
    4. 收敛检测：如果最近 N 个载荷成功率已收敛（无变化），提前终止
    """

    # 基础阈值范围
    MIN_THRESHOLD = 2
    MAX_THRESHOLD = 10
    DEFAULT_THRESHOLD = 5

    # 收敛检测窗口大小
    CONVERGENCE_WINDOW = 10
    CONVERGENCE_TOLERANCE = 0.05  # 成功率变化 < 5% 视为收敛

    def __init__(
        self,
        total_payloads: int,
        avg_asr: float = 0.3,
        attack_cost: AttackCost = AttackCost.SINGLE_TURN,
        aggression_level: str = "medium",
    ):
        self.total_payloads = total_payloads
        self.avg_asr = avg_asr
        self.attack_cost = attack_cost
        self.aggression_level = aggression_level
        self._recent_results: deque = deque(maxlen=self.CONVERGENCE_WINDOW)
        self._consecutive_failures = 0
        self._executed_count = 0
        self._success_count = 0

        # 环境变量禁用检查
        self._disabled = os.environ.get("AI300_DISABLE_ADAPTIVE_EARLY_STOP", "").lower() in ("1", "true", "yes")

    def should_stop(
        self,
        consecutive_failures: int,
        executed_count: int,
        recent_result: Optional[Dict[str, Any]] = None,
    ) -> EarlyStopDecision:
        """
        检查是否应该触发早停

        Args:
            consecutive_failures: 当前连续失败次数
            executed_count: 已执行载荷数
            recent_result: 最近一次攻击结果

        Returns:
            EarlyStopDecision 决策结果
        """
        self._consecutive_failures = consecutive_failures
        self._executed_count = executed_count

        if recent_result:
            self._recent_results.append(recent_result)
            if recent_result.get("status") == "success":
                self._success_count += 1

        if self._disabled:
            # 禁用时使用固定阈值
            return EarlyStopDecision(
                should_stop=consecutive_failures >= self.DEFAULT_THRESHOLD,
                reason="Fixed threshold (adaptive disabled)",
                adaptive_threshold=self.DEFAULT_THRESHOLD,
                remaining_budget=self.total_payloads - executed_count,
            )

        # 计算自适应阈值
        threshold = self._compute_adaptive_threshold()

        # 检查收敛
        convergence_score = self._compute_convergence_score()
        is_converged = convergence_score < self.CONVERGENCE_TOLERANCE and len(self._recent_results) >= self.CONVERGENCE_WINDOW

        # 决策
        should_stop = consecutive_failures >= threshold
        reason = f"Consecutive failures {consecutive_failures} >= threshold {threshold}"

        if is_converged and executed_count > self.CONVERGENCE_WINDOW:
            # 即使未达到失败阈值，如果成功率已收敛且足够低，也提前终止
            recent_success_rate = self._compute_recent_success_rate()
            if recent_success_rate < 0.1:
                should_stop = True
                reason = f"Success rate converged at {recent_success_rate:.0%}, below 10% threshold"

        return EarlyStopDecision(
            should_stop=should_stop,
            reason=reason,
            adaptive_threshold=threshold,
            remaining_budget=self.total_payloads - executed_count,
            convergence_score=convergence_score,
        )

    def _compute_adaptive_threshold(self) -> int:
        """计算自适应早停阈值"""
        threshold = self.DEFAULT_THRESHOLD

        # 因素 1: ASR 置信度
        if self.avg_asr >= 0.5:
            # 高 ASR 载荷：失败较少次就停（目标对此类攻击有防护）
            threshold -= 2
        elif self.avg_asr >= 0.3:
            threshold -= 1
        elif self.avg_asr < 0.1:
            # 低 ASR 载荷：容忍更多失败
            threshold += 2

        # 因素 2: 剩余预算
        remaining = self.total_payloads - self._executed_count
        remaining_ratio = remaining / max(self.total_payloads, 1)
        if remaining_ratio < 0.2:
            # 预算紧张：更激进早停
            threshold -= 1
        elif remaining_ratio > 0.7:
            # 预算充足：更宽容
            threshold += 1

        # 因素 3: 攻击成本
        if self.attack_cost == AttackCost.TREE_SEARCH:
            threshold -= 2  # 高成本攻击更激进早停
        elif self.attack_cost == AttackCost.MULTI_TURN:
            threshold -= 1
        elif self.attack_cost == AttackCost.SEQUENTIAL:
            threshold -= 1

        # 因素 4: 激进度
        if self.aggression_level == "high":
            threshold += 2  # 高激进度容忍更多失败
        elif self.aggression_level == "low":
            threshold -= 1

        return max(self.MIN_THRESHOLD, min(self.MAX_THRESHOLD, threshold))

    def _compute_convergence_score(self) -> float:
        """计算成功率收敛分数（基于滑动窗口方差）"""
        if len(self._recent_results) < self.CONVERGENCE_WINDOW:
            return 1.0  # 数据不足，不收敛

        # 计算前半段和后半段的成功率差异
        half = len(self._recent_results) // 2
        first_half = list(self._recent_results)[:half]
        second_half = list(self._recent_results)[half:]

        first_rate = sum(1 for r in first_half if r.get("status") == "success") / max(len(first_half), 1)
        second_rate = sum(1 for r in second_half if r.get("status") == "success") / max(len(second_half), 1)

        return abs(first_rate - second_rate)

    def _compute_recent_success_rate(self) -> float:
        """计算最近成功率"""
        if not self._recent_results:
            return 0.0
        successes = sum(1 for r in self._recent_results if r.get("status") == "success")
        return successes / len(self._recent_results)
