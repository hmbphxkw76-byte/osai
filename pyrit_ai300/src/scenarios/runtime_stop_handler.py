"""
Runtime Stop Strategy Event Handler — L5 执行韧性 Layer 3+5
==========================================================

替代 adaptive_runner 中的预过滤停止策略。

三层最优停止策略:
  L1: FIRST_SUCCESS (PyRIT 原生, 同一 objective 多技术链首成功即停)
  L2: OWASP 分类成功率阈值 (运行时, 本模块实现)
  L3: 全局首成功即停 (运行时, 本模块实现)

设计:
  实现 PyRIT 原生 StrategyEventHandler 接口,
  在 ON_POST_EXECUTE 事件中追踪成功/失败,
  根据阈值动态决定是否停止剩余攻击。

与预过滤的区别:
  - 预过滤: 执行前减少 seed_groups 数量 (可能过早跳过)
  - 运行时: 根据实际成功数动态决策 (更精确)
"""

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict

from pyrit.executor.core.strategy import (
    StrategyEventData,
    StrategyEventHandler,
    StrategyEvent,
)

logger = logging.getLogger(__name__)

# L2 所需成功数上限 (防止大计划数场景下阈值过高)
_MAX_SUCCESS_PER_OWASP = 5


@dataclass
class StopStrategyContext:
    """
    运行时停止策略状态

    跟踪 OWASP 分类的成功/失败计数, 在阈值达到时发出停止信号。
    """
    owasp_success: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    owasp_total: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    global_success: int = 0
    should_stop: bool = False
    stop_reason: str = ""

    def record_success(self, owasp_id: str) -> None:
        """记录一次成功"""
        self.global_success += 1
        self.owasp_success[owasp_id] += 1

    def record_attempt(self, owasp_id: str) -> None:
        """记录一次尝试"""
        self.owasp_total[owasp_id] += 1

    def check_threshold(self, owasp_id: str, threshold: float) -> bool:
        """
        检查 OWASP 分类是否达到阈值

        Returns:
            True 如果达到阈值
        """
        if threshold <= 0:
            return False
        total = self.owasp_total[owasp_id]
        if total == 0:
            return False
        required = min(
            math.ceil(total * threshold),
            _MAX_SUCCESS_PER_OWASP,
        )
        return self.owasp_success[owasp_id] >= required

    def get_stats(self) -> Dict[str, Any]:
        """获取统计摘要"""
        return {
            "owasp_success": dict(self.owasp_success),
            "owasp_total": dict(self.owasp_total),
            "global_success": self.global_success,
            "should_stop": self.should_stop,
            "stop_reason": self.stop_reason,
        }


class RuntimeStopEventHandler(StrategyEventHandler):
    """
    运行时停止策略事件处理器

    L2: OWASP 分类成功率阈值 (运行时)
    L3: 全局首成功即停 (运行时)

    用法:
        handler = RuntimeStopEventHandler(
            owasp_threshold=0.3,
            stop_on_first_success=False,
        )
        attack_executor._register_event_handler(handler)
        # 执行后检查 handler.stop_context.should_stop
    """

    def __init__(
        self,
        *,
        owasp_threshold: float = 0.0,
        stop_on_first_success: bool = False,
    ):
        """
        Args:
            owasp_threshold: L2 OWASP 分类成功率阈值 (0.0=禁用)
            stop_on_first_success: L3 全局首成功即停
        """
        self._owasp_threshold = owasp_threshold
        self._stop_on_first = stop_on_first_success
        self.stop_context = StopStrategyContext()

    async def on_event_async(self, event_data: StrategyEventData) -> None:
        """
        处理 Strategy 生命周期事件

        在 ON_POST_EXECUTE 时追踪成功/失败并检查停止条件。
        """
        if event_data.event != StrategyEvent.ON_POST_EXECUTE:
            return

        result = event_data.result
        if result is None:
            return

        # 提取 OWASP ID (从 memory_labels)
        owasp_id = "UNKNOWN"
        labels = getattr(result, "memory_labels", {}) or {}
        owasp_id = labels.get("owasp_id", "UNKNOWN")

        self.stop_context.record_attempt(owasp_id)

        outcome = getattr(result, "outcome", None)
        outcome_str = str(outcome.value).upper() if hasattr(outcome, "value") else str(outcome).upper()

        if outcome_str == "SUCCESS":
            self.stop_context.record_success(owasp_id)

            # L3: 全局首成功即停
            if self._stop_on_first:
                self.stop_context.should_stop = True
                self.stop_context.stop_reason = "L3: global first success"
                logger.info(
                    f"L3 Stop: global first success triggered "
                    f"(owasp={owasp_id})"
                )
                return

            # L2: OWASP 分类阈值
            if self._owasp_threshold > 0:
                if self.stop_context.check_threshold(owasp_id, self._owasp_threshold):
                    self.stop_context.should_stop = True
                    total = self.stop_context.owasp_total[owasp_id]
                    succ = self.stop_context.owasp_success[owasp_id]
                    self.stop_context.stop_reason = (
                        f"L2: OWASP {owasp_id} threshold reached "
                        f"({succ}/{total} >= {self._owasp_threshold:.0%})"
                    )
                    logger.info(
                        f"L2 Stop: OWASP {owasp_id} threshold reached "
                        f"({succ}/{total} >= {self._owasp_threshold:.0%})"
                    )

    def get_stats(self) -> Dict[str, Any]:
        """获取停止策略统计"""
        return self.stop_context.get_stats()
