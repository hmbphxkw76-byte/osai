"""
Scenario Event Handler
======================

PyRIT 1.0.0 StrategyEventHandler 实现 — 为 ScenarioOrchestrator 提供事件可观测性。

L5 职责分工（与原生 _DefaultAttackStrategyEventHandler 互补，不重叠）:
  原生 handler 负责:
    - Memory 持久化 (ON_POST_EXECUTE → add_attack_result_to_memory)
    - 基础日志 (start/completed/error)
  本 handler 负责 (原生不提供):
    - 结构化事件记录 (EventRecord 列表，可编程查询)
    - 精确耗时统计 (pre→post 阶段 elapsed)
    - 汇总统计 (successes/failures/errors 计数)
    - 错误回调机制 (on_error callback)
    - 全生命周期事件 (validate/setup/execute/teardown)

  两者可同时注册: 原生 handler 处理持久化，本 handler 处理可观测性。
  本 handler 是只读观察者，不修改 Strategy 执行行为。

对齐 pyrit.executor.core.strategy.StrategyEventHandler 接口：
  on_event_async(event_data: StrategyEventData) → None

事件类型（StrategyEvent）：
  - ON_PRE_VALIDATE / ON_POST_VALIDATE
  - ON_PRE_SETUP / ON_POST_SETUP
  - ON_PRE_EXECUTE / ON_POST_EXECUTE
  - ON_PRE_TEARDOWN / ON_POST_TEARDOWN
  - ON_ERROR

设计目的：
1. 记录攻击生命周期事件到日志（structured logging）
2. 收集执行耗时统计（per-attack timing）
3. 错误事件告警（ON_ERROR → logger.error + 可选 callback）
4. 不修改攻击行为（只读 observer，不干预 Strategy 执行流程）
5. 不重复原生 handler 的持久化工作（无 Memory 写入）

用法：
    handler = ScenarioEventHandler()
    attack = create_attack_instance(...)
    attack._register_event_handler(handler)
    # 执行后 handler.events 包含所有事件记录
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from pyrit.executor.core.strategy import (
    StrategyEventData,
    StrategyEventHandler,
    StrategyEvent,
)

logger = logging.getLogger(__name__)


# ============================================================
# 事件记录
# ============================================================


@dataclass
class EventRecord:
    """单条事件记录"""

    event: str
    strategy_name: str
    strategy_id: str
    timestamp: float
    error: Optional[str] = None
    result_outcome: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# Scenario Event Handler
# ============================================================


class ScenarioEventHandler(StrategyEventHandler):
    """
    Scenario 级事件处理器 — 实现原生 StrategyEventHandler 接口

    L5 职责分工：与原生 _DefaultAttackStrategyEventHandler 互补，不重叠。
    原生 handler 负责 Memory 持久化和基础日志；
    本 handler 负责结构化可观测性（耗时、汇总、回调）。

    特性：
    1. 非侵入式：只读观察者，不修改 Strategy 执行行为
    2. 结构化日志：每个生命周期事件记录到 logging + 内存列表
    3. 耗时统计：自动计算 pre→post 阶段耗时
    4. 错误捕获：ON_ERROR 事件触发可选 callback
    5. 线程安全：events 列表追加操作在 asyncio 单线程模型下安全
    6. 无持久化：不写入 Memory（由原生 handler 负责）

    注册方式（PyRIT 原生 API）：
        handler = ScenarioEventHandler()
        attack._register_event_handler(handler)

    事件流程（每个 Attack 实例的生命周期）：
        ON_PRE_VALIDATE → ON_POST_VALIDATE
        → ON_PRE_SETUP → ON_POST_SETUP
        → ON_PRE_EXECUTE → ON_POST_EXECUTE
        → ON_PRE_TEARDOWN → ON_POST_TEARDOWN
        (ON_ERROR 在任意阶段异常时触发)
    """

    def __init__(
        self,
        *,
        on_error: Optional[Callable[[Exception, str], None]] = None,
        verbose: bool = False,
    ):
        """
        初始化事件处理器

        Args:
            on_error: 错误回调函数 (exception, strategy_name) -> None
            verbose: 是否输出详细日志（默认仅 WARNING+）
        """
        self._on_error = on_error
        self._verbose = verbose
        self._timings: Dict[str, Dict[str, float]] = {}  # strategy_id → {phase: timestamp}
        self.events: List[EventRecord] = []

    async def on_event_async(
        self, event_data: StrategyEventData
    ) -> None:
        """
        处理 Strategy 生命周期事件

        Args:
            event_data: PyRIT 原生事件数据
        """
        event = event_data.event
        sid = event_data.strategy_id
        sname = event_data.strategy_name
        ts = time.time()

        # 记录时间戳用于耗时计算
        if sid not in self._timings:
            self._timings[sid] = {}
        self._timings[sid][event.value] = ts

        # 构建事件记录
        record = EventRecord(
            event=event.value,
            strategy_name=sname,
            strategy_id=sid,
            timestamp=ts,
        )

        # 提取结果信息
        if event_data.result is not None:
            outcome = getattr(event_data.result, "outcome", None)
            if outcome is not None:
                record.result_outcome = str(outcome.value) if hasattr(outcome, "value") else str(outcome)

        # 错误处理
        if event == StrategyEvent.ON_ERROR and event_data.error is not None:
            record.error = str(event_data.error)
            logger.error(
                f"[EventHandler] Strategy '{sname}' (id={sid[:8]}) ERROR: {event_data.error}"
            )
            if self._on_error:
                try:
                    self._on_error(event_data.error, sname)
                except Exception as cb_err:
                    logger.warning(f"Error callback failed: {cb_err}")
        elif event == StrategyEvent.ON_PRE_EXECUTE:
            if self._verbose:
                logger.info(f"[EventHandler] Strategy '{sname}' (id={sid[:8]}) starting execution")
        elif event == StrategyEvent.ON_POST_EXECUTE:
            # 计算执行耗时
            pre_ts = self._timings.get(sid, {}).get(StrategyEvent.ON_PRE_EXECUTE.value)
            elapsed = ts - pre_ts if pre_ts else 0.0
            record.metadata["execution_time_s"] = round(elapsed, 2)
            outcome_str = record.result_outcome or "unknown"
            logger.info(
                f"[EventHandler] Strategy '{sname}' (id={sid[:8]}) "
                f"completed: outcome={outcome_str}, elapsed={elapsed:.1f}s"
            )
        elif event == StrategyEvent.ON_PRE_VALIDATE:
            if self._verbose:
                logger.debug(f"[EventHandler] Strategy '{sname}' (id={sid[:8]}) validating")

        self.events.append(record)

    # ------------------------------------------------------------------
    # 查询接口
    # ------------------------------------------------------------------

    def get_events_for_strategy(self, strategy_id: str) -> List[EventRecord]:
        """获取指定 Strategy 的所有事件"""
        return [e for e in self.events if e.strategy_id == strategy_id]

    def get_errors(self) -> List[EventRecord]:
        """获取所有错误事件"""
        return [e for e in self.events if e.error is not None]

    def get_execution_time(self, strategy_id: str) -> Optional[float]:
        """获取指定 Strategy 的执行耗时（秒）"""
        timings = self._timings.get(strategy_id, {})
        pre = timings.get(StrategyEvent.ON_PRE_EXECUTE.value)
        post = timings.get(StrategyEvent.ON_POST_EXECUTE.value)
        if pre and post:
            return round(post - pre, 2)
        return None

    def get_summary(self) -> Dict[str, Any]:
        """获取事件统计摘要"""
        total = len(self.events)
        errors = len(self.get_errors())
        post_exec = [e for e in self.events if e.event == StrategyEvent.ON_POST_EXECUTE.value]
        successes = sum(1 for e in post_exec if e.result_outcome == "success")
        failures = sum(1 for e in post_exec if e.result_outcome and e.result_outcome != "success")

        return {
            "total_events": total,
            "total_errors": errors,
            "executions": len(post_exec),
            "successes": successes,
            "failures": failures,
            "unknown_outcomes": len(post_exec) - successes - failures,
        }
