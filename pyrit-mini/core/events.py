"""core/events.py - EventLog: append-only 事件总线（REQ-148）。

目标架构 v4.0（蓝图第十三章）六个一等公民之一：终端 / 报告 / 证据 / 回放 / 续跑的
**唯一派生源**。阶段层只写事件，禁止读取其他阶段的内部结构（不变量 I12 / NEG-3）。

设计原则:
    1. append-only：事件只追加、不修改、不删除（回放与审计的前提）
    2. 旁路安全：enabled=False 时所有写入为 no-op（`--no-events`），保证 W0 零行为回归
    3. 崩溃不丢：每条事件即时落盘 + flush（长任务中断是常态）
    4. 零依赖：仅标准库（NEG-4）

Data flow:
    各阶段 emit() -> ctx.event_log -> outputs/<run>/events.jsonl
    -> utils/display.py（终端渲染）
    -> report/generator.py（报告派生）
    -> strike/playbook/state.py（断点续跑，REQ-155）

Usage:
    from core.events import EventLog, get_event_log

    log = EventLog.attach(ctx, output_dir=ctx.output_dir, enabled=True)
    log.emit("recon", "probe", {"url": "..."}, refs={"endpoint": 0})

Academic basis:
    - arXiv:2407.01232 - PyRIT framework foundation
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 六阶段（与 1.1 阶段词汇映射一致；escalate 归 strike 内部的追加标记）
PHASES: tuple[str, ...] = ("recon", "arm", "strike", "escalate", "assess", "report")

# 事件类型（W0 最小集，后续波次可扩展；新增需登记，禁止随意增字）
EVENT_TYPES: tuple[str, ...] = (
    "phase_start",  # 阶段开始
    "phase_end",  # 阶段结束
    "probe",  # 侦察探测
    "detect",  # 组件/能力识别
    "seed_selected",  # 种子选定
    "attack_sent",  # 攻击请求发出
    "response",  # 目标响应
    "verdict",  # 评分判定
    "impact",  # 影响链判定（W3）
    "evidence",  # 证据落盘
    "cleanup",  # 副作用清理（W2）
    "degradation",  # 降级事件
    "display",  # 终端展示事件（W0-8，utils/display.py 旁路埋点）
    "error",  # 异常
)


@dataclass(frozen=True)
class Event:
    """单条事件（不可变，保证 append-only 语义）。"""

    ts: float
    run_id: str
    phase: str
    etype: str
    payload: dict[str, Any] = field(default_factory=dict)
    refs: dict[str, Any] = field(default_factory=dict)
    node_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """序列化为可 JSON 化的字典。"""
        return asdict(self)

    def to_json(self) -> str:
        """序列化为单行 JSON（JSONL 落盘用）。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


class EventLog:
    """append-only 事件总线。

    Args:
        path: JSONL 落盘路径；None 表示只存内存（测试/禁用场景）。
        run_id: 运行标识（用于跨文件关联与断点续跑）。
        enabled: False 时全部写入为 no-op（`--no-events` 旁路）。
    """

    def __init__(self, path: Path | None = None, run_id: str | None = None, enabled: bool = True) -> None:
        self.path = path
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.enabled = enabled
        self._events: list[Event] = []
        self._fh = None
        if self.enabled and self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._fh = open(self.path, "a", encoding="utf-8")
            except OSError as e:  # 落盘失败不阻断攻击主链路
                logger.warning("[EventLog] 落盘失败，降级为内存模式: %s", e)
                self._fh = None

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    @classmethod
    def attach(
        cls,
        ctx: Any,
        output_dir: Path | None = None,
        enabled: bool = True,
        run_id: str | None = None,
    ) -> "EventLog":
        """在 INIT 阶段挂载到 ctx.event_log（唯一写入点）。"""
        out = Path(output_dir) if output_dir is not None else Path(getattr(ctx, "output_dir", "outputs"))
        log = cls(path=out / "events.jsonl", run_id=run_id, enabled=enabled)
        try:
            ctx.event_log = log
        except Exception:  # ctx 不可写时降级为独立实例（不阻断）
            logger.debug("[EventLog] ctx.event_log 挂载失败，使用独立实例")
        return log

    def close(self) -> None:
        """关闭文件句柄（幂等）。"""
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except OSError:
                pass
            finally:
                self._fh = None

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def emit(
        self,
        phase: str,
        etype: str,
        payload: dict[str, Any] | None = None,
        refs: dict[str, Any] | None = None,
        node_id: str | None = None,
    ) -> Event | None:
        """写入一条事件；禁用时返回 None（调用方无需判空以外的处理）。"""
        if not self.enabled:
            return None
        evt = Event(
            ts=time.time(),
            run_id=self.run_id,
            phase=phase,
            etype=etype,
            payload=payload or {},
            refs=refs or {},
            node_id=node_id,
        )
        self._events.append(evt)
        if self._fh is not None:
            try:
                self._fh.write(evt.to_json() + "\n")
                self._fh.flush()  # 崩溃不丢证据
            except (OSError, TypeError) as e:
                logger.debug("[EventLog] 事件落盘失败（非致命）: %s", e)
        return evt

    # ------------------------------------------------------------------
    # 读取（终端/报告/回放/续跑消费）
    # ------------------------------------------------------------------
    def all(self) -> list[Event]:
        """返回内存中的全部事件。"""
        return list(self._events)

    def filter(
        self,
        phase: str | None = None,
        etype: str | None = None,
        node_id: str | None = None,
    ) -> list[Event]:
        """按维度过滤事件（报告与回放按此派生）。"""
        out = self._events
        if phase is not None:
            out = [e for e in out if e.phase == phase]
        if etype is not None:
            out = [e for e in out if e.etype == etype]
        if node_id is not None:
            out = [e for e in out if e.node_id == node_id]
        return list(out)

    @property
    def count(self) -> int:
        """已写入事件数。"""
        return len(self._events)

    def __len__(self) -> int:
        return len(self._events)


def get_event_log(ctx: Any) -> EventLog:
    """从 ctx 安全获取 EventLog；未挂载时返回**禁用实例**（保证任意调用点安全）。

    这是 W0 旁路埋点的关键：所有埋点调用点无需判空，未初始化即 no-op。
    """
    log = getattr(ctx, "event_log", None)
    if isinstance(log, EventLog):
        return log
    return EventLog(enabled=False)


def emit_event(
    ctx: Any,
    phase: str,
    etype: str,
    payload: dict[str, Any] | None = None,
    refs: dict[str, Any] | None = None,
    node_id: str | None = None,
) -> Event | None:
    """便捷埋点：ctx 未挂载 EventLog 时自动 no-op。"""
    return get_event_log(ctx).emit(phase, etype, payload, refs, node_id)
