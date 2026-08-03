# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""统一事件总线 — 结构化事件流 (JSONL + stdout)。

全阶段事件发布/订阅机制, 每个Stage在关键操作点发布事件:
  - 事件写入 JSONL 文件 (outputs/logs/events_{timestamp}.jsonl)
  - 同时 print 到 stdout (精简格式)
  - 支持程序化分析和可视化

设计原则 (R-010):
  - 非侵入式: 事件发布失败不影响流水线执行
  - PyRIT 原生优先: 不修改 PyRIT 原生代码, 仅在编排层增强
  - 结构化: 每个事件包含 timestamp, stage, event_type, data

> **日期**: 2026-8-3
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# R-012: 确保 UTF-8
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    import contextlib

    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]


@dataclass
class PipelineEvent:
    """流水线结构化事件。

    Attributes:
        timestamp: ISO 格式时间戳。
        stage: 阶段标识 (如 "stage_0.5", "stage_1", "stage_execute")。
        event_type: 事件类型 (如 "target_classified", "auth_completed", "attack_started")。
        data: 事件数据字典。
    """

    timestamp: str = ""
    stage: str = ""
    event_type: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)

    def to_summary(self) -> str:
        """精简单行摘要 (stdout)。"""
        data_str = ", ".join(f"{k}={v}" for k, v in list(self.data.items())[:4])
        return f"  [EVENT] {self.stage}/{self.event_type}: {data_str}"


class EventBus:
    """统一事件总线。

    单例模式, 管理事件写入 JSONL 文件和 stdout。

    用法::

        bus = EventBus.get_instance()
        bus.publish(PipelineEvent(stage="stage_1", event_type="datasets_loaded",
                                   data={"count": 5}))
    """

    _instance: EventBus | None = None

    def __init__(self, jsonl_path: Path | None = None) -> None:
        self._jsonl_path = jsonl_path
        self._events: list[PipelineEvent] = []
        self._enabled = True

    @classmethod
    def get_instance(cls) -> EventBus:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def init(cls, output_dir: Path | None = None) -> EventBus:
        """初始化事件总线, 设置 JSONL 输出路径。"""
        instance = cls.get_instance()
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            instance._jsonl_path = output_dir / f"events_{ts}.jsonl"
        return instance

    def publish(self, event: PipelineEvent) -> None:
        """发布事件到 JSONL + stdout。"""
        if not self._enabled:
            return
        try:
            self._events.append(event)
            # JSONL 写入
            if self._jsonl_path:
                with open(self._jsonl_path, "a", encoding="utf-8") as f:
                    f.write(event.to_json() + "\n")
            # stdout 精简输出
            print(event.to_summary())
        except Exception as e:
            logger.debug(f"EventBus publish failed (non-fatal): {e}")

    def publish_simple(
        self,
        stage: str,
        event_type: str,
        **data: Any,
    ) -> None:
        """快捷发布事件。"""
        self.publish(PipelineEvent(stage=stage, event_type=event_type, data=data))

    def get_events(self) -> list[PipelineEvent]:
        """返回所有已发布事件。"""
        return list(self._events)

    def get_events_by_stage(self, stage: str) -> list[PipelineEvent]:
        """按阶段过滤事件。"""
        return [e for e in self._events if e.stage == stage]

    def disable(self) -> None:
        """禁用事件发布 (测试用)。"""
        self._enabled = False

    def enable(self) -> None:
        """启用事件发布。"""
        self._enabled = True

    @property
    def jsonl_path(self) -> Path | None:
        return self._jsonl_path

    @property
    def event_count(self) -> int:
        return len(self._events)
