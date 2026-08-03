# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""决策全链路追溯 — 跨阶段决策记录与报告生成。.

记录从 URL 输入到报告输出的全部关键决策点,
在 Stage 6 报告中生成"决策追溯附录"。

设计原则 (R-010):
  - PyRIT 原生优先: 使用 PyRIT 原生 memory_labels 标记决策数据
  - 非侵入式: 仅在编排层记录, 不修改 PyRIT 原生组件
  - 结构化: 每条记录包含 layer, decision, reason, data, timestamp

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DecisionRecord:
    """单条决策记录。.

    Attributes:
        stage: 阶段标识 (如 "stage_0.5", "stage_2")。
        layer: 架构层 (如 "L1_SeedSource", "L3_DatasetConfig")。
        decision: 决策名称 (如 "target_classified_as_web_app")。
        reason: 决策理由。
        data: 决策相关数据。
        timestamp: 记录时间。
    """

    stage: str = ""
    layer: str = ""
    decision: str = ""
    reason: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self) -> None:
        """初始化后自动填充时间戳。."""
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        """转换为字典表示。."""
        return {
            "stage": self.stage,
            "layer": self.layer,
            "decision": self.decision,
            "reason": self.reason,
            "data": self.data,
            "timestamp": self.timestamp,
        }


class DecisionTrace:
    """决策全链路追溯器。.

    单例模式, 收集全流水线决策记录,
    在 Stage 6 生成决策追溯附录。

    用法::

        trace = DecisionTrace.get_instance()
        trace.record(stage="stage_0.5", layer="target_detection",
                     decision="classified_as_web_app",
                     reason="HTML + chat UI selectors matched",
                     data={"url": "https://...", "selectors_matched": ["textarea"]})
    """

    _instance: DecisionTrace | None = None

    def __init__(self) -> None:
        """初始化决策追溯器。."""
        self._records: list[DecisionRecord] = []

    @classmethod
    def get_instance(cls) -> DecisionTrace:
        """获取单例实例。."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """重置单例 (测试用)。."""
        cls._instance = None

    def record(
        self,
        stage: str,
        layer: str,
        decision: str,
        reason: str = "",
        **data: Any,
    ) -> None:
        """记录一条决策。."""
        record = DecisionRecord(
            stage=stage,
            layer=layer,
            decision=decision,
            reason=reason,
            data=data,
        )
        self._records.append(record)
        logger.debug(f"DecisionTrace: {stage}/{layer}/{decision}: {reason}")

    def get_records(self) -> list[DecisionRecord]:
        """返回所有决策记录。."""
        return list(self._records)

    def get_records_by_stage(self, stage: str) -> list[DecisionRecord]:
        """按阶段过滤。."""
        return [r for r in self._records if r.stage == stage]

    def get_records_by_layer(self, layer: str) -> list[DecisionRecord]:
        """按层过滤。."""
        return [r for r in self._records if r.layer == layer]

    @property
    def record_count(self) -> int:
        """返回决策记录总数。."""
        return len(self._records)

    def to_markdown(self) -> str:
        """生成决策追溯附录 Markdown。."""
        if not self._records:
            return "\n## 决策追溯附录\n\n(无决策记录)\n"

        parts = ["\n## 决策追溯附录\n"]
        parts.append(f"> 共 {len(self._records)} 条决策记录\n\n")
        parts.append("| # | 阶段 | 层 | 决策 | 理由 | 时间 |\n")
        parts.append("|---|------|-----|------|------|------|\n")
        for i, r in enumerate(self._records, 1):
            reason_short = r.reason[:60] + "..." if len(r.reason) > 60 else r.reason
            parts.append(
                f"| {i} | {r.stage} | {r.layer} | {r.decision} | "
                f"{reason_short} | {r.timestamp[:19]} |\n"
            )

        # 按阶段分组详情
        parts.append("\n### 按阶段详情\n")
        stages: dict[str, list[DecisionRecord]] = {}
        for r in self._records:
            stages.setdefault(r.stage, []).append(r)

        for stage, records in stages.items():
            parts.append(f"\n#### {stage}\n")
            for r in records:
                parts.append(f"- **{r.decision}** ({r.layer}): {r.reason}\n")
                if r.data:
                    for k, v in r.data.items():
                        val_str = str(v)[:100]
                        parts.append(f"  - {k}: `{val_str}`\n")

        return "".join(parts)
