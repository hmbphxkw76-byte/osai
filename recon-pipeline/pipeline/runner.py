# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""PipelineRunner: 串联解耦阶段的执行引擎。

设计目标:
  - 阶段之间仅通过 PipelineContext 交换数据 (解耦)
  - Runner 不感知具体阶段逻辑, 只按顺序执行 registered stages
  - 任一阶段失败不阻断整条流水线 (StageResult 隔离错误)
  - 支持 from_url() 一键端到端运行 (用户给 URL 即全跑)

用法:
    from pipeline.runner import PipelineRunner
    from pipeline.context_loader import load_context

    ctx = load_context()  # 从 .env + config/ 加载
    runner = PipelineRunner()
    result = await runner.run(ctx)   # 返回 PipelineResult
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from pipeline.models import PipelineContext, StageResult
from pipeline.registry import get_stage

logger = logging.getLogger(__name__)


# 默认阶段执行顺序 (端到端)
DEFAULT_STAGE_ORDER = ["classify", "auth", "recon", "export"]


@dataclass
class PipelineResult:
    """整条流水线执行结果。"""

    context: PipelineContext
    stages: list[StageResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.context.target_url,
            "classification": (
                self.context.classification.to_dict() if self.context.classification else None
            ),
            "auth_decision": (
                self.context.auth_decision.to_dict() if self.context.auth_decision else None
            ),
            "total_duration_seconds": round(self.total_duration_seconds, 3),
            "stages": [s.to_dict() for s in self.stages],
        }

    @property
    def failed_stages(self) -> list[StageResult]:
        return [s for s in self.stages if s.status == "failed"]

    @property
    def report(self) -> Any | None:
        for s in self.stages:
            if s.stage_name == "recon" and s.status == "success":
                return s.artifact
        return None


class PipelineRunner:
    """阶段执行引擎。"""

    def __init__(
        self,
        stage_order: list[str] | None = None,
        stop_on_failure: bool = False,
    ) -> None:
        self._order = stage_order or list(DEFAULT_STAGE_ORDER)
        self._stop_on_failure = stop_on_failure

    async def run(self, context: PipelineContext) -> PipelineResult:
        start = time.monotonic()
        result = PipelineResult(context=context)

        for stage_name in self._order:
            stage_cls = get_stage(stage_name)
            stage = stage_cls()

            # 阶段间契约: 分类/认证产物回写到 context
            if stage.should_skip(context):
                logger.info(f"[runner] skip stage '{stage_name}'")
                result.stages.append(
                    StageResult(stage_name=stage_name, status="skipped")
                )
                continue

            stage_result = await stage.execute(context)

            # 把关键产物写回 context, 供后续阶段消费
            if stage_name == "classify" and stage_result.artifact is not None:
                context.classification = stage_result.artifact
            elif stage_name == "auth" and stage_result.artifact is not None:
                context.auth_decision = stage_result.artifact
            elif stage_name == "recon" and stage_result.artifact is not None:
                # 供 Export 阶段读取
                context.report = stage_result.artifact  # type: ignore[attr-defined]

            result.stages.append(stage_result)

            if stage_result.status == "failed" and self._stop_on_failure:
                logger.error(f"[runner] stage '{stage_name}' failed; stopping pipeline")
                break

        result.total_duration_seconds = time.monotonic() - start
        return result
