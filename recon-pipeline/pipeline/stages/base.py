# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段抽象基类。

每个阶段独立、可组合、可跳过, 通过 PipelineContext 交换数据。
阶段只关心"输入 context 字段"和"输出 artifact", 不直接依赖其他阶段实现。
"""

from __future__ import annotations

import abc
import asyncio
import logging
import time
from typing import Any

from pipeline.models import StageResult

logger = logging.getLogger(__name__)


class PipelineStage(abc.ABC):
    """流水线阶段抽象基类。

    子类必须实现:
      - name: 阶段唯一名 (用于 StageResult 与注册表)
      - run(self, context) -> Any: 返回阶段产物 (写入 StageResult.artifact)
    """

    #: 阶段唯一标识
    name: str = "base"

    @abc.abstractmethod
    async def run(self, context: Any) -> Any:
        """执行阶段逻辑, 返回产物对象 (任意类型, 应支持 to_dict)。"""
        raise NotImplementedError

    async def execute(self, context: Any) -> StageResult:
        """统一包装: 计时 + 异常捕获, 返回标准 StageResult。"""
        start = time.monotonic()
        try:
            artifact = await self.run(context)
            duration = time.monotonic() - start
            logger.info(f"[{self.name}] completed in {duration:.2f}s")
            return StageResult(
                stage_name=self.name,
                status="success",
                duration_seconds=duration,
                artifact=artifact,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 - 阶段隔离, 不向上抛
            duration = time.monotonic() - start
            logger.exception(f"[{self.name}] failed: {e}")
            return StageResult(
                stage_name=self.name,
                status="failed",
                duration_seconds=duration,
                error=str(e),
            )

    def should_skip(self, context: Any) -> bool:
        """子类可重写: 返回 True 时阶段被跳过 (status=skipped)。"""
        return False
