# -*- coding: utf-8 -*-
"""
Pipeline Base
=============

所有 Pipeline 阶段的抽象基类。
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from src.utils import truncate_stage_error

from .context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class PipelineStage(ABC):
    """Pipeline 阶段基类"""

    name: str = ""
    description: str = ""

    async def execute(self, context: PipelineContext) -> StageResult:
        """执行阶段并包装结果"""
        start = time.time()
        try:
            result = await self.run(context)
        except Exception as exc:
            logger.exception("Stage %s failed", self.name)
            result = StageResult(
                stage_name=self.name,
                success=False,
                message=f"异常: {truncate_stage_error(str(exc), context.config)}",
            )
        result.stage_name = self.name
        result.duration_ms = int((time.time() - start) * 1000)
        return result

    @abstractmethod
    async def run(self, context: PipelineContext) -> StageResult:
        """子类实现的具体逻辑"""
        raise NotImplementedError

    def _config(self, context: PipelineContext, key: str, default: Any = None) -> Any:
        """从上下文配置中取值"""
        return context.config.get(key, default)

    def _spa_config(self, context: PipelineContext, key: str, default: Any = None) -> Any:
        """从 spa 配置中取值"""
        spa = context.config.get("spa_config", {})
        return spa.get(key, default)
