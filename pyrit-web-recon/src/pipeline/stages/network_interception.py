# -*- coding: utf-8 -*-
"""
阶段 6：网络拦截

启动 XHR/fetch/WebSocket 拦截，为后续流量分析收集数据。
"""

from __future__ import annotations

import logging

from src.network import HTTPInterceptor

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class NetworkInterceptionStage(PipelineStage):
    """网络拦截阶段"""

    name = "network_interception"
    description = "拦截 LLM API 网络流量"

    async def run(self, context: PipelineContext) -> StageResult:
        if context.target_type == "api":
            return StageResult(
                success=True,
                skipped=True,
                message="API 目标无需浏览器网络拦截",
                data={},
            )

        page = context.page
        if not page:
            return StageResult(success=False, message="页面未初始化")

        spa_config = self._config(context, "spa_config", {})
        interceptor = HTTPInterceptor(page, spa_config)
        await interceptor.start()
        context.interceptor = interceptor

        return StageResult(
            success=True,
            message="网络拦截已启动",
            data={"captured_count": len(interceptor.captured)},
        )
