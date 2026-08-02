# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ReconPipeline: 侦察探针编排器。

按配置顺序运行探针, 累积结果到 ReconSession.report。
支持条件跳过 (如非 Web 目标跳过 DOMProbe)。

用法::

    from core import ReconSession
    from core.pipeline import ReconPipeline
    from core.auth import APIKeyAuthProvider
    from core.probes.llm_probe import LLMProbe
    from core.probes.mcp_probe import MCPProbe

    session = ReconSession(target_url="http://example.com")
    await session.authenticate(APIKeyAuthProvider(key="sk-xxx"))

    pipeline = ReconPipeline(probes=[LLMProbe(), MCPProbe()])
    await pipeline.run(session)

    session.export(PyRITExporter(), pipeline_ctx)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class ReconPipeline:
    """侦察探针编排器。

    按顺序运行探针, 自动跳过条件不满足的探针。
    """

    def __init__(self, probes: list[ReconProbe] | None = None) -> None:
        """Initialize ReconPipeline.

        Args:
            probes: 探针列表 (按顺序执行)。
        """
        self._probes: list[ReconProbe] = probes or []

    def add_probe(self, probe: ReconProbe) -> None:
        """添加探针到末尾。"""
        self._probes.append(probe)

    async def run(self, session: ReconSession) -> None:
        """按顺序运行所有探针。

        前置条件检查:
          - requires_auth: session 必须已认证
          - requires_browser: session 必须有 browser_page

        不满足条件的探针会被跳过 (不报错)。
        """
        start_time = time.time()
        total = len(self._probes)
        executed = 0
        skipped = 0

        for i, probe in enumerate(self._probes, 1):
            # 前置检查
            if probe.requires_auth and not session.is_authenticated:
                logger.info(f"[{i}/{total}] Skipping {probe.name} (not authenticated)")
                skipped += 1
                continue

            if probe.requires_browser and session.browser_page is None:
                logger.info(f"[{i}/{total}] Skipping {probe.name} (no browser)")
                skipped += 1
                continue

            # 执行探针
            try:
                await session.run_probe(probe)
                executed += 1
            except Exception as e:
                logger.error(f"[{i}/{total}] Probe {probe.name} failed: {e}")
                skipped += 1

        duration = round(time.time() - start_time, 2)
        session.report.recon_duration_seconds = duration

        logger.info(
            f"ReconPipeline completed: {executed} executed, {skipped} skipped, "
            f"{duration}s total"
        )
