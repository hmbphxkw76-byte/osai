# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ReconPipeline: 侦察探针编排器。

按配置顺序运行探针, 累积结果到 ReconSession.report。
支持条件跳过 (如非 Web 目标跳过 DOMProbe)。

用法::

    from core import ReconSession, ReconPipeline
    from core.auth import APIKeyAuthProvider
    from core.probes import LLMProbe, MCPProbe

    session = ReconSession(target_url="http://example.com")
    await session.authenticate(APIKeyAuthProvider(key="sk-xxx"))

    pipeline = ReconPipeline(probes=[LLMProbe(), MCPProbe()])
    result = await pipeline.run(session)

    session.export(PyRITExporter(), pipeline_ctx)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# 默认每个探针的超时时间 (秒)
_DEFAULT_PROBE_TIMEOUT = 60


@dataclass
class PipelineResult:
    """Pipeline 执行结果统计。.

    Attributes:
        total: 探针总数。
        executed: 成功执行的探针数。
        skipped: 因前置条件不满足而跳过的探针数。
        failed: 执行失败的探针数。
        duration_seconds: 总耗时 (秒)。
        errors: 失败探针的错误信息列表。
    """

    total: int = 0
    executed: int = 0
    skipped: int = 0
    failed: int = 0
    duration_seconds: float = 0.0
    errors: list[tuple[str, str]] = field(default_factory=list)


class ReconPipeline:
    """侦察探针编排器。

    按顺序运行探针, 自动跳过条件不满足的探针。
    支持每探针超时保护。
    """

    def __init__(
        self,
        probes: list[ReconProbe] | None = None,
        *,
        probe_timeout: float = _DEFAULT_PROBE_TIMEOUT,
    ) -> None:
        """Initialize ReconPipeline.

        Args:
            probes: 探针列表 (按顺序执行)。
            probe_timeout: 每个探针的超时时间 (秒), 默认 60。
        """
        self._probes: list[ReconProbe] = probes or []
        self._probe_timeout = probe_timeout

    def add_probe(self, probe: ReconProbe) -> None:
        """添加探针到末尾。"""
        self._probes.append(probe)

    @property
    def probes(self) -> list[ReconProbe]:
        """探针列表 (只读)。"""
        return list(self._probes)

    async def run(self, session: ReconSession, *, raise_on_error: bool = False) -> PipelineResult:
        """按顺序运行所有探针。

        前置条件检查:
          - requires_auth: session 必须已认证
          - requires_browser: session 必须有 browser_page

        不满足条件的探针会被跳过 (不报错)。
        执行失败的探针会被记录为 failed (区别于 skipped)。

        Returns:
            PipelineResult 执行统计。
        """
        start_time = time.time()
        total = len(self._probes)
        executed = 0
        skipped = 0
        failed = 0
        errors: list[tuple[str, str]] = []

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

            # 执行探针 (带超时保护)
            try:
                await asyncio.wait_for(
                    session.run_probe(probe),
                    timeout=self._probe_timeout,
                )
                executed += 1
                logger.info(f"[{i}/{total}] {probe.name} completed")
            except asyncio.TimeoutError:
                logger.error(
                    f"[{i}/{total}] Probe {probe.name} timed out ({self._probe_timeout}s)"
                )
                failed += 1
                errors.append((probe.name, f"Timeout after {self._probe_timeout}s"))
                if raise_on_error:
                    raise TimeoutError(f"Probe {probe.name} timed out")
            except Exception as e:
                logger.error(f"[{i}/{total}] Probe {probe.name} failed: {e}")
                failed += 1
                errors.append((probe.name, str(e)))
                if raise_on_error:
                    raise

        duration = round(time.time() - start_time, 2)
        session.report.recon_duration_seconds = duration

        logger.info(
            f"ReconPipeline completed: {executed} executed, {skipped} skipped, "
            f"{failed} failed, {duration}s total"
        )

        return PipelineResult(
            total=total,
            executed=executed,
            skipped=skipped,
            failed=failed,
            duration_seconds=duration,
            errors=errors,
        )
