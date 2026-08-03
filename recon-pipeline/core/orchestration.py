# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Lightweight orchestration wrapper for recon-pipeline.

This module gives the project a recon_orchestrator-like control layer that:
1. runs probes in a defined order,
2. collects staged results,
3. attaches export hooks,
4. provides a simple execution summary.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from core.pipeline import ReconPipeline
from core.session import ReconSession
from core.exporters.base import ReconExporter
from core.probes.attack_recommender import AttackRecommender
from core.probes.base import ReconProbe
from core.task_runtime import GuardrailPolicy, ReconTask, TaskRuntime

logger = logging.getLogger(__name__)


@dataclass
class OrchestrationResult:
    session: ReconSession
    pipeline_result: Any
    export_targets: list[Any] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    audit_log: list[dict[str, Any]] = field(default_factory=list)


class ReconOrchestrator:
    """Small orchestrator that coordinates probes and export steps."""

    def __init__(
        self,
        probes: list[ReconProbe] | None = None,
        *,
        probe_timeout: float = 60.0,
        runtime: TaskRuntime | None = None,
        guardrail_policy: GuardrailPolicy | None = None,
    ) -> None:
        self.pipeline = ReconPipeline(probes=probes or [], probe_timeout=probe_timeout)
        self.recommender = AttackRecommender()
        self.runtime = runtime or TaskRuntime(guardrail_policy=guardrail_policy)
        self.guardrail_policy = self.runtime.guardrail_policy

    def add_probe(self, probe: ReconProbe) -> None:
        self.pipeline.add_probe(probe)

    async def run(self, session: ReconSession, exporters: list[ReconExporter] | None = None) -> OrchestrationResult:
        if not self.guardrail_policy.is_allowed(session.target_url):
            raise PermissionError(f"Target is blocked by guardrails: {session.target_url}")

        # Organizational boundary check
        from urllib.parse import urlparse
        parsed = urlparse(session.target_url)
        if not self.guardrail_policy.is_within_organizational_boundary(parsed.netloc):
            raise PermissionError(
                f"Target {session.target_url} is outside organizational boundary "
                f"({self.guardrail_policy.organizational_domains})"
            )

        task = ReconTask(task_id=f"session-{abs(hash(session.target_url))}", target_url=session.target_url)
        self.runtime.register_task(task)

        audit_log: list[dict[str, Any]] = []
        audit_log.append({"event": "task_started", "task_id": task.task_id, "target": session.target_url})

        pipeline_result = await self._run_pipeline_with_retries(session, task, audit_log)
        session.report.recommendations = self.recommender.recommend(session.report)
        export_targets: list[Any] = []
        if exporters:
            for exporter in exporters:
                export_targets.append(session.export(exporter))

        self.runtime.checkpoint(task, {"target_url": session.target_url, "summary": session.report.to_summary_dict(), "audit_log": audit_log})
        self.runtime.mark_done(task)

        summary = {
            "target_url": session.target_url,
            "endpoint_count": len(session.report.endpoints),
            "llm_fingerprint_count": len(session.report.llm_fingerprints),
            "mcp_tool_count": len(session.report.mcp_tools),
            "recommendation_count": len(session.report.recommendations),
            "pipeline_result": {
                "executed": pipeline_result.executed,
                "skipped": pipeline_result.skipped,
                "failed": pipeline_result.failed,
                "duration_seconds": pipeline_result.duration_seconds,
            },
        }
        return OrchestrationResult(session=session, pipeline_result=pipeline_result, export_targets=export_targets, summary=summary, audit_log=audit_log)

    async def _run_pipeline_with_retries(self, session: ReconSession, task: ReconTask, audit_log: list[dict[str, Any]]) -> Any:
        attempt = 0
        while True:
            self.runtime.mark_running(task)
            try:
                result = await self.pipeline.run(session, raise_on_error=True)
                audit_log.append({"event": "probe_completed", "task_id": task.task_id, "executed": result.executed, "attempt": attempt + 1})
                return result
            except Exception as exc:
                attempt += 1
                if attempt >= self.runtime.retry_policy.max_attempts or not self.runtime.retry_policy.should_retry(exc):
                    self.runtime.mark_failed(task, str(exc))
                    audit_log.append({"event": "task_failed", "task_id": task.task_id, "error": str(exc), "attempt": attempt})
                    raise
                audit_log.append({"event": "retry_scheduled", "task_id": task.task_id, "attempt": attempt, "error": str(exc)})
                self.runtime.wait_before_retry()

    async def run_many(
        self,
        sessions: list[ReconSession],
        exporters: list[ReconExporter] | None = None,
        *,
        concurrency: int = 2,
    ) -> list[OrchestrationResult]:
        semaphore = asyncio.Semaphore(concurrency)

        async def _run_one(session: ReconSession) -> OrchestrationResult:
            async with semaphore:
                return await self.run(session, exporters)

        return await asyncio.gather(*[_run_one(session) for session in sessions])
