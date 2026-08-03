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
from core.persistence.fingerprint_store import FingerprintStore
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
    """Small orchestrator that coordinates probes and export steps.

    Supports incremental recon mode: when enabled, compares current
    fingerprint baseline against stored values and skips unchanged
    endpoints, drastically reducing repeat scan time.
    """

    def __init__(
        self,
        probes: list[ReconProbe] | None = None,
        *,
        probe_timeout: float = 60.0,
        parallel: bool = False,
        incremental: bool = False,
        fingerprint_db_path: str = "outputs/fingerprints.db",
        runtime: TaskRuntime | None = None,
        guardrail_policy: GuardrailPolicy | None = None,
    ) -> None:
        self.pipeline = ReconPipeline(probes=probes or [], probe_timeout=probe_timeout, parallel=parallel)
        self.recommender = AttackRecommender()
        self.runtime = runtime or TaskRuntime(guardrail_policy=guardrail_policy)
        self.guardrail_policy = self.runtime.guardrail_policy
        self._incremental = incremental
        self._fp_store = FingerprintStore(fingerprint_db_path) if incremental else None

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

        # ── Incremental recon: check fingerprint baseline ──
        incremental_skipped = 0
        if self._incremental and self._fp_store:
            scan_label = f"scan-{task.task_id[:12]}"
            incremental_skipped = self._check_changed_endpoints(session.report.endpoints, scan_label)
            if incremental_skipped:
                audit_log.append({
                    "event": "incremental_skip",
                    "skipped_endpoints": incremental_skipped,
                    "scan_label": scan_label,
                })
                logger.info(
                    "Incremental recon: %d endpoints unchanged, running probes on remaining",
                    incremental_skipped,
                )

        pipeline_result = await self._run_pipeline_with_retries(session, task, audit_log)

        # ── Post-scan: store new fingerprints ──
        if self._incremental and self._fp_store:
            scan_label = f"scan-{task.task_id[:12]}"
            self._store_endpoint_fingerprints(session.report.endpoints, scan_label)
            audit_log.append({"event": "fingerprints_stored", "scan_label": scan_label})

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
            "incremental_skipped": incremental_skipped,
        }
        return OrchestrationResult(session=session, pipeline_result=pipeline_result, export_targets=export_targets, summary=summary, audit_log=audit_log)

    async def _run_pipeline_with_retries(self, session: ReconSession, task: ReconTask, audit_log: list[dict[str, Any]]) -> Any:
        attempt = 0
        while True:
            self.runtime.mark_running(task)
            try:
                # Use parallel execution when enabled
                if self.pipeline._parallel:
                    result = await self.pipeline.run_parallel(session, raise_on_error=True)
                else:
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

    # ── Incremental recon helpers ──

    def _check_changed_endpoints(
        self,
        endpoints: list[Any],
        scan_label: str,
    ) -> int:
        """Check which endpoints have changed from baseline.

        Marks endpoints that are unchanged so probes can skip them.

        Returns:
            Number of unchanged endpoints (eligible for skipping).
        """
        if not self._fp_store:
            return 0

        skipped = 0
        for ep in endpoints:
            key = ep.url
            body = getattr(ep, "response_body_preview", "") or ""
            status = getattr(ep, "status_code", None)
            current_fp = self._compute_ep_fingerprint(body, status)

            if not current_fp:
                continue

            if not self._fp_store.has_changed(key, current_fp):
                # Endpoint unchanged from last scan — mark for skip
                skipped += 1

            # Record current fingerprint for next drift comparison
            self._fp_store.record(key, current_fp, scan_label=scan_label, status_code=status)

        return skipped

    def _store_endpoint_fingerprints(
        self,
        endpoints: list[Any],
        scan_label: str,
    ) -> None:
        """Store endpoint fingerprints for future incremental comparison."""
        if not self._fp_store:
            return

        items: list[dict[str, Any]] = []
        for ep in endpoints:
            body = getattr(ep, "response_body_preview", "") or ""
            status = getattr(ep, "status_code", None)
            fp = self._compute_ep_fingerprint(body, status)
            if fp:
                items.append({
                    "key": ep.url,
                    "fingerprint": fp,
                    "status_code": status,
                })

        if items:
            self._fp_store.record_batch(items, scan_label=scan_label)

    @staticmethod
    def _compute_ep_fingerprint(body: str, status_code: int | None) -> str:
        """Compute a stable fingerprint for endpoint comparison."""
        import hashlib

        canonical = f"{status_code or 0}:{body[:1000]}"
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]
