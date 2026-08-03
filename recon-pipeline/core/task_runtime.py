# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Task runtime helpers for orchestrated recon runs.

This module adds a lightweight task queue and guardrail layer so the recon
pipeline can behave more like a real orchestrator by managing run state,
checkpointing results, and enforcing basic target/host safety rules.
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter
from urllib import request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class AlertRecord:
    severity: AlertSeverity
    code: str
    message: str
    task_id: str | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class GuardrailPolicy:
    allowed_hosts: set[str] = field(default_factory=set)
    disallow_patterns: tuple[str, ...] = ()
    allow_external_redirects: bool = False
    organizational_domains: set[str] = field(default_factory=set)
    block_unauthorized_redirects: bool = True
    max_redirect_depth: int = 5

    def is_allowed(self, target_url: str) -> bool:
        parsed = urlparse(target_url)
        host = parsed.netloc.lower()
        if self.allowed_hosts and host not in self.allowed_hosts:
            return False
        if self.disallow_patterns:
            lowered = target_url.lower()
            if any(pattern in lowered for pattern in self.disallow_patterns):
                return False
        return True

    def is_within_organizational_boundary(self, host: str) -> bool:
        """Check if a host is within the organizational boundary."""
        if not self.organizational_domains:
            return True
        host_lower = host.lower()
        return any(
            host_lower == org_domain or host_lower.endswith("." + org_domain)
            for org_domain in self.organizational_domains
        )

    def is_redirect_allowed(self, source_host: str, target_host: str) -> bool:
        """Check if a redirect from source to target is allowed."""
        if not self.block_unauthorized_redirects:
            return True
        if self.is_within_organizational_boundary(target_host):
            return True
        if source_host.lower() == target_host.lower():
            return True
        logger.warning(
            "GuardrailPolicy: blocked redirect from %s to %s (outside org boundary)",
            source_host, target_host,
        )
        return False


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    backoff_seconds: float = 0.0
    retryable_errors: tuple[str, ...] = ("transient", "timeout", "temporarily")

    def should_retry(self, error: str | Exception | None) -> bool:
        if not error:
            return False
        message = str(error).lower()
        return any(token in message for token in self.retryable_errors) or isinstance(error, TimeoutError)


@dataclass
class ReconTask:
    task_id: str
    target_url: str
    metadata: dict[str, Any] = field(default_factory=dict)
    state: str = "pending"
    attempts: int = 0
    priority: int = 0
    depends_on: tuple[str, ...] = ()


class TaskRuntime:
    """Very small task runner with checkpointing, guardrails, metrics, alerts, state persistence, and operational exports."""

    def __init__(
        self,
        checkpoint_dir: str | Path | None = None,
        guardrail_policy: GuardrailPolicy | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.checkpoint_dir = Path(checkpoint_dir or "outputs/checkpoints")
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.guardrail_policy = guardrail_policy or GuardrailPolicy()
        self.retry_policy = retry_policy or RetryPolicy()
        self._tasks: dict[str, ReconTask] = {}
        self._alerts: list[AlertRecord] = []
        self._metrics_counters: Counter[str] = Counter()
        self._metrics_gauges: dict[str, float] = {}
        self._state_path = self.checkpoint_dir / "runtime_state.json"

    def register_task(self, task: ReconTask) -> ReconTask:
        self._tasks[task.task_id] = task
        self.record_counter("task_registered", 1)
        return task

    def list_tasks(self) -> list[ReconTask]:
        return list(self._tasks.values())

    def checkpoint(self, task: ReconTask, payload: dict[str, Any]) -> Path:
        path = self.checkpoint_dir / f"{task.task_id}.json"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
        return path

    def load_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        path = self.checkpoint_dir / f"{task_id}.json"
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def can_run(self, target_url: str) -> bool:
        return self.guardrail_policy.is_allowed(target_url)

    def mark_running(self, task: ReconTask) -> None:
        task.state = "running"
        task.attempts += 1
        self.record_counter("task_runs", 1)

    def mark_done(self, task: ReconTask) -> None:
        task.state = "done"
        self.record_counter("task_done", 1)

    def mark_failed(self, task: ReconTask, reason: str) -> None:
        task.state = f"failed:{reason}"
        self.record_counter("task_failed", 1)

    def wait_before_retry(self) -> None:
        if self.retry_policy.backoff_seconds > 0:
            time.sleep(self.retry_policy.backoff_seconds)

    def record_counter(self, name: str, value: int = 1) -> None:
        self._metrics_counters[name] += value

    def set_gauge(self, name: str, value: float) -> None:
        self._metrics_gauges[name] = value

    def emit_alert(self, severity: AlertSeverity, code: str, message: str, *, task_id: str | None = None) -> AlertRecord:
        alert = AlertRecord(severity=severity, code=code, message=message, task_id=task_id)
        self._alerts.append(alert)
        return alert

    def list_alerts(self) -> list[AlertRecord]:
        return list(self._alerts)

    def get_metrics_snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(self._metrics_counters),
            "gauges": dict(self._metrics_gauges),
        }

    def get_run_statistics(self) -> dict[str, Any]:
        return {
            "tasks_total": len(self._tasks),
            "alerts_total": len(self._alerts),
            "running_tasks": sum(1 for task in self._tasks.values() if task.state == "running"),
            "done_tasks": sum(1 for task in self._tasks.values() if task.state == "done"),
        }

    def get_pending_tasks(self) -> list[ReconTask]:
        return [task for task in self._tasks.values() if task.state == "pending"]

    def get_next_ready_task(self) -> ReconTask | None:
        pending = sorted(
            self.get_pending_tasks(),
            key=lambda task: (-task.priority, task.task_id),
        )
        for task in pending:
            if all(dep in self._tasks and self._tasks[dep].state == "done" for dep in task.depends_on):
                return task
        return None

    def export_summary(self) -> dict[str, Any]:
        stats = self.get_run_statistics()
        stats.update({
            "pending_tasks": len(self.get_pending_tasks()),
            "failed_tasks": sum(1 for task in self._tasks.values() if task.state.startswith("failed:")),
            "metrics": self.get_metrics_snapshot(),
        })
        return stats

    def export_state_file(self, path: str | Path | None = None) -> Path:
        export_path = Path(path or self.checkpoint_dir / "runtime_summary.json")
        export_path.write_text(json.dumps(self.export_summary(), indent=2, ensure_ascii=False), encoding="utf-8")
        return export_path

    def render_summary_text(self) -> str:
        summary = self.export_summary()
        lines = [
            "Recon Runtime Summary",
            "=====================",
            f"Tasks total: {summary['tasks_total']}",
            f"Done: {summary['done_tasks']}",
            f"Running: {summary['running_tasks']}",
            f"Pending: {summary['pending_tasks']}",
            f"Failed: {summary['failed_tasks']}",
            f"Alerts: {summary['alerts_total']}",
        ]
        return "\n".join(lines)

    def render_summary_markdown(self) -> str:
        summary = self.export_summary()
        lines = [
            "# Recon Runtime Summary",
            "",
            "- Tasks total: {tasks_total}",
            "- Done: {done_tasks}",
            "- Running: {running_tasks}",
            "- Pending: {pending_tasks}",
            "- Failed: {failed_tasks}",
            "- Alerts: {alerts_total}",
        ]
        return "\n".join(lines).format(**summary)

    def render_summary_html(self) -> str:
        summary = self.export_summary()
        rows = "\n".join(
            [
                f"<tr><th>{key}</th><td>{value}</td></tr>"
                for key, value in [
                    ("Tasks total", summary["tasks_total"]),
                    ("Done", summary["done_tasks"]),
                    ("Running", summary["running_tasks"]),
                    ("Pending", summary["pending_tasks"]),
                    ("Failed", summary["failed_tasks"]),
                    ("Alerts", summary["alerts_total"]),
                ]
            ]
        )
        return (
            "<html><body><h1>Recon Runtime Summary</h1><table>"
            f"{rows}</table></body></html>"
        )

    def export_report(self, path: str | Path | None = None, *, fmt: str = "md") -> Path:
        export_path = Path(path or self.checkpoint_dir / f"runtime_report.{fmt}")
        if fmt.lower() == "html":
            content = self.render_summary_html()
        else:
            content = self.render_summary_markdown()
        export_path.write_text(content, encoding="utf-8")
        return export_path

    def emit_notifications(self, sink: Any | None = None) -> list[dict[str, Any]]:
        rendered = self.render_summary_text()
        if sink is None:
            return [{"type": "text", "message": rendered}]
        if hasattr(sink, "write"):
            sink.write(rendered)
            return [{"type": "stream", "message": rendered}]
        if callable(sink):
            sink(rendered)
            return [{"type": "callback", "message": rendered}]
        return [{"type": "unknown", "message": rendered}]

    def emit_webhook(self, url: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = payload or self.export_summary()
        data = json.dumps(body).encode("utf-8")
        req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=5) as response:
            response_text = response.read().decode("utf-8")
        return {"status": response.status, "body": response_text}

    def export_state_file(self, path: str | Path | None = None) -> Path:
        export_path = Path(path or self.checkpoint_dir / "runtime_summary.json")
        export_path.write_text(json.dumps(self.export_summary(), indent=2, ensure_ascii=False), encoding="utf-8")
        return export_path

    def persist_state(self) -> Path:
        state = {
            "tasks": [
                {
                    "task_id": task.task_id,
                    "target_url": task.target_url,
                    "metadata": task.metadata,
                    "state": task.state,
                    "attempts": task.attempts,
                }
                for task in self._tasks.values()
            ],
            "alerts": [
                {
                    "severity": alert.severity.value,
                    "code": alert.code,
                    "message": alert.message,
                    "task_id": alert.task_id,
                    "timestamp": alert.timestamp,
                }
                for alert in self._alerts
            ],
            "metrics": self.get_metrics_snapshot(),
        }
        with open(self._state_path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, ensure_ascii=False, default=str)
        return self._state_path

    def load_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {}
        with open(self._state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        for entry in state.get("tasks", []):
            task = ReconTask(task_id=entry["task_id"], target_url=entry["target_url"], metadata=entry.get("metadata", {}), state=entry.get("state", "pending"), attempts=entry.get("attempts", 0))
            self._tasks[task.task_id] = task
        self._alerts = [
            AlertRecord(
                severity=AlertSeverity(entry["severity"]),
                code=entry["code"],
                message=entry["message"],
                task_id=entry.get("task_id"),
                timestamp=entry.get("timestamp", time.time()),
            )
            for entry in state.get("alerts", [])
        ]
        metrics = state.get("metrics", {})
        self._metrics_counters = Counter(metrics.get("counters", {}))
        self._metrics_gauges = dict(metrics.get("gauges", {}))
        return state
