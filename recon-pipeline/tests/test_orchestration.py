from __future__ import annotations

import asyncio
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from core.orchestration import ReconOrchestrator
from core.probes import LLMProbe
from core.probes.base import ReconProbe
from core.session import ReconSession
from core.task_runtime import AlertSeverity, GuardrailPolicy, RetryPolicy, ReconTask, TaskRuntime


class FlakyProbe(ReconProbe):
    def __init__(self, fail_times: int = 1) -> None:
        self.fail_times = fail_times
        self.calls = 0

    async def probe(self, session: ReconSession) -> dict[str, object]:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("transient failure")
        return {"endpoints": []}

    @property
    def name(self) -> str:
        return "flaky"

    @property
    def requires_auth(self) -> bool:
        return False


def test_orchestrator_run_many_with_guardrails() -> None:
    runtime = TaskRuntime(checkpoint_dir="outputs/test_orchestration", guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}))
    orchestrator = ReconOrchestrator(probes=[LLMProbe()], runtime=runtime)

    sessions = [ReconSession(target_url="https://example.test"), ReconSession(target_url="https://example.test")]

    async def _run() -> None:
        results = await orchestrator.run_many(sessions, concurrency=2)
        assert len(results) == 2
        assert all(result.summary["endpoint_count"] == 0 for result in results)

    asyncio.run(_run())


def test_orchestrator_retries_transient_probe_failures() -> None:
    runtime = TaskRuntime(
        checkpoint_dir="outputs/test_orchestration",
        guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}),
        retry_policy=RetryPolicy(max_attempts=2, backoff_seconds=0.01),
    )
    orchestrator = ReconOrchestrator(probes=[FlakyProbe(fail_times=1)], runtime=runtime)
    session = ReconSession(target_url="https://example.test")

    async def _run() -> None:
        result = await orchestrator.run(session)
        assert result.pipeline_result.executed == 1
        assert runtime.list_tasks()[0].attempts == 2

    asyncio.run(_run())


def test_runtime_tracks_metrics_alerts_and_state(tmp_path) -> None:
    runtime = TaskRuntime(checkpoint_dir=tmp_path, guardrail_policy=GuardrailPolicy(allowed_hosts={"example.test"}))
    task = ReconTask(task_id="ops-task", target_url="https://example.test")
    runtime.register_task(task)
    runtime.mark_running(task)
    runtime.record_counter("task_runs", 2)
    runtime.emit_alert(AlertSeverity.WARNING, "retry", "Retrying task", task_id=task.task_id)
    runtime.persist_state()

    restored = TaskRuntime(checkpoint_dir=tmp_path)
    restored.load_state()

    metrics = restored.get_metrics_snapshot()
    assert metrics["counters"]["task_runs"] >= 2
    assert restored.list_tasks()[0].task_id == "ops-task"
    assert restored.list_alerts()[0].code == "retry"
    stats = restored.get_run_statistics()
    assert stats["alerts_total"] == 1


def test_runtime_queue_and_summary_export(tmp_path) -> None:
    runtime = TaskRuntime(checkpoint_dir=tmp_path)
    runtime.register_task(ReconTask(task_id="a", target_url="https://example.test/a"))
    runtime.register_task(ReconTask(task_id="b", target_url="https://example.test/b", priority=5))
    runtime.mark_running(runtime.list_tasks()[0])
    runtime.mark_done(runtime.list_tasks()[0])

    queued = runtime.get_pending_tasks()
    assert len(queued) == 1
    assert runtime.get_next_ready_task().task_id == "b"
    summary = runtime.export_summary()
    assert summary["tasks_total"] == 2
    assert summary["done_tasks"] == 1
    export_path = runtime.export_state_file(tmp_path / "summary.json")
    assert export_path.exists()

    rendered = runtime.render_summary_text()
    assert "Recon Runtime Summary" in rendered
    notification = runtime.emit_notifications()
    assert notification[0]["type"] == "text"


def test_runtime_can_render_markdown_and_html_reports(tmp_path) -> None:
    runtime = TaskRuntime(checkpoint_dir=tmp_path)
    runtime.register_task(ReconTask(task_id="report-task", target_url="https://example.test/report"))
    runtime.mark_running(runtime.list_tasks()[0])

    markdown = runtime.render_summary_markdown()
    assert "# Recon Runtime Summary" in markdown

    html = runtime.render_summary_html()
    assert "<html" in html.lower()

    export_path = runtime.export_report(tmp_path / "report.md")
    assert export_path.exists()


def test_runtime_can_emit_webhook_and_structured_summary(tmp_path) -> None:
    runtime = TaskRuntime(checkpoint_dir=tmp_path)
    runtime.register_task(ReconTask(task_id="c", target_url="https://example.test/c"))

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = runtime.emit_webhook(f"http://127.0.0.1:{server.server_port}")
        assert result["status"] == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    export_path = runtime.export_state_file(tmp_path / "summary.json")
    payload = export_path.read_text(encoding="utf-8")
    assert '"tasks_total"' in payload
