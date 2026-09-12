"""tests/test_events.py - EventLog 单元测试（REQ-148）。

覆盖：写入/落盘/过滤/禁用 no-op/ctx 未挂载安全降级。
"""

from __future__ import annotations

import json
from pathlib import Path

from core.events import Event, EventLog, emit_event, get_event_log


class TestEventLog:
    """EventLog 行为验证（W0 旁路埋点，零行为回归前提）。"""

    def test_emit_appends_and_counts(self) -> None:
        log = EventLog()
        evt = log.emit("recon", "probe", {"url": "http://x"}, refs={"endpoint": 0})
        assert evt is not None
        assert evt.phase == "recon"
        assert evt.etype == "probe"
        assert evt.payload["url"] == "http://x"
        assert log.count == 1
        assert len(log) == 1

    def test_persists_jsonl(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        log = EventLog(path=path)
        log.emit("strike", "attack_sent", {"seed": "s1"})
        log.emit("strike", "response", {"ok": True})
        log.close()

        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["phase"] == "strike"
        assert first["etype"] == "attack_sent"

    def test_filter_by_phase_and_type(self) -> None:
        log = EventLog()
        log.emit("recon", "probe", {}, node_id="n1")
        log.emit("arm", "seed_selected", {})
        log.emit("arm", "probe", {})

        assert len(log.filter(phase="arm")) == 2
        assert len(log.filter(etype="probe")) == 2
        assert len(log.filter(phase="arm", etype="probe")) == 1
        assert len(log.filter(node_id="n1")) == 1

    def test_disabled_is_noop(self) -> None:
        log = EventLog(enabled=False)
        assert log.emit("recon", "probe") is None
        assert log.count == 0

    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        log = EventLog(path=tmp_path / "e.jsonl")
        log.emit("recon", "probe")
        log.close()
        log.close()  # 幂等，不抛异常

    def test_unwritable_path_degrades_to_memory(self, tmp_path: Path) -> None:
        # 目录被占位为文件时，落盘失败应降级为内存模式而非抛出
        blocked = tmp_path / "blocked"
        blocked.write_text("x", encoding="utf-8")
        log = EventLog(path=blocked / "events.jsonl")
        assert log.emit("recon", "probe") is not None
        assert log.count == 1

    def test_attach_sets_ctx_event_log(self, tmp_path: Path) -> None:
        class _Ctx:
            output_dir = tmp_path

        ctx = _Ctx()
        log = EventLog.attach(ctx, output_dir=tmp_path, enabled=True, run_id="r001")
        assert ctx.event_log is log
        assert log.run_id == "r001"
        log.emit("recon", "probe")
        assert (tmp_path / "events.jsonl").exists()
        log.close()


class TestHelpers:
    """get_event_log / emit_event 安全降级验证。"""

    def test_get_event_log_missing_ctx_returns_disabled(self) -> None:
        class _Ctx:
            pass

        log = get_event_log(_Ctx())
        assert isinstance(log, EventLog)
        assert log.enabled is False
        assert log.emit("recon", "probe") is None

    def test_emit_event_without_ctx_log_is_noop(self) -> None:
        class _Ctx:
            pass

        assert emit_event(_Ctx(), "recon", "probe") is None

    def test_event_serialization(self) -> None:
        evt = Event(ts=1.0, run_id="r1", phase="arm", etype="seed_selected", payload={"n": 2})
        data = json.loads(evt.to_json())
        assert data["run_id"] == "r1"
        assert data["payload"]["n"] == 2
        assert data["node_id"] is None
