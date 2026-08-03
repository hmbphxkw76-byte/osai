# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""EventBus 单元测试。"""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.utils.event_bus import EventBus, PipelineEvent


class TestPipelineEvent:
    def test_event_creation(self) -> None:
        event = PipelineEvent(
            stage="stage_1",
            event_type="test_event",
            data={"key": "value"},
        )
        assert event.stage == "stage_1"
        assert event.event_type == "test_event"
        assert event.data == {"key": "value"}
        assert event.timestamp != ""

    def test_event_to_json(self) -> None:
        event = PipelineEvent(
            stage="stage_2",
            event_type="datasets_loaded",
            data={"count": 5},
        )
        parsed = json.loads(event.to_json())
        assert parsed["stage"] == "stage_2"
        assert parsed["data"]["count"] == 5

    def test_event_to_summary(self) -> None:
        event = PipelineEvent(
            stage="stage_1",
            event_type="init_complete",
            data={"targets": 2, "scorers": 1},
        )
        summary = event.to_summary()
        assert "[EVENT]" in summary
        assert "stage_1" in summary
        assert "init_complete" in summary


class TestEventBus:
    def setup_method(self) -> None:
        EventBus._instance = None

    def test_singleton(self) -> None:
        bus1 = EventBus.get_instance()
        bus2 = EventBus.get_instance()
        assert bus1 is bus2

    def test_publish_and_retrieve(self) -> None:
        bus = EventBus.get_instance()
        bus.disable()
        bus.publish_simple("stage_1", "test", count=3)
        bus.enable()
        # Disabled publishes shouldn't be recorded
        assert bus.event_count == 0

        bus.publish_simple("stage_1", "test", count=3)
        assert bus.event_count == 1

    def test_publish_to_jsonl(self, tmp_path: Path) -> None:
        bus = EventBus.init(output_dir=tmp_path)
        bus.publish_simple("stage_1", "init_complete", targets=2)
        assert bus.jsonl_path is not None
        assert bus.jsonl_path.exists()
        lines = bus.jsonl_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["event_type"] == "init_complete"

    def test_filter_by_stage(self) -> None:
        bus = EventBus.get_instance()
        bus._events.clear()
        bus.publish_simple("stage_1", "a")
        bus.publish_simple("stage_2", "b")
        bus.publish_simple("stage_1", "c")
        stage1_events = bus.get_events_by_stage("stage_1")
        assert len(stage1_events) == 2

    def test_disable_enable(self) -> None:
        bus = EventBus.get_instance()
        bus._events.clear()
        bus.disable()
        bus.publish_simple("stage_1", "test")
        assert bus.event_count == 0
        bus.enable()
        bus.publish_simple("stage_1", "test")
        assert bus.event_count == 1
