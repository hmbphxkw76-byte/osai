# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""DecisionTrace 单元测试。"""

from __future__ import annotations

from pipeline.utils.decision_trace import DecisionRecord, DecisionTrace


class TestDecisionRecord:
    def test_creation(self) -> None:
        record = DecisionRecord(
            stage="stage_0.5",
            layer="target_detection",
            decision="classified_as_web_app",
            reason="HTML + chat UI",
            data={"url": "https://example.com"},
        )
        assert record.stage == "stage_0.5"
        assert record.decision == "classified_as_web_app"
        assert record.timestamp != ""

    def test_to_dict(self) -> None:
        record = DecisionRecord(
            stage="stage_2",
            layer="L5_Analytics",
            decision="warm_start_loaded",
            reason="5 priors injected",
        )
        d = record.to_dict()
        assert d["stage"] == "stage_2"
        assert d["decision"] == "warm_start_loaded"


class TestDecisionTrace:
    def setup_method(self) -> None:
        DecisionTrace.reset()

    def test_singleton(self) -> None:
        t1 = DecisionTrace.get_instance()
        t2 = DecisionTrace.get_instance()
        assert t1 is t2

    def test_record_and_retrieve(self) -> None:
        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_1",
            layer="L1_SeedSource",
            decision="datasets_loaded",
            reason="3 datasets loaded",
            count=3,
        )
        assert trace.record_count == 1
        records = trace.get_records()
        assert records[0].decision == "datasets_loaded"

    def test_filter_by_stage(self) -> None:
        trace = DecisionTrace.get_instance()
        trace.record(stage="stage_1", layer="L1", decision="a")
        trace.record(stage="stage_2", layer="L3", decision="b")
        trace.record(stage="stage_1", layer="L5", decision="c")
        stage1 = trace.get_records_by_stage("stage_1")
        assert len(stage1) == 2

    def test_filter_by_layer(self) -> None:
        trace = DecisionTrace.get_instance()
        trace.record(stage="stage_1", layer="L1_SeedSource", decision="a")
        trace.record(stage="stage_2", layer="L3_DatasetConfig", decision="b")
        l1_records = trace.get_records_by_layer("L1_SeedSource")
        assert len(l1_records) == 1

    def test_to_markdown_empty(self) -> None:
        trace = DecisionTrace.get_instance()
        md = trace.to_markdown()
        assert "无决策记录" in md

    def test_to_markdown_with_records(self) -> None:
        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_0.5",
            layer="target_detection",
            decision="classified_as_web_app",
            reason="HTML response with chat UI",
            url="https://example.com",
        )
        trace.record(
            stage="stage_2",
            layer="L5_Analytics",
            decision="warm_start_loaded",
            reason="5 technique priors",
        )
        md = trace.to_markdown()
        assert "决策追溯附录" in md
        assert "classified_as_web_app" in md
        assert "warm_start_loaded" in md
        assert "stage_0.5" in md
        assert "stage_2" in md

    def test_reset(self) -> None:
        trace = DecisionTrace.get_instance()
        trace.record(stage="s1", layer="l1", decision="d1")
        assert trace.record_count == 1
        DecisionTrace.reset()
        trace2 = DecisionTrace.get_instance()
        assert trace2.record_count == 0
