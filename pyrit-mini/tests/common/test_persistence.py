"""Tests for verdict persistence + dual-口径 ASR (REQ-152 / NFR-13 ④)."""

from __future__ import annotations

from types import SimpleNamespace

from assess.persistence import (
    build_verdict_records,
    dual_asr_summary,
    load_verdicts,
    persist_verdicts,
)
from core.contracts.verdict import VerdictRecord


def _result(outcome: str, text: str = "some response", component: str = "") -> SimpleNamespace:
    meta = {"component_type": component} if component else {}
    return SimpleNamespace(_precomputed_outcome=outcome, converted_value=text, metadata=meta)


class TestBuildRecords:
    def test_builds_one_record_per_result(self) -> None:
        results = {"tap": [_result("success"), _result("failure")]}
        records = build_verdict_records(results)
        assert len(records) == 2
        assert all(isinstance(r, VerdictRecord) for r in records)
        assert records[0].attack_id == "tap#0"
        assert records[0].final_success is True
        assert records[1].final_success is False

    def test_carries_component_and_levels(self) -> None:
        results = {"mcp": [_result("success", component="mcp_tool_poisoning")]}
        records = build_verdict_records(
            results,
            impact_verdicts=[{"attack_id": "mcp#0", "verdict": "exfil_confirmed"}],
            success_levels={"by_attack": {"mcp#0": "L4"}},
        )
        assert records[0].component_key == "mcp_tool_poisoning"
        assert records[0].impact_verdict == "exfil_confirmed"
        assert records[0].success_level == "L4"

    def test_empty_input(self) -> None:
        assert build_verdict_records(None) == []


class TestDualAsr:
    def test_no_impact_data_yields_none_confirmed(self) -> None:
        records = build_verdict_records({"t": [_result("success"), _result("failure")]})
        summary = dual_asr_summary(records)
        assert summary["reported_asr"] == 50.0
        assert summary["confirmed_asr"] is None
        assert summary["confirmed_available"] is False

    def test_confirmed_counts_only_impact_states(self) -> None:
        results = {"t": [_result("success"), _result("success"), _result("success")]}
        records = build_verdict_records(
            results,
            impact_verdicts=[
                {"attack_id": "t#0", "verdict": "exfil_confirmed"},
                {"attack_id": "t#1", "verdict": "exfil_suspected"},
            ],
        )
        summary = dual_asr_summary(records)
        assert summary["reported_asr"] == 100.0
        # 3 条中仅 1 条 exfil_confirmed → 33.3%，exfil_suspected 不计
        assert summary["confirmed_asr"] == 33.3

    def test_impact_state_counts(self) -> None:
        records = build_verdict_records(
            {"t": [_result("success")]},
            impact_verdicts=[{"attack_id": "t#0", "verdict": "impact"}],
        )
        assert dual_asr_summary(records)["confirmed_asr"] == 100.0

    def test_level_histogram(self) -> None:
        records = build_verdict_records(
            {"t": [_result("success", text="x")]},
            success_levels={"by_attack": {"t#0": "L3"}},
        )
        assert dual_asr_summary(records)["level_histogram"]["L3"] == 1

    def test_empty_records(self) -> None:
        summary = dual_asr_summary([])
        assert summary["total"] == 0 and summary["confirmed_asr"] is None


class TestPersist:
    def test_writes_both_files_and_roundtrips(self, tmp_path) -> None:
        records = build_verdict_records({"tap": [_result("success")]})
        summary = persist_verdicts(tmp_path, records)
        assert summary["reported_asr"] == 100.0
        assert (tmp_path / "verdicts.json").is_file()
        assert (tmp_path / "verdicts.jsonl").is_file()

        loaded = load_verdicts(tmp_path)
        assert loaded["count"] == 1
        assert loaded["records"][0]["content_hash"]
        assert loaded["records"][0]["schema_version"] == "1.0"

    def test_idempotent_dedup_by_content_hash(self, tmp_path) -> None:
        results = {"tap": [_result("success", text="same")]}
        records = build_verdict_records(results) * 3  # duplicate references
        persist_verdicts(tmp_path, records)
        loaded = load_verdicts(tmp_path)
        assert loaded["count"] == 1

    def test_load_missing_dir_is_empty(self, tmp_path) -> None:
        loaded = load_verdicts(tmp_path / "nope")
        assert loaded["count"] == 0

    def test_level_and_verdict_persisted(self, tmp_path) -> None:
        records = build_verdict_records(
            {"t": [_result("success")]},
            impact_verdicts=[{"attack_id": "t#0", "verdict": "exfil_confirmed"}],
            success_levels={"by_attack": {"t#0": "L4"}},
        )
        persist_verdicts(tmp_path, records)
        rec = load_verdicts(tmp_path)["records"][0]
        assert rec["impact_verdict"] == "exfil_confirmed"
        assert rec["success_level"] == "L4"
