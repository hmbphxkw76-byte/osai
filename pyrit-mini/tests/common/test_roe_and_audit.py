"""Tests for REQ-163 (RoE authorization file) and REQ-169 (audit hash chain + operator)."""

from __future__ import annotations

import json
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from core.context import enforce_authorized_scope
from core.events import EventLog, verify_event_log
from core.roe import load_roe_file, merge_authorized_targets, validate_roe

_TODAY = date.today()


def _write_roe(tmp_path, *, ref="ROE-1", targets=("example.com",), start=None, end=None):
    start = start or (_TODAY - timedelta(days=1)).isoformat()
    end = end or (_TODAY + timedelta(days=1)).isoformat()
    p = tmp_path / "roe.yaml"
    p.write_text(
        f"authorization_ref: {ref}\n"
        f"targets: {list(targets)}\n"
        f"valid_from: {start}\n"
        f"valid_until: {end}\n",
        encoding="utf-8",
    )
    return p


class TestRoeLoad:
    def test_load_yaml(self, tmp_path) -> None:
        p = _write_roe(tmp_path)
        policy = load_roe_file(p)
        assert policy.authorization_ref == "ROE-1"
        assert policy.targets == ["example.com"]

    def test_load_json(self, tmp_path) -> None:
        p = tmp_path / "roe.json"
        p.write_text(json.dumps({"authorization_ref": "R2", "targets": ["a.com"], "valid_until": "2030-01-01"}), "utf-8")
        policy = load_roe_file(p)
        assert policy.authorization_ref == "R2" and policy.targets == ["a.com"]

    def test_non_mapping_raises(self, tmp_path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("- just\n- a\n- list\n", encoding="utf-8")
        with pytest.raises(ValueError):
            load_roe_file(p)

    def test_missing_file_raises(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            load_roe_file(tmp_path / "nope.yaml")


class TestRoeValidate:
    def test_valid(self, tmp_path) -> None:
        assert validate_roe(load_roe_file(_write_roe(tmp_path))) == []

    def test_missing_ref_and_targets(self, tmp_path) -> None:
        p = tmp_path / "r.yaml"
        p.write_text("notes: nothing\n", encoding="utf-8")
        problems = validate_roe(load_roe_file(p))
        assert any("authorization_ref" in x for x in problems)
        assert any("targets" in x for x in problems)

    def test_expired(self, tmp_path) -> None:
        p = _write_roe(tmp_path, start=(_TODAY - timedelta(days=30)).isoformat(), end=(_TODAY - timedelta(days=1)).isoformat())
        assert any("过期" in x for x in validate_roe(load_roe_file(p)))

    def test_not_yet_valid(self, tmp_path) -> None:
        p = _write_roe(tmp_path, start=(_TODAY + timedelta(days=1)).isoformat(), end=(_TODAY + timedelta(days=30)).isoformat())
        assert any("尚未生效" in x for x in validate_roe(load_roe_file(p)))

    def test_merge_targets_order_preserving(self) -> None:
        from core.roe import ROEPolicy

        merged = merge_authorized_targets(["a.com", "*.b.com"], ROEPolicy(targets=["*.b.com", "c.com"]))
        assert merged == ["a.com", "*.b.com", "c.com"]


def _args(**kw) -> SimpleNamespace:
    base = {
        "authorized_targets": None,
        "roe_file": None,
        "require_roe": False,
        "_burp_list": [],
        "target_api_endpoint": None,
        "browser_url": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


class _Ctx:
    def __init__(self) -> None:
        self.authorized_targets: list[str] = []
        self.roe_policy: dict = {}


class TestEnforcement:
    def test_require_roe_without_file_exits(self) -> None:
        with pytest.raises(SystemExit):
            enforce_authorized_scope(_args(require_roe=True), _Ctx())

    def test_missing_roe_file_with_require_exits(self, tmp_path) -> None:
        with pytest.raises(SystemExit):
            enforce_authorized_scope(_args(roe_file=str(tmp_path / "no.yaml"), require_roe=True), _Ctx())

    def test_missing_roe_file_without_require_warns_and_continues(self, tmp_path) -> None:
        ctx = _Ctx()
        enforce_authorized_scope(_args(roe_file=str(tmp_path / "no.yaml")), ctx)
        assert ctx.authorized_targets == []

    def test_valid_roe_merges_and_sets_policy(self, tmp_path) -> None:
        ctx = _Ctx()
        args = _args(roe_file=str(_write_roe(tmp_path, targets=("example.com",))))
        enforce_authorized_scope(args, ctx)
        assert "example.com" in ctx.authorized_targets
        assert ctx.roe_policy.get("authorization_ref") == "ROE-1"

    def test_expired_roe_without_require_continues(self, tmp_path) -> None:
        ctx = _Ctx()
        p = _write_roe(tmp_path, start=(_TODAY - timedelta(days=9)).isoformat(), end=(_TODAY - timedelta(days=1)).isoformat())
        enforce_authorized_scope(_args(roe_file=str(p)), ctx)
        assert ctx.roe_policy  # loaded, but not fatal

    def test_expired_roe_with_require_exits(self, tmp_path) -> None:
        p = _write_roe(tmp_path, start=(_TODAY - timedelta(days=9)).isoformat(), end=(_TODAY - timedelta(days=1)).isoformat())
        with pytest.raises(SystemExit):
            enforce_authorized_scope(_args(roe_file=str(p), require_roe=True), _Ctx())

    def test_default_behavior_unchanged(self) -> None:
        ctx = _Ctx()
        enforce_authorized_scope(_args(authorized_targets="a.com"), ctx)
        assert ctx.authorized_targets == ["a.com"]


class TestTenantIdentity:
    """REQ-167：operator/tenant 并入 memory labels（默认行为不变）。"""

    @staticmethod
    def _parse(argv: list[str]):
        from core.config import parse_args

        return parse_args(argv)

    def test_operator_and_tenant_merged(self) -> None:
        args = self._parse(["--target", "model", "--operator", "alice", "--tenant", "t1"])
        assert args.memory_labels_parsed == {"operator": "alice", "tenant": "t1"}

    def test_cli_identity_overrides_json_labels(self) -> None:
        args = self._parse(
            [
                "--target",
                "model",
                "--memory-labels",
                '{"operator": "json-op", "run": "r1"}',
                "--operator",
                "cli-op",
            ]
        )
        assert args.memory_labels_parsed == {"operator": "cli-op", "run": "r1"}

    def test_tenant_only(self) -> None:
        args = self._parse(["--target", "model", "--tenant", "acme"])
        assert args.memory_labels_parsed == {"tenant": "acme"}

    def test_default_behavior_unchanged(self) -> None:
        args = self._parse(["--target", "model"])
        assert not args.memory_labels_parsed


class TestAuditHashChain:
    def test_chain_is_valid(self, tmp_path) -> None:
        path = tmp_path / "events.jsonl"
        log = EventLog(path=path, operator="alice", enabled=True)
        log.emit("recon", "phase_start")
        log.emit("recon", "probe", {"url": "http://x"})
        log.emit("strike", "attack_sent", {"n": 1})
        log.close()

        result = verify_event_log(path)
        assert result["valid"] is True
        assert result["checked"] == 3
        assert result["legacy"] == 0

    def test_operator_recorded(self, tmp_path) -> None:
        path = tmp_path / "events.jsonl"
        log = EventLog(path=path, operator="bob", enabled=True)
        log.emit("recon", "phase_start")
        log.close()
        first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert first["operator"] == "bob"
        assert first["hash"] and first["prev_hash"] == ""

    def test_tamper_detected(self, tmp_path) -> None:
        path = tmp_path / "events.jsonl"
        log = EventLog(path=path, operator="alice", enabled=True)
        log.emit("recon", "phase_start")
        log.emit("strike", "attack_sent")
        log.close()

        lines = path.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[1])
        data["payload"] = {"tampered": True}
        lines[1] = json.dumps(data, ensure_ascii=False)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_event_log(path)
        assert result["valid"] is False
        assert result["reason"] == "hash_mismatch"
        assert result["broken_at"] == 2

    def test_legacy_lines_counted_not_failed(self, tmp_path) -> None:
        path = tmp_path / "events.jsonl"
        legacy = {"ts": 1.0, "run_id": "r", "phase": "recon", "etype": "probe", "payload": {}, "refs": {}, "node_id": None}
        path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
        result = verify_event_log(path)
        assert result["valid"] is True and result["legacy"] == 1 and result["checked"] == 0

    def test_missing_file(self, tmp_path) -> None:
        result = verify_event_log(tmp_path / "nope.jsonl")
        assert result["valid"] is False and result["reason"] == "file_not_found"

    def test_disabled_log_is_noop(self, tmp_path) -> None:
        log = EventLog(path=tmp_path / "events.jsonl", enabled=False)
        assert log.emit("recon", "phase_start") is None
        assert not (tmp_path / "events.jsonl").exists()
