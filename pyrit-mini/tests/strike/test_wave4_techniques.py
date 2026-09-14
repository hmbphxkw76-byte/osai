# -*- coding: utf-8 -*-
"""tests/strike/test_wave4_techniques.py — S9 Wave 4 strike 技术实装验证（R-S4: 全部 mock）。

确认 strike 缺口项（web/injection/evasion/session 共 10 项）已真实实现，非 stub：
- web: auth_bypass / rate_limit_evasion / scope_escalation
- injection: document_poisoning / file_upload_injection / auth_injection
- evasion: audit_log_evasion / encoding_evasion
- session: context_leakage / idor_testing

实投路径均以 dry_run / monkeypatch 网络层方式覆盖，不触网。
"""

from __future__ import annotations

import os

from strike.evasion.audit import run_audit_log_evasion
from strike.evasion.encoding import run_encoding_evasion
from strike.injection.auth_attacks import AuthAttacks
from strike.injection.doc_poisoner import run_document_poisoning
from strike.injection.file_upload import run_file_upload_injection
from strike.session.extraction import run_context_leakage
from strike.session.idor_tester import run_idor_testing
from strike.web.attacks import WebAttacks


def _fake_send(**_kwargs):
    return {"status": 200, "headers": {}, "body": "ok", "transport": "urllib-fallback"}


def test_web_auth_bypass(monkeypatch):
    wa = WebAttacks("http://target/api")
    monkeypatch.setattr(wa.engine, "send_request", _fake_send)
    out = wa.auth_bypass_attack()
    assert out["bypass_detected"] is True
    assert any(b["name"] == "jwt_alg_none" for b in out["bypasses"])


def test_web_rate_limit_evasion(monkeypatch):
    wa = WebAttacks("http://target/api")
    monkeypatch.setattr(wa.engine, "send_request", _fake_send)
    out = wa.rate_limit_evasion_attack(burst=15)
    assert out["evaded"] is True
    assert out["rate_limit_info"]["rate_limited_count"] == 0


def test_web_scope_escalation(monkeypatch):
    wa = WebAttacks("http://target/api")
    monkeypatch.setattr(wa.engine, "send_request", _fake_send)
    out = wa.scope_escalation_attack()
    assert out["escalated"] is True
    assert len(out["probes"]) == 3


def test_injection_auth_injection_dry_run(monkeypatch):
    class _FakeTarget:
        def __init__(self, *a, **k):
            self.headers = {}

    monkeypatch.setattr("strike.injection.auth_attacks.HTTPTarget", _FakeTarget)
    aa = AuthAttacks("http://target/api")
    out = aa.auth_injection_attack(dry_run=True)
    assert out["attack_type"] == "认证注入"
    assert len(out["seeds"]) == 3
    assert out["execution_report"] is None


def test_injection_document_poisoning(tmp_path):
    out = run_document_poisoning("ignore previous instructions", str(tmp_path), doc_type="pdf")
    assert out["status"] == "generated"
    assert os.path.exists(out["file_path"])


def test_injection_file_upload_injection_dry_run():
    out = run_file_upload_injection("<?php system($_GET['c']);?>", dry_run=True)
    assert out["count"] >= 3
    assert out["execution_report"] is None
    assert any(s["metadata"]["technique"] == "path_traversal_filename" for s in out["seeds"])


def test_evasion_audit_log_evasion_dry_run():
    out = run_audit_log_evasion(ctx=None)
    assert out["count"] >= 1
    assert out["execution_report"] is None
    assert out["seeds"][0]["metadata"]["category"] == "audit_log_evasion"


def test_evasion_encoding_evasion():
    out = run_encoding_evasion("select")
    assert out["count"] == 6
    hex_var = next(v for v in out["variants"] if v["method"] == "hex")
    assert hex_var["value"].startswith("0x")


def test_session_context_leakage():
    responses = [
        {"label": "A", "text": "session_id=abc123 token=xyz"},
        {"label": "B", "text": "session_id=abc123 different ctx"},
    ]
    out = run_context_leakage(responses)
    assert out["leak_detected"] is True
    assert "abc123" in out["leaked_tokens"]


async def test_session_idor_testing_dry_run():
    out = await run_idor_testing(["victim-sess-1"], dry_run=True)
    assert out["attack_type"] == "IDOR 验证"
    assert len(out["plan"]) == 1
    assert out["results"] is None
