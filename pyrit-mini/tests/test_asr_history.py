"""Companion test for ``core.asr_history`` (CP-009 S3).

验证 ASR history 读写件（_make_seed_key / update_asr_history）行为，
并将写入路径 monkeypatch 到临时文件以避免污染 data/seeds/asr_history.json。
"""

import json

import pytest

import core.asr_history as mod


@pytest.fixture
def patched_path(tmp_path, monkeypatch):
    p = tmp_path / "asr_history.json"
    monkeypatch.setattr(mod, "_ASR_HISTORY_PATH", p)
    return p


def test_make_seed_key_deterministic():
    k1 = mod._make_seed_key("objective A")
    k2 = mod._make_seed_key("objective A")
    assert k1 == k2 and len(k1) == 16


def test_make_seed_key_distinct():
    assert mod._make_seed_key("A") != mod._make_seed_key("B")


def test_update_asr_history_writes(patched_path):
    mod.update_asr_history({"t1": 0.5}, seed_asr={"objective X": 0.9})
    data = json.loads(patched_path.read_text(encoding="utf-8"))
    assert data["asr"] == {"t1": 0.5}
    assert "objective X" in data["seed_asr"]
