"""Tests for REQ-152: ExfilChannel (canary/OOB receipts) + ADR-008 four-state verdict."""

from __future__ import annotations

import urllib.request

import pytest

from assess.impact.exfil import (
    CANARY_PREFIX,
    OOBReceiptLog,
    build_callback_url,
    extract_canaries,
    generate_canary,
)
from assess.impact.verdict import (
    CONTENT_ONLY,
    EXFIL_CONFIRMED,
    EXFIL_SUSPECTED,
    IMPACT,
    decide_verdict,
    is_confirmed,
)


class TestCanary:
    def test_unique_and_prefixed(self) -> None:
        a, b = generate_canary(), generate_canary()
        assert a != b
        assert a.startswith(CANARY_PREFIX + "_")

    def test_extract_canaries(self) -> None:
        c1, c2 = generate_canary(), generate_canary()
        text = f"sent {c1} and also {c2} plus noise"
        assert set(extract_canaries(text)) == {c1, c2}

    def test_extract_from_non_string(self) -> None:
        assert extract_canaries(None) == []

    def test_build_callback_url(self) -> None:
        url = build_callback_url("http://127.0.0.1:8899", "AOBC_deadbeef")
        assert url == "http://127.0.0.1:8899?c=AOBC_deadbeef"
        url2 = build_callback_url("http://h/p?x=1", "AOBC_deadbeef")
        assert url2.endswith("&c=AOBC_deadbeef")


class TestReceiptLog:
    def test_record_and_query(self) -> None:
        log = OOBReceiptLog()
        canary = generate_canary()
        assert log.has_receipt(canary) is False
        log.record(canary=canary, path="/cb", remote="10.0.0.9")
        assert log.has_receipt(canary) is True
        assert len(log.find(canary)) == 1
        log.clear()
        assert log.has_receipt(canary) is False

    def test_wait_zero_timeout_single_check(self) -> None:
        log = OOBReceiptLog()
        assert log.wait(generate_canary(), timeout=0.0) is False


class TestVerdict:
    def test_oob_receipt_gives_exfil_confirmed(self) -> None:
        log = OOBReceiptLog()
        canary = generate_canary()
        log.record(canary=canary)
        v = decide_verdict(canaries=[canary], receipt_log=log, response_text="anything")
        assert v["verdict"] == EXFIL_CONFIRMED and v["confirmed"] is True

    def test_side_effect_second_check_gives_impact(self) -> None:
        v = decide_verdict(side_effect_confirmed=True)
        assert v["verdict"] == IMPACT and v["confirmed"] is True

    def test_text_marker_is_only_suspected(self) -> None:
        v = decide_verdict(response_text="I have exfil_data and transmitted to http://x")
        assert v["verdict"] == EXFIL_SUSPECTED and v["confirmed"] is False

    def test_canary_echo_without_receipt_is_suspected(self) -> None:
        canary = generate_canary()
        log = OOBReceiptLog()  # no receipt recorded
        v = decide_verdict(canaries=[canary], receipt_log=log, response_text=f"leaked {canary}")
        assert v["verdict"] == EXFIL_SUSPECTED and v["confirmed"] is False

    def test_plain_content_only(self) -> None:
        v = decide_verdict(response_text="Here is a normal answer.")
        assert v["verdict"] == CONTENT_ONLY and v["confirmed"] is False

    def test_is_confirmed_only_two_states(self) -> None:
        assert is_confirmed(IMPACT) and is_confirmed(EXFIL_CONFIRMED)
        assert not is_confirmed(EXFIL_SUSPECTED)
        assert not is_confirmed(CONTENT_ONLY)
        assert not is_confirmed(None)

    def test_broken_receipt_log_does_not_fake_confirmation(self) -> None:
        class _Broken:
            def has_receipt(self, canary):
                raise RuntimeError("boom")

        v = decide_verdict(canaries=[generate_canary()], receipt_log=_Broken())
        assert v["confirmed"] is False


class TestOOBListenerE2E:
    def test_listener_records_callback(self) -> None:
        from assess.impact.exfil import get_receipt_log
        from tools.oob_listener import OOBListener

        log = get_receipt_log()
        log.clear()
        listener = OOBListener(port=0).start()
        try:
            canary = generate_canary()
            with urllib.request.urlopen(build_callback_url(listener.url, canary), timeout=5) as resp:
                assert resp.status == 200
            assert log.wait(canary, timeout=3.0) is True
            assert log.find(canary)[0].path.startswith("/?c=")
        finally:
            listener.stop()
            log.clear()

    def test_listener_random_port(self) -> None:
        from tools.oob_listener import OOBListener

        listener = OOBListener(port=0).start()
        try:
            assert listener.port > 0
            assert listener.url.startswith("http://127.0.0.1:")
        finally:
            listener.stop()


@pytest.mark.parametrize("state", [IMPACT, EXFIL_CONFIRMED, EXFIL_SUSPECTED, CONTENT_ONLY])
def test_verdict_states_are_stable_strings(state: str) -> None:
    assert isinstance(state, str) and state.islower()
