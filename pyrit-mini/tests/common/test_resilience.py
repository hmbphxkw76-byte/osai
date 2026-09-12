"""Tests for REQ-170: circuit breaker + transient 5xx retry (wired into RateLimitedTarget)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from core.resilience import (
    ON_OPEN_PAUSE,
    ON_OPEN_SLOW,
    ON_OPEN_TERMINATE,
    CircuitBreaker,
    CircuitOpenError,
    CircuitTerminatedError,
    ResiliencePolicy,
    RetryPolicy,
    build_target_resilience,
    classify_status,
    counts_toward_breaker,
    default_settings,
    is_transient_error,
    make_retry_policy,
    status_from_exception,
)
from recon.target_wrapper import RateLimitedTarget


class _HTTPError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status} error")
        self.status_code = status


class _Resp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeTarget:
    """Minimal stand-in for a PyRIT PromptTarget delegate."""

    def __init__(self, outcomes: list[object]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list) -> list:
        self.calls += 1
        outcome = self._outcomes.pop(0) if self._outcomes else "ok"
        if isinstance(outcome, Exception):
            raise outcome
        return [outcome]


def _make_wrapper(
    outcomes: list[object],
    *,
    breaker: CircuitBreaker | None = None,
    policy: ResiliencePolicy | None = None,
    retry: RetryPolicy | None = None,
    events: list | None = None,
) -> RateLimitedTarget:
    """Build a RateLimitedTarget bypassing PromptTarget.__init__ (unit isolation)."""
    obj = RateLimitedTarget.__new__(RateLimitedTarget)
    obj._target = _FakeTarget(outcomes)
    obj._breaker = breaker
    obj._policy = (policy or ResiliencePolicy()).normalized()
    obj._retry_policy = retry or RetryPolicy(max_attempts=3, base_delay=0.0, max_delay=0.0, jitter=False)
    sink = events if events is not None else []
    obj._on_breaker_event = (lambda e: sink.append(e)) if events is not None else None
    obj._endpoint = "https://t.example.com"
    obj._endpoint_attr = "t.example.com"
    obj._use_tls = True
    obj._auth_manager = None
    obj._auth_state = None
    obj._semaphore = asyncio.Semaphore(1)
    return obj


def _run(wrapper: RateLimitedTarget):
    return asyncio.run(wrapper._send_with_auth_recovery(normalized_conversation=[]))


class TestStatusClassification:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [(200, "success"), (204, "success"), (429, "rate_limited"), (503, "transient"), (401, "auth"), (404, "permanent")],
    )
    def test_classify_status(self, status: int, expected: str) -> None:
        assert classify_status(status) == expected

    def test_none_status(self) -> None:
        assert classify_status(None) == "unknown"

    def test_status_from_exception_attr(self) -> None:
        assert status_from_exception(_HTTPError(502)) == 502

    def test_status_from_response(self) -> None:
        exc = Exception("boom")
        exc.response = _Resp(504)  # type: ignore[attr-defined]
        assert status_from_exception(exc) == 504

    def test_status_from_exception_missing(self) -> None:
        assert status_from_exception(Exception("plain")) is None

    def test_is_transient(self) -> None:
        assert is_transient_error(_HTTPError(503)) is True
        assert is_transient_error(_HTTPError(408)) is True
        assert is_transient_error(TimeoutError("timeout")) is True
        # 429 由 PyRIT 原生重试，本层不重复
        assert is_transient_error(_HTTPError(429)) is False
        assert is_transient_error(_HTTPError(400)) is False

    def test_counts_toward_breaker_includes_429(self) -> None:
        assert counts_toward_breaker(_HTTPError(429)) is True
        assert counts_toward_breaker(_HTTPError(500)) is True
        assert counts_toward_breaker(_HTTPError(404)) is False


class TestRetryPolicy:
    def test_exponential_without_jitter(self) -> None:
        policy = RetryPolicy(max_attempts=4, base_delay=1.0, max_delay=100.0, jitter=False)
        assert [policy.delay_for(i) for i in (1, 2, 3, 4)] == [1.0, 2.0, 4.0, 8.0]

    def test_capped_at_max_delay(self) -> None:
        policy = RetryPolicy(base_delay=10.0, max_delay=15.0, jitter=False)
        assert policy.delay_for(5) == 15.0

    def test_jitter_bounded(self) -> None:
        policy = RetryPolicy(base_delay=4.0, max_delay=100.0, jitter=True)
        for attempt in range(1, 5):
            assert 0.0 <= policy.delay_for(attempt) <= 4.0 * (2 ** (attempt - 1))

    def test_make_retry_policy_from_settings(self) -> None:
        policy = make_retry_policy({"retry_max_attempts": 7, "retry_base_delay": 2.0, "retry_max_delay": 9.0, "retry_jitter": False})
        assert policy.max_attempts == 7 and policy.base_delay == 2.0 and policy.max_delay == 9.0
        assert policy.jitter is False


class TestCircuitBreaker:
    def test_closed_allows(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states)
        assert breaker.before_request().allowed is True
        assert states["t"]["state"] == "closed"

    def test_opens_after_threshold(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=2, cooldown_seconds=60)
        breaker.record_failure("503")
        assert breaker.before_request().allowed is True
        breaker.record_failure("503")
        decision = breaker.before_request()
        assert decision.allowed is False and decision.state == "open"
        assert decision.retry_after > 0

    def test_half_open_after_cooldown_then_closes_on_success(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=0.0)
        breaker.record_failure("503")
        assert breaker.before_request().allowed is True  # cooldown 0 → half_open
        assert states["t"]["state"] == "half_open"
        breaker.record_success()
        assert states["t"]["state"] == "closed" and states["t"]["failures"] == 0

    def test_half_open_failure_reopens_immediately(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=0.0)
        breaker.record_failure("503")
        assert states["t"]["state"] == "open"
        assert breaker.before_request().allowed is True  # cooldown 0 → half_open
        assert states["t"]["state"] == "half_open"
        breaker.record_failure("503")  # half_open 下任何失败立即 open
        assert states["t"]["state"] == "open"
        assert states["t"]["opened_at"] > 0  # 重新打开并刷新打开时间戳

    def test_half_open_probe_limit(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=0.0, half_open_max_calls=1)
        breaker.record_failure("503")
        assert breaker.before_request().allowed is True
        second = breaker.before_request()
        assert second.allowed is False and second.reason == "half_open_probe_busy"

    def test_state_is_stored_in_shared_dict(self) -> None:
        states: dict = {}
        CircuitBreaker("shared", states).record_failure("x")
        assert "shared" in states and states["shared"]["failures"] == 1


class TestDefaults:
    def test_defaults_yaml_declares_resilience_block(self) -> None:
        settings = default_settings()
        for key in (
            "breaker_failure_threshold",
            "breaker_cooldown_seconds",
            "on_open",
            "retry_max_attempts",
            "retry_base_delay",
            "retry_max_delay",
            "retry_jitter",
        ):
            assert key in settings, f"defaults.yaml:resilience 缺少 {key}（C7 断链）"


class TestBuildTargetResilience:
    def _ctx(self) -> SimpleNamespace:
        return SimpleNamespace(_circuit_breaker_states={}, orchestration_log=[], event_log=None)

    def test_returns_kwargs(self) -> None:
        kwargs = build_target_resilience(self._ctx(), "https://t")
        assert set(kwargs) == {"circuit_breaker", "resilience_policy", "on_breaker_event"}

    def test_records_into_orchestration_log(self) -> None:
        ctx = self._ctx()
        kwargs = build_target_resilience(ctx, "https://t")
        kwargs["circuit_breaker"].record_failure("503")
        kwargs["on_breaker_event"]({"state": "open", "action": "blocked"})
        assert ctx.orchestration_log[0]["decision"] == "circuit_breaker"
        assert ctx._circuit_breaker_states  # 状态写入既有 ctx 字段（消除 stub）

    def test_event_sink_failure_is_non_fatal(self) -> None:
        ctx = SimpleNamespace(_circuit_breaker_states={}, orchestration_log=None, event_log=None)

        class _Boom:
            def append(self, _item):
                raise RuntimeError("boom")

        ctx.orchestration_log = _Boom()
        kwargs = build_target_resilience(ctx, "https://t")
        kwargs["on_breaker_event"]({"state": "open"})  # 不抛异常

    def test_ctx_without_field_returns_empty(self) -> None:
        assert build_target_resilience(SimpleNamespace(), "https://t") == {}


class TestRateLimitedTargetIntegration:
    def test_transient_retry_then_success(self) -> None:
        wrapper = _make_wrapper([_HTTPError(503), _HTTPError(502), "ok"])
        assert _run(wrapper) == ["ok"]
        assert wrapper._target.calls == 3

    def test_stops_at_max_attempts(self) -> None:
        wrapper = _make_wrapper([_HTTPError(500)] * 5)
        with pytest.raises(_HTTPError):
            _run(wrapper)
        assert wrapper._target.calls == 3  # max_attempts=3

    def test_non_transient_not_retried(self) -> None:
        wrapper = _make_wrapper([_HTTPError(400)])
        with pytest.raises(_HTTPError):
            _run(wrapper)
        assert wrapper._target.calls == 1

    def test_breaker_opens_and_blocks(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=60)
        policy = ResiliencePolicy(on_open=ON_OPEN_PAUSE, max_pause_seconds=0.0)
        wrapper = _make_wrapper([_HTTPError(503)] * 6, breaker=breaker, policy=policy)
        with pytest.raises(_HTTPError):
            _run(wrapper)
        assert states["t"]["state"] == "open"
        with pytest.raises(CircuitOpenError):
            _run(wrapper)

    def test_terminate_policy_raises_terminated(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=60)
        breaker.record_failure("503")
        wrapper = _make_wrapper(["ok"], breaker=breaker, policy=ResiliencePolicy(on_open=ON_OPEN_TERMINATE))
        with pytest.raises(CircuitTerminatedError):
            _run(wrapper)
        assert wrapper._target.calls == 0

    def test_pause_policy_recovers_when_cooldown_elapsed(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=0.0)
        breaker.record_failure("503")
        wrapper = _make_wrapper(["ok"], breaker=breaker, policy=ResiliencePolicy(on_open=ON_OPEN_PAUSE))
        assert _run(wrapper) == ["ok"]

    def test_slow_policy_recovers(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=0.0)
        breaker.record_failure("503")
        wrapper = _make_wrapper(["ok"], breaker=breaker, policy=ResiliencePolicy(on_open=ON_OPEN_SLOW))
        assert _run(wrapper) == ["ok"]

    def test_breaker_records_success_after_recovery(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=4, cooldown_seconds=60)
        events: list = []
        wrapper = _make_wrapper(["ok"], breaker=breaker, events=events)
        assert _run(wrapper) == ["ok"]
        assert states["t"]["successes"] == 1
        assert events == []  # closed → 无需留痕

    def test_no_breaker_still_retries(self) -> None:
        wrapper = _make_wrapper([_HTTPError(503), "ok"])
        assert _run(wrapper) == ["ok"]

    def test_breaker_events_emitted_on_open(self) -> None:
        states: dict = {}
        breaker = CircuitBreaker("t", states, failure_threshold=1, cooldown_seconds=60)
        events: list = []
        wrapper = _make_wrapper([_HTTPError(503)] * 4, breaker=breaker, events=events)
        with pytest.raises(_HTTPError):
            _run(wrapper)
        assert any(e.get("state") == "open" for e in events)
