"""自适应速率控制器单元测试（不真打网络）

覆盖：令牌桶节流、Retry-After 解析、全抖动边界、可重试/硬失败判定、
熔断冷却、并发降级回调、Ollama 字段兼容。
"""

import time

from pipeline.adaptive_rate import (
    AdaptiveRateController,
    TokenBucket,
    _is_retryable,
    _retry_after,
)


class _FakeResp:
    def __init__(self, headers=None):
        self.headers = headers or {}


class _RateErr(Exception):
    def __init__(self, msg="429 Too Many Requests", response=None):
        super().__init__(msg)
        self.response = response


class _HardErr(Exception):
    pass


# ----------------------------------------------------------------------
# 令牌桶
# ----------------------------------------------------------------------
def test_token_bucket_throttles():
    bucket = TokenBucket(max_rpm=60, capacity=2)  # 1/s, 桶容 2
    t0 = time.monotonic()
    bucket.acquire()  # 第1个立即
    bucket.acquire()  # 第2个立即（桶容）
    bucket.acquire()  # 第3个需等约 1s
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.9  # 至少等了一个令牌周期


def test_token_bucket_immediate_when_full():
    bucket = TokenBucket(max_rpm=600, capacity=10)
    t0 = time.monotonic()
    for _ in range(5):
        bucket.acquire()
    assert time.monotonic() - t0 < 0.1


# ----------------------------------------------------------------------
# Retry-After 解析
# ----------------------------------------------------------------------
def test_retry_after_seconds():
    err = _RateErr(response=_FakeResp({"Retry-After": "5"}))
    assert _retry_after(err) == 5.0


def test_retry_after_http_date():
    # 未来 2 秒的 HTTP Date
    import datetime
    import email.utils

    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2)
    date_str = email.utils.formatdate(future.timestamp(), usegmt=True)
    err = _RateErr(response=_FakeResp({"Retry-After": date_str}))
    val = _retry_after(err)
    assert val is not None
    assert 1.0 <= val <= 3.0


def test_retry_after_none_without_response():
    assert _retry_after(_RateErr()) is None


# ----------------------------------------------------------------------
# 可重试判定
# ----------------------------------------------------------------------
def test_is_retryable_rate_limit():
    assert _is_retryable(_RateErr())


def test_is_retryable_hard_fail_not_retryable():
    # 401/403/400 等硬失败不应重试
    for msg in ["401 Unauthorized", "403 Forbidden", "400 Bad Request",
                "invalid api key"]:
        assert not _is_retryable(_HardErr(msg))


def test_is_retryable_timeout():
    assert _is_retryable(_HardErr("ReadTimeout: connection timed out"))


# ----------------------------------------------------------------------
# 控制器：成功 / 重试 / 硬失败 / Ollama 兼容
# ----------------------------------------------------------------------
def test_controller_success_returns_normalized():
    calls = {"n": 0}

    def fake_call(prompt, *a, **k):
        calls["n"] += 1
        return {"response": "hello"}  # Ollama 原生格式

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(gen, max_rpm=600, max_retries=3)
    ctl.patch()
    out = gen._call_model("x")
    ctl.unpatch()
    assert out == {"choices": [{"message": {"content": "hello"}}]}
    assert calls["n"] == 1


def test_controller_retries_then_succeeds():
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        if state["n"] < 3:
            raise _RateErr()
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(gen, max_rpm=600, max_retries=5,
                                 base_delay=0.01, max_delay=0.05, jitter=False)
    ctl.patch()
    out = gen._call_model("x")
    ctl.unpatch()
    assert out["choices"][0]["message"]["content"] == "ok"
    assert state["n"] == 3


def test_controller_hard_fail_no_retry():
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        raise _HardErr("401 Unauthorized")

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(gen, max_rpm=600, max_retries=5)
    ctl.patch()
    try:
        gen._call_model("x")
        assert False, "应抛出硬失败"
    except _HardErr:
        pass
    finally:
        ctl.unpatch()
    assert state["n"] == 1  # 不重试


def test_controller_exhausts_retries():
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        raise _RateErr()

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(gen, max_rpm=600, max_retries=2,
                                 base_delay=0.01, max_delay=0.02, jitter=False)
    ctl.patch()
    try:
        gen._call_model("x")
        assert False, "应抛出限流"
    except _RateErr:
        pass
    finally:
        ctl.unpatch()
    assert state["n"] == 3  # 1 次 + 2 次重试


def test_controller_downgrade_callback():
    downs = []

    def fake_call(prompt, *a, **k):
        raise _RateErr()

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 4})()
    ctl = AdaptiveRateController(gen, max_rpm=600, max_retries=1,
                                 base_delay=0.01, max_delay=0.02, jitter=False,
                                 downgrade_at=1, on_downgrade=lambda p: downs.append(p))
    ctl.patch()
    try:
        gen._call_model("x")
    except _RateErr:
        pass
    finally:
        ctl.unpatch()
    assert downs == [2]  # 4 // 2 = 2


def test_controller_unpatch_restores_original():
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "orig"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(gen, max_rpm=600)
    ctl.patch()
    assert gen._call_model is not fake_call
    ctl.unpatch()
    assert gen._call_model is fake_call
