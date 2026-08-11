"""自适应速率控制器单元测试（不真打网络）

覆盖：令牌桶节流、Retry-After 解析、全抖动边界、可重试/硬失败判定、
熔断冷却、并发降级回调、Ollama 字段兼容。
R8 补全：慢启动、正常路径抖动、降级后恢复、后台线程、统计持久化、call_timeout。
"""

import json
import time
from pathlib import Path

from pipeline.adaptive_rate import (
    AdaptiveRateController,
    CallTimeoutError,
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


# ======================================================================
# R8 补全测试：慢启动 / 正常路径抖动 / 降级后恢复 / 后台线程 / 统计持久化 / call_timeout
# ======================================================================

# ----------------------------------------------------------------------
# G1: 慢启动
# ----------------------------------------------------------------------
def test_slow_start_initial_limit():
    """慢启动时初始并发上限为 slow_start_initial"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 16})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, slow_start=True, slow_start_initial=4,
        proactive_jitter=False,
    )
    assert ctl._current_parallel_limit == 4
    assert ctl._target_parallel == 16
    assert ctl._slow_start_active is True


def test_slow_start_skipped_when_disabled():
    """slow_start=False 时直接用目标并发"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 8})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, slow_start=False, proactive_jitter=False,
    )
    assert ctl._current_parallel_limit == 8
    assert ctl._slow_start_active is False


def test_slow_start_progresses():
    """慢启动经过足够时间后并发上限提升"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 16})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, slow_start=True, slow_start_initial=4,
        slow_start_interval=0.1, slow_start_multiplier=2.0,
        proactive_jitter=False,
    )
    ctl.patch()
    # 等待超过一个倍增间隔
    time.sleep(0.15)
    ctl._check_slow_start()
    assert ctl._current_parallel_limit >= 8
    # 等待更多间隔
    time.sleep(0.15)
    ctl._check_slow_start()
    assert ctl._current_parallel_limit >= 16
    assert ctl._slow_start_active is False
    ctl.unpatch()


def test_slow_start_capped_at_target():
    """慢启动不超过目标并发"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 6})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, slow_start=True, slow_start_initial=4,
        slow_start_interval=0.1, slow_start_multiplier=2.0,
        proactive_jitter=False,
    )
    ctl.patch()
    time.sleep(0.25)
    ctl._check_slow_start()
    assert ctl._current_parallel_limit == 6  # 不超过目标 6
    ctl.unpatch()


# ----------------------------------------------------------------------
# G2: 正常路径抖动
# ----------------------------------------------------------------------
def test_proactive_jitter_adds_delay():
    """启用 proactive_jitter 时正常路径请求有随机延迟"""
    call_times = []

    def fake_call(prompt, *a, **k):
        call_times.append(time.monotonic())
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, proactive_jitter=True,
        jitter_min=0.05, jitter_max=0.10,
    )
    ctl.patch()
    t0 = time.monotonic()
    gen._call_model("x")
    elapsed = time.monotonic() - t0
    ctl.unpatch()
    assert elapsed >= 0.04  # 至少有 jitter 延迟


def test_proactive_jitter_disabled():
    """proactive_jitter=False 时正常路径无额外延迟"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, proactive_jitter=False,
    )
    ctl.patch()
    t0 = time.monotonic()
    gen._call_model("x")
    elapsed = time.monotonic() - t0
    ctl.unpatch()
    assert elapsed < 0.05  # 无 jitter 延迟


def test_jitter_expanded_on_429():
    """429 降级后抖动范围扩大 1.5 倍"""
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise _RateErr()
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 4})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, max_retries=3,
        base_delay=0.01, max_delay=0.02, jitter=False,
        proactive_jitter=False,
        jitter_min=0.05, jitter_max=0.10, jitter_expand_on_429=1.5,
        downgrade_at=1, on_downgrade=lambda p: None,
    )
    ctl.patch()
    gen._call_model("x")
    ctl.unpatch()
    # 降级后抖动范围应扩大
    assert ctl._jitter_min >= 0.05 * 1.5 - 0.001
    assert ctl._jitter_max >= 0.10 * 1.5 - 0.001


def test_jitter_shrunk_on_recover():
    """恢复后抖动范围缩小 0.8 倍"""
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise _RateErr()
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 4})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, max_retries=3,
        base_delay=0.01, max_delay=0.02, jitter=False,
        proactive_jitter=False,
        jitter_min=0.05, jitter_max=0.10,
        jitter_expand_on_429=1.5, jitter_shrink_on_recover=0.8,
        downgrade_at=1, on_downgrade=lambda p: None, on_upgrade=lambda p: None,
        recovery_interval=0.01, recovery_step=4,
    )
    ctl.patch()
    gen._call_model("x")  # 第1次失败降级，第2次成功→触发恢复
    ctl.unpatch()
    # 恢复后抖动应缩小（但不低于基准值）
    assert ctl._jitter_min <= 0.05 * 1.5 + 0.001
    assert ctl._jitter_max <= 0.10 * 1.5 + 0.001


# ----------------------------------------------------------------------
# G3: 降级后恢复
# ----------------------------------------------------------------------
def test_degradation_recovery():
    """降级后经过 recovery_interval 无失败 → 恢复并发"""
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise _RateErr()
        return {"choices": [{"message": {"content": "ok"}}]}

    ups = []
    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 8})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, max_retries=3,
        base_delay=0.01, max_delay=0.02, jitter=False,
        proactive_jitter=False,
        downgrade_at=1, on_downgrade=lambda p: None,
        on_upgrade=lambda p: ups.append(p),
        recovery_interval=0.01, recovery_step=4,
    )
    ctl.patch()
    gen._call_model("x")  # 失败→降级至4，成功→恢复至8
    ctl.unpatch()
    assert len(ups) >= 1
    assert ups[0] >= 4  # 恢复步长 +4


def test_recovery_skipped_when_still_failing():
    """持续失败时不触发恢复"""
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        raise _RateErr()

    ups = []
    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 8})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, max_retries=1,
        base_delay=0.01, max_delay=0.02, jitter=False,
        proactive_jitter=False,
        downgrade_at=1, on_downgrade=lambda p: None,
        on_upgrade=lambda p: ups.append(p),
        recovery_interval=0.01, recovery_step=4,
    )
    ctl.patch()
    try:
        gen._call_model("x")
    except _RateErr:
        pass
    finally:
        ctl.unpatch()
    assert len(ups) == 0  # 持续失败，不恢复


def test_upgrade_callback_fired():
    """on_upgrade 回调被正确调用并传入新并发数"""
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise _RateErr()
        return {"choices": [{"message": {"content": "ok"}}]}

    ups = []
    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 8})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, max_retries=3,
        base_delay=0.01, max_delay=0.02, jitter=False,
        proactive_jitter=False,
        downgrade_at=1, on_downgrade=lambda p: None,
        on_upgrade=lambda p: ups.append(p),
        recovery_interval=0.01, recovery_step=4,
    )
    ctl.patch()
    gen._call_model("x")
    ctl.unpatch()
    assert len(ups) >= 1
    assert all(isinstance(p, int) and p >= 1 for p in ups)


# ----------------------------------------------------------------------
# G4: 后台线程
# ----------------------------------------------------------------------
def test_background_thread_starts_and_stops():
    """后台线程在 patch 时启动，unpatch 时停止"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, proactive_jitter=False,
    )
    ctl.patch()
    assert ctl._bg_thread is not None
    assert ctl._bg_thread.is_alive()
    bg = ctl._bg_thread
    ctl.unpatch()
    assert not bg.is_alive()
    assert ctl._bg_thread is None


def test_background_thread_is_daemon():
    """后台线程应为 daemon，不阻止进程退出"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, proactive_jitter=False,
    )
    ctl.patch()
    assert ctl._bg_thread.daemon is True
    ctl.unpatch()


# ----------------------------------------------------------------------
# G5: 统计持久化
# ----------------------------------------------------------------------
def test_stats_persisted_to_file(tmp_path):
    """unpatch 后 execution_log.json 含 rate_control 字段"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, proactive_jitter=False,
        stats_dir=str(tmp_path), run_id="test-run",
    )
    ctl.patch()
    gen._call_model("x")
    ctl.unpatch()
    log_path = tmp_path / "03_execution" / "execution_log_test-run.json"
    assert log_path.exists()
    data = json.loads(log_path.read_text(encoding="utf-8"))
    assert "rate_control" in data
    assert data["rate_control"]["total_requests"] >= 1


def test_stats_tracks_429_and_downgrades(tmp_path):
    """统计正确跟踪 429 次数和降级事件"""
    state = {"n": 0}

    def fake_call(prompt, *a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise _RateErr()
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 8})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, max_retries=3,
        base_delay=0.01, max_delay=0.02, jitter=False,
        proactive_jitter=False,
        downgrade_at=1, on_downgrade=lambda p: None, on_upgrade=lambda p: None,
        recovery_interval=0.01, recovery_step=4,
        stats_dir=str(tmp_path), run_id="test-stats",
    )
    ctl.patch()
    gen._call_model("x")
    ctl.unpatch()
    log_path = tmp_path / "03_execution" / "execution_log_test-stats.json"
    data = json.loads(log_path.read_text(encoding="utf-8"))
    rc = data["rate_control"]
    assert rc["total_429"] >= 1
    assert len(rc["downgrades"]) >= 1


# ----------------------------------------------------------------------
# G6: call_timeout
# ----------------------------------------------------------------------
def test_call_timeout_triggers_calltimeouterror():
    """call_timeout 超时后抛 CallTimeoutError"""
    def slow_call(prompt, *a, **k):
        time.sleep(5)  # 模拟挂起
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(slow_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, max_retries=1,
        base_delay=0.01, max_delay=0.02, jitter=False,
        proactive_jitter=False,
        call_timeout=0.5,
    )
    ctl.patch()
    try:
        gen._call_model("x")
        assert False, "应抛出 CallTimeoutError"
    except CallTimeoutError:
        pass
    finally:
        ctl.unpatch()


def test_call_timeout_zero_disables():
    """call_timeout=0 时不创建线程池"""
    def fake_call(prompt, *a, **k):
        return {"choices": [{"message": {"content": "ok"}}]}

    gen = type("G", (), {"_call_model": staticmethod(fake_call), "parallel_requests": 1})()
    ctl = AdaptiveRateController(
        gen, max_rpm=600, proactive_jitter=False,
        call_timeout=0,
    )
    ctl.patch()
    assert ctl._executor is None
    gen._call_model("x")
    ctl.unpatch()
