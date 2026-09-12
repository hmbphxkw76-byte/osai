# -*- coding: utf-8 -*-
"""tests/test_cancellation.py — plan Wave 4.6（取消不得强杀）回归测试。

缺陷：`core/logging_config.py` 的 SIGINT 处理器在二次中断时调用 `os._exit(130)`。
`os._exit` 不抛异常、不展开栈 → 所有 `finally`（资源释放 / checkpoint 落盘 /
报告收尾）被跳过，运行产物停在半写状态且无留痕。

修复：取消状态统一由 `core.cancellation.CancellationToken` 持有；
两次中断都以**异常**方式退出（`KeyboardInterrupt` → `SystemExit(130)`），
`finally` 得以完整执行。

Constitution: C3（取消状态单一持有者）、C9（取消原因可追溯）。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.cancellation import (
    INTERRUPT_EXIT_CODE,
    CancellationToken,
    CancelledError,
    get_cancellation_token,
    request_cancel,
    reset_cancellation_token,
)


@pytest.fixture(autouse=True)
def _clean_token():
    """每个用例前复位进程级令牌，避免互相污染。"""
    reset_cancellation_token()
    yield
    reset_cancellation_token()


# ── 令牌基本语义 ────────────────────────────────────────────────────────────


def test_token_starts_not_cancelled():
    token = CancellationToken()
    assert token.is_cancelled is False
    assert token.count == 0
    assert token.reason is None
    assert bool(token) is False


def test_cancel_sets_state_and_records_reason():
    token = CancellationToken()
    assert token.cancel(reason="用户 Ctrl+C") == 1
    assert token.is_cancelled is True
    assert token.reason == "用户 Ctrl+C"
    assert bool(token) is True


def test_cancel_counts_requests_and_keeps_first_reason():
    """多次取消必须计数，且保留**首因**便于定位根因（C9）。"""
    token = CancellationToken()
    assert token.cancel(reason="first") == 1
    assert token.cancel(reason="second") == 2
    assert token.count == 2
    assert token.reason == "first"


def test_raise_if_cancelled_raises_only_when_cancelled():
    token = CancellationToken()
    token.raise_if_cancelled()  # 未取消：不抛
    token.cancel("x")
    with pytest.raises(CancelledError):
        token.raise_if_cancelled()


def test_reset_clears_state():
    token = CancellationToken()
    token.cancel("x")
    token.reset()
    assert token.is_cancelled is False and token.count == 0 and token.reason is None


def test_snapshot_is_serializable_for_audit_trail():
    token = CancellationToken()
    token.cancel("SIGINT")
    snap = token.snapshot()
    assert snap == {"cancelled": True, "count": 1, "reason": "SIGINT"}


# ── 进程级唯一实例（C3） ────────────────────────────────────────────────────


def test_global_token_is_singleton():
    assert get_cancellation_token() is get_cancellation_token()


def test_request_cancel_affects_global_token():
    assert request_cancel("test") == 1
    assert get_cancellation_token().is_cancelled is True


# ── 信号处理：不再 os._exit 强杀 ────────────────────────────────────────────


def test_signal_handler_first_press_raises_keyboard_interrupt():
    """首次中断：KeyboardInterrupt，让 asyncio/流水线正常展开栈执行 finally。"""
    from core.logging_config import _signal_handler

    with pytest.raises(KeyboardInterrupt):
        _signal_handler(2, None)


def test_signal_handler_second_press_raises_system_exit_not_os_exit():
    """二次中断：抛 SystemExit（会执行 finally），不得调用 os._exit。"""
    from core.logging_config import _signal_handler

    with pytest.raises(KeyboardInterrupt):
        _signal_handler(2, None)

    with pytest.raises(SystemExit) as exc:
        _signal_handler(2, None)
    assert exc.value.code == INTERRUPT_EXIT_CODE


def test_os_exit_no_longer_called_in_logging_config():
    """AST 层面确认不再**调用** os._exit（注释中出现该词不算，防复发）。"""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("core/logging_config.py").read_text(encoding="utf-8"))
    called = {
        f"{ast.unparse(node.func)}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert "os._exit" not in called, f"仍存在进程级强杀调用：{called & {'os._exit'}}"


def test_signal_handler_marks_token_cancelled():
    from core.logging_config import _signal_handler

    with pytest.raises(KeyboardInterrupt):
        _signal_handler(2, None)
    assert get_cancellation_token().is_cancelled is True


def test_finally_runs_on_both_interrupts():
    """核心验收：两次中断都必须让 finally 完整执行（这是 os._exit 做不到的）。"""
    from core.logging_config import _signal_handler

    cleaned: list[str] = []

    def _phase():
        try:
            _signal_handler(2, None)
        finally:
            cleaned.append("cleanup")

    with pytest.raises(KeyboardInterrupt):
        _phase()

    with pytest.raises(SystemExit):
        _phase()

    assert cleaned == ["cleanup", "cleanup"]


def test_install_signal_handlers_mounts_token_on_ctx():
    from core.logging_config import install_signal_handlers

    ctx = SimpleNamespace()
    try:
        install_signal_handlers(ctx)
        assert ctx.cancellation_token is get_cancellation_token()
    finally:
        # 恢复默认处理器，避免影响后续用例
        import signal

        signal.signal(signal.SIGINT, signal.default_int_handler)


def test_install_signal_handlers_tolerates_readonly_ctx(caplog):
    """ctx 为只读替身时不得阻塞信号安装（降级留痕，C9）。"""
    from core.logging_config import install_signal_handlers

    class _ReadOnly:
        __slots__ = ()

    try:
        with caplog.at_level("WARNING", logger="core.logging_config"):
            install_signal_handlers(_ReadOnly())
        assert any("cancellation_token" in r.getMessage() for r in caplog.records)
    finally:
        import signal

        signal.signal(signal.SIGINT, signal.default_int_handler)
