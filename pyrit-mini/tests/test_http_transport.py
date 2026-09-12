# -*- coding: utf-8 -*-
"""tests/test_http_transport.py — plan Wave 2.10（C1 R-NATIVE-4 / C13）回归测试。

`strike/web/http_engine.py` 此前用 `urllib.request` 自建连接发请求，违反宪法
C1 R-NATIVE-4（Target 须用 PyRIT 原生类）与 C13 原则 2（扩展层只构造 payload/target
配置，攻击执行一律委托原生类）。本测试锁定：
    1. 请求执行**委托** `pyrit.prompt_target.HTTPTarget`；
    2. 原始 HTTP 请求由本模块构造（payload 层职责），格式合法；
    3. 原生通道不可用时降级**必须留痕**，且结果标记 `transport` 字段（C9 禁止静默）。
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from strike.web.http_engine import (
    TRANSPORT_FALLBACK,
    TRANSPORT_NATIVE,
    HTTPAttackEngine,
)

# ── 原始请求构造（payload 层职责） ──────────────────────────────────────────


def test_build_raw_request_has_valid_request_line():
    raw = HTTPAttackEngine._build_raw_request("POST", "https://example.com/api/chat", {}, "")
    assert raw.splitlines()[0] == "POST /api/chat HTTP/1.1"


def test_build_raw_request_injects_host_header():
    raw = HTTPAttackEngine._build_raw_request("GET", "https://api.example.com:8443/v1/x", {}, "")
    assert "Host: api.example.com:8443" in raw


def test_build_raw_request_appends_custom_headers_and_body():
    raw = HTTPAttackEngine._build_raw_request("POST", "https://example.com/p", {"X-Test": "1"}, '{"a": 1}')
    assert "X-Test: 1" in raw
    assert raw.endswith("\n\n" + '{"a": 1}')


def test_build_raw_request_method_is_uppercased():
    raw = HTTPAttackEngine._build_raw_request("delete", "https://example.com/p", {}, "")
    assert raw.startswith("DELETE ")


# ── 委托 PyRIT 原生 HTTPTarget ──────────────────────────────────────────────


def _install_native_mocks(status: int = 200, headers: dict | None = None, text: str = "OK-BODY"):
    """安装原生通道替身，返回 (HTTPTarget mock, 用后可读取的调用记录)。"""
    headers = headers if headers is not None else {"X-Cache": "HIT"}
    target = MagicMock()

    async def _fake_send(*, message):  # noqa: ARG001 - 签名需与原生一致
        callback = target_cls.call_args.kwargs["callback_function"]
        callback(response=SimpleNamespace(status_code=status, headers=headers, text=text))
        return [SimpleNamespace(message_pieces=[SimpleNamespace(converted_value=text, response_error="none")])]

    target.send_prompt_async = AsyncMock(side_effect=_fake_send)
    target_cls = MagicMock(return_value=target)
    return target_cls, target


def test_send_delegates_to_native_http_target():
    engine = HTTPAttackEngine("https://example.com/api/chat")
    target_cls, _ = _install_native_mocks()

    with (
        patch("pyrit.memory.CentralMemory") as mem,
        patch("pyrit.prompt_target.HTTPTarget", target_cls, create=True),
    ):
        mem.get_memory_instance.return_value = MagicMock()
        result = engine.send_request(method="POST", url="https://example.com/api/chat", body="hello")

    target_cls.assert_called_once()
    assert result["transport"] == TRANSPORT_NATIVE
    assert result["status"] == 200
    assert result["body"] == "OK-BODY"
    assert result["headers"]["X-Cache"] == "HIT"


def test_native_path_receives_raw_request_with_body():
    engine = HTTPAttackEngine("https://example.com/api/chat")
    target_cls, _ = _install_native_mocks()

    with (
        patch("pyrit.memory.CentralMemory") as mem,
        patch("pyrit.prompt_target.HTTPTarget", target_cls, create=True),
    ):
        mem.get_memory_instance.return_value = MagicMock()
        engine.send_request(method="POST", url="https://example.com/api/chat", body="PAYLOAD")

    http_request = target_cls.call_args.kwargs["http_request"]
    assert "POST /api/chat HTTP/1.1" in http_request
    assert http_request.endswith("PAYLOAD")


def test_native_response_error_is_surfaced():
    engine = HTTPAttackEngine("https://example.com/x")
    target_cls = MagicMock()
    target = MagicMock()

    async def _fake_send(*, message):  # noqa: ARG001
        return [SimpleNamespace(message_pieces=[SimpleNamespace(converted_value="", response_error="blocked")])]

    target.send_prompt_async = AsyncMock(side_effect=_fake_send)
    target_cls.return_value = target

    with (
        patch("pyrit.memory.CentralMemory") as mem,
        patch("pyrit.prompt_target.HTTPTarget", target_cls, create=True),
    ):
        mem.get_memory_instance.return_value = MagicMock()
        result = engine.send_request()

    assert result["error"] == "blocked"
    assert result["transport"] == TRANSPORT_NATIVE


# ── 降级必须留痕（C9） ──────────────────────────────────────────────────────


def test_fallback_used_when_native_unavailable_and_logs_warning(caplog):
    """原生不可用时降级，但必须 WARNING 说明原因，禁止静默（C1 违例要可见）。"""
    engine = HTTPAttackEngine("http://127.0.0.1:9/none", default_timeout=1.0)

    with patch("pyrit.memory.CentralMemory") as mem:
        mem.get_memory_instance.side_effect = ValueError("Central memory instance has not been set")
        with caplog.at_level("WARNING", logger="strike.web.http_engine"):
            result = engine.send_request()

    assert result["transport"] == TRANSPORT_FALLBACK
    assert any("HTTPTarget" in r.getMessage() for r in caplog.records)
    assert engine._native_unavailable_reason is not None


def test_fallback_reason_cached_to_avoid_warning_flood(caplog):
    """降级原因只探测一次：避免每个 payload 重复告警刷屏。"""
    engine = HTTPAttackEngine("http://127.0.0.1:9/none", default_timeout=1.0)
    with patch("pyrit.memory.CentralMemory") as mem:
        mem.get_memory_instance.side_effect = ValueError("no memory")
        with caplog.at_level("WARNING", logger="strike.web.http_engine"):
            engine.send_request()
            first = len(caplog.records)
            engine.send_request()

    assert len(caplog.records) == first, "降级原因应被缓存，不应每个 payload 重复告警"
    assert mem.get_memory_instance.call_count == 1


# ── 调用方复用同一链路 ──────────────────────────────────────────────────────


def test_send_single_payload_returns_name_and_transport():
    engine = HTTPAttackEngine("https://example.com/api/chat")
    target_cls, _ = _install_native_mocks()
    with (
        patch("pyrit.memory.CentralMemory") as mem,
        patch("pyrit.prompt_target.HTTPTarget", target_cls, create=True),
    ):
        mem.get_memory_instance.return_value = MagicMock()
        result = engine._send_single_payload({"name": "PUT方法", "method": "PUT", "body": "{}"})

    assert result["name"] == "PUT方法"
    assert result["transport"] == TRANSPORT_NATIVE


def test_cache_poison_header_uses_two_requests_and_detects_cache_header():
    engine = HTTPAttackEngine("https://example.com/")
    target_cls, _ = _install_native_mocks(headers={"X-Cache": "HIT"})
    with (
        patch("pyrit.memory.CentralMemory") as mem,
        patch("pyrit.prompt_target.HTTPTarget", target_cls, create=True),
    ):
        mem.get_memory_instance.return_value = MagicMock()
        result = engine._test_cache_poison_header("X-Forwarded-Host")

    assert target_cls.call_count == 2, "缓存投毒需「注入 + 验证」两次请求"
    assert result["cache_hit"] is True
    assert result["first_status"] == 200 and result["second_status"] == 200


def test_version_bypass_preserves_url_field():
    engine = HTTPAttackEngine("https://example.com/api/v1/chat")
    target_cls, _ = _install_native_mocks()
    with (
        patch("pyrit.memory.CentralMemory") as mem,
        patch("pyrit.prompt_target.HTTPTarget", target_cls, create=True),
    ):
        mem.get_memory_instance.return_value = MagicMock()
        result = engine._send_version_bypass_request("https://example.com", {"name": "v0版本", "path": "/api/v0/admin"})

    assert result["url"] == "https://example.com/api/v0/admin"
    assert result["name"] == "v0版本"


def test_execute_attack_returns_all_results():
    engine = HTTPAttackEngine("https://example.com/")
    target_cls, _ = _install_native_mocks()
    with (
        patch("pyrit.memory.CentralMemory") as mem,
        patch("pyrit.prompt_target.HTTPTarget", target_cls, create=True),
    ):
        mem.get_memory_instance.return_value = MagicMock()
        report = engine.execute_attack("t", [{"name": "a"}, {"name": "b"}])

    assert report["attack_type"] == "t"
    assert len(report["results"]) == 2


def test_rate_limit_test_uses_shared_transport():
    """WebAttacks 不得再自建 urllib 连接，必须复用引擎的传输链路。"""
    from strike.web.attacks import WebAttacks

    wa = WebAttacks("http://127.0.0.1:9/none", default_timeout=1.0)
    with patch.object(wa.engine, "send_request") as send:
        send.return_value = {"status": 429, "headers": {}, "transport": TRANSPORT_FALLBACK}
        report = wa.rate_limit_test(max_concurrent=3, timeout=1.0)

    assert send.call_count == 3
    assert report["attack_type"] == "速率限制测试"


def test_run_coroutine_sync_works_inside_running_loop():
    """同步入口在 async 上下文中仍可用（转到独立线程执行）。"""
    import asyncio

    from strike.web.http_engine import _run_coroutine_sync

    async def _outer():
        async def _inner():
            return 42

        return _run_coroutine_sync(_inner())

    assert asyncio.run(_outer()) == 42
