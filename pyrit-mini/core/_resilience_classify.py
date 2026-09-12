"""core/_resilience_classify.py — 故障分类与瞬时判定（从 core/resilience 抽出，R-DELIVERY-1）。

集中"HTTP 状态 / 异常 → 韧性类别"的纯函数与常量，供 `core/resilience` 的
熔断/重试策略消费。零依赖（仅标准库），不抛异常。
"""

from __future__ import annotations

# 瞬时（可重试）HTTP 状态；429 **不在此列**（由 PyRIT 原生重试处理，避免双重退避）
_TRANSIENT_STATUS = frozenset({408, 500, 502, 503, 504, 507, 509})
# 计入熔断的失败状态（含 429：限流本身是"目标在拒绝服务"的信号）
_BREAKER_FAILURE_STATUS = frozenset(_TRANSIENT_STATUS | {429})

_TRANSIENT_EXC_NAMES = frozenset(
    {
        "APIStatusError",
        "InternalServerError",
        "BadGatewayError",
        "ServiceUnavailableError",
        "GatewayTimeoutError",
        "TimeoutException",
        "APITimeoutError",
        "APIConnectionError",
        "ConnectError",
        "ReadTimeout",
        "ConnectTimeout",
        "RemoteProtocolError",
        "ServerDisconnectedError",
    }
)

# 超时类瞬时故障：单独一档（BL-038 接真 CP-003：`timeout_max_retries` / `timeout_max_delay`）。
# 超时与 5xx 的成本模型不同：超时常由长响应/慢端点触发，需要**更多次数 + 更长上限**
# 才有救回价值；5xx 快速失败则更适合短退避。分档后 ASR 免受"一刀切"策略的假阴性拖累。
_TIMEOUT_EXC_NAMES = frozenset(
    {
        "TimeoutException",
        "APITimeoutError",
        "ReadTimeout",
        "ConnectTimeout",
        "asyncio.TimeoutError",
    }
)
_TIMEOUT_TEXT_TOKENS = ("timeout", "timed out")


def classify_status(status: int | None) -> str:
    """Map an HTTP status into a resilience category."""
    if status is None:
        return "unknown"
    if 200 <= status < 300:
        return "success"
    if status == 429:
        return "rate_limited"
    if status in _TRANSIENT_STATUS:
        return "transient"
    if status in (401, 403):
        return "auth"
    return "permanent"


def status_from_exception(exc: BaseException) -> int | None:
    """Best-effort extraction of an HTTP status code from an exception."""
    for attr in ("status_code", "http_status", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and 100 <= value < 600:
            return value
    response = getattr(exc, "response", None)
    code = getattr(response, "status_code", None)
    if isinstance(code, int):
        return code
    return None


def is_timeout_error(exc: BaseException) -> bool:
    """True for timeout-class transient failures (distinct from 5xx)."""
    name = type(exc).__name__
    if name in _TIMEOUT_EXC_NAMES:
        return True
    text = str(exc).lower()
    return any(token in text for token in _TIMEOUT_TEXT_TOKENS)


def is_transient_error(exc: BaseException) -> bool:
    """True for retryable transient failures (5xx / 408 / timeout / connection)."""
    status = status_from_exception(exc)
    if status is not None:
        return status in _TRANSIENT_STATUS
    name = type(exc).__name__
    if name in _TRANSIENT_EXC_NAMES:
        return True
    text = str(exc).lower()
    return any(token in text for token in ("timeout", "connection reset", "temporarily unavailable", "502", "503", "504"))


def counts_toward_breaker(exc: BaseException) -> bool:
    """True when the failure should increment the breaker counter (incl. 429)."""
    status = status_from_exception(exc)
    if status is not None:
        return status in _BREAKER_FAILURE_STATUS
    return is_transient_error(exc)
