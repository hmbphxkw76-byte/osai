"""core/resilience.py — 熔断 + 瞬时故障重试（REQ-170 / R-S3 / NFR-14）。

目标（REQ-170）：
    ① 目标 5xx/限流触发熔断，策略可配（pause / slow / terminate）；
    ② 客户端 5xx 重试（指数退避 + jitter，参数取自 `config/defaults.yaml:resilience`）；
    ③ 接线 `ctx._circuit_breaker_states`（消除 stub —— 该字段此前零消费者）；
    ④ 熔断决策写入 `ctx.orchestration_log` + EventLog。

设计约束：
    - **零新增依赖**（NEG-4）：仅标准库（`time` / `random` / `dataclasses`）。
    - 状态直接存放在 `ctx._circuit_breaker_states`（既有字段即存储，SSOT，可序列化进
      报告/manifest），不在 ctx 上新增旁路属性（NEG-3 / I12）。
    - 默认**不改变攻击语义**：仅在瞬时故障（5xx / 408 / 超时 / 连接）时重试；
      429 交由 PyRIT 原生 `@pyrit_target_retry` 处理，避免双重退避放大。

学术依据：
    - Nygard, "Release It!" 2nd Ed. (2018) — Circuit Breaker
    - NIST SP 800-115 Sec4 — 面向不可靠目标的服务降级策略
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# 熔断状态
STATE_CLOSED = "closed"
STATE_OPEN = "open"
STATE_HALF_OPEN = "half_open"

# 熔断打开时的策略（REQ-170 ①）
ON_OPEN_PAUSE = "pause"
ON_OPEN_SLOW = "slow"
ON_OPEN_TERMINATE = "terminate"
ON_OPEN_STRATEGIES: tuple[str, ...] = (ON_OPEN_PAUSE, ON_OPEN_SLOW, ON_OPEN_TERMINATE)

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


class CircuitOpenError(RuntimeError):
    """熔断打开，请求被拒绝（上层可选择降级/终止）。"""


class CircuitTerminatedError(CircuitOpenError):
    """策略 `terminate`：熔断打开且不再重试（对应 campaign 终止）。"""


@dataclass
class BreakerDecision:
    """单次准入判定的结果。"""

    allowed: bool
    state: str
    retry_after: float = 0.0
    reason: str = ""


@dataclass
class RetryPolicy:
    """瞬时故障重试参数（REQ-170 ②）。"""

    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 20.0
    jitter: bool = True
    _rng: random.Random = field(default_factory=random.Random, repr=False)

    def delay_for(self, attempt: int) -> float:
        """Exponential backoff with optional full jitter (AWS 建议)."""
        attempt = max(1, int(attempt))
        raw = min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
        if not self.jitter:
            return round(raw, 3)
        return round(self._rng.uniform(0.0, raw), 3)


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


class CircuitBreaker:
    """Per-target circuit breaker whose state lives in a shared dict (ctx field)."""

    def __init__(
        self,
        key: str,
        states: dict[str, dict[str, Any]],
        *,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        half_open_max_calls: int = 1,
    ) -> None:
        self.key = key
        self._states = states
        self.failure_threshold = max(1, int(failure_threshold))
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self.half_open_max_calls = max(1, int(half_open_max_calls))

    # -- internal ---------------------------------------------------------
    def _state(self) -> dict[str, Any]:
        return self._states.setdefault(
            self.key,
            {
                "state": STATE_CLOSED,
                "failures": 0,
                "successes": 0,
                "opened_at": 0.0,
                "half_open_calls": 0,
                "last_reason": "",
            },
        )

    # -- API --------------------------------------------------------------
    def before_request(self) -> BreakerDecision:
        st = self._state()
        state = st.get("state", STATE_CLOSED)

        if state == STATE_OPEN:
            elapsed = time.time() - float(st.get("opened_at") or 0.0)
            if elapsed >= self.cooldown_seconds:
                st["state"] = STATE_HALF_OPEN
                st["half_open_calls"] = 0
            else:
                return BreakerDecision(
                    allowed=False,
                    state=STATE_OPEN,
                    retry_after=round(self.cooldown_seconds - elapsed, 2),
                    reason=str(st.get("last_reason") or "circuit_open"),
                )

        if st.get("state") == STATE_HALF_OPEN:
            if int(st.get("half_open_calls") or 0) >= self.half_open_max_calls:
                return BreakerDecision(allowed=False, state=STATE_HALF_OPEN, retry_after=1.0, reason="half_open_probe_busy")
            st["half_open_calls"] = int(st.get("half_open_calls") or 0) + 1

        return BreakerDecision(allowed=True, state=str(st.get("state", STATE_CLOSED)))

    def record_success(self) -> None:
        st = self._state()
        st["state"] = STATE_CLOSED
        st["failures"] = 0
        st["half_open_calls"] = 0
        st["successes"] = int(st.get("successes") or 0) + 1

    def record_failure(self, reason: str = "") -> None:
        st = self._state()
        st["failures"] = int(st.get("failures") or 0) + 1
        st["last_reason"] = reason[:200]
        # half_open 下任何失败立即重新打开（快速失败）
        if st.get("state") == STATE_HALF_OPEN or int(st["failures"]) >= self.failure_threshold:
            st["state"] = STATE_OPEN
            st["opened_at"] = time.time()

    def snapshot(self) -> dict[str, Any]:
        return dict(self._state())

    @property
    def is_open(self) -> bool:
        return self._state().get("state") == STATE_OPEN


@dataclass
class ResiliencePolicy:
    """熔断打开时的处置策略（REQ-170 ①）。"""

    on_open: str = ON_OPEN_PAUSE
    max_pause_seconds: float = 30.0

    def normalized(self) -> "ResiliencePolicy":
        strategy = str(self.on_open or ON_OPEN_PAUSE).lower()
        if strategy not in ON_OPEN_STRATEGIES:
            strategy = ON_OPEN_PAUSE
        return ResiliencePolicy(on_open=strategy, max_pause_seconds=max(0.0, float(self.max_pause_seconds)))


def default_settings() -> dict[str, Any]:
    """Read `config/defaults.yaml:resilience` with module-level fallbacks."""
    fallback: dict[str, Any] = {
        "breaker_failure_threshold": 5,
        "breaker_cooldown_seconds": 30.0,
        "breaker_half_open_max_calls": 1,
        "on_open": ON_OPEN_PAUSE,
        "max_pause_seconds": 30.0,
        "retry_max_attempts": 3,
        "retry_base_delay": 1.0,
        "retry_max_delay": 20.0,
        "retry_jitter": True,
    }
    try:
        from core._config_parsers import _load_defaults

        data = _load_defaults() or {}
        block = data.get("resilience") if isinstance(data, dict) else None
        if isinstance(block, dict):
            fallback.update({k: v for k, v in block.items() if k in fallback})
    except Exception as e:  # 配置不可用不得阻断攻击主链路
        logger.debug("[Resilience] defaults 读取失败，使用内置缺省: %s", e)
    return fallback


def make_retry_policy(settings: dict[str, Any] | None = None) -> RetryPolicy:
    s = settings or default_settings()
    return RetryPolicy(
        max_attempts=int(s.get("retry_max_attempts", 3)),
        base_delay=float(s.get("retry_base_delay", 1.0)),
        max_delay=float(s.get("retry_max_delay", 20.0)),
        jitter=bool(s.get("retry_jitter", True)),
    )


def build_target_resilience(ctx: Any, endpoint: str) -> dict[str, Any]:
    """Build `RateLimitedTarget` resilience kwargs bound to `ctx` (REQ-170 ③④).

    The breaker state is stored **inside** `ctx._circuit_breaker_states` (existing
    field), and every state transition is mirrored into `ctx.orchestration_log`
    + EventLog so the decision is auditable.
    """
    states = getattr(ctx, "_circuit_breaker_states", None)
    if states is None:  # 防御：ctx 非标准实现
        return {}
    settings = default_settings()
    key = endpoint or "default"
    breaker = CircuitBreaker(
        key,
        states,
        failure_threshold=int(settings.get("breaker_failure_threshold", 5)),
        cooldown_seconds=float(settings.get("breaker_cooldown_seconds", 30.0)),
        half_open_max_calls=int(settings.get("breaker_half_open_max_calls", 1)),
    )
    policy = ResiliencePolicy(
        on_open=str(settings.get("on_open", ON_OPEN_PAUSE)),
        max_pause_seconds=float(settings.get("max_pause_seconds", 30.0)),
    ).normalized()

    def _record(event: dict[str, Any]) -> None:
        try:
            ctx.orchestration_log.append(
                {
                    "phase": "strike",
                    "decision": "circuit_breaker",
                    "input": {"target": key},
                    "output": event,
                    "reasoning": "REQ-170：目标 5xx/限流触发熔断，策略=%s" % policy.on_open,
                }
            )
            from core.events import emit_event

            emit_event(ctx, "strike", "degradation", payload={"circuit_breaker": key, **event})
        except Exception as e:
            logger.debug("[Resilience] breaker event record skipped: %s", e)

    return {
        "circuit_breaker": breaker,
        "resilience_policy": policy,
        "on_breaker_event": _record,
    }
