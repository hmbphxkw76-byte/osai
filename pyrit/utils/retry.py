"""
===============================================================================
OffSec AI-300 — 传输层重试逻辑
===============================================================================
跨模块共享的指数退避重试逻辑。

P2 重构: 重试逻辑分层
  ✅ 传输层重试 (utils/retry.py): 网络/HTTP 层面异常 → 指数退避重试
  ✅ 编排层重试 (PyRIT 框架): PromptSendingAttack(max_attempts_on_failure=3)
===============================================================================
"""
import random

# ── 跨模块共享：指数退避重试逻辑 ──
_RETRYABLE_KEYWORDS = [
    "429", "rate limit", "500", "503", "timeout",
    "connection error", "server error", "service unavailable",
]

_RETRYABLE_EXCEPTION_TYPES = (
    "requests.RequestException",
    "requests.ConnectionError",
    "requests.Timeout",
    "requests.HTTPError",
    "OSError",
    "ConnectionError",
    "TimeoutError",
)


def is_retryable_error(exc: Exception) -> bool:
    """判断异常是否为可重试的网络/HTTP 错误。

    检查策略: 优先按异常类名判定，回退到错误消息关键字匹配。
    """
    exc_type_name = type(exc).__qualname__
    if exc_type_name in _RETRYABLE_EXCEPTION_TYPES:
        return True
    err_str = str(exc).lower()
    return any(keyword in err_str for keyword in _RETRYABLE_KEYWORDS)


def backoff_delay(attempt: int, *, jitter_min: float = 0.0, jitter_max: float = 1.5) -> float:
    """计算指数退避延迟（秒），含随机抖动避免惊群效应。

    Args:
        attempt: 当前重试次数（0-based）
        jitter_min: 最小抖动（秒）
        jitter_max: 最大抖动（秒）
    Returns:
        等待秒数 = 2^attempt + uniform(jitter_min, jitter_max)
    """
    return (2 ** attempt) + random.uniform(jitter_min, jitter_max)
