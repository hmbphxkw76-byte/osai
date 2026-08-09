# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""限速 Target 包装器 — 合法扩展 (原生 RPM 委托 + 自研并发重试填补空白) (R-022: PyRIT 原生 PromptTarget 接口实现)..

双轨制审查结论 (L5 对齐):
  本模块 **不构成双轨制**。RPM 限速已完全委托原生 API，自研部分仅填补
  PyRIT 原生不提供的功能空白。

原生委托 (零自研):
  - RPM 限速 → 设置原生 ``_max_requests_per_minute`` 属性,
    由原生 ``limit_requests_per_minute`` 装饰器自动生效

自研扩展 (原生无等效, 合法填补空白):
  1. **并发信号量** — 同一端点的多请求并发控制 (原生仅 RPM, 无并发上限)
  2. **错误重试** — 429/503/502/500/504 HTTP 错误的自动重试 (原生无重试)
  3. **超时重试** — ``APITimeoutError`` / ``APIConnectionError`` 独立重试
  4. **Retry-After** — 响应头解析 + 差异化退避策略
  5. **指数退避 + 抖动** — 避免重试风暴

学术依据:
  - Circuit Breaker Pattern (Nygard, "Release It!")
  - Exponential Backoff with Jitter (AWS Architecture Blog)
  - OpenAI API Rate Limiting 最佳实践

设计原则:
  - 原生优先: RPM 通过 ``_max_requests_per_minute`` 原生属性控制
  - 补充而非替代: 保留并发信号量和重试逻辑作为原生缺失的补充
  - 非侵入式: 不继承、不覆盖原生方法，仅在外层增加重试逻辑
  - 共享信号量: 同一端点的多个 Target 实例共享并发限制

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 20:00 — v7.0: RPM 限速改为设置原生 ``_max_requests_per_minute``
>     属性, 消除自研 RPM 逻辑, 保留并发信号量 + 重试逻辑
>   2026-8-1 21:00 — L5 双轨制审查: 确认本模块为合法扩展, 非双轨制
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from collections import deque
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

# 运行时导入 PromptTarget 以注册虚拟子类
try:
    from pyrit.prompt_target import PromptTarget as _PromptTarget
except ImportError:
    _PromptTarget = None

if TYPE_CHECKING:
    from pyrit.prompt_target import PromptTarget
# R5: AIMD 动态调整 — 响应时间滑动窗口大小
_RTT_WINDOW_SIZE = 20
# R5: 响应时间恶化阈值 (P90/P50 比率 > 此值时触发更激进的 RPM 降低)
_RTT_DEGRADATION_RATIO = 2.0


# ============================================================

_semaphore_registry: dict[str, asyncio.Semaphore] = {}
_registry_lock = asyncio.Lock()


async def _get_shared_semaphore(endpoint: str, max_concurrency: int) -> asyncio.Semaphore:
    """获取或创建共享信号量。."""
    async with _registry_lock:
        if endpoint not in _semaphore_registry:
            _semaphore_registry[endpoint] = asyncio.Semaphore(max_concurrency)
        return _semaphore_registry[endpoint]


# ============================================================
# 重试配置
# ============================================================

_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BASE_DELAY = 1.0
_DEFAULT_MAX_DELAY = 30.0
_DEFAULT_JITTER = 0.5

# G7: 不可重试的 HTTP 状态码 — 认证/请求错误/空响应, 立即失败
# 204 = 空响应 (DeepSeek 付费版仍可能返回), 重试无意义
_NON_RETRYABLE_STATUS_CODES = {400, 401, 403, 404, 405, 422, 204}

# 触发重试的 HTTP 状态码
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# 触发重试的异常类型名
_RETRYABLE_EXCEPTION_NAMES = {
    "APITimeoutError",
    "APIConnectionError",
    "APIStatusError",
    "asyncio.TimeoutError",
    "TimeoutError",
}

# 超时类异常 (使用更大的退避延迟)
_TIMEOUT_EXCEPTION_NAMES = {
    "APITimeoutError",
    "asyncio.TimeoutError",
    "TimeoutError",
}

# 速率限制类异常 (优先使用 Retry-After 头)
_RATE_LIMIT_STATUS_CODES = {429}
_SERVER_ERROR_STATUS_CODES = {500, 502, 503, 504}


def _is_retryable_error(error: Exception) -> bool:
    """判断错误是否可重试。."""
    error_type_name = type(error).__name__
    if error_type_name in _RETRYABLE_EXCEPTION_NAMES:
        return True

    # 检查 HTTP 状态码 (如果错误对象有 status_code 属性)
    status_code = getattr(error, "status_code", None)
    if status_code and status_code in _RETRYABLE_STATUS_CODES:
        return True

    error_str = str(error).lower()
    return bool(any(code in error_str for code in ("429", "503", "502", "500", "504")))


def _is_non_retryable_error(error: Exception) -> bool:
    """G7: 判断错误是否为不可重试 (认证失败/请求错误/空响应).

    401/403/400/404/422/204 等状态码不应重试, 应立即失败.
    204 空响应 ("The chat returned an empty response") 重试无意义.
    """
    import re

    status_code = getattr(error, "status_code", None)
    if status_code and status_code in _NON_RETRYABLE_STATUS_CODES:
        return True

    error_str = str(error).lower()
    # 204 空响应: "The chat returned an empty response (no content, audio, or tool_calls)"
    if "204" in error_str and ("empty" in error_str or "no content" in error_str):
        return True
    if "empty response" in error_str and "tool_calls" in error_str:
        return True
    # 仅匹配精确状态码 (避免 4000 匹配 400)
    code_matches = re.findall(r"\b(40[01345]|422|204)\b", error_str)
    return bool(code_matches)


def _extract_retry_after(error: Exception) -> float | None:
    """从错误中提取 Retry-After 值 (秒)。."""
    # 检查 response headers
    response = getattr(error, "response", None)
    if response:
        headers = getattr(response, "headers", None)
        if headers:
            retry_after = headers.get("retry-after") or headers.get("Retry-After")
            if retry_after:
                try:
                    return float(retry_after)
                except (ValueError, TypeError):
                    pass
    return None


def _compute_backoff(
    attempt: int,
    *,
    base_delay: float = _DEFAULT_BASE_DELAY,
    max_delay: float = _DEFAULT_MAX_DELAY,
    jitter: float = _DEFAULT_JITTER,
) -> float:
    """计算指数退避延迟 + 抖动。."""
    delay = min(base_delay * (2**attempt), max_delay)
    jitter_amount = delay * jitter * (random.random() * 2 - 1)
    return max(0.1, delay + jitter_amount)


# ============================================================
# Rate Limited Target 包装器
# ============================================================


class RateLimitedTarget:
    """限速 Target 包装器 — 原生 RPM + 自研并发重试。.

    v7.0: RPM 限速通过设置原生 ``_max_requests_per_minute`` 属性实现,
    并发控制和错误重试保留自研实现。

    P1: 通过 ``abc.ABCMeta.register()`` 注册为 ``PromptTarget`` 的虚拟子类,
    使 ``isinstance(target, PromptTarget)`` 返回 ``True``,
    无需实现所有抽象方法。

    使用方式::

        from pipeline.targets.rate_limited_target import RateLimitedTarget

        rate_limited = RateLimitedTarget(
            target=original_target,
            max_concurrency=3,
            max_retries=5,
            requests_per_minute=60,  # 原生 _max_requests_per_minute
        )
        # 使用 rate_limited 代替 original_target

    包装模式:
      - RPM 限速: 设置 ``target._max_requests_per_minute`` (原生装饰器自动生效)
      - 并发控制: ``asyncio.Semaphore`` (同端点共享)
      - 错误重试: 指数退避 + Retry-After 头解析
      - 属性透传: ``__getattr__`` 代理到原始 Target
    """

    def __init__(
        self,
        *,
        target: PromptTarget,
        endpoint: str | None = None,
        max_concurrency: int = 3,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        requests_per_minute: int | None = None,
        base_delay: float = _DEFAULT_BASE_DELAY,
        max_delay: float = _DEFAULT_MAX_DELAY,
        jitter: float = _DEFAULT_JITTER,
    ) -> None:
        """初始化限速包装器。.

        Args:
            target: 原始 PyRIT Target 实例。
            endpoint: API 端点 URL (用于共享信号量, 默认从 target 推断)。
            max_concurrency: 最大并发请求数 (同端点共享)。
            max_retries: 最大重试次数。
            requests_per_minute: 每分钟最大请求数 (设置原生 ``_max_requests_per_minute``)。
            base_delay: 初始退避延迟 (秒)。
            max_delay: 最大退避延迟 (秒)。
            jitter: 抖动比例 (0.0~1.0)。
        """
        self._target = target
        self._endpoint = endpoint or self._infer_endpoint(target)
        self._max_concurrency = max_concurrency
        self._max_retries = max_retries
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._jitter = jitter

        # v7.0: 设置原生 _max_requests_per_minute (原生装饰器自动限速)
        if requests_per_minute is not None and requests_per_minute > 0:
            target._max_requests_per_minute = requests_per_minute
            logger.info(
                f"RateLimitedTarget: native _max_requests_per_minute={requests_per_minute} "
                f"set on {type(target).__name__}"
            )

        # 透传原始 Target 的属性
        self._retry_count = 0
        self._total_delay = 0.0

        # G6: AIMD 自适应限速状态
        self._initial_rpm = requests_per_minute or 0
        self._current_rpm = self._initial_rpm
        self._aimd_min_rpm = max(1, (requests_per_minute or 60) // 10)
        self._aimd_increase_step = max(1, (requests_per_minute or 60) // 20)

        # R5: 响应时间滑动窗口 (用于动态调整 AIMD 参数)
        self._rtt_window: deque[float] = deque(maxlen=_RTT_WINDOW_SIZE)
        self._rtt_p50: float = 0.0
        self._rtt_p90: float = 0.0

        # R5: 动态 AIMD 倍率 (根据响应时间趋势调整)
        # decrease_factor > 1.0 表示更激进的降低 (如 0.4x 而非 0.5x)
        self._dynamic_decrease_factor = 0.5  # 默认减半
        self._dynamic_increase_step = self._aimd_increase_step

    def _infer_endpoint(self, target: PromptTarget) -> str:
        """从 Target 推断端点 URL。."""
        try:
            endpoint = getattr(target, "_endpoint", None) or getattr(target, "endpoint", None)
            if endpoint:
                return str(endpoint)
        except Exception:
            pass
        return f"target_{id(target)}"

    @property
    def inner_target(self) -> PromptTarget:
        """获取原始 Target 实例。."""
        return self._target

    @property
    def retry_count(self) -> int:
        """总重试次数。."""
        return self._retry_count

    @property
    def total_delay(self) -> float:
        """总退避延迟 (秒)。."""
        return self._total_delay

    @property
    def current_rpm(self) -> int:
        """G6: 当前实际 RPM 限速值。."""
        return self._current_rpm

    @property
    def rtt_p50(self) -> float:
        """R5: P50 响应时间 (秒)。."""
        return self._rtt_p50

    @property
    def rtt_p90(self) -> float:
        """R5: P90 响应时间 (秒)。."""
        return self._rtt_p90

    def _record_rtt(self, rtt: float) -> None:
        """R5: 记录响应时间并更新 P50/P90 + 动态 AIMD 参数.

        当 P90/P50 比率超过阈值时, 增大 decrease_factor (更激进地降低 RPM),
        减小 increase_step (更保守地增加 RPM).
        当响应时间稳定时, 恢复默认 AIMD 参数.
        """
        self._rtt_window.append(rtt)
        if len(self._rtt_window) < 3:
            return

        sorted_rtts = sorted(self._rtt_window)
        n = len(sorted_rtts)
        self._rtt_p50 = sorted_rtts[n // 2]
        self._rtt_p90 = sorted_rtts[int(n * 0.9)]

        # R5: 根据响应时间趋势动态调整 AIMD 参数
        if self._rtt_p50 > 0:
            ratio = self._rtt_p90 / self._rtt_p50
            if ratio > _RTT_DEGRADATION_RATIO:
                # 响应时间恶化 — 更激进地降低, 更保守地增加
                self._dynamic_decrease_factor = 0.35  # 减到 35% (比默认 50% 更激进)
                self._dynamic_increase_step = max(1, self._aimd_increase_step // 2)
                logger.debug(
                    f"R5: RTT degradation detected (P50={self._rtt_p50:.2f}s, "
                    f"P90={self._rtt_p90:.2f}s, ratio={ratio:.1f}), "
                    f"AIMD: decrease_factor={self._dynamic_decrease_factor}, "
                    f"increase_step={self._dynamic_increase_step}"
                )
            else:
                # 响应时间稳定 — 恢复默认 AIMD 参数
                self._dynamic_decrease_factor = 0.5
                self._dynamic_increase_step = self._aimd_increase_step

    def _aimd_decrease(self) -> None:
        """G6+R5: AIMD Multiplicative Decrease — 429 时 RPM 降低.

        R5: decrease_factor 根据响应时间趋势动态调整 (0.35~0.5).
        参考: TCP Congestion Control (Jacobson, RFC 5681).
        """
        if self._current_rpm <= 0:
            return
        old_rpm = self._current_rpm
        self._current_rpm = max(
            self._aimd_min_rpm,
            int(self._current_rpm * self._dynamic_decrease_factor),
        )
        if self._current_rpm != old_rpm:
            with contextlib.suppress(AttributeError, TypeError):
                self._target._max_requests_per_minute = self._current_rpm
            logger.info(
                f"G6+R5 AIMD: RPM decreased {old_rpm} -> {self._current_rpm} "
                f"(endpoint={self._endpoint}, factor={self._dynamic_decrease_factor})"
            )

    def _aimd_increase(self) -> None:
        """G6+R5: AIMD Additive Increase — 成功时 RPM 线性增加.

        R5: increase_step 根据响应时间趋势动态调整.
        参考: TCP Congestion Control (Jacobson, RFC 5681).
        """
        if self._initial_rpm <= 0:
            return  # 无 RPM 限制时不调整
        if self._current_rpm >= self._initial_rpm:
            return  # 不超过初始值
        old_rpm = self._current_rpm
        self._current_rpm = min(
            self._initial_rpm,
            self._current_rpm + self._dynamic_increase_step,
        )
        if self._current_rpm != old_rpm:
            with contextlib.suppress(AttributeError, TypeError):
                self._target._max_requests_per_minute = self._current_rpm
            logger.debug(
                f"G6+R5 AIMD: RPM increased {old_rpm} -> {self._current_rpm} "
                f"(endpoint={self._endpoint}, step={self._dynamic_increase_step})"
            )

    def __getattr__(self, name: str) -> Any:
        """透传属性访问到原始 Target。."""
        return getattr(self._target, name)

    async def send_prompt_async(self, *args: Any, **kwargs: Any) -> Any:
        """发送 prompt (带限速 + 差异化重试 + G6: AIMD 自适应限速 + G7: 不可重试立即失败).

        代理调用原始 Target 的 ``send_prompt_async``，增加:
          1. 共享信号量 (同端点并发控制)
          2. G7: 不可重试错误 (401/403/400/404/422) 立即失败
          3. 差异化重试策略:
             - 429: 优先使用 Retry-After 头, G6: AIMD 降低 RPM
             - 5xx: 标准指数退避
             - 超时: 更大基础延迟, 退避倍率 2x
          4. ``Retry-After`` 头解析
          5. G6: 成功时 AIMD 增加 RPM
        """
        semaphore = await _get_shared_semaphore(self._endpoint, self._max_concurrency)

        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            async with semaphore:
                try:
                    rtt_start = time.monotonic()
                    result = await self._target.send_prompt_async(*args, **kwargs)
                    rtt = time.monotonic() - rtt_start
                    # R5: 记录响应时间并动态调整 AIMD 参数
                    self._record_rtt(rtt)
                    # G6: AIMD Additive Increase — 成功后缓慢增加 RPM
                    self._aimd_increase()
                    return result
                except Exception as e:
                    last_error = e

                    # G7: 不可重试错误 (401/403/400/404/422) 立即失败
                    if _is_non_retryable_error(e):
                        logger.error(
                            f"RateLimitedTarget: non-retryable error "
                            f"(status={getattr(e, 'status_code', '?')}), "
                            f"endpoint={self._endpoint}"
                        )
                        raise

                    if not _is_retryable_error(e):
                        raise

                    if attempt >= self._max_retries:
                        logger.error(
                            f"RateLimitedTarget: max_retries ({self._max_retries}) "
                            f"exceeded for endpoint={self._endpoint}"
                        )
                        raise

                    # G6: AIMD Multiplicative Decrease — 429 时 RPM 减半
                    status_code = getattr(e, "status_code", None)
                    if status_code == 429 or "429" in str(e):
                        self._aimd_decrease()

                    # P1: 差异化退避策略
                    retry_after = _extract_retry_after(e)
                    if retry_after is not None:
                        delay = retry_after
                    else:
                        # 超时异常使用更大基础延迟
                        error_type = type(e).__name__
                        if error_type in _TIMEOUT_EXCEPTION_NAMES:
                            delay = _compute_backoff(
                                attempt,
                                base_delay=self._base_delay * 2,
                                max_delay=self._max_delay,
                                jitter=self._jitter,
                            )
                        else:
                            delay = _compute_backoff(
                                attempt,
                                base_delay=self._base_delay,
                                max_delay=self._max_delay,
                                jitter=self._jitter,
                            )

                    self._retry_count += 1
                    self._total_delay += delay

                    logger.warning(
                        f"RateLimitedTarget: retry {attempt + 1}/{self._max_retries} "
                        f"after {delay:.1f}s (endpoint={self._endpoint}, "
                        f"error={type(e).__name__})"
                    )

                    await asyncio.sleep(delay)

        if last_error:
            raise last_error

    # 代理其他常用方法
    async def _send_chat_request_async(self, *args: Any, **kwargs: Any) -> Any:
        """代理 ``_send_chat_request_async``。."""
        semaphore = await _get_shared_semaphore(self._endpoint, self._max_concurrency)
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            async with semaphore:
                try:
                    return await self._target._send_chat_request_async(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    if not _is_retryable_error(e):
                        raise
                    if attempt >= self._max_retries:
                        raise
                    delay = _compute_backoff(attempt, base_delay=self._base_delay, max_delay=self._max_delay)
                    self._retry_count += 1
                    self._total_delay += delay
                    logger.warning(f"RateLimitedTarget: retry {attempt + 1}/{self._max_retries} after {delay:.1f}s")
                    await asyncio.sleep(delay)

        if last_error:
            raise last_error


def wrap_target_with_rate_limit(
    target: PromptTarget,
    *,
    endpoint: str | None = None,
    max_concurrency: int = 3,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    requests_per_minute: int | None = None,
) -> RateLimitedTarget:
    """为 Target 包装限速和重试能力。.

    v7.0: RPM 通过原生 ``_max_requests_per_minute`` 实现,
    并发控制和重试保留自研实现。

    Args:
        target: 原始 Target 实例。
        endpoint: API 端点 URL (可选)。
        max_concurrency: 最大并发数。
        max_retries: 最大重试次数。
        requests_per_minute: 每分钟最大请求数 (设置原生属性)。

    Returns:
        RateLimitedTarget 包装后的实例。
    """
    return RateLimitedTarget(
        target=target,
        endpoint=endpoint,
        max_concurrency=max_concurrency,
        max_retries=max_retries,
        requests_per_minute=requests_per_minute,
    )


# P1: 注册为 PromptTarget 的虚拟子类
# 使 isinstance(target, PromptTarget) 返回 True, 无需实现所有抽象方法
if _PromptTarget is not None and hasattr(_PromptTarget, "register"):
    _PromptTarget.register(RateLimitedTarget)


# P1: 信号量清理函数
def cleanup_semaphores() -> None:
    """清理共享信号量注册表。.

    在流水线结束后调用, 避免信号量泄漏。
    特别是在 Windows 上, asyncio.Semaphore 如果不被清理可能导致事件循环警告。
    """
    global _semaphore_registry
    _semaphore_registry.clear()
    logger.debug("Semaphore registry cleaned up")
