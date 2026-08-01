"""自适应速率控制器（规则八 — 生产级限流防护）

通过 monkeypatch generator 的 _call_model 实现四层防护，避免被 API
速率限制封禁：

1. 令牌桶主动节流（TokenBucket）：从源头不突破每分钟请求配额。
2. Retry-After 优先：被动退避时优先尊重服务端返回的 Retry-After 头。
3. 指数退避 + 全抖动（full jitter）：避免重试风暴（惊群）放大封禁风险。
4. 连续失败熔断 + 并发自动降级：超阈值静默冷却，仍失败则下调并发，
   绝不无限重试导致永久封禁。

不修改 garak 源码，仅对运行期 generator 实例打补丁。
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# 令牌桶：主动节流，从源头不触发限流
# ----------------------------------------------------------------------
class TokenBucket:
    """简单令牌桶限速器（线程安全依赖调用方串行；本流水线单线程驱动）

    :param max_rpm: 每分钟允许的最大请求数
    :param capacity: 桶容量（突发上限），默认等于 max_rpm
    """

    def __init__(self, max_rpm: float, capacity: float | None = None) -> None:
        self.rate = max_rpm / 60.0  # 令牌/秒
        self.capacity = float(capacity if capacity is not None else max_rpm)
        self._tokens = self.capacity
        self._ts = time.monotonic()

    def acquire(self, n: int = 1) -> None:
        """阻塞直至桶中有 n 个令牌可用"""
        while True:
            now = time.monotonic()
            elapsed = now - self._ts
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._ts = now
            if self._tokens >= n:
                self._tokens -= n
                return
            # 计算需要等待的时间（留一点余量避免空转）
            wait = (n - self._tokens) / self.rate
            time.sleep(min(wait, 0.5))


# ----------------------------------------------------------------------
# 自适应速率控制器
# ----------------------------------------------------------------------
class AdaptiveRateController:
    """对 garak generator 注入自适应速率控制。

    :param generator: garak generator 实例（需有 _call_model 方法）
    :param max_rpm: 令牌桶每分钟请求上限（主动节流）
    :param base_delay: 退避基数（秒）
    :param max_delay: 退避上限（秒）
    :param max_retries: 单请求最大重试次数
    :param cooldown: 连续失败达阈值后的静默冷却时长（秒）
    :param cooldown_threshold: 触发冷却的连续失败次数
    :param downgrade_at: 触发并发降级的连续失败次数
    :param jitter: 是否启用全抖动退避（防惊群）
    :param on_downgrade: 并发降级回调（回调收到新的并发数）
    """

    def __init__(
        self,
        generator,
        *,
        max_rpm: float = 60.0,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int = 5,
        cooldown: float = 30.0,
        cooldown_threshold: int = 5,
        downgrade_at: int = 3,
        jitter: bool = True,
        on_downgrade: Callable[[int], None] | None = None,
    ) -> None:
        self.generator = generator
        self.max_rpm = max_rpm
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.cooldown = cooldown
        self.cooldown_threshold = cooldown_threshold
        self.downgrade_at = downgrade_at
        self.jitter = jitter
        self.on_downgrade = on_downgrade

        self._original: Callable | None = None
        self._consecutive_failures = 0
        self._bucket = TokenBucket(max_rpm)

    def patch(self) -> None:
        """打补丁：包装 _call_model 加入令牌桶 + 退避 + 熔断 + 降级"""
        if self._original is not None:
            return  # 已 patch
        original = self.generator._call_model

        def wrapped(prompt: str, *args, **kwargs):
            # 1) 主动节流：令牌桶阻塞
            self._bucket.acquire()

            attempt = 0
            while True:
                try:
                    result = original(prompt, *args, **kwargs)
                    # 成功：连续失败计数清零
                    self._consecutive_failures = 0
                    # Ollama 兼容：部分版本返回原生 `response` 字段
                    if isinstance(result, dict) and "response" in result and "choices" not in result:
                        result = {"choices": [{"message": {"content": result["response"]}}]}
                    return result
                except Exception as e:
                    if not _is_retryable(e):
                        # 硬失败（401/403/400 等）：直接抛出，不重试
                        raise
                    attempt += 1
                    self._consecutive_failures += 1

                    # 4) 并发自动降级回调
                    if (
                        self.on_downgrade is not None
                        and self._consecutive_failures == self.downgrade_at
                    ):
                        try:
                            self.on_downgrade(max(1, self._current_parallel() // 2))
                        except Exception:
                            logger.debug("并发降级回调失败", exc_info=True)

                    # 4) 连续失败熔断：超阈值静默冷却
                    if self._consecutive_failures >= self.cooldown_threshold:
                        logger.warning(
                            "连续限流 %d 次，冷却 %.0fs 后重试",
                            self._consecutive_failures, self.cooldown,
                        )
                        time.sleep(self.cooldown)

                    if attempt > self.max_retries:
                        logger.error("已达最大重试次数 %d，放弃请求", self.max_retries)
                        raise

                    # 2)+3) 退避：优先 Retry-After，否则指数退避 + 全抖动
                    ra = _retry_after(e)
                    if ra is not None:
                        delay = ra
                    else:
                        cap = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
                        delay = random.uniform(0, cap) if self.jitter else cap
                    logger.info("请求受限，退避 %.1fs 后重试 (第 %d/%d 次)",
                                delay, attempt, self.max_retries)
                    time.sleep(delay)

        self._original = original
        self.generator._call_model = wrapped

    def unpatch(self) -> None:
        """还原补丁"""
        if self._original is not None:
            self.generator._call_model = self._original
            self._original = None

    def _current_parallel(self) -> int:
        """读取 generator 当前并发数（供降级回调参考）"""
        val = getattr(self.generator, "parallel_requests", None)
        if isinstance(val, int) and val >= 1:
            return val
        return 1


# ----------------------------------------------------------------------
# 辅助判定
# ----------------------------------------------------------------------
# 可重试的瞬时错误信号（限流 / 网关 / 网络层）
_RETRYABLE_SIGNALS = (
    "429", "rate", "ratelimit", "too many requests",
    "503", "529", "502", "504", "gateway", "bad gateway",
    "timeout", "timed out", "connection", "reset by peer",
    "busy", "unavailable", "temporarily",
)

# 硬失败（不应重试，重试只会加速封禁或暴露无效凭据）
_HARD_FAIL_SIGNALS = (
    "401", "403", "unauthorized", "forbidden", "invalid api key",
    "400", "bad request", "authentication",
)


def _is_retryable(exc: Exception) -> bool:
    """判断异常是否可重试（限流 / 瞬时错误），硬失败返回 False"""
    msg = str(exc).lower()
    if any(s in msg for s in _HARD_FAIL_SIGNALS):
        return False
    return any(s in msg for s in _RETRYABLE_SIGNALS)


def _retry_after(exc: Exception) -> float | None:
    """从异常中提取 Retry-After 指示的等待秒数（优先于指数退避）

    兼容 httpx / requests 异常对象上可能挂载的 response 属性。
    """
    resp = getattr(exc, "response", None)
    if resp is None:
        return None
    ra = resp.headers.get("Retry-After") if hasattr(resp, "headers") else None
    if not ra:
        return None
    ra = str(ra).strip()
    try:
        return float(ra)  # 秒数形式
    except ValueError:
        pass
    # HTTP Date 形式（如 "Wed, 21 Oct 2026 07:28:00 GMT"）
    try:
        import datetime
        import email.utils
        dt = email.utils.parsedate_to_datetime(ra)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        delta = (dt - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None
