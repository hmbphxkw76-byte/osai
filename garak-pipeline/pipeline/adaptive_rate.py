"""自适应速率控制器（规则八 — 生产级限流防护）

通过 monkeypatch generator 的 _call_model 实现多层防护，避免被 API
速率限制封禁：

1. 令牌桶主动节流（TokenBucket）：从源头不突破每分钟请求配额。
2. 慢启动（SlowStart）：初始并发=4，每 slow_start_interval 秒倍增到目标并发。
3. 正常路径抖动（ProactiveJitter）：每次 API 调用前加随机延迟（默认 0.05-0.30s），
   打破规律时间指纹，避免被 WAF/API 速率检测识别为自动化扫描。
4. Retry-After 优先：被动退避时优先尊重服务端返回的 Retry-After 头。
5. 指数退避 + 全抖动（full jitter）：避免重试风暴（惊群）放大封禁风险。
6. 连续失败熔断 + 并发自动降级：超阈值静默冷却，仍失败则下调并发，
   绝不无限重试导致永久封禁。
7. 降级后渐进恢复（DegradationRecovery）：一段时间无 429 后逐步恢复并发，
   每次步长 +4，抖动范围缩小 0.8 倍。
8. 后台线程（BackgroundThread）：daemon 线程负责慢启动加速和渐进恢复的定时检查。
9. 统计持久化（RateStatsCollector）：统计信息写入 execution_log.json 的 rate_control 字段。

不修改 garak 源码，仅对运行期 generator 实例打补丁。
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import random
import threading
import time
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class CallTimeoutError(TimeoutError):
    """单次 _call_model 调用超过 call_timeout 仍未返回。

    语义：区别于网络层 read timeout（服务端主动断开并抛异常），
    这是"服务端静默挂起、连接保持 ESTABLISHED 但无响应"的防死锁兜底。
    被 AdaptiveRateController 视为可重试瞬时错误。
    """


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
    :param on_upgrade: 并发恢复回调（回调收到新的并发数）
    :param call_timeout: 单次 _call_model 调用的硬超时（秒）。超过则放弃该次
        调用并视为可重试瞬时错误，防止目标静默挂起导致整条流水线死锁。
        默认 0 表示不启用线程级超时（沿用 garak 自身 timeout）。

    --- 慢启动 (R8-1) ---
    :param slow_start: 是否启用慢启动（初始并发低，逐步提升到目标并发）
    :param slow_start_initial: 慢启动初始并发数
    :param slow_start_interval: 慢启动倍增间隔（秒）
    :param slow_start_multiplier: 慢启动倍增系数（默认 2.0）

    --- 正常路径抖动 (R8-2) ---
    :param proactive_jitter: 是否在正常路径每次请求前加随机抖动
    :param jitter_min: 抖动下限（秒）
    :param jitter_max: 抖动上限（秒）
    :param jitter_expand_on_429: 遇 429 后抖动范围扩大倍数
    :param jitter_shrink_on_recover: 恢复时抖动范围缩小倍数

    --- 降级后恢复 (R8-4) ---
    :param recovery_interval: 无失败后等待多久开始恢复并发（秒）
    :param recovery_step: 每次恢复并发步长

    --- 统计持久化 (R8-6) ---
    :param stats_dir: 统计产物目录（用于写入 execution_log.json）
    :param run_id: 运行标识（用于统计产物文件名）
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
        on_upgrade: Callable[[int], None] | None = None,
        call_timeout: float = 0.0,
        # 慢启动
        slow_start: bool = True,
        slow_start_initial: int = 4,
        slow_start_interval: float = 30.0,
        slow_start_multiplier: float = 2.0,
        # 正常路径抖动
        proactive_jitter: bool = True,
        jitter_min: float = 0.05,
        jitter_max: float = 0.30,
        jitter_expand_on_429: float = 1.5,
        jitter_shrink_on_recover: float = 0.8,
        # 降级后恢复
        recovery_interval: float = 60.0,
        recovery_step: int = 4,
        # 统计持久化
        stats_dir: str | None = None,
        run_id: str | None = None,
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
        self.on_upgrade = on_upgrade
        self.call_timeout = float(call_timeout)

        # 慢启动参数
        self.slow_start = slow_start
        self.slow_start_initial = slow_start_initial
        self.slow_start_interval = slow_start_interval
        self.slow_start_multiplier = slow_start_multiplier

        # 正常路径抖动参数
        self.proactive_jitter = proactive_jitter
        self._jitter_min_base = jitter_min
        self._jitter_max_base = jitter_max
        self.jitter_expand_on_429 = jitter_expand_on_429
        self.jitter_shrink_on_recover = jitter_shrink_on_recover

        # 降级后恢复参数
        self.recovery_interval = recovery_interval
        self.recovery_step = recovery_step

        # 统计持久化
        self.stats_dir = stats_dir
        self.run_id = run_id

        # 内部状态
        self._original: Callable | None = None
        self._consecutive_failures = 0
        self._bucket = TokenBucket(max_rpm)
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None

        # 目标并发（从 generator 读取）
        self._target_parallel = self._current_parallel()

        # 慢启动状态
        self._current_parallel_limit = (
            min(slow_start_initial, self._target_parallel)
            if slow_start
            else self._target_parallel
        )
        self._slow_start_active = slow_start
        self._slow_start_start_time = time.monotonic()

        # 抖动范围（可动态调整）
        self._jitter_min = jitter_min
        self._jitter_max = jitter_max

        # 降级/恢复状态
        self._degraded = False
        self._last_failure_time: float | None = None

        # 后台线程
        self._bg_thread: threading.Thread | None = None
        self._bg_stop = threading.Event()
        self._lock = threading.Lock()

        # 统计收集器
        self._stats: dict = {
            "total_requests": 0,
            "total_retries": 0,
            "total_429": 0,
            "total_timeouts": 0,
            "downgrades": [],
            "upgrades": [],
            "slow_start_progress": [],
            "current_parallel": self._current_parallel_limit,
            "jitter_range": [self._jitter_min, self._jitter_max],
        }

    def patch(self) -> None:
        """打补丁：包装 _call_model 加入全部速率控制逻辑"""
        if self._original is not None:
            return  # 已 patch
        original = self.generator._call_model

        # 线程级超时熔断：用独立线程池托住 original 调用，
        # 避免目标静默挂起时主线程永久阻塞在 socket.recv()。
        # 注意：Python 无法强制杀死超时线程，它会在后台成为僵尸线程，
        # 但主流程能立即返回并走重试/放弃逻辑，不再死锁整条流水线。
        if self.call_timeout and self.call_timeout > 0:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="garak-call-timeout"
            )

        def _call_with_timeout(prompt, *args, **kwargs):
            """在线程池中执行 original，超时即放弃并抛 CallTimeoutError。"""
            if self._executor is None:
                return original(prompt, *args, **kwargs)
            fut = self._executor.submit(original, prompt, *args, **kwargs)
            try:
                return fut.result(timeout=self.call_timeout)
            except concurrent.futures.TimeoutError:
                # 取消 future（若尚未开始）；已运行的线程不可强杀，置为僵尸。
                fut.cancel()
                raise CallTimeoutError(
                    f"_call_model 超过 {self.call_timeout:.0f}s 未返回，"
                    f"疑似目标静默挂起（连接 ESTABLISHED 但无响应）"
                ) from None

        def wrapped(prompt: str, *args, **kwargs):
            # 1) 主动节流：令牌桶阻塞
            self._bucket.acquire()

            # 2) 正常路径抖动：打破规律时间指纹
            if self.proactive_jitter:
                lo, hi = self._get_jitter_range()
                time.sleep(random.uniform(lo, hi))

            # 3) 慢启动检查：在后台线程辅助下，主线程也做即时检查
            self._check_slow_start()

            attempt = 0
            while True:
                self._stats["total_requests"] += 1
                try:
                    result = _call_with_timeout(prompt, *args, **kwargs)
                    # 成功：连续失败计数清零
                    self._consecutive_failures = 0
                    # 检查是否需要渐进恢复并发
                    self._check_recovery()
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
                    self._stats["total_retries"] += 1
                    self._last_failure_time = time.monotonic()

                    if isinstance(e, CallTimeoutError):
                        self._stats["total_timeouts"] += 1
                    else:
                        self._stats["total_429"] += 1

                    # 6) 并发自动降级回调
                    if (
                        self.on_downgrade is not None
                        and self._consecutive_failures == self.downgrade_at
                    ):
                        new_parallel = max(1, self._get_current_parallel_limit() // 2)
                        self._set_current_parallel_limit(new_parallel)
                        self._degraded = True
                        # 抖动范围扩大
                        self._expand_jitter_range()
                        try:
                            self.on_downgrade(new_parallel)
                        except Exception:
                            logger.debug("并发降级回调失败", exc_info=True)
                        self._stats["downgrades"].append({
                            "time": time.strftime("%H:%M:%S"),
                            "from": self._get_current_parallel_limit() * 2,
                            "to": new_parallel,
                        })

                    # 6) 连续失败熔断：超阈值静默冷却
                    if self._consecutive_failures >= self.cooldown_threshold:
                        logger.warning(
                            "连续限流 %d 次，冷却 %.0fs 后重试",
                            self._consecutive_failures, self.cooldown,
                        )
                        time.sleep(self.cooldown)

                    if attempt > self.max_retries:
                        logger.error("已达最大重试次数 %d，放弃请求", self.max_retries)
                        raise

                    # 4)+5) 退避：优先 Retry-After，否则指数退避 + 全抖动
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

        # 启动后台线程
        self._start_background_thread()

    def unpatch(self) -> None:
        """还原补丁并关闭线程池"""
        # 停止后台线程
        self._stop_background_thread()

        # 持久化统计
        self._persist_stats()

        if self._original is not None:
            self.generator._call_model = self._original
            self._original = None
        if self._executor is not None:
            self._executor.shutdown(wait=False)
            self._executor = None

    # ------------------------------------------------------------------
    # 慢启动逻辑
    # ------------------------------------------------------------------
    def _check_slow_start(self) -> None:
        """检查慢启动是否可以提升并发上限"""
        if not self._slow_start_active:
            return
        with self._lock:
            elapsed = time.monotonic() - self._slow_start_start_time
            steps = int(elapsed / self.slow_start_interval)
            new_limit = min(
                self._target_parallel,
                int(self.slow_start_initial * (self.slow_start_multiplier ** steps)),
            )
            if new_limit > self._current_parallel_limit:
                old = self._current_parallel_limit
                self._current_parallel_limit = new_limit
                logger.info(
                    "慢启动：并发从 %d 提升至 %d（目标 %d）",
                    old, new_limit, self._target_parallel,
                )
                self._stats["slow_start_progress"].append({
                    "time": time.strftime("%H:%M:%S"),
                    "from": old,
                    "to": new_limit,
                })
                self._stats["current_parallel"] = new_limit
            if new_limit >= self._target_parallel:
                self._slow_start_active = False
                logger.info("慢启动完成，已达目标并发 %d", self._target_parallel)

    # ------------------------------------------------------------------
    # 抖动范围管理
    # ------------------------------------------------------------------
    def _get_jitter_range(self) -> tuple[float, float]:
        """获取当前抖动范围（线程安全）"""
        with self._lock:
            return self._jitter_min, self._jitter_max

    def _expand_jitter_range(self) -> None:
        """429 后扩大抖动范围"""
        with self._lock:
            self._jitter_min = self._jitter_min * self.jitter_expand_on_429
            self._jitter_max = self._jitter_max * self.jitter_expand_on_429
            self._stats["jitter_range"] = [self._jitter_min, self._jitter_max]
            logger.debug(
                "抖动范围扩大至 [%.3f, %.3f]", self._jitter_min, self._jitter_max
            )

    def _shrink_jitter_range(self) -> None:
        """恢复后缩小抖动范围"""
        with self._lock:
            self._jitter_min = max(
                self._jitter_min * self.jitter_shrink_on_recover,
                self._jitter_min_base,
            )
            self._jitter_max = max(
                self._jitter_max * self.jitter_shrink_on_recover,
                self._jitter_max_base,
            )
            self._stats["jitter_range"] = [self._jitter_min, self._jitter_max]
            logger.debug(
                "抖动范围缩小至 [%.3f, %.3f]", self._jitter_min, self._jitter_max
            )

    # ------------------------------------------------------------------
    # 降级后恢复逻辑
    # ------------------------------------------------------------------
    def _check_recovery(self) -> None:
        """成功路径中检查是否可以渐进恢复并发"""
        if not self._degraded or self._last_failure_time is None:
            return
        elapsed_since_failure = time.monotonic() - self._last_failure_time
        if elapsed_since_failure < self.recovery_interval:
            return
        # 达到恢复条件
        new_parallel = min(
            self._target_parallel,
            self._get_current_parallel_limit() + self.recovery_step,
        )
        if new_parallel > self._get_current_parallel_limit():
            old = self._get_current_parallel_limit()
            self._set_current_parallel_limit(new_parallel)
            # 缩小抖动范围
            self._shrink_jitter_range()
            if self.on_upgrade:
                try:
                    self.on_upgrade(new_parallel)
                except Exception:
                    logger.debug("并发恢复回调失败", exc_info=True)
            self._stats["upgrades"].append({
                "time": time.strftime("%H:%M:%S"),
                "from": old,
                "to": new_parallel,
            })
            self._stats["current_parallel"] = new_parallel
            logger.info(
                "渐进恢复：并发从 %d 恢复至 %d", old, new_parallel
            )
            if new_parallel >= self._target_parallel:
                self._degraded = False
                logger.info("并发已完全恢复至目标值 %d", self._target_parallel)

    # ------------------------------------------------------------------
    # 后台线程
    # ------------------------------------------------------------------
    def _start_background_thread(self) -> None:
        """启动后台 daemon 线程，负责慢启动加速和渐进恢复的定时检查"""
        self._bg_stop.clear()
        self._bg_thread = threading.Thread(
            target=self._bg_loop, name="garak-rate-bg", daemon=True
        )
        self._bg_thread.start()
        logger.debug("后台速率监控线程已启动")

    def _stop_background_thread(self) -> None:
        """停止后台线程"""
        self._bg_stop.set()
        if self._bg_thread is not None and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=2)
        self._bg_thread = None

    def _bg_loop(self) -> None:
        """后台线程主循环：每 5s 检查慢启动和恢复"""
        while not self._bg_stop.wait(5):
            if self._bg_stop.is_set():
                break
            try:
                # 慢启动检查
                if self._slow_start_active:
                    self._check_slow_start()
                # 恢复检查
                if self._degraded and self._last_failure_time is not None:
                    self._check_recovery()
            except Exception:
                logger.debug("后台线程检查异常", exc_info=True)

    # ------------------------------------------------------------------
    # 统计持久化
    # ------------------------------------------------------------------
    def _persist_stats(self) -> None:
        """将速率控制统计写入 execution_log.json 的 rate_control 字段"""
        if not self.stats_dir or not self.run_id:
            return
        try:
            log_path = Path(self.stats_dir) / "03_execution" / f"execution_log_{self.run_id}.json"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            existing: dict = {}
            if log_path.exists():
                existing = json.loads(log_path.read_text(encoding="utf-8"))
            existing["rate_control"] = self._stats
            log_path.write_text(
                json.dumps(existing, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("速率控制统计已写入 %s", log_path)
        except Exception:
            logger.debug("统计持久化失败", exc_info=True)

    # ------------------------------------------------------------------
    # 并发读取/设置辅助
    # ------------------------------------------------------------------
    def _current_parallel(self) -> int:
        """读取 generator 当前并发数（供降级回调参考）"""
        val = getattr(self.generator, "parallel_requests", None)
        if isinstance(val, int) and val >= 1:
            return val
        return 1

    def _get_current_parallel_limit(self) -> int:
        """获取当前并发上限（线程安全）"""
        with self._lock:
            return self._current_parallel_limit

    def _set_current_parallel_limit(self, val: int) -> None:
        """设置当前并发上限（线程安全）"""
        with self._lock:
            self._current_parallel_limit = val


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
    # 线程级超时熔断：目标静默挂起，视为可重试瞬时错误
    if isinstance(exc, CallTimeoutError):
        return True
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
