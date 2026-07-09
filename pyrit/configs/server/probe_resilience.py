"""
===============================================================================
Config Center — 探测韧性模块 (Probe Resilience)
===============================================================================
统一处理探测过程中的异常分类、超时自适应、速率限制检测等问题。

解决问题:
  1. 对端服务器中断/崩溃时（如 web 程序突然挂掉），
     httpx 可能在 broken pipe 上挂起读不到响应。纯靠前端 watchdog
     不够，需要在后端做"绝对兜底超时 + 异常分类"。
  2. API 速率限制（HTTP 429）触发时，必须给用户明确提示，
     并自动调整后续请求的节奏（背压）。
  3. 不同异常类型（连接失败 / 读超时 / 服务器崩溃 / 限流）需要
     在前端呈现不同的提示和建议。

设计原则:
  ✅ 纯函数式辅助 — 不与具体探测业务耦合
  ✅ 可被 routes.py / smart_discovery.py / deep_recon.py 复用
  ✅ 异常类型 → 中文友好提示 + 建议动作（前端直接展示）
===============================================================================
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


# ── 异常分类 ──────────────────────────────────────────────────────────────

# 服务端中断/崩溃类（连接已建立但对端突然断开）— 区别于普通连接失败
_SERVER_CRASH_EXCEPTIONS: tuple[type[BaseException], ...] = (
    httpx.ReadError,
    httpx.RemoteProtocolError,
    httpx.CloseError,
    httpx.ProtocolError,
    ConnectionResetError,
    BrokenPipeError,
    ConnectionAbortedError,
)

# 连接阶段失败（DNS / TCP / TLS）— 与服务端崩溃区分
_CONNECT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
)

# 超时类
_TIMEOUT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    httpx.TimeoutException,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    asyncio.TimeoutError,
)


@dataclass
class ProbeErrorInfo:
    """探测异常分类信息。"""

    error_type: str               # timeout / connect_error / server_crash / rate_limited / ssl / unknown
    error_message: str            # 用户友好的中文描述
    detail: str                   # 原始异常简要（脱敏后）
    suggestion: str               # 给用户的下一步建议
    retryable: bool = True        # 是否建议重试
    rate_limited: bool = False    # 是否被限流
    retry_after: Optional[float] = None  # 限流时的退避秒数
    status_code: Optional[int] = None    # 触发异常的 HTTP 状态码

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 安全 dict。"""
        return {
            "error_type": self.error_type,
            "error_message": self.error_message,
            "detail": self.detail[:300],
            "suggestion": self.suggestion,
            "retryable": self.retryable,
            "rate_limited": self.rate_limited,
            "retry_after": self.retry_after,
            "status_code": self.status_code,
        }


def classify_exception(exc: BaseException, context: str = "") -> ProbeErrorInfo:
    """将任意探测异常分类为 ProbeErrorInfo。

    Args:
        exc: 捕获到的异常对象
        context: 探测上下文（例：'首页抓取' / 'LLM 端点探测 /v1/models'）

    Returns:
        ProbeErrorInfo（前端可直接渲染或作为 toast 展示）
    """
    raw = f"{type(exc).__name__}: {str(exc)[:200]}".strip()

    # ── 限流（从异常消息中识别 429）──
    if isinstance(exc, httpx.HTTPStatusError):
        sc = exc.response.status_code if exc.response is not None else None
        if sc == 429 or "429" in raw or "too many" in raw.lower() or "rate limit" in raw.lower():
            retry_after = _extract_retry_after(exc.response) if exc.response is not None else None
            return ProbeErrorInfo(
                error_type="rate_limited",
                error_message=f"{context or '探测'} 触发目标速率限制 (HTTP 429)",
                detail=raw,
                suggestion=(
                    "目标已触发限流。已自动降低后续请求频率。"
                    + (f" 建议等待 {retry_after:.1f}s 后重试" if retry_after else " 建议稍后重试或减少并发")
                ),
                retryable=True,
                rate_limited=True,
                retry_after=retry_after,
                status_code=sc,
            )
        if sc in (502, 503, 504):
            return ProbeErrorInfo(
                error_type="server_unavailable",
                error_message=f"{context or '目标'} 返回 {sc}（服务暂不可用）",
                detail=raw,
                suggestion="目标服务暂时不可用，请稍后重试或检查目标是否过载",
                retryable=True,
                status_code=sc,
            )
        if sc is not None and 500 <= sc < 600:
            return ProbeErrorInfo(
                error_type="server_error",
                error_message=f"{context or '目标'} 返回 {sc}（服务器内部错误）",
                detail=raw,
                suggestion="目标服务器内部错误，可能在重启中或资源耗尽，请稍后重试",
                retryable=True,
                status_code=sc,
            )

    # ── 服务端中断/崩溃 ──
    if isinstance(exc, _SERVER_CRASH_EXCEPTIONS):
        return ProbeErrorInfo(
            error_type="server_crash",
            error_message=f"{context or '目标'} 连接中断（服务器可能已崩溃或主动断开）",
            detail=raw,
            suggestion=(
                "对端程序异常中断（broken pipe / connection reset）。\n"
                "  • 检查目标服务是否还在运行\n"
                "  • 若目标是 Docker 容器，尝试 `docker ps` 查看状态\n"
                "  • 等待几秒后重新点击探测"
            ),
            retryable=True,
        )

    # ── 连接阶段失败 ──
    if isinstance(exc, _CONNECT_EXCEPTIONS):
        return ProbeErrorInfo(
            error_type="connect_error",
            error_message=f"{context or '目标'} 连接失败（网络不可达或服务未启动）",
            detail=raw,
            suggestion=(
                "无法建立到目标的连接。\n"
                "  • 检查目标 URL 是否正确（注意 http/https 与端口）\n"
                "  • 在浏览器中打开该 URL 确认服务可达\n"
                "  • 检查防火墙 / VPN 设置"
            ),
            retryable=True,
        )

    # ── 超时 ──
    if isinstance(exc, _TIMEOUT_EXCEPTIONS):
        return ProbeErrorInfo(
            error_type="timeout",
            error_message=f"{context or '探测'} 请求超时",
            detail=raw,
            suggestion=(
                "目标响应过慢或网络延迟较高。\n"
                "  • 适当增大步骤 1 的「超时」值\n"
                "  • 检查目标机器的 CPU/内存是否过载\n"
                "  • 若使用 VPN/代理，尝试切换网络"
            ),
            retryable=True,
        )

    # ── SSL 错误 ──
    if "ssl" in raw.lower() or "certificate" in raw.lower():
        return ProbeErrorInfo(
            error_type="ssl",
            error_message=f"{context or '目标'} SSL/TLS 证书错误",
            detail=raw,
            suggestion="自签名证书错误：请取消勾选「验证 SSL 证书」后重试",
            retryable=True,
        )

    # ── 未知 ──
    return ProbeErrorInfo(
        error_type="unknown",
        error_message=f"{context or '探测'} 失败",
        detail=raw,
        suggestion="未知异常，请查看服务端日志或稍后重试",
        retryable=True,
    )


def classify_response_for_rate_limit(response: httpx.Response) -> Optional[ProbeErrorInfo]:
    """检查 HTTP 响应是否触发速率限制（429）。

    用法：在探测循环中 `resp = await client.get(...)` 后调用，
    若返回非 None 表示该响应是 429。

    Returns:
        ProbeErrorInfo(rate_limited=True) 或 None
    """
    if response.status_code == 429:
        retry_after = _extract_retry_after(response)
        return ProbeErrorInfo(
            error_type="rate_limited",
            error_message="目标触发速率限制 (HTTP 429)",
            detail=f"Retry-After: {response.headers.get('Retry-After', '未指定')}",
            suggestion=(
                "已检测到速率限制。已自动降低后续请求频率。"
                + (f" 建议等待 {retry_after:.1f}s 后重试" if retry_after else " 建议稍后重试")
            ),
            retryable=True,
            rate_limited=True,
            retry_after=retry_after,
            status_code=429,
        )
    return None


def _extract_retry_after(response: Optional[httpx.Response]) -> Optional[float]:
    """从 Retry-After 头解析退避秒数（支持秒数与 HTTP 日期格式）。"""
    if response is None:
        return None
    val = response.headers.get("Retry-After")
    if not val:
        return None
    val = val.strip()
    try:
        return max(0.0, float(val))
    except ValueError:
        # 可能是 HTTP-date
        try:
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone
            target = parsedate_to_datetime(val)
            if target is None:
                return None
            now = datetime.now(tz=target.tzinfo or timezone.utc)
            return max(0.0, (target - now).total_seconds())
        except Exception:
            return None


# ── 自适应超时 ────────────────────────────────────────────────────────────

@dataclass
class AdaptiveTimeout:
    """自适应超时控制器。

    工作原理:
      - 起始 base_timeout（如 8s）
      - 若连续观察到 429，timeout 自动上调（降低频率）
      - 若连续成功无错误，timeout 缓慢恢复到基线
      - 若对端崩溃（server_crash），timeout 立即翻倍给对端恢复时间

    使用:
        at = AdaptiveTimeout(base=8.0, max_=60.0)
        timeout = at.current()  # 每次探测前取
        ... do probe ...
        if got_429: at.on_rate_limited()
        if got_crash: at.on_server_crash()
        if got_success: at.on_success()
    """
    base: float = 8.0
    max_: float = 60.0
    _current: float = field(init=False)
    _consecutive_rate_limits: int = field(default=0, init=False)
    _consecutive_successes: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._current = self.base

    def current(self) -> float:
        """获取当前推荐 timeout。"""
        return self._current

    def on_rate_limited(self, retry_after: Optional[float] = None) -> float:
        """观察到 429 后调用，返回新的 timeout。"""
        self._consecutive_rate_limits += 1
        self._consecutive_successes = 0
        # 触发限流：timeout 翻倍（最低 12s）
        bump = max(1.5, 1.0 + 0.5 * self._consecutive_rate_limits)
        if retry_after is not None:
            # 至少等到 Retry-After
            self._current = max(self._current * bump, retry_after + 1.0)
        else:
            self._current = min(self._current * bump, self.max_)
        logger.info(
            "[AdaptiveTimeout] 触发限流 ×%d → timeout=%.1fs",
            self._consecutive_rate_limits, self._current,
        )
        return self._current

    def on_server_crash(self) -> float:
        """对端崩溃/中断后调用：timeout 立即翻倍。"""
        self._consecutive_rate_limits = 0
        self._consecutive_successes = 0
        self._current = min(self._current * 2.0, self.max_)
        logger.warning(
            "[AdaptiveTimeout] 对端崩溃 → timeout 翻倍至 %.1fs", self._current,
        )
        return self._current

    def on_success(self) -> float:
        """成功请求后调用：成功计数达到 5 时缓慢恢复基线。"""
        self._consecutive_rate_limits = 0
        self._consecutive_successes += 1
        if self._consecutive_successes >= 5 and self._current > self.base:
            self._current = max(self.base, self._current * 0.9)
            self._consecutive_successes = 0
            logger.debug("[AdaptiveTimeout] 连续成功 → timeout 恢复至 %.1fs", self._current)
        return self._current


# ── 速率限制聚合器 ────────────────────────────────────────────────────────

@dataclass
class RateLimitTracker:
    """单次探测过程中聚合 429 / 限速信息。

    使用:
        tracker = RateLimitTracker()
        for url in urls:
            resp = await client.get(url)
            tracker.record(resp)
        if tracker.hit_count > 0:
            ... 在响应中携带 ...
    """
    hit_count: int = 0
    sample_responses: list[dict] = field(default_factory=list)
    max_retry_after: float = 0.0
    first_hit_at: float = 0.0
    _sample_limit: int = 3

    def record(self, response: httpx.Response) -> bool:
        """记录一个响应，返回是否触发了限流。"""
        if response.status_code != 429:
            return False
        self.hit_count += 1
        if self.first_hit_at == 0.0:
            self.first_hit_at = time.time()
        retry_after = _extract_retry_after(response)
        if retry_after is not None and retry_after > self.max_retry_after:
            self.max_retry_after = retry_after
        if len(self.sample_responses) < self._sample_limit:
            self.sample_responses.append({
                "url": str(response.request.url)[:200],
                "status": response.status_code,
                "retry_after": retry_after,
                "limit": response.headers.get("X-RateLimit-Limit"),
                "remaining": response.headers.get("X-RateLimit-Remaining"),
                "reset": response.headers.get("X-RateLimit-Reset"),
            })
        return True

    def to_dict(self) -> dict[str, Any]:
        """导出为 JSON dict。"""
        return {
            "hit_count": self.hit_count,
            "max_retry_after": self.max_retry_after,
            "sample_responses": self.sample_responses,
            "rate_limited": self.hit_count > 0,
        }


# ── 带绝对兜底的协程运行器 ────────────────────────────────────────────────

async def run_with_absolute_timeout(
    coro_factory,
    absolute_timeout: float,
    step_name: str = "探测",
):
    """运行异步任务并强制应用绝对超时（覆盖一切内部心跳）。

    用途：在 routes.py 中调用时，传入一个返回新协程的可调用对象
    (lambda: smart_discover(...))，这样 `asyncio.wait_for` 才能在
    超时后真正取消底层协程，而不是只中断一层 await。

    Args:
        coro_factory: 返回协程的可调用对象
        absolute_timeout: 绝对超时（秒）
        step_name: 步骤名（用于异常消息）

    Returns:
        协程返回值

    Raises:
        asyncio.TimeoutError: 超时
    """
    try:
        return await asyncio.wait_for(coro_factory(), timeout=absolute_timeout)
    except asyncio.TimeoutError:
        logger.warning("[%s] 绝对兜底超时 %.1fs 触发，强制取消", step_name, absolute_timeout)
        raise


# ── 安全异步 gather（带异常隔离 + 全局超时）──────────────────────────────

async def safe_gather_with_limit(
    coros: list,
    concurrency: int = 5,
    global_timeout: Optional[float] = None,
    rate_tracker: Optional[RateLimitTracker] = None,
) -> list:
    """并发执行多个协程，受信号量约束，任一异常不会污染其他。

    Args:
        coros: 协程列表
        concurrency: 最大并发
        global_timeout: 整体超时（None = 不限制）
        rate_tracker: 可选限流聚合器，协程返回 httpx.Response 时自动记录

    Returns:
        与输入等长的结果列表，失败的协程对应位置为 None 或抛出的异常对象
    """
    sem = asyncio.Semaphore(concurrency)

    async def _wrap(coro):
        async with sem:
            try:
                return await coro
            except Exception as e:  # noqa: BLE001
                logger.debug("safe_gather 协程失败: %s", e)
                return None

    tasks = [_wrap(c) for c in coros]
    if global_timeout is not None:
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=global_timeout)
    else:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    # 将异常对象转 None（避免上层 try/except 误判）
    return [r if not isinstance(r, BaseException) else None for r in results]
