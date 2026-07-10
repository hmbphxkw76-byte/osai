"""
===============================================================================
BudgetController — 速率与 Token 预算管控
===============================================================================
管理 API 调用资源:
  - Token 预算: 总预算/已使用/剩余追踪
  - 速率限制: RPM (请求/分钟) 和 TPM (Token/分钟) 控制
  - 自适应并发: 根据 429 错误率动态调整并发数
  - 成本预估: 基于模型定价的实时成本计算

与 PyRITNativeOrchestrator 协同:
  Orchestrator 每次攻击前调用 check_budget(),
  攻击后调用 record_usage()。
===============================================================================
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class TokenBudget:
    """Token 预算配置。"""
    total_budget: int = 100000          # 总 Token 预算
    used_tokens: int = 0
    warning_threshold: float = 0.80     # 80% 时警告
    critical_threshold: float = 0.95    # 95% 时停止

    @property
    def remaining(self) -> int:
        return max(0, self.total_budget - self.used_tokens)

    @property
    def usage_ratio(self) -> float:
        return self.used_tokens / self.total_budget if self.total_budget > 0 else 0.0

    @property
    def is_exhausted(self) -> bool:
        return self.usage_ratio >= self.critical_threshold

    @property
    def is_warning(self) -> bool:
        return self.usage_ratio >= self.warning_threshold

    def consume(self, tokens: int) -> bool:
        """消费 Token，返回是否成功（未超预算）。"""
        if self.used_tokens + tokens > self.total_budget * self.critical_threshold:
            return False
        self.used_tokens += tokens
        return True


@dataclass
class RateLimiter:
    """速率限制器 — 基于滑动窗口的 RPM/TPM 控制。"""
    rpm_limit: int = 60           # 每分钟最大请求数
    tpm_limit: int = 100000       # 每分钟最大 Token 数
    window_seconds: float = 60.0  # 滑动窗口大小

    # 滑动窗口记录
    _request_times: deque = field(default_factory=deque)
    _token_records: deque = field(default_factory=lambda: deque(maxlen=1000))

    def _clean_window(self) -> None:
        """清理过期记录。"""
        now = time.time()
        cutoff = now - self.window_seconds
        while self._request_times and self._request_times[0] < cutoff:
            self._request_times.popleft()
        while self._token_records and self._token_records[0][0] < cutoff:
            self._token_records.popleft()

    @property
    def current_rpm(self) -> int:
        """当前窗口内的请求数。"""
        self._clean_window()
        return len(self._request_times)

    @property
    def current_tpm(self) -> int:
        """当前窗口内的 Token 数。"""
        self._clean_window()
        return sum(tokens for _, tokens in self._token_records)

    @property
    def rpm_available(self) -> int:
        return max(0, self.rpm_limit - self.current_rpm)

    @property
    def tpm_available(self) -> int:
        return max(0, self.tpm_limit - self.current_tpm)

    def record_request(self, tokens: int = 0) -> None:
        """记录一次请求。"""
        now = time.time()
        self._request_times.append(now)
        self._token_records.append((now, tokens))

    async def wait_if_needed(self) -> float:
        """如果需要限速，等待并返回等待时间。"""
        self._clean_window()

        wait_time = 0.0
        if self.current_rpm >= self.rpm_limit and self._request_times:
            # 等到最早的请求过期
            wait_time = self._request_times[0] + self.window_seconds - time.time()
        elif self.current_tpm >= self.tpm_limit and self._token_records:
            wait_time = self._token_records[0][0] + self.window_seconds - time.time()

        if wait_time > 0:
            await asyncio.sleep(wait_time)
            self._clean_window()

        return max(0, wait_time)


class BudgetController:
    """预算与速率控制器。

    使用示例:
        budget = BudgetController(token_budget=100000, rpm_limit=60)
        async with budget:
            # 攻击代码
            budget.record_usage(tokens=500)
    """

    # 模型定价 (USD per 1K tokens)
    MODEL_PRICING = {
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "claude-3-opus": {"input": 0.015, "output": 0.075},
        "claude-3-sonnet": {"input": 0.003, "output": 0.015},
        "gemini-pro": {"input": 0.0005, "output": 0.0015},
        "deepseek-chat": {"input": 0.00014, "output": 0.00028},
    }

    def __init__(
        self,
        *,
        token_budget: int = 100000,
        rpm_limit: int = 60,
        tpm_limit: int = 100000,
        max_concurrent: int = 5,
        model_name: str = "gpt-4",
        auto_adjust: bool = True,
    ):
        self.token_budget = TokenBudget(total_budget=token_budget)
        self.rate_limiter = RateLimiter(rpm_limit=rpm_limit, tpm_limit=tpm_limit)
        self.max_concurrent = max_concurrent
        self.model_name = model_name
        self.auto_adjust = auto_adjust

        # 并发控制
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_requests: int = 0

        # 统计
        self.total_requests: int = 0
        self.total_tokens_used: int = 0
        self.total_cost: float = 0.0
        self.rate_limit_hits: int = 0
        self.errors_429: int = 0

        # 自适应并发调整
        self._consecutive_429: int = 0
        self._consecutive_success: int = 0

    async def __aenter__(self):
        """异步上下文管理器入口 — 获取并发槽位。"""
        await self._semaphore.acquire()
        await self.rate_limiter.wait_if_needed()
        self._active_requests += 1
        return self

    async def __aexit__(self, *args):
        """异步上下文管理器出口 — 释放并发槽位。"""
        self._active_requests -= 1
        self._semaphore.release()

    def check_budget(self, estimated_tokens: int) -> bool:
        """检查是否有足够预算执行攻击。

        Args:
            estimated_tokens: 预估消耗的 Token 数

        Returns:
            bool: 预算是否充足
        """
        if self.token_budget.is_exhausted:
            logger.warning(
                f"Token 预算已耗尽: {self.token_budget.used_tokens}/{self.token_budget.total_budget}"
            )
            return False

        if self.token_budget.usage_ratio >= self.token_budget.warning_threshold:
            logger.warning(
                f"Token 预算预警: {self.token_budget.usage_ratio:.0%} 已使用"
            )

        return True

    def record_usage(
        self, tokens: int = 0, input_tokens: int = 0, output_tokens: int = 0,
    ) -> None:
        """记录一次 API 调用消耗。

        Args:
            tokens: 总 Token 数
            input_tokens: 输入 Token 数（用于成本计算）
            output_tokens: 输出 Token 数（用于成本计算）
        """
        self.total_requests += 1
        self.total_tokens_used += tokens
        self.token_budget.consume(tokens)
        self.rate_limiter.record_request(tokens)

        # 成本计算
        pricing = self.MODEL_PRICING.get(self.model_name, {"input": 0.01, "output": 0.03})
        cost = (
            input_tokens * pricing["input"] / 1000 +
            output_tokens * pricing["output"] / 1000
        )
        self.total_cost += cost

    def report_rate_limit(self, is_429: bool = False) -> None:
        """报告速率限制情况。"""
        self.rate_limit_hits += 1
        if is_429:
            self.errors_429 += 1
            self._consecutive_429 += 1
            self._consecutive_success = 0

            # 自适应降低并发
            if self.auto_adjust and self._consecutive_429 >= 3:
                new_concurrent = max(1, self.max_concurrent - 1)
                if new_concurrent != self.max_concurrent:
                    logger.info(
                        f"自适应降低并发: {self.max_concurrent} → {new_concurrent} "
                        f"(连续 429: {self._consecutive_429})"
                    )
                    self.max_concurrent = new_concurrent
                    self._semaphore = asyncio.Semaphore(new_concurrent)
        else:
            self._consecutive_429 = 0
            self._consecutive_success += 1

            # 自适应恢复并发
            if (
                self.auto_adjust and
                self._consecutive_success >= 20 and
                self.max_concurrent < 5
            ):
                new_concurrent = min(5, self.max_concurrent + 1)
                logger.info(f"自适应恢复并发: {self.max_concurrent} → {new_concurrent}")
                self.max_concurrent = new_concurrent
                self._semaphore = asyncio.Semaphore(new_concurrent)

    def get_status(self) -> dict:
        """获取预算状态摘要。"""
        return {
            "token_budget": {
                "total": self.token_budget.total_budget,
                "used": self.token_budget.used_tokens,
                "remaining": self.token_budget.remaining,
                "usage_ratio": self.token_budget.usage_ratio,
                "is_warning": self.token_budget.is_warning,
                "is_exhausted": self.token_budget.is_exhausted,
            },
            "rate_limiter": {
                "rpm_limit": self.rate_limiter.rpm_limit,
                "current_rpm": self.rate_limiter.current_rpm,
                "rpm_available": self.rate_limiter.rpm_available,
                "tpm_limit": self.rate_limiter.tpm_limit,
                "current_tpm": self.rate_limiter.current_tpm,
                "tpm_available": self.rate_limiter.tpm_available,
            },
            "concurrency": {
                "max": self.max_concurrent,
                "active": self._active_requests,
            },
            "stats": {
                "total_requests": self.total_requests,
                "total_tokens": self.total_tokens_used,
                "total_cost_usd": round(self.total_cost, 4),
                "rate_limit_hits": self.rate_limit_hits,
                "errors_429": self.errors_429,
                "model": self.model_name,
            },
        }


__all__ = ["BudgetController", "TokenBudget", "RateLimiter"]
