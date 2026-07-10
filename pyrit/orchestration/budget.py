"""预算与速率管控 — Token 预算 / 速率限制 / 成本控制.

实现精细化的资源管控：
- Token 配额管理：总预算跟踪 + 分层限额
- 速率控制：滑动窗口 RPM / TPM 限流
- 成本核算：多模型定价自适应计算
- 自适应并发调整：基于预算余量动态调节并发数
"""

from __future__ import annotations

import logging
import time
import threading
from collections import deque
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================
# Token Budget
# ============================================================

@dataclass
class TokenBudget:
    """Token 预算管理器."""

    total_budget: int = 1_000_000
    used: int = 0
    reserved: int = 0

    def available(self) -> int:
        """剩余可用 tokens."""
        return max(0, self.total_budget - self.used - self.reserved)

    def can_allocate(self, tokens: int) -> bool:
        """检查是否可分配."""
        return self.available() >= tokens

    def allocate(self, tokens: int) -> bool:
        """分配 tokens."""
        if self.can_allocate(tokens):
            self.reserved += tokens
            return True
        return False

    def commit(self, tokens: int) -> None:
        """确认消耗."""
        actual = min(tokens, self.reserved)
        self.used += actual
        self.reserved -= actual

    def release(self, tokens: int) -> None:
        """释放预留."""
        self.reserved = max(0, self.reserved - tokens)

    def reset(self) -> None:
        """重置预算."""
        self.used = 0
        self.reserved = 0

    @property
    def usage_ratio(self) -> float:
        """预算使用率 (0.0~1.0)."""
        if self.total_budget == 0:
            return 1.0
        return self.used / self.total_budget

    @property
    def exhausted(self) -> bool:
        """预算是否耗尽."""
        return self.available() <= 0


# ============================================================
# Rate Limiter (Sliding Window)
# ============================================================

class RateLimiter:
    """基于滑动窗口的速率限制器.

    同时控制：
    - RPM (Requests Per Minute): 每分钟请求数
    - TPM (Tokens Per Minute): 每分钟 Token 数
    """

    def __init__(
        self,
        rpm_limit: int = 60,
        tpm_limit: int = 100_000,
        window_seconds: float = 60.0,
    ):
        self.rpm_limit = rpm_limit
        self.tpm_limit = tpm_limit
        self.window_seconds = window_seconds

        self._request_times: deque[float] = deque()
        self._token_usage: deque[tuple[float, int]] = deque()  # (time, tokens)
        self._lock = threading.Lock()

    def can_request(self, tokens: int = 0) -> bool:
        """检查是否可以发起请求."""
        with self._lock:
            self._cleanup()
            rpm_ok = len(self._request_times) < self.rpm_limit
            tpm_ok = self._current_tpm() + tokens <= self.tpm_limit
            return rpm_ok and tpm_ok

    def record_request(self, tokens: int = 0) -> None:
        """记录一次请求."""
        with self._lock:
            now = time.time()
            self._request_times.append(now)
            self._token_usage.append((now, tokens))
            self._cleanup()

    def wait_if_needed(self, tokens: int = 0) -> float:
        """如果需要限流则计算等待时间."""
        with self._lock:
            self._cleanup()

            wait_time = 0.0

            # RPM 检查
            if len(self._request_times) >= self.rpm_limit:
                oldest = self._request_times[0]
                wait_time = max(wait_time, oldest + self.window_seconds - time.time())

            # TPM 检查
            current_tpm = self._current_tpm()
            if current_tpm + tokens > self.tpm_limit:
                oldest = self._token_usage[0][0]
                wait_time = max(wait_time, oldest + self.window_seconds - time.time())

            return max(0.0, wait_time)

    @property
    def current_rpm(self) -> int:
        """当前窗口内请求数."""
        with self._lock:
            self._cleanup()
            return len(self._request_times)

    @property
    def current_tpm(self) -> int:
        """当前窗口内 token 数."""
        with self._lock:
            self._cleanup()
            return self._current_tpm()

    def _current_tpm(self) -> int:
        return sum(t for _, t in self._token_usage)

    def _cleanup(self) -> None:
        """清理过期记录."""
        cutoff = time.time() - self.window_seconds
        while self._request_times and self._request_times[0] < cutoff:
            self._request_times.popleft()
        while self._token_usage and self._token_usage[0][0] < cutoff:
            self._token_usage.popleft()


# ============================================================
# Budget Controller
# ============================================================

# 各模型 Token 定价 (USD per 1K tokens)
MODEL_PRICING: dict[str, tuple[float, float]] = {
    # (input_price, output_price) per 1K tokens
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "claude-3-opus": (0.015, 0.075),
    "claude-3-sonnet": (0.003, 0.015),
    "claude-3-haiku": (0.00025, 0.00125),
    "gemini-1.5-pro": (0.0035, 0.0105),
    "gemini-1.5-flash": (0.000075, 0.0003),
    "deepseek-v3": (0.00027, 0.0011),
    "qwen-max": (0.0028, 0.0084),
    "default": (0.005, 0.015),
}


class BudgetController:
    """综合预算控制器.

    整合 Token 预算 + 速率限制 + 成本核算。
    """

    def __init__(
        self,
        total_tokens: int = 1_000_000,
        max_cost: float = 50.0,
        rpm_limit: int = 60,
        tpm_limit: int = 100_000,
        model_name: str = "gpt-4o",
    ):
        self.token_budget = TokenBudget(total_budget=total_tokens)
        self.max_cost = max_cost
        self.rate_limiter = RateLimiter(rpm_limit=rpm_limit, tpm_limit=tpm_limit)
        self.model_name = model_name

        # 累计成本
        self.total_cost: float = 0.0
        self.total_requests: int = 0
        self.total_tokens_used: int = 0

    def can_proceed(self, tokens: int = 500) -> bool:
        """检查是否可以继续执行."""
        if self.is_exhausted:
            return False
        cost = self._estimate_cost(tokens, is_output=True)
        if self.total_cost + cost > self.max_cost:
            return False
        if not self.token_budget.can_allocate(tokens):
            return False
        if not self.rate_limiter.can_request(tokens):
            return False
        return True

    def consume(
        self,
        tokens: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        model_override: Optional[str] = None,
    ) -> float:
        """消耗预算并返回成本."""
        total_tokens = tokens or (input_tokens + output_tokens)
        if total_tokens <= 0:
            return 0.0

        model = model_override or self.model_name
        cost = self._calculate_cost(model, input_tokens or tokens, output_tokens or 0)

        self.token_budget.commit(total_tokens)
        self.rate_limiter.record_request(total_tokens)
        self.total_cost += cost
        self.total_requests += 1
        self.total_tokens_used += total_tokens

        logger.debug(
            f"Budget consumed: {total_tokens} tokens, ${cost:.6f} "
            f"(total: ${self.total_cost:.4f}/{self.max_cost:.2f})"
        )
        return cost

    def adaptive_concurrency(self, base_concurrency: int = 5) -> int:
        """根据预算余量自适应调整并发数."""
        remaining = self.token_budget.available()
        if remaining <= 0:
            return 0
        ratio = remaining / self.token_budget.total_budget
        if ratio > 0.5:
            return base_concurrency
        elif ratio > 0.25:
            return max(1, base_concurrency // 2)
        else:
            return max(1, base_concurrency // 4)

    def wait_for_capacity(self, tokens: int = 500) -> None:
        """等待直到有足够容量."""
        wait = self.rate_limiter.wait_if_needed(tokens)
        if wait > 0:
            logger.info(f"Rate limited: waiting {wait:.1f}s")
            time.sleep(wait)

    @property
    def is_exhausted(self) -> bool:
        return self.token_budget.exhausted or self.total_cost >= self.max_cost

    @property
    def summary(self) -> dict:
        return {
            "token_budget_used": self.token_budget.usage_ratio,
            "tokens_remaining": self.token_budget.available(),
            "total_cost": round(self.total_cost, 4),
            "max_cost": self.max_cost,
            "total_requests": self.total_requests,
            "current_rpm": self.rate_limiter.current_rpm,
            "current_tpm": self.rate_limiter.current_tpm,
            "is_exhausted": self.is_exhausted,
        }

    def _estimate_cost(self, tokens: int, is_output: bool = True) -> float:
        return self._calculate_cost(
            self.model_name,
            input_tokens=tokens if not is_output else 0,
            output_tokens=tokens if is_output else 0,
        )

    @staticmethod
    def _calculate_cost(
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """根据模型定价计算成本."""
        pricing = MODEL_PRICING.get(model, MODEL_PRICING["default"])
        input_price_per_1k, output_price_per_1k = pricing
        cost = (input_tokens / 1000) * input_price_per_1k + \
               (output_tokens / 1000) * output_price_per_1k
        return round(cost, 6)
