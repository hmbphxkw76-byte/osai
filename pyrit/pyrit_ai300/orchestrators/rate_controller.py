# -*- coding: utf-8 -*-
"""
AI-300 Framework - Rate Controller
速率控制器：基于目标类型自动选择最优并发值

设计原则：
- 不同目标类型有不同的最优并发值（GPU 内存、API 限流、浏览器资源）
- 支持 Semaphore 并发控制 + Token Bucket 速率限制
- 配置层可选覆盖，未配置时使用目标类型默认值
- Playwright 目标强制串行（单浏览器实例无法并发）
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict

logger = logging.getLogger(__name__)


# 目标类型默认并发值（基于最佳实践）
# - ollama: 2（本地 GPU 内存有限，避免 OOM）
# - openai: 5（远程 API，平衡速度和 RPM 限流）
# - http: 3（自托管 API，中等并发）
# - playwright: 1（单浏览器实例，必须串行）
DEFAULT_CONCURRENCY: Dict[str, int] = {
    "ollama": 2,
    "openai": 5,
    "http": 3,
    "playwright": 1,
}

# 目标类型默认速率限制（每秒请求数，0 = 无限制）
DEFAULT_RATE_LIMIT: Dict[str, float] = {
    "ollama": 0,       # 本地无限制
    "openai": 10.0,    # 保守值，避免触发 RPM 限流
    "http": 0,         # 自托管默认无限制
    "playwright": 0,   # 浏览器操作本身较慢，无需额外限制
}


@dataclass
class RateController:
    """
    速率控制器

    支持两种控制机制：
    1. Semaphore 并发控制：限制同时执行的最大请求数
    2. Token Bucket 速率限制：限制每秒最大请求数

    Args:
        target_type: 目标类型（ollama/openai/http/playwright）
        max_concurrent: 最大并发数（0 则使用目标类型默认值）
        rate_limit: 每秒最大请求数（0 则无限制）
    """

    target_type: str = "ollama"
    max_concurrent: int = 0
    rate_limit: float = 0.0

    # 内部状态
    _semaphore: asyncio.Semaphore = field(init=False, repr=False)
    _last_request_time: float = field(default=0.0, init=False, repr=False)
    _lock: asyncio.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """初始化 Semaphore 和 Lock"""
        # 解析并发数：0 则使用目标类型默认值
        if self.max_concurrent <= 0:
            self.max_concurrent = DEFAULT_CONCURRENCY.get(self.target_type, 1)

        # Playwright 目标强制串行
        if self.target_type == "playwright":
            self.max_concurrent = 1

        # 解析速率限制：0 则使用目标类型默认值
        if self.rate_limit <= 0:
            self.rate_limit = DEFAULT_RATE_LIMIT.get(self.target_type, 0.0)

        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._lock = asyncio.Lock()

        logger.info(
            "\n######## 速率控制 ########\nRateController created: type=%s, max_concurrent=%d, rate_limit=%.1f req/s",
            self.target_type,
            self.max_concurrent,
            self.rate_limit,
        )

    @property
    def semaphore(self) -> asyncio.Semaphore:
        """获取 Semaphore 实例"""
        return self._semaphore

    @property
    def concurrency(self) -> int:
        """获取当前并发数"""
        return self.max_concurrent

    async def acquire(self) -> None:
        """
        获取执行许可

        先获取 Semaphore，再检查速率限制。
        """
        await self._semaphore.acquire()

        if self.rate_limit > 0:
            async with self._lock:
                now = time.monotonic()
                interval = 1.0 / self.rate_limit
                elapsed = now - self._last_request_time
                if elapsed < interval:
                    wait_time = interval - elapsed
                    logger.debug("Rate limit: waiting %.3fs", wait_time)
                    await asyncio.sleep(wait_time)
                self._last_request_time = time.monotonic()

    def release(self) -> None:
        """释放执行许可"""
        self._semaphore.release()

    async def __aenter__(self) -> RateController:
        """异步上下文管理器入口"""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """异步上下文管理器出口"""
        self.release()

    def summary(self) -> str:
        """返回配置摘要"""
        return (
            f"RateController(type={self.target_type}, "
            f"concurrent={self.max_concurrent}, "
            f"rate_limit={self.rate_limit:.1f} req/s)"
        )


def create_rate_controller(
    target_type: str,
    max_concurrent: int = 0,
    rate_limit: float = 0.0,
) -> RateController:
    """
    工厂函数：创建速率控制器

    Args:
        target_type: 目标类型
        max_concurrent: 最大并发数（0 则使用默认值）
        rate_limit: 每秒最大请求数（0 则使用默认值）

    Returns:
        RateController 实例
    """
    return RateController(
        target_type=target_type,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit,
    )


def get_default_concurrency(target_type: str) -> int:
    """获取目标类型的默认并发数"""
    if target_type in ("playwright", "spa_chat"):
        return 1  # 浏览器目标必须串行
    return DEFAULT_CONCURRENCY.get(target_type, 1)


def get_default_rate_limit(target_type: str) -> float:
    """获取目标类型的默认速率限制"""
    return DEFAULT_RATE_LIMIT.get(target_type, 0.0)
