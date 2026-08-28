"""RateLimitedTarget — 共享信号量 + 差异化重试的 PromptTarget 包装器。

核心特性:
    - 同端点并发控制 (共享 asyncio.Semaphore)
    - 差异化重试 (429/5xx/timeout)
    - Retry-After 头解析
    - 指数退避 + 抖动
    - 不可重试状态码立即失败
    - __getattr__ 属性透传
    - PromptTarget 虚拟子类注册

L5 v4 关键修复:
    - 包装 _send_prompt_to_target_async 而非 send_prompt_async
      原因: PromptTarget.send_prompt_async 是 @final 方法，负责
      validation + normalization + conversation 管理。
      RateLimitedTarget 重写 send_prompt_async 会绕过这些关键步骤，
      导致 AttackExecutor 无法正确管理对话状态。
    - 正确方式: 仅包装 _send_prompt_to_target_async，让
      PromptTarget.send_prompt_async 的 final 方法正常调用。
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

from pyrit.prompt_target.common.prompt_target import PromptTarget

logger = logging.getLogger(__name__)

# 不可重试状态码 (立即失败)
# 注意: 204 (No Content) 不在此列表中 — LongCat API 可能返回 204 空响应，
# 需要重试以获取实际内容
# L5 v4: 移除 422 — JSON 控制字符错误可能是偶发的，重试可能成功
_NON_RETRYABLE_STATUS_CODES = frozenset({400, 401, 403, 404, 405})

# 可重试状态码
_RETRYABLE_STATUS_CODES = frozenset({422, 429, 500, 502, 503, 504})

# 超时异常类型名
_TIMEOUT_EXCEPTION_NAMES = frozenset(
    {
        "APITimeoutError",
        "asyncio.TimeoutError",
        "TimeoutError",
        "ReadTimeout",
        "ConnectTimeout",
        "PoolTimeout",
    }
)


class RateLimitedTarget:
    """带限速 + 重试的 PromptTarget 包装器。

    包装任意 PromptTarget 实例，提供:
        - 并发控制 (共享信号量)
        - 差异化重试 (429 优先使用 Retry-After)
        - 指数退避 + 抖动
        - 不可重试错误立即失败
        - 属性透传到原始 Target

    L5 v4: 仅包装 _send_prompt_to_target_async，不重写 send_prompt_async。
    这样 PromptTarget.send_prompt_async (final) 方法正常执行
    validation + normalization + conversation 管理。

    Args:
        target: 被包装的 PromptTarget 实例。
        endpoint: 端点 URL (用于共享信号量, None 则从 target 提取)。
        max_concurrency: 最大并发数。
        max_retries: 最大重试次数 (429/5xx)。
        requests_per_minute: 每分钟最大请求数 (可选)。
        timeout_max_retries: 超时独立重试预算。
        timeout_max_delay: 超时最大退避延迟 (秒)。
    """

    def __init__(
        self,
        *,
        target: PromptTarget,
        endpoint: str | None = None,
        max_concurrency: int = 3,
        max_retries: int = 3,
        requests_per_minute: int | None = None,
        timeout_max_retries: int = 5,
        timeout_max_delay: float = 120.0,
    ) -> None:
        self._target = target
        self._endpoint = endpoint or getattr(target, "_endpoint", str(id(target)))
        self._max_retries = max_retries
        self._timeout_max_retries = timeout_max_retries
        self._timeout_max_delay = timeout_max_delay
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._rpm = requests_per_minute

        # RPM 限速
        self._rpm_semaphore: asyncio.Semaphore | None = None
        if requests_per_minute:
            self._rpm_semaphore = asyncio.Semaphore(requests_per_minute)

        # L5 v4: 保存原始 target 的关键属性引用
        # 使 RateLimitedTarget 在 AttackExecutor 中表现为 PromptTarget
        self._memory = getattr(target, "_memory", None)
        self._verbose = getattr(target, "_verbose", False)
        self._max_requests_per_minute = getattr(target, "_max_requests_per_minute", None)
        self._endpoint_attr = getattr(target, "_endpoint", "")
        self._model_name = getattr(target, "_model_name", "")
        self._underlying_model = getattr(target, "_underlying_model", None)
        self._configuration = getattr(target, "_configuration", None)
        self._identifier = getattr(target, "_identifier", None)
        self.supported_converters = getattr(target, "supported_converters", [])

    async def _send_prompt_to_target_async(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
        """带限速 + 重试的 prompt 发送到目标。

        L5 v4: 包装 _send_prompt_to_target_async 而非 send_prompt_async。
        这样 PromptTarget.send_prompt_async (final) 方法正常执行
        validation + normalization + conversation 管理。

        流程:
            1. 获取共享信号量 (同端点并发控制)
            2. 调用原始 target._send_prompt_to_target_async()
            3. 成功 → 返回结果
            4. 失败 → 判断是否可重试:
                - 不可重试 (400/401/403/404/405) → 立即 raise
                - 可重试 (422/429/500/502/503/504/timeout) → 指数退避重试
            5. 429 优先使用 Retry-After 头
            6. 超时使用独立重试预算 + 更大退避延迟
        """
        async with self._semaphore:
            return await self._send_with_retry(normalized_conversation=normalized_conversation)

    async def _send_with_retry(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
        """执行带重试的发送。"""
        last_exception: Exception | None = None
        timeout_retries = 0

        for attempt in range(self._max_retries + 1):
            try:
                result = await self._target._send_prompt_to_target_async(
                    normalized_conversation=normalized_conversation,
                )
                return result

            except Exception as e:
                last_exception = e
                error_info = _classify_error(e)

                if not error_info["retryable"]:
                    logger.debug("Non-retryable error, failing immediately: %s", e)
                    raise

                if error_info["is_timeout"]:
                    if timeout_retries >= self._timeout_max_retries:
                        logger.error("Timeout retry budget exhausted (%d/%d)", timeout_retries, self._timeout_max_retries)
                        raise
                    timeout_retries += 1
                    delay = min(
                        self._timeout_max_delay,
                        2.0**timeout_retries + random.uniform(0, 1.0),
                    )
                else:
                    delay = error_info.get("retry_after") or min(
                        30.0,
                        2.0**attempt + random.uniform(0, 1.0),
                    )

                logger.warning(
                    "Retryable error (attempt %d/%d): %s. Waiting %.1fs",
                    attempt + 1,
                    self._max_retries,
                    error_info["type"],
                    delay,
                )
                await asyncio.sleep(delay)

        if last_exception:
            raise last_exception
        raise RuntimeError("_send_prompt_to_target_async exhausted retries without exception")

    def __getattr__(self, name: str) -> Any:
        """透传属性到原始 Target。

        注意: 此方法仅在属性未在 RateLimitedTarget 实例上找到时调用。
        已在 __init__ 中复制的属性不会触发此方法。
        """
        return getattr(self._target, name)


def _classify_error(exc: Exception) -> dict[str, Any]:
    """分类异常，决定是否可重试。

    Returns:
        包含以下键的字典:
            - retryable: bool — 是否可重试
            - is_timeout: bool — 是否超时
            - retry_after: float | None — Retry-After 头值 (秒)
            - type: str — 错误类型描述
    """
    exc_name = type(exc).__name__
    exc_str = str(exc).lower()

    # 超时
    if exc_name in _TIMEOUT_EXCEPTION_NAMES or "timeout" in exc_str or "timed out" in exc_str:
        return {"retryable": True, "is_timeout": True, "retry_after": None, "type": f"timeout:{exc_name}"}

    # HTTP 状态码
    for code in _NON_RETRYABLE_STATUS_CODES:
        if str(code) in exc_str:
            return {"retryable": False, "is_timeout": False, "retry_after": None, "type": f"http:{code}"}

    # 204 — 空响应 (LongCat API 可能返回), 需要重试
    if "204" in exc_str or "no content" in exc_str:
        return {"retryable": True, "is_timeout": False, "retry_after": None, "type": "http:204_empty"}

    # 429 — 解析 Retry-After
    if "429" in exc_str:
        retry_after = _parse_retry_after(exc_str)
        return {"retryable": True, "is_timeout": False, "retry_after": retry_after, "type": "http:429"}

    # 5xx
    for code in _RETRYABLE_STATUS_CODES:
        if str(code) in exc_str:
            return {"retryable": True, "is_timeout": False, "retry_after": None, "type": f"http:{code}"}

    # 连接错误
    if "connection" in exc_str or "connect" in exc_str:
        return {"retryable": True, "is_timeout": False, "retry_after": None, "type": "connection_error"}

    # 默认不可重试
    return {"retryable": False, "is_timeout": False, "retry_after": None, "type": exc_name}


def _parse_retry_after(error_str: str) -> float | None:
    """从错误信息中解析 Retry-After 值。"""
    import re

    match = re.search(r"retry[- ]after[:\s]+(\d+)", error_str, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None


# 注册为 PromptTarget 虚拟子类
PromptTarget.register(RateLimitedTarget)
