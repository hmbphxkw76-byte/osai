"""
Rate-Limited Target Wrapper (PyRIT 原生优先 + 自建补充)
=====================================================

API 级别并发控制 + 503/502 重试退避。

PyRIT 原生 vs 自建对照（对齐 Resiliency 文档）：
  ┌──────────────────────┬──────────────────────────────────┬──────────────────────────────┐
  │ 功能                  │ PyRIT 原生                       │ 自建补充                      │
  ├──────────────────────┼──────────────────────────────────┼──────────────────────────────┤
  │ RPM 限速              │ ✅ @limit_requests_per_minute   │ —（不重复实现）               │
  │                      │    装饰器在 ChatTarget 等已应用   │                              │
  │ 429 重试              │ ✅ @pyrit_target_retry           │ —（不重复实现）               │
  │                      │    tenacity 指数退避             │                              │
  │ EmptyResponse 重试   │ ✅ @pyrit_target_retry           │ —                             │
  │ RETRY_* 环境变量      │ ✅ _DynamicStopAfterAttempt     │ —                             │
  │                      │    运行时读取                    │                              │
  │ batch_size=1 强制    │ ✅ _validate_rate_limit_params  │ —                             │
  │    （RPM 模式下）     │    在 batch_helper.py           │                              │
  ├──────────────────────┼──────────────────────────────────┼──────────────────────────────┤
  │ 503/502 重试          │ ❌ pyrit_target_retry 不含       │ ✅ _retry_with_backoff       │
  │                      │    InternalServerError           │    扩展可重试状态码           │
  │ API 并发信号量        │ ❌ AttackExecutor.max_concurrency│ ✅ asyncio.Semaphore         │
  │                      │    只控 objective 级并发          │    + 共享注册表               │
  │ APITimeoutError 重试 │ ❌ 不在重试列表中                │ ✅ 包含在可重试异常中          │
  └──────────────────────┴──────────────────────────────────┴──────────────────────────────┘

PyRIT Resiliency 三层重试机制（官方文档）：
  L1 (pyrit_target_retry): RateLimitError(429) / EmptyResponseException / RateLimitException
     → 指数退避，RETRY_MAX_NUM_ATTEMPTS / RETRY_WAIT_MIN_SECONDS / RETRY_WAIT_MAX_SECONDS
  L2 (pyrit_json_retry): InvalidJsonException → 立即重试
  L3 (Scenario max_retries): 工作流级重试，跳过已完成目标

  本模块补充 L1 的盲区：503/502/500/504 + APITimeoutError + APIConnectionError
  这些错误在 PyRIT 的 _handle_openai_request_async 中直接 raise，
  不被 @pyrit_target_retry 捕获（装饰器只匹配 RateLimitError/EmptyResponse/RateLimitException）。

实现方式：
  通过替换目标实例的 `_send_prompt_to_target_async` 方法（PyRIT abstract method），
  在 PyRIT 原生的 @limit_requests_per_minute + @pyrit_target_retry 装饰器链之上，
  额外包裹 API 并发信号量 + 503 重试逻辑。

  注意：PyRIT 原生装饰器已在类定义时应用到 _send_prompt_to_target_async 上，
  我们保存的 original_method 已包含原生装饰器链，因此原生 RPM 限速和 429 重试
  仍然生效，我们的包装层只添加额外的信号量和 503 重试。
"""

import asyncio
import logging
import os
import random
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ── 可重试的 HTTP 状态码（补充 PyRIT 原生未覆盖的 5xx）──
# PyRIT 原生 @pyrit_target_retry 已处理 429 (RateLimitError/RateLimitException)
# 我们补充 500/502/503/504（scheduler queue full 等临时过载）
_RETRYABLE_STATUS_CODES = frozenset({500, 502, 503, 504})

# ── 可重试的异常类型名（补充 PyRIT 原生未覆盖的）──
# PyRIT 原生已覆盖: RateLimitError, EmptyResponseException, RateLimitException
# 我们补充: InternalServerError(503), APIStatusError(5xx), APITimeoutError, APIConnectionError
_RETRYABLE_EXCEPTION_NAMES = frozenset({
    "InternalServerError",
    "APIStatusError",  # 子类化检查 status_code
    "APITimeoutError",
    "APIConnectionError",
    "ServerErrorException",  # PyRIT 的 5xx 异常
})

# 超时类异常的最大重试次数（每次超时等待 300s+，重试过多不可行）
# 重试 3 次（1 次原始 + 2 次重试），平衡可用性与总耗时
_TIMEOUT_EXCEPTION_NAMES = frozenset({
    "APITimeoutError",
    "APIConnectionError",
})
_TIMEOUT_MAX_RETRIES = 3


@dataclass
class RateLimitConfig:
    """
    API 级别限速/重试配置（补充 PyRIT 原生盲区）

    PyRIT 原生已处理（通过 @limit_requests_per_minute + @pyrit_target_retry）：
      - RPM 限速（max_requests_per_minute 参数透传到 TargetParams）
      - 429 重试（tenacity 指数退避，RETRY_* 环境变量控制）
      - EmptyResponse 重试

    本配置控制自建补充部分：
      - API 并发信号量（PyRIT 无此功能）
      - 503/502/500/504 重试（PyRIT @pyrit_target_retry 不覆盖）
      - APITimeoutError/APIConnectionError 重试（PyRIT 不覆盖）

    Attributes:
        max_concurrent_requests: 同时 pending 的 API 请求上限（信号量大小）
            - 10 = 保守（推荐用于共享 API / 云 API）
            - 20 = 平衡
            - 50 = 激进（仅本地 Ollama / vLLM）
            - None = 不限制
        retry_max_attempts: 503/502 重试最大次数（含首次请求）
            - 默认从 PyRIT RETRY_MAX_NUM_ATTEMPTS 环境变量读取（对齐 L1 重试配置）
            - 3 = 默认（1 次原始 + 2 次重试）
        retry_initial_wait: 首次重试等待秒数（指数退避起始值）
            - 默认从 PyRIT RETRY_WAIT_MIN_SECONDS 环境变量读取
        retry_max_wait: 最大重试等待秒数（指数退避上限）
            - 默认从 PyRIT RETRY_WAIT_MAX_SECONDS 环境变量读取
        retry_jitter: 抖动系数（0.0-1.0，防止重试风暴）
    """
    max_concurrent_requests: Optional[int] = 5
    retry_max_attempts: int = 0  # 0 = 从 RETRY_MAX_NUM_ATTEMPTS 环境变量读取
    retry_initial_wait: float = 0  # 0 = 从 RETRY_WAIT_MIN_SECONDS 环境变量读取
    retry_max_wait: float = 0  # 0 = 从 RETRY_WAIT_MAX_SECONDS 环境变量读取
    retry_jitter: float = 0.3

    def __post_init__(self):
        if self.retry_jitter < 0 or self.retry_jitter > 1:
            raise ValueError("retry_jitter must be in [0.0, 1.0]")

    @property
    def effective_retry_max_attempts(self) -> int:
        """从环境变量解析有效重试次数（对齐 PyRIT L1 重试配置）"""
        if self.retry_max_attempts > 0:
            return self.retry_max_attempts
        return int(os.getenv("RETRY_MAX_NUM_ATTEMPTS", "10"))

    @property
    def effective_retry_initial_wait(self) -> float:
        """从环境变量解析有效初始等待时间"""
        if self.retry_initial_wait > 0:
            return self.retry_initial_wait
        return float(os.getenv("RETRY_WAIT_MIN_SECONDS", "5"))

    @property
    def effective_retry_max_wait(self) -> float:
        """从环境变量解析有效最大等待时间"""
        if self.retry_max_wait > 0:
            return self.retry_max_wait
        return float(os.getenv("RETRY_WAIT_MAX_SECONDS", "220"))


# ── 全局信号量注册表（同端点共享信号量）──
_semaphore_registry: dict[str, asyncio.Semaphore] = {}


def get_shared_semaphore(key: str, max_concurrent: int) -> asyncio.Semaphore:
    """
    获取或创建共享信号量

    相同 key（通常用端点 URL）的信号量会被复用，
    确保多个 target 实例共享同一个并发限制。

    Args:
        key: 信号量唯一标识（通常用 endpoint URL）
        max_concurrent: 最大并发数

    Returns:
        共享的 asyncio.Semaphore 实例
    """
    if key not in _semaphore_registry:
        _semaphore_registry[key] = asyncio.Semaphore(max_concurrent)
        logger.info(f"Created shared API semaphore: key={key}, max_concurrent={max_concurrent}")
    return _semaphore_registry[key]


def reset_semaphore_registry() -> None:
    """重置信号量注册表（用于测试）"""
    _semaphore_registry.clear()


def _is_retryable_error(error: Exception) -> bool:
    """
    判断错误是否可重试（补充 PyRIT 原生未覆盖的错误类型）

    PyRIT 原生 @pyrit_target_retry 已处理（不需要我们重试）：
      - RateLimitError (OpenAI 429)
      - RateLimitException (PyRIT 429)
      - EmptyResponseException (204)

    我们补充处理：
      - InternalServerError (503 scheduler queue full)
      - APIStatusError with 5xx status_code
      - APITimeoutError / APIConnectionError (瞬时网络错误)
      - ServerErrorException (PyRIT 5xx)

    Args:
        error: 捕获的异常

    Returns:
        True 如果错误可重试
    """
    error_type_name = type(error).__name__

    # 直接类型名匹配
    if error_type_name in _RETRYABLE_EXCEPTION_NAMES:
        # APIStatusError 需要检查状态码
        if error_type_name == "APIStatusError":
            status_code = getattr(error, "status_code", None)
            if status_code is not None and status_code in _RETRYABLE_STATUS_CODES:
                return True
            # APIStatusError 但状态码不在可重试列表中
            return False
        return True

    # 检查 status_code 属性（适用于各种 API 错误子类）
    status_code = getattr(error, "status_code", None)
    if status_code is not None and status_code in _RETRYABLE_STATUS_CODES:
        return True

    # 检查异常链中的 cause
    cause = getattr(error, "__cause__", None) or getattr(error, "__context__", None)
    if cause is not None and cause is not error:
        return _is_retryable_error(cause)

    return False


def _extract_retry_after(error: Exception) -> Optional[float]:
    """
    从错误中提取 Retry-After 值（秒）

    某些 API 在 429/503 响应头中返回 Retry-After 值，
    指示客户端应等待多长时间后重试。

    Args:
        error: 捕获的异常

    Returns:
        等待秒数，或 None 如果未提供
    """
    # 检查 response.headers 中的 Retry-After
    response = getattr(error, "response", None)
    if response is not None:
        headers = getattr(response, "headers", None)
        if headers:
            retry_after = headers.get("retry-after") or headers.get("Retry-After")
            if retry_after:
                try:
                    return float(retry_after)
                except (ValueError, TypeError):
                    pass

    # 检查 error 对象上的 retry_after 属性
    retry_after = getattr(error, "retry_after", None)
    if retry_after is not None:
        try:
            return float(retry_after)
        except (ValueError, TypeError):
            pass

    return None


async def _retry_with_backoff(
    api_call: Any,
    config: RateLimitConfig,
    *,
    call_description: str = "API request",
) -> Any:
    """
    带指数退避的重试执行（补充 PyRIT L1 重试盲区）

    对齐 PyRIT Resiliency 文档的 retry 理念，但扩展到 503/502/500/504：
    - PyRIT 原生 @pyrit_target_retry 仅重试 RateLimitError(429) + EmptyResponseException
    - 本函数补充重试 InternalServerError(503) + APIStatusError(5xx) + 网络瞬时错误
    - 退避参数复用 PyRIT 的 RETRY_* 环境变量（统一配置源）

    注意：PyRIT 原生装饰器已在 original_method 中生效，429 和 EmptyResponse
    会被原生重试处理，不会到达本函数。本函数只处理原生不覆盖的错误。

    Args:
        api_call: 异步可调用对象（无参数）
        config: 限速/重试配置
        call_description: 调用描述（用于日志）

    Returns:
        api_call 的返回值

    Raises:
        最后一个异常（如果所有重试都失败）
    """
    max_attempts = config.effective_retry_max_attempts
    initial_wait = config.effective_retry_initial_wait
    max_wait = config.effective_retry_max_wait

    last_error: Optional[Exception] = None

    for attempt in range(max_attempts):
        try:
            return await api_call()
        except Exception as e:
            last_error = e
            if not _is_retryable_error(e):
                # 不可重试的错误，直接抛出
                raise

            # 超时类异常限制重试次数（每次超时 300s+，重试过多不可行）
            err_type = type(e).__name__
            is_timeout_err = err_type in _TIMEOUT_EXCEPTION_NAMES
            if is_timeout_err and attempt >= _TIMEOUT_MAX_RETRIES - 1:
                logger.warning(
                    f"⚠ {call_description} got {err_type} (attempt {attempt + 1}/{_TIMEOUT_MAX_RETRIES}), "
                    f"timeout retry limit reached: {e}"
                )
                print(
                    f"  [!] {call_description}: API timeout after {attempt + 1} attempts "
                    f"({_TIMEOUT_MAX_RETRIES} max). Last error: {e}"
                )
                raise

            if attempt >= max_attempts - 1:
                # 最后一次重试也失败了
                logger.warning(
                    f"{call_description} failed after {max_attempts} attempts: "
                    f"{type(e).__name__}: {e}"
                )
                raise

            # 计算等待时间：指数退避 + 抖动（对齐 PyRIT tenacity wait_random_exponential）
            base_wait = initial_wait * (2 ** attempt)
            jitter = base_wait * config.retry_jitter * random.random()
            wait_time = min(base_wait + jitter, max_wait)

            # 检查 Retry-After 头
            retry_after = _extract_retry_after(e)
            if retry_after is not None:
                wait_time = max(wait_time, retry_after)

            # 超时类异常使用更长的退避时间（给 API 更多恢复时间）
            if is_timeout_err:
                wait_time = max(wait_time, 10.0 * (attempt + 1))

            effective_max = _TIMEOUT_MAX_RETRIES if is_timeout_err else max_attempts
            logger.warning(
                f"⚠ {call_description} got {type(e).__name__} (attempt {attempt + 1}/{effective_max}), "
                f"retrying in {wait_time:.1f}s: {e}"
            )
            if is_timeout_err:
                print(
                    f"  [!] {call_description}: API timeout (attempt {attempt + 1}/{effective_max}), "
                    f"retrying in {wait_time:.1f}s..."
                )
            await asyncio.sleep(wait_time)

    # 理论上不会到达这里
    raise last_error  # type: ignore[misc]


def wrap_target_with_rate_limiting(
    target: Any,
    config: Optional[RateLimitConfig] = None,
    *,
    semaphore_key: Optional[str] = None,
) -> Any:
    """
    为 PromptTarget 实例添加 API 级别并发控制和 503 重试

    PyRIT 原生优先策略：
    - RPM 限速 → 已由 PyRIT @limit_requests_per_minute 装饰器处理（通过 TargetParams.max_requests_per_minute）
    - 429 重试 → 已由 PyRIT @pyrit_target_retry 装饰器处理（通过 RETRY_* 环境变量）
    - 我们只补充：API 并发信号量 + 503/502/500/504 重试

    通过替换目标实例的 `_send_prompt_to_target_async` 方法实现：
    - original_method 已包含 PyRIT 原生装饰器链（@limit_requests_per_minute + @pyrit_target_retry）
    - 我们的包装层在原生装饰器之上添加信号量 + 503 重试
    - 对 Scorer / AdversarialChat 等所有使用该 target 的组件透明

    Args:
        target: PyRIT PromptTarget 实例
        config: 限速/重试配置（None=使用默认配置）
        semaphore_key: 共享信号量的唯一标识（通常用 endpoint URL）
            - 相同 key 的多个 target 实例共享同一个信号量
            - None=每次调用创建独立信号量（不推荐）

    Returns:
        原始 target 实例（已原地修改）

    Example:
        >>> target = await create_prompt_target(...)
        >>> target = wrap_target_with_rate_limiting(
        ...     target,
        ...     config=RateLimitConfig(max_concurrent_requests=10),
        ...     semaphore_key="https://api.nvidia.com/v1",
        ... )
    """
    if config is None:
        config = RateLimitConfig()

    # 获取或创建信号量
    semaphore: Optional[asyncio.Semaphore] = None
    if config.max_concurrent_requests is not None and config.max_concurrent_requests > 0:
        if semaphore_key:
            semaphore = get_shared_semaphore(semaphore_key, config.max_concurrent_requests)
        else:
            semaphore = asyncio.Semaphore(config.max_concurrent_requests)

    # 保存原始方法（已包含 PyRIT 原生 @limit_requests_per_minute + @pyrit_target_retry 装饰器链）
    original_method = target._send_prompt_to_target_async

    # 目标标识（用于日志）
    target_name = type(target).__name__
    target_model = getattr(target, "_model_name", "unknown")

    async def rate_limited_send_prompt(*, normalized_conversation: Any) -> Any:
        """
        限速版 _send_prompt_to_target_async

        执行顺序：
        1. 获取 API 并发信号量（自建，PyRIT 无此功能）
        2. 调用 original_method（已包含 PyRIT 原生装饰器链）：
           a. @limit_requests_per_minute → RPM 限速 sleep（如果配置了 max_requests_per_minute）
           b. @pyrit_target_retry → 429/EmptyResponse 重试（tenacity 指数退避）
           c. 实际 _send_prompt_to_target_async → API 调用
        3. 如果 original_method 抛出 503/502/500/504 → 自建重试（补充 PyRIT 盲区）
        4. 释放信号量
        """
        # 定义带 503 重试的 API 调用
        async def _do_api_call() -> Any:
            return await original_method(normalized_conversation=normalized_conversation)

        call_desc = f"{target_name}/{target_model}"

        # 并发限制 + 503 重试
        if semaphore is not None:
            async with semaphore:
                return await _retry_with_backoff(_do_api_call, config, call_description=call_desc)
        else:
            return await _retry_with_backoff(_do_api_call, config, call_description=call_desc)

    # 原地替换方法
    target._send_prompt_to_target_async = rate_limited_send_prompt

    logger.info(
        f"Rate limiting applied to {target_name}/{target_model}: "
        f"max_concurrent={config.max_concurrent_requests}, "
        f"503_retry_attempts={config.effective_retry_max_attempts} "
        f"(from RETRY_MAX_NUM_ATTEMPTS env), "
        f"semaphore_key={semaphore_key}"
    )

    return target


def create_rate_limit_config_from_env(
    max_concurrent: Optional[int] = None,
    max_rpm: Optional[int] = None,
    retry_attempts: Optional[int] = None,
) -> RateLimitConfig:
    """
    从环境变量/参数创建 RateLimitConfig

    优先级：显式参数 > 环境变量 > PyRIT 原生默认值

    RPM 限速说明：
        max_rpm 参数已废弃（PyRIT 原生 @limit_requests_per_minute 已处理）。
        保留参数仅为向后兼容，实际 RPM 限速请通过 TargetParams.max_requests_per_minute 设置。
        PyRIT 原生装饰器会自动读取 target._max_requests_per_minute 并 sleep(60/rpm)。

    重试说明：
        retry_attempts 默认从 PyRIT 的 RETRY_MAX_NUM_ATTEMPTS 环境变量读取，
        与 PyRIT L1 重试（@pyrit_target_retry）共用配置源，确保统一。

    Args:
        max_concurrent: 最大并发 API 请求数
        max_rpm: (已废弃) 每分钟最大请求数，请用 TargetParams.max_requests_per_minute
        retry_attempts: 503/502 重试次数（默认从 RETRY_MAX_NUM_ATTEMPTS 读取）

    Returns:
        RateLimitConfig 实例
    """
    if max_concurrent is None:
        max_concurrent_env = os.getenv("API_MAX_CONCURRENCY")
        if max_concurrent_env is not None:
            max_concurrent = int(max_concurrent_env)

    # retry_attempts: 优先显式参数，其次 API_RETRY_MAX_ATTEMPTS，最后 0（从 RETRY_MAX_NUM_ATTEMPTS 读取）
    if retry_attempts is None:
        api_retry_str = os.getenv("API_RETRY_MAX_ATTEMPTS")
        if api_retry_str is not None:
            retry_attempts = int(api_retry_str)
        else:
            retry_attempts = 0  # 0 = 从 RETRY_MAX_NUM_ATTEMPTS 读取

    return RateLimitConfig(
        max_concurrent_requests=max_concurrent,
        retry_max_attempts=retry_attempts,
    )
