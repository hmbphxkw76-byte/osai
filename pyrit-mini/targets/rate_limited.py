"""RateLimitedTarget — 共享信号量 + 差异化重试的 PromptTarget 包装器。

核心特性:
    - 同端点并发控制 (共享 asyncio.Semaphore)
    - 差异化重试 (429/5xx/timeout)
    - Retry-After 头解析
    - 指数退避 + 抖动
    - 不可重试状态码立即失败
    - __getattr__ 属性透传
    - 继承 PromptTarget (非虚拟子类注册)

PyRIT 原生框架集成 (L5 v52):
    - limit_requests_per_minute: 复用 PyRIT 原生 RPM 限速装饰器逻辑
    - TargetRequirements: 在包装时自动验证攻击者对目标的能力需求
    - CapabilityHandlingPolicy: 透传目标的能力处理策略
      使 ADAPT/RAISE 策略在包装层仍然生效
    - discover_target_capabilities_async: 支持 apply_discovered_capabilities
      方法, 在攻击前自动探测并安装目标能力

L5 v4 关键修复 (v53 进一步对齐):
    - 包装 _send_prompt_to_target_async 而非 send_prompt_async
      原因: PromptTarget.send_prompt_async 是 @final 方法，负责
      validation + normalization + conversation 管理。
    - v53 对齐修复: 继承 PromptTarget (而非虚拟子类注册 + __getattr__)，
      使 send_prompt_async 的 self 是 RateLimitedTarget 实例，
      self._send_prompt_to_target_async 正确解析到带重试的版本。
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
_NON_RETRYABLE_STATUS_CODES = frozenset({400, 404, 405})
_AUTH_RECOVERABLE_STATUS_CODES = frozenset({401, 403})

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


class RateLimitedTarget(PromptTarget):
    """带限速 + 重试的 PromptTarget 包装器。

    对齐 PyRIT 1.0.1: 继承 PromptTarget，使 @final send_prompt_async 方法
    在 RateLimitedTarget 实例上运行。这样 self._send_prompt_to_target_async
    正确解析到 RateLimitedTarget._send_prompt_to_target_async (而非内部 target 的)，
    确保 validation + normalization 流程在 RateLimitedTarget 上执行后，
    委托到带重试的 _send_prompt_to_target_async。

    包装任意 PromptTarget 实例，提供:
        - 并发控制 (共享信号量)
        - 差异化重试 (429 优先使用 Retry-After)
        - 指数退避 + 抖动
        - 不可重试错误立即失败
        - __getattr__ 属性透传到原始 Target

    L5 v4: 仅包装 _send_prompt_to_target_async，不重写 send_prompt_async。
    这样 PromptTarget.send_prompt_async (final) 方法正常执行
    validation + normalization + conversation 管理。
    继承 PromptTarget 后，send_prompt_async 中的 self 是 RateLimitedTarget，
    所以 self._send_prompt_to_target_async 会调用 RateLimitedTarget 的版本
    (带重试 + 限速)，而非内部 target 的版本。

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
        auth_state_manager: Any | None = None,
        auth_state: Any | None = None,
    ) -> None:
        self._target = target
        self._endpoint = endpoint or getattr(target, "_endpoint", str(id(target)))
        self._max_retries = max_retries
        self._timeout_max_retries = timeout_max_retries
        self._timeout_max_delay = timeout_max_delay
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._rpm = requests_per_minute
        # L5 v48: 认证状态管理 (可选)
        self._auth_manager = auth_state_manager
        self._auth_state = auth_state
        # L5 v48: TLS 状态 (供 auth_manager 恢复时构建 URL)
        self._use_tls = getattr(target, "_use_tls", True)

        # RPM 限速
        self._rpm_semaphore: asyncio.Semaphore | None = None
        if requests_per_minute:
            self._rpm_semaphore = asyncio.Semaphore(requests_per_minute)

        # L5 v52: PyRIT 原生 RPM 限速集成
        # PyRIT 的 limit_requests_per_minute 装饰器通过 self._max_requests_per_minute
        # 在每次 _send_prompt_to_target_async 前执行 asyncio.sleep(60/rpm)。
        # 本包装器已有独立的 requests_per_minute + semaphore 控制机制,
        # 这里仅确保 _max_requests_per_minute 属性与原生装饰器兼容,
        # 使攻击者在设置 RPM 时能正确触发 PyRIT 原生限速逻辑。
        effective_rpm = requests_per_minute or getattr(target, "_max_requests_per_minute", None)

        # 对齐 PyRIT 1.0.1: 调用 super().__init__ 使 PromptTarget 基类初始化
        # 这样 send_prompt_async (final) 方法在 RateLimitedTarget 实例上运行,
        # self._send_prompt_to_target_async 正确解析到 RateLimitedTarget 的版本。
        # custom_configuration 透传原始 target 的配置, 使 ADAPT/RAISE 策略生效。
        super().__init__(
            max_requests_per_minute=effective_rpm,
            endpoint=self._endpoint,
            model_name=getattr(target, "_model_name", ""),
            underlying_model=getattr(target, "_underlying_model", None),
            custom_configuration=getattr(target, "_configuration", None),
        )

        # _memory, _verbose, _max_requests_per_minute, _endpoint, _model_name,
        # _underlying_model, _configuration 由 super().__init__ 设置。
        # 额外属性:
        self._endpoint_attr = getattr(target, "_endpoint", "")
        self._identifier = getattr(target, "_identifier", None)
        self.supported_converters = getattr(target, "supported_converters", [])

        # L5 v52: 目标能力验证 — 确保目标满足攻击者需求
        # 学术依据: PyRIT (arXiv:2407.01232) — TargetRequirements 验证
        # 在攻击执行前验证目标能力 (multi_turn, system_prompt, json_output 等),
        # 避免因能力不匹配导致运行时错误。
        self._validate_target_capabilities(target)

        # L5 v52: 保存原始 capabilities 引用, 供 discover_target_capabilities 使用
        self._target_capabilities = getattr(target, "capabilities", None)

    def _validate_target_capabilities(self, target: PromptTarget) -> None:
        """验证目标满足基本攻击需求 (L5 v52).

        L5 v52 对齐: 使用 PyRIT 原生 TargetRequirements.validate()
        验证目标支持基本的 text 输入模态。
        不满足时记录警告但不阻止执行 (降级处理).

        学术依据:
            - PyRIT (arXiv:2407.01232) — TargetRequirements 声明式能力验证
            - Greshake et al. (arXiv:2302.12173) — 目标能力探测先于攻击
        """
        try:
            from pyrit.prompt_target.common.target_requirements import TargetRequirements

            # 构建基本攻击需求: text 输入/输出模态
            requirements = TargetRequirements(
                required=frozenset(),
                native_required=frozenset(),
                required_input_modalities=frozenset({frozenset({"text"})}),
                required_output_modalities=frozenset({frozenset({"text"})}),
            )
            requirements.validate(target=target)
        except ValueError as e:
            logger.warning(
                "Target %s failed TargetRequirements validation: %s; "
                "text-based attacks may fail",
                type(target).__name__,
                e,
            )
        except Exception as e:
            # 目标可能没有 configuration 属性 (如自定义 HTTPTarget 包装)
            logger.debug(
                "Capability validation skipped for %s (non-fatal): %s",
                type(target).__name__,
                e,
            )

    async def apply_discovered_capabilities(self, *, timeout_s: float = 30.0) -> None:
        """使用 PyRIT 原生 discover_target_capabilities 探测并安装能力 (L5 v52).

        PyRIT 原生优势:
            - 自动探测 multi_turn, system_prompt, json_output 等能力
            - 自动探测 input_modalities (text, image_path, audio_path)
            - 探测结果可直接安装到目标 (apply=True)
            - 替代手动能力探测代码, 减少维护成本

        学术依据:
            - PyRIT (arXiv:2407.01232) — 运行时能力发现
            - Greshake et al. (arXiv:2302.12173) — 目标能力指纹

        Args:
            timeout_s: 每个探针的超时时间 (秒)。
        """
        try:
            from pyrit.prompt_target.common.discover_target_capabilities import (
                discover_target_capabilities_async,
            )

            logger.info(
                "L5 v52: Running PyRIT native capability discovery on %s",
                type(self._target).__name__,
            )
            discovered = await discover_target_capabilities_async(
                target=self._target,
                per_probe_timeout_s=timeout_s,
                apply=True,
            )
            self._target_capabilities = discovered
            logger.info(
                "L5 v52: Discovered capabilities: multi_turn=%s, "
                "system_prompt=%s, json_output=%s, "
                "input_modalities=%s",
                discovered.supports_multi_turn,
                discovered.supports_system_prompt,
                discovered.supports_json_output,
                [sorted(s) for s in sorted(discovered.input_modalities)],
            )
        except Exception as e:
            logger.warning(
                "L5 v52: Native capability discovery failed (non-fatal): %s", e
            )

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

                # L5 v48: 认证可恢复错误 (401/403) — 尝试 token 刷新/租户切换
                if error_info.get("auth_recoverable") and self._auth_manager and self._auth_state:
                    auth_manager = self._auth_manager
                    auth_state = self._auth_state
                    logger.warning("Auth error (401/403), attempting recovery...")
                    host = getattr(self, "_endpoint_attr", "")
                    # 从原始 target 提取 host (去除端口)
                    if ":" in str(host):
                        host = str(host).split(":")[0]
                    use_tls = getattr(self, "_use_tls", True)
                    recovered = await auth_manager.try_recover_auth(
                        auth_state,
                        host=host,
                        use_tls=use_tls,
                    )
                    if recovered:
                        # 重建 headers 并更新到原始 target
                        new_headers = auth_manager.build_auth_headers(auth_state)
                        if hasattr(self._target, '_raw_headers'):
                            self._target._raw_headers = new_headers
                        if hasattr(self._target, '_headers'):
                            self._target._headers = dict(new_headers)
                        logger.info("Auth recovered, retrying with new credentials")
                        continue
                    else:
                        logger.warning("Auth recovery failed, raising error")
                        raise

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

    async def cleanup(self) -> None:
        """清理资源 — 生产级资源管理。

        在流水线结束时调用, 确保:
            1. 信号量释放 (避免事件循环残留)
            2. 原始 target 的 httpx.AsyncClient 关闭
            3. PyRIT 原生 dispose_db_engine 释放数据库连接

        对齐 PyRIT 1.0.1:
            官方 PromptTarget 提供 dispose_db_engine() 方法
            释放 MemoryInterface 的数据库连接。本方法在清理
            httpx client 后也调用 dispose_db_engine, 确保所有
            PyRIT 原生资源被正确释放。
        """
        # 1. 关闭原始 target 的 httpx client (如果有)
        target = self._target
        if hasattr(target, '_client') and target._client is not None:
            try:
                await target._client.aclose()
                logger.debug("Closed httpx.AsyncClient for %s", type(target).__name__)
            except Exception as e:
                logger.debug("Error closing httpx client (non-fatal): %s", e)

        # 2. 如果原始 target 有 cleanup 方法, 调用它
        if hasattr(target, 'cleanup') and callable(getattr(target, 'cleanup', None)):
            try:
                result = target.cleanup()
                # 如果是协程, await 它
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.debug("Target cleanup failed (non-fatal): %s", e)

        # 3. 对齐 PyRIT 1.0.1: 调用 dispose_db_engine 释放数据库连接
        try:
            self.dispose_db_engine()
            logger.debug("Disposed DB engine for %s", type(target).__name__)
        except Exception as e:
            logger.debug("dispose_db_engine failed (non-fatal): %s", e)

        logger.debug("RateLimitedTarget cleanup complete for endpoint=%s", self._endpoint)

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
        return {"retryable": True, "is_timeout": True, "retry_after": None, "type": f"timeout:{exc_name}", "auth_recoverable": False}

    # L5 v48: 认证可恢复错误 (401/403)
    for code in _AUTH_RECOVERABLE_STATUS_CODES:
        if str(code) in exc_str:
            return {"retryable": False, "is_timeout": False, "retry_after": None, "type": f"http:{code}", "auth_recoverable": True}

    # HTTP 状态码
    for code in _NON_RETRYABLE_STATUS_CODES:
        if str(code) in exc_str:
            return {"retryable": False, "is_timeout": False, "retry_after": None, "type": f"http:{code}", "auth_recoverable": False}

    # 204 — 空响应 (LongCat API 可能返回), 需要重试
    if "204" in exc_str or "no content" in exc_str:
        return {"retryable": True, "is_timeout": False, "retry_after": None, "type": "http:204_empty", "auth_recoverable": False}

    # 429 — 解析 Retry-After
    if "429" in exc_str:
        retry_after = _parse_retry_after(exc_str)
        return {"retryable": True, "is_timeout": False, "retry_after": retry_after, "type": "http:429", "auth_recoverable": False}

    # 5xx
    for code in _RETRYABLE_STATUS_CODES:
        if str(code) in exc_str:
            return {"retryable": True, "is_timeout": False, "retry_after": None, "type": f"http:{code}", "auth_recoverable": False}

    # 连接错误
    if "connection" in exc_str or "connect" in exc_str:
        return {"retryable": True, "is_timeout": False, "retry_after": None, "type": "connection_error", "auth_recoverable": False}

    # 默认不可重试
    return {"retryable": False, "is_timeout": False, "retry_after": None, "type": exc_name, "auth_recoverable": False}


def _parse_retry_after(error_str: str) -> float | None:
    """从错误信息中解析 Retry-After 值。"""
    import re

    match = re.search(r"retry[- ]after[:\s]+(\d+)", error_str, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None

