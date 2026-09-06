"""RateLimitedTarget — PyRIT 原生装饰器的增强包装器。

核心设计理念 (生产级 PyRIT 1.0.1 对齐):
    PyRIT 1.0.1 的 OpenAIChatTarget / OpenAIResponseTarget / HTTPTarget
    已通过原生装饰器提供了完整的限速 + 重试机制:

    1. ``@limit_requests_per_minute`` — PyRIT 原生 RPM 限速
       在 ``_send_prompt_to_target_async`` 前执行 ``asyncio.sleep(60/rpm)``。
       来源: ``pyrit.prompt_target.common.utils``

    2. ``@pyrit_target_retry`` — PyRIT 原生重试装饰器 (tenacity 库)
       自动重试 ``RateLimitError``、``EmptyResponseException``、
       ``RateLimitException``，指数退避 + 随机抖动。
       来源: ``pyrit.exceptions.exception_classes``
       配置: 环境变量 ``RETRY_MAX_NUM_ATTEMPTS`` (默认 10)、
       ``RETRY_WAIT_MIN_SECONDS`` (默认 5)、``RETRY_WAIT_MAX_SECONDS`` (默认 220)。

    3. ``_handle_openai_request_async`` — OpenAITarget 统一错误处理
       精确处理 ``BadRequestError``、``RateLimitError``、
       ``APIStatusError``、``APITimeoutError``、``APIConnectionError``、
       ``AuthenticationError``，基于异常类型而非字符串匹配。
       自动提取 ``Retry-After`` 头和 ``x-request-id``。

    RateLimitedTarget 在此基础上增强:
        - **并发控制** (``asyncio.Semaphore``): 同端点最大并发数，
          PyRIT 原生不提供此功能 (原生仅限速不限并发)。
        - **认证恢复** (401/403): 自动 token 刷新 / 租户切换，
          学术依据: Heroux et al. (arXiv:2403.04206) §3.2。
        - **能力验证**: 使用 PyRIT 原生 ``TargetRequirements.validate()``
          在包装时验证目标满足 text 模态需求。
        - **资源清理**: ``dispose_db_engine()`` + httpx client 关闭。

    关键对齐 (vs 旧版自研重试):
        - 删除自研 ``_classify_error`` + ``_send_with_retry`` 逻辑
        - 删除自研 HTTP 状态码字符串匹配
        - 保留并发控制 (PyRIT 原生不提供)
        - 保留认证恢复 (PyRIT 原生不提供)
        - 透传原生 ``@limit_requests_per_minute`` 和 ``@pyrit_target_retry``
          (不覆盖被包装 target 的 ``_send_prompt_to_target_async``)

学术依据:
    - PyRIT (arXiv:2407.01232) — TargetRequirements 声明式能力验证
    - Greshake et al. (arXiv:2302.12173) — 目标能力探测先于攻击
    - Heroux et al. (arXiv:2403.04206) — 认证失效恢复策略
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pyrit.prompt_target.common.prompt_target import PromptTarget

logger = logging.getLogger(__name__)

# 认证可恢复状态码 — 触发 token 刷新 / 租户切换
_AUTH_RECOVERABLE_STATUS_CODES = frozenset({401, 403})


class RateLimitedTarget(PromptTarget):
    """PyRIT 原生装饰器增强的 PromptTarget 包装器。

    对齐 PyRIT 1.0.1 架构:
        继承 ``PromptTarget``，使 ``@final send_prompt_async`` 方法
        在 ``RateLimitedTarget`` 实例上运行。这样:
        - ``send_prompt_async`` 的 validation + normalization + conversation
          管理在 ``RateLimitedTarget`` 上执行。
        - ``self._send_prompt_to_target_async`` 正确解析到
          ``RateLimitedTarget._send_prompt_to_target_async`` (带并发控制 +
          认证恢复)。

    包装策略 (PyRIT 原生优先):
        - **不覆盖** 被包装 target 的 ``_send_prompt_to_target_async``，
          而是在其中调用 ``self._target._send_prompt_to_target_async()``。
          这保留了被包装 target 上的原生装饰器:
          ``@limit_requests_per_minute`` + ``@pyrit_target_retry``。
        - 仅在调用前后添加并发控制 (Semaphore) 和认证恢复逻辑。

    增强功能 (PyRIT 原生不提供):
        - 并发控制: ``asyncio.Semaphore(max_concurrency)`` 同端点最大并发
        - 认证恢复: 401/403 时自动 token 刷新 / 租户切换
        - 能力验证: ``TargetRequirements.validate()`` 包装时验证
        - 资源清理: ``dispose_db_engine()`` + httpx client 关闭

    Args:
        target: 被包装的 PromptTarget 实例。
        endpoint: 端点 URL (用于共享信号量, None 则从 target 提取)。
        max_concurrency: 最大并发数 (PyRIT 原生不提供)。
        auth_state_manager: 认证状态管理器 (可选)。
        auth_state: 认证状态 (可选)。
    """

    def __init__(
        self,
        *,
        target: PromptTarget,
        endpoint: str | None = None,
        max_concurrency: int = 3,
        auth_state_manager: Any | None = None,
        auth_state: Any | None = None,
    ) -> None:
        self._target = target
        self._endpoint = endpoint or getattr(target, "_endpoint", str(id(target)))
        self._semaphore = asyncio.Semaphore(max_concurrency)

        # 认证状态管理 (可选)
        self._auth_manager = auth_state_manager
        self._auth_state = auth_state
        # TLS 状态 (供 auth_manager 恢复时构建 URL)
        self._use_tls = getattr(target, "_use_tls", True)

        # 对齐 PyRIT 1.0.1: 调用 super().__init__ 使 PromptTarget 基类初始化
        # 这样 send_prompt_async (final) 方法在 RateLimitedTarget 实例上运行,
        # self._send_prompt_to_target_async 正确解析到 RateLimitedTarget 的版本。
        # custom_configuration 透传原始 target 的配置, 使 ADAPT/RAISE 策略生效。
        # max_requests_per_minute 透传原始 target 的 RPM (原生装饰器使用此值)。
        effective_rpm = getattr(target, "_max_requests_per_minute", None)

        super().__init__(
            max_requests_per_minute=effective_rpm,
            endpoint=self._endpoint,
            model_name=getattr(target, "_model_name", ""),
            underlying_model=getattr(target, "_underlying_model", None),
            custom_configuration=getattr(target, "_configuration", None),
        )

        # 额外属性透传
        self._endpoint_attr = getattr(target, "_endpoint", "")
        self._identifier = getattr(target, "_identifier", None)
        self.supported_converters = getattr(target, "supported_converters", [])

        # 目标能力验证 — 使用 PyRIT 原生 TargetRequirements.validate()
        self._validate_target_capabilities(target)

        # 保存原始 capabilities 引用, 供 discover_target_capabilities 使用
        self._target_capabilities = getattr(target, "capabilities", None)

    def _validate_target_capabilities(self, target: PromptTarget) -> None:
        """验证目标满足基本攻击需求。

        使用 PyRIT 原生 ``TargetRequirements.validate()`` 验证目标支持
        基本的 text 输入模态。不满足时记录警告但不阻止执行 (降级处理)。

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
        """使用 PyRIT 原生 ``discover_target_capabilities`` 探测并安装能力。

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
                "Running PyRIT native capability discovery on %s",
                type(self._target).__name__,
            )
            discovered = await discover_target_capabilities_async(
                target=self._target,
                per_probe_timeout_s=timeout_s,
                apply=True,
            )
            self._target_capabilities = discovered
            logger.info(
                "Discovered capabilities: multi_turn=%s, "
                "system_prompt=%s, json_output=%s, "
                "input_modalities=%s",
                discovered.supports_multi_turn,
                discovered.supports_system_prompt,
                discovered.supports_json_output,
                [sorted(s) for s in sorted(discovered.input_modalities)],
            )
        except Exception as e:
            logger.warning(
                "Native capability discovery failed (non-fatal): %s", e
            )

    async def _send_prompt_to_target_async(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
        """带并发控制 + 认证恢复的 prompt 发送到目标。

        PyRIT 原生优先策略:
            调用 ``self._target._send_prompt_to_target_async()``，而非
            覆盖其逻辑。这保留了被包装 target 上的原生装饰器:
            - ``@limit_requests_per_minute`` — PyRIT 原生 RPM 限速
            - ``@pyrit_target_retry`` — PyRIT 原生重试 (tenacity)
              自动处理 RateLimitError、EmptyResponseException、
              RateLimitException 的指数退避重试。

        增强逻辑 (PyRIT 原生不提供):
            1. 获取共享信号量 (同端点并发控制)
            2. 调用原始 target._send_prompt_to_target_async()
               (含原生 @limit_requests_per_minute + @pyrit_target_retry)
            3. 认证错误 (401/403) — 尝试 token 刷新/租户切换
            4. 认证恢复成功 → 更新 headers 并重试
            5. 认证恢复失败 → raise
        """
        async with self._semaphore:
            return await self._send_with_auth_recovery(
                normalized_conversation=normalized_conversation,
            )

    async def _send_with_auth_recovery(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
        """执行发送，带认证恢复逻辑。

        PyRIT 原生 ``@pyrit_target_retry`` 装饰器已处理:
        - RateLimitError (429) — 指数退避重试
        - EmptyResponseException (204) — 重试
        - RateLimitException — 重试
        - APITimeoutError / APIConnectionError — 重试

        本方法仅处理 PyRIT 原生不覆盖的认证恢复场景 (401/403)。
        学术依据: Heroux et al. (arXiv:2403.04206) §3.2 — 认证失效恢复策略
        """
        try:
            # 调用被包装 target 的 _send_prompt_to_target_async
            # 这保留了原生装饰器: @limit_requests_per_minute + @pyrit_target_retry
            return await self._target._send_prompt_to_target_async(
                normalized_conversation=normalized_conversation,
            )
        except Exception as e:
            # 检查是否为认证可恢复错误 (401/403)
            if not self._is_auth_recoverable(e):
                raise

            # 尝试认证恢复
            if not self._auth_manager or not self._auth_state:
                raise

            logger.warning("Auth error (401/403), attempting recovery...")
            host = getattr(self, "_endpoint_attr", "")
            if ":" in str(host):
                host = str(host).split(":")[0]
            use_tls = getattr(self, "_use_tls", True)

            recovered = await self._auth_manager.try_recover_auth(
                self._auth_state,
                host=host,
                use_tls=use_tls,
            )

            if not recovered:
                logger.warning("Auth recovery failed, raising error")
                raise

            # 认证恢复成功 — 更新 headers 并重试
            new_headers = self._auth_manager.build_auth_headers(self._auth_state)
            if hasattr(self._target, "_raw_headers"):
                self._target._raw_headers = new_headers
            if hasattr(self._target, "_headers"):
                self._target._headers = dict(new_headers)
            logger.info("Auth recovered, retrying with new credentials")

            # 重试一次 (原生装饰器会处理后续的 RateLimit/Timeout 重试)
            return await self._target._send_prompt_to_target_async(
                normalized_conversation=normalized_conversation,
            )

    @staticmethod
    def _is_auth_recoverable(exc: Exception) -> bool:
        """检查异常是否为认证可恢复错误 (401/403)。

        PyRIT 原生 OpenAITarget 使用 ``AuthenticationError`` 异常类型
        表示 401/403 错误。此外也检查异常消息中的状态码。

        Args:
            exc: 异常对象。

        Returns:
            True 如果是认证可恢复错误。
        """
        exc_name = type(exc).__name__
        # OpenAI SDK 的 AuthenticationError
        if exc_name == "AuthenticationError":
            return True
        # 检查异常消息中的状态码
        exc_str = str(exc).lower()
        return any(str(code) in exc_str for code in _AUTH_RECOVERABLE_STATUS_CODES)

    async def cleanup(self) -> None:
        """清理资源 — 生产级资源管理 (幂等, 可安全多次调用)。

        在流水线结束时调用, 确保:
            1. 原始 target 的 httpx.AsyncClient 关闭
            2. 原始 target 的 cleanup 方法调用
            3. PyRIT 原生 ``dispose_db_engine()`` 释放数据库连接

        幂等性: 使用 ``_is_cleaned`` 标志, 第二次调用直接返回。
        这在 ``main.py._cleanup_resources`` 的 finally 块中很重要 —
        正常退出路径已调用过 cleanup, finally 块的兜底调用不会重复执行。
        """
        if getattr(self, "_is_cleaned", False):
            logger.debug("Cleanup already done for endpoint=%s, skipping", self._endpoint)
            return
        self._is_cleaned = True

        # 1. 关闭原始 target 的 httpx client (如果有)
        target = self._target
        if hasattr(target, "_client") and target._client is not None:
            try:
                await target._client.aclose()
                logger.debug("Closed httpx.AsyncClient for %s", type(target).__name__)
            except Exception as e:
                logger.debug("Error closing httpx client (non-fatal): %s", e)

        # 2. 如果原始 target 有 cleanup 方法, 调用它
        if hasattr(target, "cleanup") and callable(getattr(target, "cleanup", None)):
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
