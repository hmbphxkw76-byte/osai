"""RateLimitedTarget - PyRIT native PromptTarget decorator (Production-grade PyRIT 1.0.1 aligned).

Aligned with PyRIT 1.0.1 architecture:
    PyRIT 1.0.1's OpenAIChatTarget / OpenAIResponseTarget / HTTPTarget
    already include rate limiting + Retry:

    1. ``@limit_requests_per_minute`` - PyRIT native RPM rate limit decorator
       Applied to ``_send_prompt_to_target_async`` with ``asyncio.sleep(60/rpm)``
       Reference: ``pyrit.prompt_target.common.utils``

    2. ``@pyrit_target_retry`` - PyRIT native Retry decorator (tenacity based)
       Auto Retry on ``RateLimitError`` / ``EmptyResponseException`` /
       ``RateLimitException`` + ``APITimeoutError`` / ``APIConnectionError``
       Reference: ``pyrit.exceptions.exception_classes``
       Configurable: ``RETRY_MAX_NUM_ATTEMPTS`` (default 10),
       ``RETRY_WAIT_MIN_SECONDS`` (default 5), ``RETRY_WAIT_MAX_SECONDS`` (default 220)

    3. ``_handle_openai_request_async`` - OpenAITarget native Error handling
       Handles ``BadRequestError`` / ``RateLimitError`` / ``APIStatusError`` /
       ``APITimeoutError`` / ``APIConnectionError`` / ``AuthenticationError``
       Parses ``Retry-After`` header + ``x-request-id`` for diagnostics

    RateLimitedTarget adds on top of PyRIT native:
        - **Concurrency control** (``asyncio.Semaphore``):
          PyRIT native lacks concurrent request throttling
        - **Auth recovery** (401/403): Auto token refresh + credential rotation
          Academic basis: Heroux et al. (arXiv:2403.04206) Sec3.2
        - **Capability verification**: Pre-flight PyRIT native ``TargetRequirements.validate()``
          Ensures text modality support before attack execution
        - **Resource cleanup**: ``dispose_db_engine()`` + httpx client closure

    Design principle (vs overriding Retry):
        - Does **not** override wrapped target's ``_send_prompt_to_target_async``
          Instead delegates to ``self._target._send_prompt_to_target_async()``
          preserving native decorators: ``@limit_requests_per_minute`` + ``@pyrit_target_retry``
        - Adds Semaphore-based concurrency control (PyRIT native gap)
        - Adds auth recovery layer (401/403 → token refresh → retry)
        - Adds capability verification (PyRIT TargetRequirements)
        - Adds production-grade cleanup (httpx + dispose_db_engine)

Academic basis:
    - PyRIT (arXiv:2407.01232) - TargetRequirements Capability verification
    - Greshake et al. (arXiv:2302.12173) - Prompt injection attack surface
    - Heroux et al. (arXiv:2403.04206) - Auth token lifecycle management
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pyrit.prompt_target.common.prompt_target import PromptTarget

from core.resilience import (
    ON_OPEN_PAUSE,
    ON_OPEN_SLOW,
    ON_OPEN_TERMINATE,
    CircuitOpenError,
    CircuitTerminatedError,
    ResiliencePolicy,
    RetryPolicy,
    counts_toward_breaker,
    is_transient_error,
    make_retry_policy,
)

logger = logging.getLogger(__name__)

# Auth recovery: 401/403 status codes trigger token refresh
_AUTH_RECOVERABLE_STATUS_CODES = frozenset({401, 403})


class RateLimitedTarget(PromptTarget):
    """RateLimitedTarget - PyRIT 1.0.1 native PromptTarget decorator.

    Aligned with PyRIT 1.0.1 architecture:
        ``PromptTarget`` has ``@final send_prompt_async`` method.
        ``RateLimitedTarget`` wraps any PromptTarget and:
        - Preserves ``send_prompt_async`` validation + normalization + conversation tracking
        - Overrides ``self._send_prompt_to_target_async`` to add:
          concurrency control + auth recovery + capability verification

    Decorator pattern (PyRIT native preserved):
        - **Not overridden**: Wrapped target's ``_send_prompt_to_target_async``
          Instead calls ``self._target._send_prompt_to_target_async()``
          preserving native decorators:
          ``@limit_requests_per_minute`` + ``@pyrit_target_retry``
        - Adds: Semaphore-based concurrency control

    Enhancement layers (PyRIT native gap):
        - Concurrency: ``asyncio.Semaphore(max_concurrency)``
        - Auth recovery: 401/403 → token refresh + credential rotation
        - Capability verification: ``TargetRequirements.validate()``
        - Resource cleanup: ``dispose_db_engine()`` + httpx client

    Args:
        target: PyRIT native PromptTarget to wrap
        endpoint: Target URL (if None, imports from target)
        max_concurrency: Max concurrent requests (PyRIT native lacks this)
        auth_state_manager: Optional auth state manager for token refresh
        auth_state: Optional auth state for credential rotation
    """

    def __init__(
        self,
        *,
        target: PromptTarget,
        endpoint: str | None = None,
        max_concurrency: int = 3,
        auth_state_manager: Any | None = None,
        auth_state: Any | None = None,
        circuit_breaker: Any | None = None,
        resilience_policy: Any | None = None,
        retry_policy: Any | None = None,
        on_breaker_event: Any | None = None,
    ) -> None:
        self._target = target
        self._endpoint = endpoint or getattr(target, "_endpoint", str(id(target)))
        self._semaphore = asyncio.Semaphore(max_concurrency)

        # == REQ-170：熔断 + 瞬时故障重试 ==
        # breaker 由 core.resilience.build_target_resilience(ctx, endpoint) 构造，
        # 状态落在 ctx._circuit_breaker_states（既有字段，消除 stub）。
        self._breaker = circuit_breaker
        self._policy = (resilience_policy or ResiliencePolicy()).normalized()
        self._retry_policy: RetryPolicy = retry_policy or make_retry_policy()
        self._on_breaker_event = on_breaker_event

        # Auth recovery (optional)
        self._auth_manager = auth_state_manager
        self._auth_state = auth_state
        # TLS verify (from auth_manager or target URL)
        self._use_tls = getattr(target, "_use_tls", True)

        # PyRIT 1.0.1: super().__init__ propagates PromptTarget fields
        # send_prompt_async (@final) is inherited, RateLimitedTarget overrides
        # self._send_prompt_to_target_async to add concurrency + auth recovery
        # custom_configuration is read from target, ADAPT/RAISE not needed
        # max_requests_per_minute is propagated from target's RPM setting
        effective_rpm = getattr(target, "_max_requests_per_minute", None)

        super().__init__(
            max_requests_per_minute=effective_rpm,
            endpoint=self._endpoint,
            model_name=getattr(target, "_model_name", ""),
            underlying_model=getattr(target, "_underlying_model", None),
            custom_configuration=getattr(target, "_configuration", None),
        )

        # Propagate target attributes
        self._endpoint_attr = getattr(target, "_endpoint", "")
        self._identifier = getattr(target, "_identifier", None)
        self.supported_converters = getattr(target, "supported_converters", [])

        # Capability verification - PyRIT TargetRequirements.validate()
        self._validate_target_capabilities(target)

        # Capabilities cache, populated by discover_target_capabilities
        self._target_capabilities = getattr(target, "capabilities", None)

    def _validate_target_capabilities(self, target: PromptTarget) -> None:
        """Pre-flight capability verification via PyRIT 1.0.1 TargetRequirements.validate().

        PyRIT native ``TargetRequirements.validate()`` checks:
        - text input/output modality support
        - Raises ValueError if target cannot handle text-based attacks

        Academic basis:
        - PyRIT (arXiv:2407.01232) - TargetRequirements Capability verification
        - Greshake et al. (arXiv:2302.12173) - Attack surface validation
        """
        try:
            # Verify: text input/output modality support
            from pyrit.prompt_target.common.target_capabilities import (
                TargetRequirements,
            )

            requirements = TargetRequirements(
                required=frozenset(),
                native_required=frozenset(),
                required_input_modalities=frozenset({frozenset({"text"})}),
                required_output_modalities=frozenset({frozenset({"text"})}),
            )
            requirements.validate(target=target)
        except ValueError as e:
            logger.warning(
                "Target %s failed TargetRequirements validation: %s; text-based attacks may fail",
                type(target).__name__,
                e,
            )
        except Exception as e:
            logger.debug(
                "Capability validation skipped for %s (non-fatal): %s",
                type(target).__name__,
                e,
            )

    async def apply_discovered_capabilities(self, *, timeout_s: float = 30.0) -> None:
        """Apply PyRIT native ``discover_target_capabilities`` results.

        PyRIT native discovers:
        - Conversation capabilities: multi_turn, system_prompt, json_output
        - Input modalities: text, image_path, audio_path
        - Applies discovered capabilities to target (apply=True)
        - Updates self._target_capabilities

        Academic basis:
        - PyRIT (arXiv:2407.01232) - Capability discovery
        - Greshake et al. (arXiv:2302.12173) - Target fingerprinting

        Args:
            timeout_s: Per-probe timeout for capability discovery (seconds)
        """
        try:
            from pyrit.prompt_target.common.utils import (
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
                "Discovered capabilities: multi_turn=%s, system_prompt=%s, json_output=%s, input_modalities=%s",
                discovered.supports_multi_turn,
                discovered.supports_system_prompt,
                discovered.supports_json_output,
                [sorted(s) for s in sorted(discovered.input_modalities)],
            )
        except Exception as e:
            logger.debug("Native capability discovery failed (non-fatal): %s", e)

    async def _send_prompt_to_target_async(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
        """Concurrency-controlled + auth-recovery prompt dispatch.

        PyRIT native preserved:
            Calls ``self._target._send_prompt_to_target_async()``
            preserving native decorators:
            - ``@limit_requests_per_minute`` - PyRIT native RPM rate limit
            - ``@pyrit_target_retry`` - PyRIT native Retry (tenacity)
               Handles RateLimitError / EmptyResponseException / RateLimitException

        Enhancement layers (PyRIT native gap):
            1. Semaphore-based concurrency control (prevents overload)
            2. Delegates to target._send_prompt_to_target_async()
               (preserves @limit_requests_per_minute + @pyrit_target_retry)
            3. Auth recovery on 401/403 (token refresh + credential rotation)
            4. Success → return result
            5. Non-recoverable error → raise
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
        """Auth-recovery wrapper around target dispatch.

        PyRIT native ``@pyrit_target_retry`` handles:
        - RateLimitError (429) - Auto Retry with exponential backoff
        - EmptyResponseException (204) - Auto Retry
        - RateLimitException - Auto Retry
        - APITimeoutError / APIConnectionError - Auto Retry

        This layer adds auth recovery (401/403) not covered by PyRIT native.
        Academic basis: Heroux et al. (arXiv:2403.04206) Sec3.2 - Token lifecycle
        """
        await self._await_circuit_clearance()
        try:
            result = await self._dispatch_with_transient_retry(
                normalized_conversation=normalized_conversation,
            )
        except Exception as e:
            self._record_breaker_failure(e)
            if not self._is_auth_recoverable(e):
                raise

            # Auth recovery path: 401/403
            if not self._auth_manager or not self._auth_state:
                raise

            logger.warning("Auth error (401/403), attempting recovery...")
            host = getattr(self, "_endpoint_attr", "")
            use_tls = getattr(self, "_use_tls", True)

            recovered = await self._auth_manager.try_recover_auth(
                self._auth_state,
                host=host,
                use_tls=use_tls,
            )

            if not recovered:
                raise

            # Refresh headers and retry
            new_headers = self._auth_manager.build_auth_headers(self._auth_state)
            if hasattr(self._target, "_raw_headers"):
                self._target._raw_headers = new_headers
            if hasattr(self._target, "_headers"):
                self._target._headers = new_headers
            logger.info("Auth recovered, retrying with new credentials")

            result = await self._dispatch_with_transient_retry(
                normalized_conversation=normalized_conversation,
            )
        self._record_breaker_success()
        return result

    # ------------------------------------------------------------------
    # REQ-170：熔断准入 / 瞬时重试 / 事件留痕
    # ------------------------------------------------------------------
    async def _await_circuit_clearance(self) -> None:
        """按策略处置打开中的熔断：`pause` / `slow` 等待，`terminate` 直接终止。

        `pause` 与 `slow` 的差异：`slow` 语义上表示"降速继续"（等待后仍走同一路径），
        `pause` 表示"暂停后重试"；两者等待上限均由 `max_pause_seconds` 约束，
        超限即拒绝（不无限阻塞 campaign）。
        """
        if self._breaker is None:
            return
        decision = self._breaker.before_request()
        if decision.allowed:
            return

        strategy = self._policy.on_open
        self._emit_breaker_event(
            {
                "state": decision.state,
                "action": "blocked",
                "strategy": strategy,
                "retry_after": decision.retry_after,
                "reason": decision.reason,
            }
        )
        if strategy == ON_OPEN_TERMINATE:
            raise CircuitTerminatedError(f"circuit open (terminate) for {self._endpoint}: {decision.reason}")

        wait = min(decision.retry_after, self._policy.max_pause_seconds) if strategy in (ON_OPEN_PAUSE, ON_OPEN_SLOW) else 0.0
        if wait > 0:
            logger.warning(
                "[Resilience] circuit open for %s; %s %.1fs before retry (reason=%s)",
                self._endpoint,
                strategy,
                wait,
                decision.reason,
            )
            await asyncio.sleep(wait)
            decision = self._breaker.before_request()
            if decision.allowed:
                self._emit_breaker_event({"state": decision.state, "action": "resumed", "strategy": strategy})
                return
        raise CircuitOpenError(f"circuit open for {self._endpoint}: {decision.reason}")

    async def _dispatch_with_transient_retry(
        self,
        *,
        normalized_conversation: list[Any],
    ) -> list[Any]:
        """把原生派发包在瞬时故障重试里（5xx / 408 / 超时 / 连接）。

        `429/RateLimit` **不在**本层重试 —— 交由 PyRIT 原生 `@pyrit_target_retry`
        处理，避免双层退避放大（REQ-170 ②）。
        """
        attempt = 0
        while True:
            try:
                # Delegate: preserves @limit_requests_per_minute + @pyrit_target_retry
                return await self._target._send_prompt_to_target_async(
                    normalized_conversation=normalized_conversation,
                )
            except Exception as e:
                attempt += 1
                if attempt >= self._retry_policy.max_attempts or not is_transient_error(e):
                    raise
                delay = self._retry_policy.delay_for(attempt)
                logger.warning(
                    "[Resilience] transient failure on %s (attempt %d/%d): %s; retrying in %.2fs",
                    self._endpoint,
                    attempt,
                    self._retry_policy.max_attempts,
                    e,
                    delay,
                )
                await asyncio.sleep(delay)

    def _record_breaker_failure(self, exc: Exception) -> None:
        if self._breaker is None or not counts_toward_breaker(exc):
            return
        self._breaker.record_failure(f"{type(exc).__name__}: {exc}")
        snapshot = self._breaker.snapshot()
        self._emit_breaker_event(
            {
                "state": snapshot.get("state"),
                "action": "failure_recorded",
                "failures": snapshot.get("failures"),
                "reason": snapshot.get("last_reason", ""),
            }
        )

    def _record_breaker_success(self) -> None:
        if self._breaker is None:
            return
        previous = self._breaker.snapshot().get("state")
        self._breaker.record_success()
        if previous != "closed":
            self._emit_breaker_event({"state": "closed", "action": "recovered", "previous": previous})

    def _emit_breaker_event(self, event: dict[str, Any]) -> None:
        """把熔断决策投递到注入的事件槽（ctx.orchestration_log + EventLog）。"""
        if self._on_breaker_event is None:
            return
        try:
            self._on_breaker_event(event)
        except Exception as e:
            logger.debug("[Resilience] breaker event sink failed: %s", e)

    @staticmethod
    def _is_auth_recoverable(exc: Exception) -> bool:
        """Check if exception is auth-recoverable (401/403).

        PyRIT native OpenAITarget raises ``AuthenticationError`` for 401/403.
        This check catches both class name and status code in error string.

        Args:
            exc: Exception to classify

        Returns:
            True if exception indicates auth failure (401/403)
        """
        exc_name = type(exc).__name__
        # OpenAI SDK AuthenticationError
        if exc_name == "AuthenticationError":
            return True
        # Fallback: check status code in error string
        exc_str = str(exc).lower()
        return any(str(code) in exc_str for code in _AUTH_RECOVERABLE_STATUS_CODES)

    async def cleanup(self) -> None:
        """Production-grade resource cleanup (idempotent, safe for finally blocks).

        Ensures:
        1. Wrapped target's httpx.AsyncClient is closed
        2. Wrapped target's cleanup is called (if exists)
        3. PyRIT native ``dispose_db_engine()`` is called

        Note: Uses ``_is_cleaned`` flag to prevent double cleanup.
        Called by ``main.py._cleanup_resources`` in finally block.
        Production-grade: cleanup is idempotent, safe for finally blocks.
        """
        if getattr(self, "_is_cleaned", False):
            return
        self._is_cleaned = True

        # 1. Close target's httpx client (if exists)
        target = self._target
        if hasattr(target, "_client") and target._client is not None:
            try:
                await target._client.aclose()
                logger.debug("Closed httpx.AsyncClient for %s", type(target).__name__)
            except Exception as e:
                logger.debug("Error closing httpx client: %s", e)

        # 2. Call target's cleanup (if exists)
        if hasattr(target, "cleanup") and callable(getattr(target, "cleanup", None)):
            try:
                result = target.cleanup()
                # Handle both sync and async cleanup
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.debug("Error during target cleanup: %s", e)

        # 3. PyRIT 1.0.1: dispose_db_engine
        try:
            from pyrit.common.dispose_db import dispose_db_engine

            dispose_db_engine()
            logger.debug("Disposed DB engine for %s", type(target).__name__)
        except Exception as e:
            logger.debug("Error disposing DB engine: %s", e)

        logger.debug("RateLimitedTarget cleanup complete for endpoint=%s", self._endpoint)

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to wrapped target.

        Ensures RateLimitedTarget is transparent wrapper for PromptTarget.
        """
        return getattr(self._target, name)
