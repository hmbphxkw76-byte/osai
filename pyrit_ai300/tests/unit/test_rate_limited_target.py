"""
Unit tests for Rate-Limited Target Wrapper (PyRIT 原生优先版)
=============================================================

Tests the API-level concurrency limiting (semaphore) and 503/502 retry
with backoff. RPM limiting is now handled by PyRIT native
@limit_requests_per_minute decorator (tested separately).

Key changes from v1:
  - RateLimitConfig no longer has max_requests_per_minute (PyRIT native)
  - retry_max_attempts defaults to 0 (reads from RETRY_MAX_NUM_ATTEMPTS env)
  - retry_initial_wait/retry_max_wait default to 0 (reads from RETRY_WAIT_* env)
  - New effective_* properties for runtime env var resolution
"""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.targets.rate_limited_target import (
    RateLimitConfig,
    _is_retryable_error,
    _extract_retry_after,
    _retry_with_backoff,
    wrap_target_with_rate_limiting,
    get_shared_semaphore,
    reset_semaphore_registry,
    create_rate_limit_config_from_env,
)


# ── RateLimitConfig ──


class TestRateLimitConfig:
    """Tests for RateLimitConfig dataclass"""

    def test_default_values(self):
        cfg = RateLimitConfig()
        assert cfg.max_concurrent_requests == 10
        # retry_max_attempts=0 means "read from env"
        assert cfg.retry_max_attempts == 0
        assert cfg.retry_initial_wait == 0
        assert cfg.retry_max_wait == 0
        assert cfg.retry_jitter == 0.3

    def test_custom_values(self):
        cfg = RateLimitConfig(
            max_concurrent_requests=5,
            retry_max_attempts=5,
            retry_initial_wait=0.5,
            retry_max_wait=60.0,
            retry_jitter=0.5,
        )
        assert cfg.max_concurrent_requests == 5
        assert cfg.retry_max_attempts == 5
        assert cfg.retry_initial_wait == 0.5
        assert cfg.retry_max_wait == 60.0
        assert cfg.retry_jitter == 0.5

    def test_invalid_jitter_high(self):
        with pytest.raises(ValueError, match="retry_jitter must be in"):
            RateLimitConfig(retry_jitter=1.5)

    def test_invalid_jitter_negative(self):
        with pytest.raises(ValueError, match="retry_jitter must be in"):
            RateLimitConfig(retry_jitter=-0.1)

    def test_none_max_concurrent(self):
        cfg = RateLimitConfig(max_concurrent_requests=None)
        assert cfg.max_concurrent_requests is None

    def test_effective_retry_max_attempts_from_explicit(self):
        """Explicit retry_max_attempts takes priority."""
        cfg = RateLimitConfig(retry_max_attempts=5)
        assert cfg.effective_retry_max_attempts == 5

    def test_effective_retry_max_attempts_from_env(self):
        """When retry_max_attempts=0, reads from RETRY_MAX_NUM_ATTEMPTS env."""
        old = os.environ.get("RETRY_MAX_NUM_ATTEMPTS")
        try:
            os.environ["RETRY_MAX_NUM_ATTEMPTS"] = "7"
            cfg = RateLimitConfig(retry_max_attempts=0)
            assert cfg.effective_retry_max_attempts == 7
        finally:
            if old is not None:
                os.environ["RETRY_MAX_NUM_ATTEMPTS"] = old
            else:
                os.environ.pop("RETRY_MAX_NUM_ATTEMPTS", None)

    def test_effective_retry_max_attempts_default(self):
        """When env not set, defaults to 10 (PyRIT default)."""
        os.environ.pop("RETRY_MAX_NUM_ATTEMPTS", None)
        cfg = RateLimitConfig(retry_max_attempts=0)
        assert cfg.effective_retry_max_attempts == 10

    def test_effective_retry_initial_wait_from_env(self):
        """When retry_initial_wait=0, reads from RETRY_WAIT_MIN_SECONDS env."""
        old = os.environ.get("RETRY_WAIT_MIN_SECONDS")
        try:
            os.environ["RETRY_WAIT_MIN_SECONDS"] = "3"
            cfg = RateLimitConfig(retry_initial_wait=0)
            assert cfg.effective_retry_initial_wait == 3.0
        finally:
            if old is not None:
                os.environ["RETRY_WAIT_MIN_SECONDS"] = old
            else:
                os.environ.pop("RETRY_WAIT_MIN_SECONDS", None)

    def test_effective_retry_max_wait_from_env(self):
        """When retry_max_wait=0, reads from RETRY_WAIT_MAX_SECONDS env."""
        old = os.environ.get("RETRY_WAIT_MAX_SECONDS")
        try:
            os.environ["RETRY_WAIT_MAX_SECONDS"] = "120"
            cfg = RateLimitConfig(retry_max_wait=0)
            assert cfg.effective_retry_max_wait == 120.0
        finally:
            if old is not None:
                os.environ["RETRY_WAIT_MAX_SECONDS"] = old
            else:
                os.environ.pop("RETRY_WAIT_MAX_SECONDS", None)


# ── Error classification ──


class TestIsRetryableError:
    """Tests for _is_retryable_error"""

    def test_internal_server_error(self):
        error = type("InternalServerError", (Exception,), {})()
        assert _is_retryable_error(error) is True

    def test_api_timeout_error(self):
        error = type("APITimeoutError", (Exception,), {})()
        assert _is_retryable_error(error) is True

    def test_api_connection_error(self):
        error = type("APIConnectionError", (Exception,), {})()
        assert _is_retryable_error(error) is True

    def test_server_error_exception(self):
        """PyRIT's ServerErrorException should be retryable."""
        error = type("ServerErrorException", (Exception,), {})()
        assert _is_retryable_error(error) is True

    def test_api_status_error_503(self):
        error = type("APIStatusError", (Exception,), {"status_code": 503})()
        assert _is_retryable_error(error) is True

    def test_api_status_error_502(self):
        error = type("APIStatusError", (Exception,), {"status_code": 502})()
        assert _is_retryable_error(error) is True

    def test_api_status_error_500(self):
        error = type("APIStatusError", (Exception,), {"status_code": 500})()
        assert _is_retryable_error(error) is True

    def test_api_status_error_504(self):
        error = type("APIStatusError", (Exception,), {"status_code": 504})()
        assert _is_retryable_error(error) is True

    def test_api_status_error_400_not_retryable(self):
        error = type("APIStatusError", (Exception,), {"status_code": 400})()
        assert _is_retryable_error(error) is False

    def test_rate_limit_exception_not_in_list(self):
        """RateLimitException is NOT in our list (PyRIT native handles it).

        PyRIT's @pyrit_target_retry already retries RateLimitException(429).
        Our wrapper only supplements 5xx errors.
        """
        error = type("RateLimitException", (Exception,), {})()
        assert _is_retryable_error(error) is False

    def test_generic_value_error_not_retryable(self):
        error = ValueError("test")
        assert _is_retryable_error(error) is False

    def test_error_with_status_code_attribute(self):
        error = type("CustomError", (Exception,), {"status_code": 502})()
        assert _is_retryable_error(error) is True

    def test_error_with_cause_chain(self):
        cause = type("InternalServerError", (Exception,), {})()
        wrapper = ValueError("wrapper")
        wrapper.__cause__ = cause
        assert _is_retryable_error(wrapper) is True

    def test_authentication_error_not_retryable(self):
        error = type("AuthenticationError", (Exception,), {})()
        assert _is_retryable_error(error) is False


# ── Retry-After extraction ──


class TestExtractRetryAfter:
    """Tests for _extract_retry_after"""

    def test_no_retry_after(self):
        error = Exception("test")
        assert _extract_retry_after(error) is None

    def test_retry_after_attribute(self):
        error = Exception("test")
        error.retry_after = 5.0
        assert _extract_retry_after(error) == 5.0

    def test_retry_after_from_response_headers(self):
        response = MagicMock()
        response.headers = {"retry-after": "10"}
        error = Exception("test")
        error.response = response
        assert _extract_retry_after(error) == 10.0

    def test_retry_after_case_insensitive(self):
        response = MagicMock()
        response.headers = {"Retry-After": "15"}
        error = Exception("test")
        error.response = response
        assert _extract_retry_after(error) == 15.0

    def test_retry_after_invalid_value(self):
        error = Exception("test")
        error.retry_after = "invalid"
        assert _extract_retry_after(error) is None


# ── Retry with backoff ──


class TestRetryWithBackoff:
    """Tests for _retry_with_backoff"""

    @pytest.mark.asyncio
    async def test_success_first_try(self):
        call = AsyncMock(return_value="ok")
        config = RateLimitConfig(retry_max_attempts=3, retry_initial_wait=0.01)
        result = await _retry_with_backoff(call, config, call_description="test")
        assert result == "ok"
        assert call.call_count == 1

    @pytest.mark.asyncio
    async def test_success_after_retry(self):
        retryable_error = type("InternalServerError", (Exception,), {})()
        call = AsyncMock(side_effect=[retryable_error, retryable_error, "ok"])
        config = RateLimitConfig(retry_max_attempts=3, retry_initial_wait=0.01, retry_jitter=0.0)
        result = await _retry_with_backoff(call, config, call_description="test")
        assert result == "ok"
        assert call.call_count == 3

    @pytest.mark.asyncio
    async def test_non_retryable_error_raised_immediately(self):
        error = ValueError("not retryable")
        call = AsyncMock(side_effect=error)
        config = RateLimitConfig(retry_max_attempts=3, retry_initial_wait=0.01)
        with pytest.raises(ValueError, match="not retryable"):
            await _retry_with_backoff(call, config, call_description="test")
        assert call.call_count == 1

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self):
        retryable_error = type("InternalServerError", (Exception,), {})()
        call = AsyncMock(side_effect=retryable_error)
        config = RateLimitConfig(retry_max_attempts=2, retry_initial_wait=0.01, retry_jitter=0.0)
        with pytest.raises(Exception):
            await _retry_with_backoff(call, config, call_description="test")
        assert call.call_count == 2

    @pytest.mark.asyncio
    async def test_exponential_backoff_timing(self):
        """Test that backoff waits increase exponentially"""
        retryable_error = type("InternalServerError", (Exception,), {})()
        call = AsyncMock(side_effect=retryable_error)
        config = RateLimitConfig(
            retry_max_attempts=3,
            retry_initial_wait=0.1,
            retry_max_wait=1.0,
            retry_jitter=0.0,
        )
        with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(Exception):
                await _retry_with_backoff(call, config, call_description="test")
            # Should have slept twice (between 3 attempts)
            assert mock_sleep.call_count == 2
            # First sleep ~0.1, second ~0.2
            first_wait = mock_sleep.call_args_list[0][0][0]
            second_wait = mock_sleep.call_args_list[1][0][0]
            assert 0.1 <= first_wait <= 0.15  # with jitter=0, should be ~0.1
            assert 0.2 <= second_wait <= 0.25  # with jitter=0, should be ~0.2

    @pytest.mark.asyncio
    async def test_uses_env_vars_when_config_zero(self):
        """When retry_max_attempts=0, should use RETRY_MAX_NUM_ATTEMPTS env."""
        old_attempts = os.environ.get("RETRY_MAX_NUM_ATTEMPTS")
        old_min = os.environ.get("RETRY_WAIT_MIN_SECONDS")
        try:
            os.environ["RETRY_MAX_NUM_ATTEMPTS"] = "2"
            os.environ["RETRY_WAIT_MIN_SECONDS"] = "0.01"
            retryable_error = type("InternalServerError", (Exception,), {})()
            call = AsyncMock(side_effect=retryable_error)
            config = RateLimitConfig(retry_jitter=0.0)
            with pytest.raises(Exception):
                await _retry_with_backoff(call, config, call_description="test")
            assert call.call_count == 2  # RETRY_MAX_NUM_ATTEMPTS=2
        finally:
            for key, val in [("RETRY_MAX_NUM_ATTEMPTS", old_attempts), ("RETRY_WAIT_MIN_SECONDS", old_min)]:
                if val is not None:
                    os.environ[key] = val
                else:
                    os.environ.pop(key, None)


# ── Shared semaphore ──


class TestSharedSemaphore:
    """Tests for get_shared_semaphore and reset_semaphore_registry"""

    def test_get_shared_semaphore_creates_new(self):
        reset_semaphore_registry()
        sem = get_shared_semaphore("test_key", 5)
        assert sem is not None
        assert isinstance(sem, asyncio.Semaphore)

    def test_get_shared_semaphore_reuses_existing(self):
        reset_semaphore_registry()
        sem1 = get_shared_semaphore("shared_key", 10)
        sem2 = get_shared_semaphore("shared_key", 20)  # max_concurrent ignored on reuse
        assert sem1 is sem2

    def test_different_keys_different_semaphores(self):
        reset_semaphore_registry()
        sem1 = get_shared_semaphore("key1", 5)
        sem2 = get_shared_semaphore("key2", 5)
        assert sem1 is not sem2

    def test_reset_clears_registry(self):
        get_shared_semaphore("temp_key", 5)
        reset_semaphore_registry()
        assert len(_get_registry()) == 0 if _get_registry() else True


def _get_registry():
    from src.targets.rate_limited_target import _semaphore_registry
    return _semaphore_registry


# ── wrap_target_with_rate_limiting ──


class TestWrapTarget:
    """Tests for wrap_target_with_rate_limiting"""

    def test_wrap_returns_same_target(self):
        target = MagicMock()
        target._send_prompt_to_target_async = AsyncMock(return_value="ok")
        result = wrap_target_with_rate_limiting(target, config=RateLimitConfig())
        assert result is target

    def test_wrap_replaces_method(self):
        target = MagicMock()
        original_method = AsyncMock(return_value="ok")
        target._send_prompt_to_target_async = original_method
        wrap_target_with_rate_limiting(target, config=RateLimitConfig())
        # The method should be replaced
        assert target._send_prompt_to_target_async is not original_method

    @pytest.mark.asyncio
    async def test_wrapped_target_calls_original(self):
        target = MagicMock()
        original_method = AsyncMock(return_value=[MagicMock()])
        target._send_prompt_to_target_async = original_method
        target._model_name = "test-model"

        wrap_target_with_rate_limiting(
            target,
            config=RateLimitConfig(max_concurrent_requests=None, retry_max_attempts=1),
        )

        conv = [MagicMock()]
        result = await target._send_prompt_to_target_async(normalized_conversation=conv)
        original_method.assert_called_once_with(normalized_conversation=conv)
        assert result is not None

    @pytest.mark.asyncio
    async def test_wrapped_target_retries_on_503(self):
        target = MagicMock()
        retryable_error = type("InternalServerError", (Exception,), {})()
        original_method = AsyncMock(side_effect=[retryable_error, [MagicMock()]])
        target._send_prompt_to_target_async = original_method
        target._model_name = "test-model"

        wrap_target_with_rate_limiting(
            target,
            config=RateLimitConfig(
                max_concurrent_requests=None,
                retry_max_attempts=3,
                retry_initial_wait=0.01,
                retry_jitter=0.0,
            ),
        )

        conv = [MagicMock()]
        await target._send_prompt_to_target_async(normalized_conversation=conv)
        assert original_method.call_count == 2  # failed once, succeeded on retry

    @pytest.mark.asyncio
    async def test_wrapped_target_concurrency_limit(self):
        """Test that semaphore limits concurrent calls"""
        target = MagicMock()
        call_count = [0]
        max_concurrent = [0]

        async def slow_call(*, normalized_conversation):
            call_count[0] += 1
            max_concurrent[0] = max(max_concurrent[0], call_count[0])
            await asyncio.sleep(0.05)
            call_count[0] -= 1
            return [MagicMock()]

        target._send_prompt_to_target_async = slow_call
        target._model_name = "test-model"

        wrap_target_with_rate_limiting(
            target,
            config=RateLimitConfig(max_concurrent_requests=2, retry_max_attempts=1),
            semaphore_key="test_concurrency",
        )

        # Launch 5 concurrent calls
        tasks = [
            target._send_prompt_to_target_async(normalized_conversation=[MagicMock()])
            for _ in range(5)
        ]
        await asyncio.gather(*tasks)

        # Max concurrent should be <= 2
        assert max_concurrent[0] <= 2

    def test_wrap_with_none_config_uses_default(self):
        target = MagicMock()
        target._send_prompt_to_target_async = AsyncMock()
        wrap_target_with_rate_limiting(target, config=None)
        # Should not raise
        assert target._send_prompt_to_target_async is not None

    @pytest.mark.asyncio
    async def test_non_retryable_error_not_retried(self):
        target = MagicMock()
        error = ValueError("not retryable")
        original_method = AsyncMock(side_effect=error)
        target._send_prompt_to_target_async = original_method
        target._model_name = "test-model"

        wrap_target_with_rate_limiting(
            target,
            config=RateLimitConfig(
                max_concurrent_requests=None,
                retry_max_attempts=3,
                retry_initial_wait=0.01,
            ),
        )

        with pytest.raises(ValueError, match="not retryable"):
            await target._send_prompt_to_target_async(normalized_conversation=[MagicMock()])
        # Should only be called once (no retry)
        assert original_method.call_count == 1


# ── create_rate_limit_config_from_env ──


class TestCreateFromEnv:
    """Tests for create_rate_limit_config_from_env"""

    def test_default_values(self):
        # Clear env vars
        for key in ("API_MAX_CONCURRENCY", "API_RETRY_MAX_ATTEMPTS", "RETRY_MAX_NUM_ATTEMPTS"):
            os.environ.pop(key, None)
        cfg = create_rate_limit_config_from_env()
        assert cfg.max_concurrent_requests is None
        # retry_max_attempts=0 means "read from RETRY_MAX_NUM_ATTEMPTS at runtime"
        assert cfg.retry_max_attempts == 0

    def test_from_explicit_params(self):
        cfg = create_rate_limit_config_from_env(
            max_concurrent=5,
            retry_attempts=5,
        )
        assert cfg.max_concurrent_requests == 5
        assert cfg.retry_max_attempts == 5

    def test_from_env_vars(self):
        os.environ["API_MAX_CONCURRENCY"] = "8"
        os.environ["API_RETRY_MAX_ATTEMPTS"] = "4"
        try:
            cfg = create_rate_limit_config_from_env()
            assert cfg.max_concurrent_requests == 8
            assert cfg.retry_max_attempts == 4
        finally:
            for key in ("API_MAX_CONCURRENCY", "API_RETRY_MAX_ATTEMPTS"):
                os.environ.pop(key, None)

    def test_explicit_params_override_env(self):
        os.environ["API_MAX_CONCURRENCY"] = "8"
        try:
            cfg = create_rate_limit_config_from_env(max_concurrent=3)
            assert cfg.max_concurrent_requests == 3
        finally:
            os.environ.pop("API_MAX_CONCURRENCY", None)

    def test_max_rpm_parameter_ignored(self):
        """max_rpm parameter is deprecated (PyRIT native handles RPM)."""
        cfg = create_rate_limit_config_from_env(max_rpm=100)
        # max_rpm should not affect RateLimitConfig (no max_requests_per_minute field)
        assert not hasattr(cfg, "max_requests_per_minute")

    def test_retry_falls_back_to_retry_env(self):
        """When API_RETRY_MAX_ATTEMPTS not set, retry_max_attempts=0 (reads RETRY_MAX_NUM_ATTEMPTS)."""
        os.environ.pop("API_RETRY_MAX_ATTEMPTS", None)
        cfg = create_rate_limit_config_from_env()
        assert cfg.retry_max_attempts == 0
        # effective value should come from RETRY_MAX_NUM_ATTEMPTS or default 10
        assert cfg.effective_retry_max_attempts == 10
