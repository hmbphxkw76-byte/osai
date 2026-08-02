# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tests for rate_limited_target.py — 限速 Target 包装器.

测试覆盖:
  - _is_retryable_error: 判断错误是否可重试
  - _extract_retry_after: Retry-After 头解析
  - _compute_backoff: 指数退避计算
  - RateLimitedTarget: 初始化、属性透传、重试逻辑
  - wrap_target_with_rate_limit: 工厂函数
  - cleanup_semaphores: 信号量清理
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from pipeline.targets.rate_limited_target import (
    RateLimitedTarget,
    _compute_backoff,
    _extract_retry_after,
    _is_retryable_error,
    cleanup_semaphores,
    wrap_target_with_rate_limit,
)


class TestIsRetryableError:
    """_is_retryable_error 单元测试."""

    def test_timeout_error_is_retryable(self) -> None:
        """TimeoutError 应该可重试."""
        assert _is_retryable_error(TimeoutError("timed out"))

    def test_asyncio_timeout_is_retryable(self) -> None:
        """asyncio.TimeoutError 应该可重试."""
        assert _is_retryable_error(asyncio.TimeoutError())

    def test_value_error_is_not_retryable(self) -> None:
        """ValueError 不应该可重试."""
        assert not _is_retryable_error(ValueError("bad value"))

    def test_http_429_in_message_is_retryable(self) -> None:
        """错误消息中包含 429 应该可重试."""
        err = Exception("HTTP 429: Too Many Requests")
        assert _is_retryable_error(err)

    def test_http_503_in_message_is_retryable(self) -> None:
        """错误消息中包含 503 应该可重试."""
        err = Exception("HTTP 503: Service Unavailable")
        assert _is_retryable_error(err)

    def test_http_200_not_retryable(self) -> None:
        """正常响应错误不应该可重试."""
        err = Exception("HTTP 200: OK")
        assert not _is_retryable_error(err)

    def test_error_with_status_code_429(self) -> None:
        """带 status_code=429 的错误应该可重试."""
        err = Exception("rate limited")
        err.status_code = 429  # type: ignore[attr-defined]
        assert _is_retryable_error(err)

    def test_error_with_status_code_500(self) -> None:
        """带 status_code=500 的错误应该可重试."""
        err = Exception("server error")
        err.status_code = 500  # type: ignore[attr-defined]
        assert _is_retryable_error(err)

    def test_error_with_status_code_400_not_retryable(self) -> None:
        """带 status_code=400 的错误不应该可重试."""
        err = Exception("bad request")
        err.status_code = 400  # type: ignore[attr-defined]
        assert not _is_retryable_error(err)


class TestExtractRetryAfter:
    """_extract_retry_after 单元测试."""

    def test_no_response_returns_none(self) -> None:
        """无 response 属性时返回 None."""
        err = Exception("no response")
        assert _extract_retry_after(err) is None

    def test_with_retry_after_header(self) -> None:
        """有 Retry-After 头时返回对应值."""
        err = Exception("rate limited")
        mock_response = MagicMock()
        mock_response.headers = {"Retry-After": "5.0"}
        err.response = mock_response  # type: ignore[attr-defined]
        assert _extract_retry_after(err) == 5.0

    def test_with_lowercase_header(self) -> None:
        """小写 retry-after 头也能解析."""
        err = Exception("rate limited")
        mock_response = MagicMock()
        mock_response.headers = {"retry-after": "3.0"}
        err.response = mock_response  # type: ignore[attr-defined]
        assert _extract_retry_after(err) == 3.0

    def test_invalid_header_value_returns_none(self) -> None:
        """无效的 Retry-After 值返回 None."""
        err = Exception("rate limited")
        mock_response = MagicMock()
        mock_response.headers = {"Retry-After": "invalid"}
        err.response = mock_response  # type: ignore[attr-defined]
        assert _extract_retry_after(err) is None


class TestComputeBackoff:
    """_compute_backoff 单元测试."""

    def test_backoff_increases_with_attempts(self) -> None:
        """退避延迟随重试次数增加."""
        delays = [_compute_backoff(i, jitter=0.0) for i in range(5)]
        for i in range(1, len(delays)):
            assert delays[i] >= delays[i - 1]

    def test_backoff_respects_max_delay(self) -> None:
        """退避延迟不超过 max_delay."""
        delay = _compute_backoff(20, max_delay=10.0, jitter=0.0)
        assert delay <= 10.0

    def test_backoff_minimum_delay(self) -> None:
        """退避延迟最小 0.1 秒."""
        delay = _compute_backoff(0, base_delay=0.01, jitter=1.0)
        assert delay >= 0.1

    def test_jitter_within_bounds(self) -> None:
        """抖动后的延迟在合理范围内."""
        for _ in range(20):
            delay = _compute_backoff(2, base_delay=1.0, max_delay=60.0, jitter=0.5)
            assert 0.1 <= delay <= 60.0


class TestRateLimitedTarget:
    """RateLimitedTarget 单元测试."""

    def test_init_defaults(self) -> None:
        """默认参数初始化."""
        mock_target = MagicMock()
        target = RateLimitedTarget(target=mock_target)
        assert target.inner_target is mock_target
        assert target.retry_count == 0
        assert target.total_delay == 0.0

    def test_init_with_rpm(self) -> None:
        """设置 requests_per_minute 写入原生属性."""
        mock_target = MagicMock()
        RateLimitedTarget(
            target=mock_target,
            requests_per_minute=60,
        )
        assert mock_target._max_requests_per_minute == 60

    def test_init_with_explicit_endpoint(self) -> None:
        """显式指定 endpoint."""
        mock_target = MagicMock()
        target = RateLimitedTarget(
            target=mock_target,
            endpoint="https://api.example.com/v1/chat",
        )
        assert target._endpoint == "https://api.example.com/v1/chat"

    def test_infer_endpoint_from_target(self) -> None:
        """从 target 自动推断 endpoint."""
        mock_target = MagicMock()
        mock_target._endpoint = "https://api.test.com/v1"
        target = RateLimitedTarget(target=mock_target)
        assert target._endpoint == "https://api.test.com/v1"

    def test_infer_endpoint_fallback(self) -> None:
        """无 endpoint 属性时回退到 id-based."""
        mock_target = MagicMock(spec=[])  # 无任何属性
        target = RateLimitedTarget(target=mock_target)
        assert target._endpoint.startswith("target_")

    def test_getattr_proxy(self) -> None:
        """__getattr__ 代理属性到原始 target."""
        mock_target = MagicMock()
        mock_target.model_name = "gpt-4o"
        target = RateLimitedTarget(target=mock_target)
        assert target.model_name == "gpt-4o"

    @pytest.mark.asyncio
    async def test_send_prompt_success_no_retry(self) -> None:
        """成功发送不触发重试."""
        mock_target = MagicMock()
        mock_target.send_prompt_async = AsyncMock(return_value="ok")
        target = RateLimitedTarget(
            target=mock_target,
            endpoint="test_success",
            max_concurrency=1,
        )
        result = await target.send_prompt_async(prompt="hello")
        assert result == "ok"
        assert target.retry_count == 0

    @pytest.mark.asyncio
    async def test_send_prompt_retries_on_429(self) -> None:
        """429 错误触发重试."""
        mock_target = MagicMock()
        error = Exception("HTTP 429")
        error.status_code = 429  # type: ignore[attr-defined]
        mock_target.send_prompt_async = AsyncMock(
            side_effect=[error, "ok"],
        )
        target = RateLimitedTarget(
            target=mock_target,
            endpoint="test_429",
            max_concurrency=1,
            max_retries=3,
            base_delay=0.01,
            max_delay=0.1,
            jitter=0.0,
        )
        result = await target.send_prompt_async(prompt="hello")
        assert result == "ok"
        assert target.retry_count == 1

    @pytest.mark.asyncio
    async def test_send_prompt_non_retryable_error_not_retried(self) -> None:
        """不可重试的错误不重试."""
        mock_target = MagicMock()
        error = ValueError("bad request")
        mock_target.send_prompt_async = AsyncMock(side_effect=error)
        target = RateLimitedTarget(
            target=mock_target,
            endpoint="test_non_retryable",
            max_concurrency=1,
            max_retries=3,
        )
        with pytest.raises(ValueError, match="bad request"):
            await target.send_prompt_async(prompt="hello")
        assert target.retry_count == 0

    @pytest.mark.asyncio
    async def test_send_prompt_max_retries_exceeded(self) -> None:
        """超过最大重试次数后抛出错误."""
        mock_target = MagicMock()
        error = Exception("HTTP 503")
        error.status_code = 503  # type: ignore[attr-defined]
        mock_target.send_prompt_async = AsyncMock(side_effect=error)
        target = RateLimitedTarget(
            target=mock_target,
            endpoint="test_max_retries",
            max_concurrency=1,
            max_retries=2,
            base_delay=0.01,
            max_delay=0.1,
            jitter=0.0,
        )
        with pytest.raises(Exception, match="HTTP 503"):
            await target.send_prompt_async(prompt="hello")
        assert target.retry_count == 2

    @pytest.mark.asyncio
    async def test_send_prompt_uses_retry_after_header(self) -> None:
        """Retry-After 头被用于退避延迟."""
        mock_target = MagicMock()
        error = Exception("rate limited")
        error.status_code = 429  # type: ignore[attr-defined]
        mock_response = MagicMock()
        mock_response.headers = {"Retry-After": "0.01"}
        error.response = mock_response  # type: ignore[attr-defined]
        mock_target.send_prompt_async = AsyncMock(
            side_effect=[error, "ok"],
        )
        target = RateLimitedTarget(
            target=mock_target,
            endpoint="test_retry_after",
            max_concurrency=1,
            max_retries=3,
        )
        result = await target.send_prompt_async(prompt="hello")
        assert result == "ok"
        assert target.retry_count == 1


class TestWrapTargetWithRateLimit:
    """wrap_target_with_rate_limit 工厂函数测试."""

    def test_factory_returns_rate_limited_target(self) -> None:
        """工厂函数返回 RateLimitedTarget 实例."""
        mock_target = MagicMock()
        wrapped = wrap_target_with_rate_limit(
            mock_target,
            endpoint="https://api.test.com",
            max_concurrency=5,
            max_retries=10,
            requests_per_minute=100,
        )
        assert isinstance(wrapped, RateLimitedTarget)
        assert wrapped._max_concurrency == 5
        assert wrapped._max_retries == 10
        assert mock_target._max_requests_per_minute == 100


class TestCleanupSemaphores:
    """cleanup_semaphores 单元测试."""

    def test_cleanup_clears_registry(self) -> None:
        """清理后注册表为空."""
        # 先填充注册表
        from pipeline.targets.rate_limited_target import _semaphore_registry
        _semaphore_registry["test"] = asyncio.Semaphore(1)
        assert len(_semaphore_registry) > 0
        cleanup_semaphores()
        assert len(_semaphore_registry) == 0
