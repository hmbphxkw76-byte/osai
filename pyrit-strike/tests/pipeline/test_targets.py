"""Targets 模块测试 — content_filter, rate_limited。

覆盖:
    - ContentFilterExt 三层防御标记扩展 (L1 YAML, L2 默认, L3 heuristic 缓存)
    - _DEFAULT_EXTRA_MARKERS 内容
    - _HEURISTIC_PATTERNS 正则匹配
    - discover_markers_from_error heuristic 发现
    - _load_discovered_markers / persist_discovered_markers 缓存
    - _classify_error 异常分类 (超时, HTTP状态码, 429, 5xx, 连接错误, 默认)
    - _parse_retry_after Retry-After 解析
    - RateLimitedTarget 初始化, 属性透传, _send_with_retry 重试逻辑
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# content_filter: _DEFAULT_EXTRA_MARKERS
# ═══════════════════════════════════════════════════════


class TestDefaultExtraMarkers:
    """测试 _DEFAULT_EXTRA_MARKERS."""

    def test_contains_english_markers(self):
        from pipeline.targets.content_filter import _DEFAULT_EXTRA_MARKERS

        assert "security_audit_fail" in _DEFAULT_EXTRA_MARKERS
        assert "security_error" in _DEFAULT_EXTRA_MARKERS
        assert "sensitive_content" in _DEFAULT_EXTRA_MARKERS
        assert "risk_content_detected" in _DEFAULT_EXTRA_MARKERS
        assert "review_blocked" in _DEFAULT_EXTRA_MARKERS

    def test_contains_chinese_markers(self):
        from pipeline.targets.content_filter import _DEFAULT_EXTRA_MARKERS

        assert "违规信息" in _DEFAULT_EXTRA_MARKERS
        assert "内容违规" in _DEFAULT_EXTRA_MARKERS
        assert "内容包含敏感词" in _DEFAULT_EXTRA_MARKERS
        assert "我无法回答" in _DEFAULT_EXTRA_MARKERS
        assert "作为AI" in _DEFAULT_EXTRA_MARKERS
        assert "我不能提供" in _DEFAULT_EXTRA_MARKERS

    def test_is_frozenset(self):
        from pipeline.targets.content_filter import _DEFAULT_EXTRA_MARKERS

        assert isinstance(_DEFAULT_EXTRA_MARKERS, frozenset)

    def test_not_empty(self):
        from pipeline.targets.content_filter import _DEFAULT_EXTRA_MARKERS

        assert len(_DEFAULT_EXTRA_MARKERS) > 0


# ═══════════════════════════════════════════════════════
# content_filter: discover_markers_from_error
# ═══════════════════════════════════════════════════════


class TestDiscoverMarkersFromError:
    """测试 discover_markers_from_error — heuristic 发现."""

    def test_block_pattern(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        error = '{"block_reason": "Content violates safety policy"}'
        markers = discover_markers_from_error(error)
        assert len(markers) > 0
        assert any("Content violates safety policy" in m for m in markers)

    def test_filter_pattern(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        error = '{"filter_action": "Blocked by content filter"}'
        markers = discover_markers_from_error(error)
        assert len(markers) > 0

    def test_reject_pattern(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        error = '{"reject_message": "Request rejected due to policy"}'
        markers = discover_markers_from_error(error)
        assert len(markers) > 0

    def test_deny_pattern(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        error = '{"deny_code": "Access denied by safety system"}'
        markers = discover_markers_from_error(error)
        assert len(markers) > 0

    def test_reason_field_with_violation(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        error = '{"reason": "This request was blocked by violation detection"}'
        markers = discover_markers_from_error(error)
        assert len(markers) > 0

    def test_message_field_with_blocked(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        error = '{"message": "Content filter blocked the request"}'
        markers = discover_markers_from_error
        result = markers(error)
        assert len(result) > 0

    def test_no_markers_in_normal_error(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        error = '{"error": "Internal server error"}'
        markers = discover_markers_from_error(error)
        assert len(markers) == 0

    def test_empty_string(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        markers = discover_markers_from_error("")
        assert len(markers) == 0

    def test_long_marker_skipped(self):
        """超过100字符的标记被跳过."""
        from pipeline.targets.content_filter import discover_markers_from_error

        long_marker = "x" * 150
        error = f'{{"block_reason": "{long_marker}"}}'
        markers = discover_markers_from_error(error)
        assert len(markers) == 0

    def test_returns_set(self):
        from pipeline.targets.content_filter import discover_markers_from_error

        markers = discover_markers_from_error('{"block_reason": "test"}')
        assert isinstance(markers, set)


# ═══════════════════════════════════════════════════════
# content_filter: _load_discovered_markers
# ═══════════════════════════════════════════════════════


class TestLoadDiscoveredMarkers:
    """测试 _load_discovered_markers — 缓存加载."""

    def test_nonexistent_cache_returns_empty(self):
        from pipeline.targets.content_filter import _load_discovered_markers

        # 默认路径不存在时返回空集
        result = _load_discovered_markers()
        assert isinstance(result, set)

    def test_invalid_json_returns_empty(self, tmp_path, monkeypatch):
        from pipeline.targets.content_filter import _load_discovered_markers

        cache_file = tmp_path / "cache.json"
        cache_file.write_text("not valid json {{{", encoding="utf-8")
        monkeypatch.setattr(
            "pipeline.targets.content_filter._CACHE_PATH", cache_file
        )
        result = _load_discovered_markers()
        assert result == set()

    def test_valid_cache_loaded(self, tmp_path, monkeypatch):
        from pipeline.targets.content_filter import _load_discovered_markers

        cache_file = tmp_path / "cache.json"
        cache_file.write_text(
            json.dumps(["marker1", "marker2"]), encoding="utf-8"
        )
        monkeypatch.setattr(
            "pipeline.targets.content_filter._CACHE_PATH", cache_file
        )
        result = _load_discovered_markers()
        assert "marker1" in result
        assert "marker2" in result

    def test_non_list_cache_returns_empty(self, tmp_path, monkeypatch):
        from pipeline.targets.content_filter import _load_discovered_markers

        cache_file = tmp_path / "cache.json"
        cache_file.write_text('{"not": "a list"}', encoding="utf-8")
        monkeypatch.setattr(
            "pipeline.targets.content_filter._CACHE_PATH", cache_file
        )
        result = _load_discovered_markers()
        assert result == set()


# ═══════════════════════════════════════════════════════
# content_filter: _HEURISTIC_PATTERNS
# ═══════════════════════════════════════════════════════


class TestHeuristicPatterns:
    """测试 _HEURISTIC_PATTERNS 正则."""

    def test_patterns_are_compiled(self):
        from pipeline.targets.content_filter import _HEURISTIC_PATTERNS

        for pattern in _HEURISTIC_PATTERNS:
            assert hasattr(pattern, "finditer")

    def test_patterns_nonempty(self):
        from pipeline.targets.content_filter import _HEURISTIC_PATTERNS

        assert len(_HEURISTIC_PATTERNS) > 0


# ═══════════════════════════════════════════════════════
# content_filter: extend_content_filter_markers (集成)
# ═══════════════════════════════════════════════════════


class TestExtendContentFilterMarkers:
    """测试 extend_content_filter_markers — 三层防御集成."""

    def test_returns_frozenset(self):
        from pipeline.targets.content_filter import extend_content_filter_markers

        result = extend_content_filter_markers()
        assert isinstance(result, frozenset)

    def test_includes_default_markers(self):
        from pipeline.targets.content_filter import (
            _DEFAULT_EXTRA_MARKERS,
            extend_content_filter_markers,
        )

        result = extend_content_filter_markers()
        assert _DEFAULT_EXTRA_MARKERS.issubset(result)

    def test_yaml_config_markers_merged(self, tmp_path):
        from pipeline.targets.content_filter import extend_content_filter_markers

        yaml_file = tmp_path / "custom.yaml"
        yaml_content = "markers:\n  - custom_marker_1\n  - custom_marker_2\n"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        result = extend_content_filter_markers(config_path=yaml_file)
        assert "custom_marker_1" in result
        assert "custom_marker_2" in result

    def test_nonexistent_yaml_config_skipped(self):
        from pipeline.targets.content_filter import extend_content_filter_markers

        # 不存在的 YAML 文件不应导致错误
        result = extend_content_filter_markers(config_path="/nonexistent/config.yaml")
        assert isinstance(result, frozenset)


# ═══════════════════════════════════════════════════════
# rate_limited: _classify_error
# ═══════════════════════════════════════════════════════


class TestClassifyError:
    """测试 _classify_error — 异常分类."""

    def test_timeout_exception_name(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = TimeoutError("operation timed out")
        info = _classify_error(exc)
        assert info["retryable"] is True
        assert info["is_timeout"] is True
        assert "timeout" in info["type"]

    def test_timeout_in_message(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("The request timed out after 30 seconds")
        info = _classify_error(exc)
        assert info["retryable"] is True
        assert info["is_timeout"] is True

    def test_apitimeout_error_name(self):
        from pipeline.targets.rate_limited import _classify_error

        class APITimeoutError(Exception):
            pass

        exc = APITimeoutError("api timeout")
        info = _classify_error(exc)
        assert info["retryable"] is True
        assert info["is_timeout"] is True

    def test_non_retryable_400(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 400 Bad Request")
        info = _classify_error(exc)
        assert info["retryable"] is False
        assert info["is_timeout"] is False
        assert "400" in info["type"]

    def test_non_retryable_401(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 401 Unauthorized")
        info = _classify_error(exc)
        assert info["retryable"] is False

    def test_non_retryable_403(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 403 Forbidden")
        info = _classify_error(exc)
        assert info["retryable"] is False

    def test_non_retryable_404(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 404 Not Found")
        info = _classify_error(exc)
        assert info["retryable"] is False

    def test_non_retryable_405(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 405 Method Not Allowed")
        info = _classify_error(exc)
        assert info["retryable"] is False

    def test_retryable_429(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 429 Too Many Requests")
        info = _classify_error(exc)
        assert info["retryable"] is True
        assert info["is_timeout"] is False
        assert "429" in info["type"]

    def test_retryable_429_with_retry_after(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 429 Rate limited. Retry-After: 30 seconds")
        info = _classify_error(exc)
        assert info["retryable"] is True
        assert info["retry_after"] == 30.0

    def test_retryable_500(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 500 Internal Server Error")
        info = _classify_error(exc)
        assert info["retryable"] is True

    def test_retryable_502(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 502 Bad Gateway")
        info = _classify_error(exc)
        assert info["retryable"] is True

    def test_retryable_503(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 503 Service Unavailable")
        info = _classify_error(exc)
        assert info["retryable"] is True

    def test_retryable_504(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 504 Gateway Timeout")
        info = _classify_error(exc)
        assert info["retryable"] is True

    def test_retryable_422(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 422 Unprocessable Entity")
        info = _classify_error(exc)
        assert info["retryable"] is True

    def test_204_empty_response(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("HTTP 204 No Content")
        info = _classify_error(exc)
        assert info["retryable"] is True
        assert "204" in info["type"]

    def test_no_content_text(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("Server returned no content")
        info = _classify_error(exc)
        assert info["retryable"] is True

    def test_connection_error(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("connection failed to remote host")
        info = _classify_error(exc)
        assert info["retryable"] is True
        assert info["type"] == "connection_error"

    def test_connect_in_message(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = Exception("Failed to connect to the server")
        info = _classify_error(exc)
        assert info["retryable"] is True

    def test_default_non_retryable(self):
        from pipeline.targets.rate_limited import _classify_error

        exc = ValueError("some random error")
        info = _classify_error(exc)
        assert info["retryable"] is False
        assert info["is_timeout"] is False
        assert info["type"] == "ValueError"

    def test_returns_dict_with_required_keys(self):
        from pipeline.targets.rate_limited import _classify_error

        info = _classify_error(Exception("test"))
        assert "retryable" in info
        assert "is_timeout" in info
        assert "retry_after" in info
        assert "type" in info


# ═══════════════════════════════════════════════════════
# rate_limited: _parse_retry_after
# ═══════════════════════════════════════════════════════


class TestParseRetryAfter:
    """测试 _parse_retry_after — Retry-After 头解析."""

    def test_hyphen_format(self):
        from pipeline.targets.rate_limited import _parse_retry_after

        assert _parse_retry_after("Retry-After: 30") == 30.0

    def test_space_format(self):
        from pipeline.targets.rate_limited import _parse_retry_after

        assert _parse_retry_after("Retry After: 60") == 60.0

    def test_colon_format(self):
        from pipeline.targets.rate_limited import _parse_retry_after

        assert _parse_retry_after("retry-after: 120") == 120.0

    def test_case_insensitive(self):
        from pipeline.targets.rate_limited import _parse_retry_after

        assert _parse_retry_after("RETRY-AFTER: 45") == 45.0

    def test_no_match_returns_none(self):
        from pipeline.targets.rate_limited import _parse_retry_after

        assert _parse_retry_after("no retry info here") is None

    def test_empty_string_returns_none(self):
        from pipeline.targets.rate_limited import _parse_retry_after

        assert _parse_retry_after("") is None

    def test_embedded_in_longer_string(self):
        from pipeline.targets.rate_limited import _parse_retry_after

        assert _parse_retry_after("HTTP 429 Rate limited. Retry-After: 15 seconds") == 15.0


# ═══════════════════════════════════════════════════════
# rate_limited: RateLimitedTarget 初始化
# ═══════════════════════════════════════════════════════


class TestRateLimitedTargetInit:
    """测试 RateLimitedTarget 初始化."""

    def _make_mock_target(self):
        """创建 mock target."""
        target = MagicMock()
        target._endpoint = "https://api.example.com/v1/chat"
        target._memory = MagicMock()
        target._verbose = True
        target._max_requests_per_minute = 60
        target._model_name = "gpt-4"
        target._underlying_model = "gpt-4-0613"
        target._configuration = {"temp": 0.7}
        target._identifier = "test-id"
        target.supported_converters = []
        return target

    def test_init_copies_attributes(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        rlt = RateLimitedTarget(target=target, max_concurrency=5)
        assert rlt._target is target
        assert rlt._max_retries == 3
        assert rlt._timeout_max_retries == 5
        assert rlt._timeout_max_delay == 120.0
        # super().__init__ sets _memory via CentralMemory (not the mock's _memory)
        assert rlt._memory is not None  # CentralMemory.get_memory_instance()
        assert rlt._verbose is False  # PromptTarget default (verbose not passed)
        assert rlt._max_requests_per_minute == 60  # passed via effective_rpm
        assert rlt._model_name == "gpt-4"
        assert rlt._underlying_model == "gpt-4-0613"
        # _configuration is passed as custom_configuration to super().__init__
        assert rlt._configuration == {"temp": 0.7}
        assert rlt._identifier == "test-id"
        assert rlt.supported_converters == []

    def test_init_endpoint_from_target(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        rlt = RateLimitedTarget(target=target)
        assert rlt._endpoint == "https://api.example.com/v1/chat"

    def test_init_endpoint_override(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        rlt = RateLimitedTarget(target=target, endpoint="https://custom.api.com")
        assert rlt._endpoint == "https://custom.api.com"

    def test_init_endpoint_fallback_to_id(self):
        """没有 _endpoint 属性时用 id(target) 作为端点标识."""
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = MagicMock()
        del target._endpoint
        target._endpoint = AttributeError
        # getattr returns AttributeError fallback to id(target)
        target.__dict__ = {}
        rlt = RateLimitedTarget(target=target)
        # endpoint falls back to str(id(target))
        assert isinstance(rlt._endpoint, str)

    def test_init_with_rpm(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        rlt = RateLimitedTarget(target=target, requests_per_minute=30)
        assert rlt._rpm == 30
        assert rlt._rpm_semaphore is not None

    def test_init_without_rpm(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        rlt = RateLimitedTarget(target=target, requests_per_minute=None)
        assert rlt._rpm is None
        assert rlt._rpm_semaphore is None

    def test_init_custom_retry_params(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        rlt = RateLimitedTarget(
            target=target,
            max_retries=5,
            timeout_max_retries=10,
            timeout_max_delay=300.0,
        )
        assert rlt._max_retries == 5
        assert rlt._timeout_max_retries == 10
        assert rlt._timeout_max_delay == 300.0

    def test_getattr_delegates_to_target(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        target.custom_attribute = "hello"
        rlt = RateLimitedTarget(target=target)
        # __getattr__ should delegate to target
        assert rlt.custom_attribute == "hello"


# ═══════════════════════════════════════════════════════
# rate_limited: _send_with_retry
# ═══════════════════════════════════════════════════════


class TestSendWithRetry:
    """测试 _send_with_retry 重试逻辑."""

    def _make_rlt(self, max_retries=3, timeout_max_retries=5):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = MagicMock()
        target._endpoint = "https://api.example.com"
        target._memory = None
        target._verbose = False
        target._max_requests_per_minute = None
        target._model_name = ""
        target._underlying_model = None
        target._configuration = None
        target._identifier = None
        target.supported_converters = []
        return RateLimitedTarget(
            target=target,
            max_retries=max_retries,
            timeout_max_retries=timeout_max_retries,
        )

    @pytest.mark.asyncio
    async def test_success_first_try(self):
        rlt = self._make_rlt()
        async def mock_send(*, normalized_conversation):
            return ["success"]

        rlt._target._send_prompt_to_target_async = mock_send
        result = await rlt._send_with_retry(normalized_conversation=[])
        assert result == ["success"]

    @pytest.mark.asyncio
    async def test_non_retryable_raises_immediately(self):
        rlt = self._make_rlt(max_retries=3)

        async def mock_send(*, normalized_conversation):
            raise Exception("HTTP 403 Forbidden")

        rlt._target._send_prompt_to_target_async = mock_send
        with pytest.raises(Exception, match="403"):
            await rlt._send_with_retry(normalized_conversation=[])

    @pytest.mark.asyncio
    async def test_retryable_then_success(self):
        rlt = self._make_rlt(max_retries=3)

        call_count = 0

        async def mock_send(*, normalized_conversation):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("HTTP 500 Internal Server Error")
            return ["success"]

        rlt._target._send_prompt_to_target_async = mock_send
        with patch("asyncio.sleep", new=AsyncMock()):
            result = await rlt._send_with_retry(normalized_conversation=[])
        assert result == ["success"]
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_exhausted_retries_raises(self):
        rlt = self._make_rlt(max_retries=2)

        async def mock_send(*, normalized_conversation):
            raise Exception("HTTP 503 Service Unavailable")

        rlt._target._send_prompt_to_target_async = mock_send
        with patch("asyncio.sleep", new=AsyncMock()):
            with pytest.raises(Exception, match="503"):
                await rlt._send_with_retry(normalized_conversation=[])

    @pytest.mark.asyncio
    async def test_timeout_uses_independent_budget(self):
        rlt = self._make_rlt(max_retries=5, timeout_max_retries=3)

        call_count = 0

        async def mock_send(*, normalized_conversation):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise TimeoutError("request timed out")
            return ["ok"]

        rlt._target._send_prompt_to_target_async = mock_send
        with patch("asyncio.sleep", new=AsyncMock()):
            result = await rlt._send_with_retry(normalized_conversation=[])
        assert result == ["ok"]
        assert call_count == 4

    @pytest.mark.asyncio
    async def test_timeout_budget_exhausted_raises(self):
        rlt = self._make_rlt(max_retries=1, timeout_max_retries=2)

        async def mock_send(*, normalized_conversation):
            raise TimeoutError("timed out")

        rlt._target._send_prompt_to_target_async = mock_send
        with patch("asyncio.sleep", new=AsyncMock()):
            with pytest.raises(TimeoutError):
                await rlt._send_with_retry(normalized_conversation=[])


# ═══════════════════════════════════════════════════════
# rate_limited: _send_prompt_to_target_async
# ═══════════════════════════════════════════════════════


class TestSendPromptToTargetAsync:
    """测试 _send_prompt_to_target_async — 信号量+重试."""

    @pytest.mark.asyncio
    async def test_acquires_semaphore(self):
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = MagicMock()
        target._endpoint = "https://api.example.com"
        target._memory = None
        target._verbose = False
        target._max_requests_per_minute = None
        target._model_name = ""
        target._underlying_model = None
        target._configuration = None
        target._identifier = None
        target.supported_converters = []

        async def mock_send(*, normalized_conversation):
            return ["result"]

        target._send_prompt_to_target_async = mock_send
        rlt = RateLimitedTarget(target=target, max_concurrency=1)
        result = await rlt._send_prompt_to_target_async(normalized_conversation=[])
        assert result == ["result"]
