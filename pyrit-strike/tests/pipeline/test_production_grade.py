"""生产级边界测试 — 覆盖 Content-Length 更新、None prompt 防护、
HTTP method 验证、adaptive_json_callback 性能优化、资源清理。

测试覆盖:
    1. JSONSafeHTTPTarget._update_content_length — Content-Length 正确更新
    2. JSONSafeHTTPTarget._inject_prompt_into_request — None prompt 防护
    3. build_httpx_api_target — HTTP method 验证
    4. _make_adaptive_json_callback — 性能优化 (一次解析)
    5. RateLimitedTarget.cleanup — 资源清理
    6. PipelineContext — Playwright 资源引用存储
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
# JSONSafeHTTPTarget._update_content_length
# ═══════════════════════════════════════════════════════


class TestUpdateContentLength:
    """测试 _update_content_length — Content-Length 正确更新."""

    def test_updates_content_length_after_json_injection(self):
        """JSON body 重新序列化后 Content-Length 应更新."""
        from pipeline.recon.target_builder import JSONSafeHTTPTarget

        # 原始请求: Content-Length 是旧的值 (7 bytes for {"prompt":"{PROMPT}"})
        http_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 22\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )
        # 模拟注入后的请求 (prompt 已被替换)
        injected = http_request.replace("{PROMPT}", "Hello world this is a longer prompt")
        result = JSONSafeHTTPTarget._update_content_length(injected)

        # Content-Length 应该是新 body 的字节数
        body = result.split("\r\n\r\n", 1)[1]
        expected_len = len(body.encode("utf-8"))
        assert f"Content-Length: {expected_len}" in result

    def test_adds_content_length_if_missing(self):
        """没有 Content-Length 头但有 body 时应添加."""
        from pipeline.recon.target_builder import JSONSafeHTTPTarget

        http_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            '{"prompt":"hello"}'
        )
        result = JSONSafeHTTPTarget._update_content_length(http_request)
        body = result.split("\r\n\r\n", 1)[1]
        expected_len = len(body.encode("utf-8"))
        assert f"Content-Length: {expected_len}" in result

    def test_no_content_length_for_no_body(self):
        """无 body 时不添加 Content-Length."""
        from pipeline.recon.target_builder import JSONSafeHTTPTarget

        http_request = (
            "GET /api/status HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
        )
        result = JSONSafeHTTPTarget._update_content_length(http_request)
        # 不应有 Content-Length (GET 无 body)
        assert "Content-Length" not in result

    def test_preserves_other_headers(self):
        """更新 Content-Length 时不应丢失其他头."""
        from pipeline.recon.target_builder import JSONSafeHTTPTarget

        http_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Authorization: Bearer token123\r\n"
            "Content-Length: 22\r\n"
            "\r\n"
            '{"prompt":"hello world"}'
        )
        result = JSONSafeHTTPTarget._update_content_length(http_request)
        assert "Host: example.com" in result
        assert "Content-Type: application/json" in result
        assert "Authorization: Bearer token123" in result

    def test_unicode_body_length_correct(self):
        """Unicode body 的 Content-Length 应按 UTF-8 字节数计算."""
        from pipeline.recon.target_builder import JSONSafeHTTPTarget

        # 中文字符: 每个字符 3 字节 UTF-8
        body = '{"prompt":"你好世界"}'
        http_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
            + body
        )
        result = JSONSafeHTTPTarget._update_content_length(http_request)
        expected_len = len(body.encode("utf-8"))
        assert f"Content-Length: {expected_len}" in result


# ═══════════════════════════════════════════════════════
# JSONSafeHTTPTarget._inject_prompt_into_request — None prompt
# ═══════════════════════════════════════════════════════


class TestInjectPromptNoneGuard:
    """测试 None prompt 防护."""

    def test_none_converted_value_treated_as_empty(self):
        """converted_value 为 None 时应替换为空字符串."""
        from pipeline.recon.target_builder import JSONSafeHTTPTarget

        http_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 22\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )

        target = JSONSafeHTTPTarget(
            http_request=http_request,
            use_tls=False,
            callback_function=lambda r: "",
        )

        # Mock MessagePiece with None converted_value
        mock_piece = MagicMock()
        mock_piece.converted_value = None

        result = target._inject_prompt_into_request(mock_piece)
        # {PROMPT} 应被替换为空字符串
        assert "{PROMPT}" not in result
        assert '""' in result or '"prompt":""' in result.replace(" ", "")

    def test_non_string_converted_value_converted_to_str(self):
        """非字符串 converted_value 应转为字符串."""
        from pipeline.recon.target_builder import JSONSafeHTTPTarget

        http_request = (
            "POST /api/chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 22\r\n"
            "\r\n"
            '{"prompt":"{PROMPT}"}'
        )

        target = JSONSafeHTTPTarget(
            http_request=http_request,
            use_tls=False,
            callback_function=lambda r: "",
        )

        mock_piece = MagicMock()
        mock_piece.converted_value = 12345  # int

        result = target._inject_prompt_into_request(mock_piece)
        assert "12345" in result
        assert "{PROMPT}" not in result


# ═══════════════════════════════════════════════════════
# build_httpx_api_target — HTTP method 验证
# ═══════════════════════════════════════════════════════


class TestBuildHttpxApiTargetValidation:
    """测试 build_httpx_api_target 参数验证."""

    def _make_parsed(self):
        """创建 mock ParsedBurpRequest."""
        from pipeline.recon.burp_parser import ParsedBurpRequest

        return ParsedBurpRequest(
            method="POST",
            url="https://api.example.com/v1/chat",
            host="api.example.com",
            path="/v1/chat",
            headers={"Content-Type": "application/json"},
            raw_headers=[("Content-Type", "application/json"), ("Authorization", "Bearer test")],
            body='{"prompt":"hi"}',
            use_tls=True,
            is_sse=False,
            http_version="HTTP/1.1",
            has_prompt_placeholder=True,
        )

    def test_invalid_method_raises_value_error(self):
        """不合法的 HTTP method 应抛出 ValueError."""
        from pipeline.recon.target_builder import build_httpx_api_target

        parsed = self._make_parsed()
        with pytest.raises(ValueError, match="Invalid HTTP method"):
            build_httpx_api_target(parsed, method="INVALID")

    def test_file_upload_with_get_raises_value_error(self):
        """file_path + GET 方法应抛出 ValueError."""
        from pipeline.recon.target_builder import build_httpx_api_target

        parsed = self._make_parsed()
        with pytest.raises(ValueError, match="File upload requires"):
            build_httpx_api_target(parsed, method="GET", file_path="/tmp/test.txt")

    def test_json_and_form_mutually_exclusive(self):
        """json_data + form_data 同时传应抛出 ValueError."""
        from pipeline.recon.target_builder import build_httpx_api_target

        parsed = self._make_parsed()
        with pytest.raises(ValueError, match="mutually exclusive"):
            build_httpx_api_target(
                parsed,
                method="POST",
                json_data={"key": "value"},
                form_data={"key": "value"},
            )

    def test_valid_method_lowercase_normalized(self):
        """小写 method 应被标准化为大写."""
        from pipeline.recon.target_builder import build_httpx_api_target

        parsed = self._make_parsed()
        # 不应抛出异常
        target = build_httpx_api_target(parsed, method="post")
        assert target is not None


# ═══════════════════════════════════════════════════════
# _make_adaptive_json_callback — 性能优化
# ═══════════════════════════════════════════════════════


class TestAdaptiveJsonCallbackOptimized:
    """测试优化后的 adaptive_json_callback."""

    def test_openai_format_extraction(self):
        """OpenAI 格式 JSON 应正确提取."""
        from pipeline.recon.target_builder import _make_adaptive_json_callback

        callback = _make_adaptive_json_callback()
        mock_response = MagicMock()
        mock_response.content = json.dumps(
            {"choices": [{"message": {"content": "Hello world"}}]}
        ).encode("utf-8")

        result = callback(mock_response)
        assert result == "Hello world"

    def test_data_content_extraction(self):
        """data.content 路径应正确提取."""
        from pipeline.recon.target_builder import _make_adaptive_json_callback

        callback = _make_adaptive_json_callback()
        mock_response = MagicMock()
        mock_response.content = json.dumps(
            {"data": {"content": "Response text"}}
        ).encode("utf-8")

        result = callback(mock_response)
        assert result == "Response text"

    def test_non_json_returns_raw_text(self):
        """非 JSON 响应应返回原始文本."""
        from pipeline.recon.target_builder import _make_adaptive_json_callback

        callback = _make_adaptive_json_callback()
        mock_response = MagicMock()
        mock_response.content = b"Plain text response"

        result = callback(mock_response)
        assert result == "Plain text response"

    def test_empty_content_returns_empty(self):
        """空内容应返回空字符串."""
        from pipeline.recon.target_builder import _make_adaptive_json_callback

        callback = _make_adaptive_json_callback()
        mock_response = MagicMock()
        mock_response.content = b""

        result = callback(mock_response)
        assert result == ""

    def test_text_attribute_fallback(self):
        """无 content 属性时应使用 text 属性."""
        from pipeline.recon.target_builder import _make_adaptive_json_callback

        callback = _make_adaptive_json_callback()
        mock_response = MagicMock(spec=["text"])
        mock_response.text = json.dumps({"response": "From text attr"})

        result = callback(mock_response)
        assert result == "From text attr"

    def test_all_paths_fail_returns_raw(self):
        """所有路径都找不到时应返回原始文本."""
        from pipeline.recon.target_builder import _make_adaptive_json_callback

        callback = _make_adaptive_json_callback()
        mock_response = MagicMock()
        mock_response.content = json.dumps(
            {"unknown_key": "unknown value"}
        ).encode("utf-8")

        result = callback(mock_response)
        # 应返回原始 JSON 文本
        assert "unknown_key" in result

    def test_nested_data_choices_extraction(self):
        """嵌套 data.choices[0].message.content 应正确提取."""
        from pipeline.recon.target_builder import _make_adaptive_json_callback

        callback = _make_adaptive_json_callback()
        mock_response = MagicMock()
        mock_response.content = json.dumps(
            {"data": {"choices": [{"message": {"content": "Nested response"}}]}}
        ).encode("utf-8")

        result = callback(mock_response)
        assert result == "Nested response"


# ═══════════════════════════════════════════════════════
# RateLimitedTarget.cleanup — 资源清理
# ═══════════════════════════════════════════════════════


class TestRateLimitedTargetCleanup:
    """测试 RateLimitedTarget.cleanup — 资源清理."""

    def _make_mock_target(self):
        """创建 mock target."""
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
        target._client = None
        return target

    @pytest.mark.asyncio
    async def test_cleanup_closes_httpx_client(self):
        """cleanup 应关闭 httpx.AsyncClient."""
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        target._client = AsyncMock()
        rlt = RateLimitedTarget(target=target)
        # Mock dispose_db_engine to avoid DB issues in test
        with patch.object(rlt, 'dispose_db_engine'):
            await rlt.cleanup()
        target._client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_calls_target_cleanup(self):
        """cleanup 应调用原始 target 的 cleanup 方法."""
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        target.cleanup = AsyncMock()
        rlt = RateLimitedTarget(target=target)
        # Mock dispose_db_engine to avoid DB issues in test
        with patch.object(rlt, 'dispose_db_engine'):
            await rlt.cleanup()
        target.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_idempotent_no_client(self):
        """无 httpx client 时 cleanup 不应报错."""
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        target._client = None
        rlt = RateLimitedTarget(target=target)
        # Mock dispose_db_engine to avoid DB issues in test
        with patch.object(rlt, 'dispose_db_engine'):
            await rlt.cleanup()  # 不应抛出异常

    @pytest.mark.asyncio
    async def test_cleanup_handles_errors_gracefully(self):
        """cleanup 中异常不应传播."""
        from pipeline.targets.rate_limited import RateLimitedTarget

        target = self._make_mock_target()
        target._client = AsyncMock()
        target._client.aclose.side_effect = RuntimeError("close failed")
        rlt = RateLimitedTarget(target=target)
        # Mock dispose_db_engine to avoid DB issues in test
        with patch.object(rlt, 'dispose_db_engine'):
            await rlt.cleanup()  # 不应抛出异常


# ═══════════════════════════════════════════════════════
# PipelineContext — Playwright 资源引用存储
# ═══════════════════════════════════════════════════════


class TestPipelineContextPlaywrightFields:
    """测试 PipelineContext 的 Playwright 资源字段."""

    def test_playwright_fields_default_none(self):
        """Playwright 资源字段默认应为 None."""
        from pipeline.context import PipelineContext

        args = MagicMock()
        ctx = PipelineContext(args=args)
        assert ctx._playwright_instance is None
        assert ctx._browser is None
        assert ctx._browser_context is None

    def test_playwright_fields_settable(self):
        """Playwright 资源字段应可设置."""
        from pipeline.context import PipelineContext

        args = MagicMock()
        ctx = PipelineContext(args=args)
        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()

        ctx._playwright_instance = mock_pw
        ctx._browser = mock_browser
        ctx._browser_context = mock_context

        assert ctx._playwright_instance is mock_pw
        assert ctx._browser is mock_browser
        assert ctx._browser_context is mock_context


# ═══════════════════════════════════════════════════════
# _cleanup_resources — main.py 资源清理函数
# ═══════════════════════════════════════════════════════


class TestCleanupResources:
    """测试 main.py 的 _cleanup_resources 函数."""

    @pytest.mark.asyncio
    async def test_cleanup_resources_with_playwright(self):
        """有 Playwright 资源时应正确清理."""
        from pipeline.context import PipelineContext
        from main import _cleanup_resources

        args = MagicMock()
        ctx = PipelineContext(args=args)

        ctx._browser_context = AsyncMock()
        ctx._browser = AsyncMock()
        ctx._playwright_instance = AsyncMock()

        await _cleanup_resources(ctx)

        ctx._browser_context.close.assert_called_once()
        ctx._browser.close.assert_called_once()
        ctx._playwright_instance.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_resources_with_rate_limited_target(self):
        """有 RateLimitedTarget 时应调用其 cleanup."""
        from pipeline.context import PipelineContext
        from main import _cleanup_resources

        args = MagicMock()
        ctx = PipelineContext(args=args)

        mock_target = MagicMock()
        mock_target.cleanup = AsyncMock()
        ctx.objective_target = mock_target

        await _cleanup_resources(ctx)
        mock_target.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_resources_no_targets(self):
        """无任何 target 时不应报错."""
        from pipeline.context import PipelineContext
        from main import _cleanup_resources

        args = MagicMock()
        ctx = PipelineContext(args=args)
        ctx.objective_target = None
        ctx.multi_turn_target = None

        await _cleanup_resources(ctx)  # 不应抛出异常

    @pytest.mark.asyncio
    async def test_cleanup_resources_extra_targets(self):
        """跨端口发现的目标也应被清理."""
        from pipeline.context import PipelineContext
        from main import _cleanup_resources

        args = MagicMock()
        ctx = PipelineContext(args=args)

        mock_port_target = MagicMock()
        mock_port_target.cleanup = AsyncMock()
        ctx.extra_objective_targets = {3001: mock_port_target}

        await _cleanup_resources(ctx)
        mock_port_target.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_resources_handles_errors(self):
        """清理中异常不应传播."""
        from pipeline.context import PipelineContext
        from main import _cleanup_resources

        args = MagicMock()
        ctx = PipelineContext(args=args)

        ctx._browser = AsyncMock()
        ctx._browser.close.side_effect = RuntimeError("close failed")

        # 不应抛出异常
        await _cleanup_resources(ctx)
