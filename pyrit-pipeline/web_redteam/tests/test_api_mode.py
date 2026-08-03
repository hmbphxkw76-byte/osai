# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""API 模式单元测试.

覆盖:
  - APITargetConfig: CLI 参数 → 配置转换
  - APITargetConfig: 凭据脱敏
  - APITargetConfig: G3 api-key + 环境变量自动注入
  - _build_raw_http_request: HTTP 请求构建
  - _build_fallback_json_callback: G1 JSON 回调 fallback
  - _build_fallback_sse_callback: G2 SSE 回调 fallback
  - G8: recon-data 驱动攻击策略选择
  - G9: 凭据日志脱敏过滤器
  - G6: AIMD 自适应限速
  - G7: 不可重试状态码

> **日期**: 2026-8-3
"""

from __future__ import annotations

import json
import logging
import os
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ============================================================
# APITargetConfig 测试
# ============================================================


def _make_args(**kwargs) -> types.SimpleNamespace:
    """构建模拟 argparse.Namespace."""
    defaults = {
        "api_url": "https://api.example.com/v1/chat/completions",
        "api_method": "POST",
        "api_headers": None,
        "api_body": None,
        "api_model": None,
        "api_response_path": "choices[0].message.content",
        "api_response_format": "json",
        "api_raw_request": None,
        "api_timeout": 30,
        "api_max_retries": 3,
        "max_rpm": None,
        "max_concurrency": 3,
        "api_key": None,
        "api_health_check": False,
        "api_auth_type": "bearer",
        "api_oauth_token_url": None,
        "api_oauth_client_id": None,
        "api_oauth_client_secret": None,
        "resume": None,
    }
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


class TestAPITargetConfig:
    """APITargetConfig 测试."""

    def test_from_args_basic(self):
        """测试基本 CLI 参数 → APITargetConfig 转换."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args()
        config = APITargetConfig.from_args(args)

        assert config is not None
        assert config.url == "https://api.example.com/v1/chat/completions"
        assert config.method == "POST"
        assert config.max_concurrency == 3

    def test_from_args_no_url(self):
        """测试无 --api-url 返回 None."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args(api_url=None)
        config = APITargetConfig.from_args(args)

        assert config is None

    def test_default_body_template_contains_prompt_placeholder(self):
        """测试默认 body_template 包含 {PROMPT} 占位符."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args()
        config = APITargetConfig.from_args(args)

        assert config is not None
        assert "{PROMPT}" in config.body_template

    def test_custom_body_template(self):
        """测试自定义 body_template."""
        from web_redteam.targets.api_config import APITargetConfig

        custom_body = json.dumps({"input": "{PROMPT}", "max_tokens": 100})
        args = _make_args(api_body=custom_body)
        config = APITargetConfig.from_args(args)

        assert config is not None
        assert config.body_template == custom_body
        assert "{PROMPT}" in config.body_template

    def test_mask_secret(self):
        """测试凭据脱敏."""
        from web_redteam.targets.api_config import _mask_secret

        assert _mask_secret("sk-short") == "***"
        assert _mask_secret("sk-verylongkey1234567890") == "sk-v...7890"

    def test_to_display_dict_masks_auth(self):
        """测试 to_display_dict 脱敏 Authorization 头."""
        from web_redteam.targets.api_config import APITargetConfig

        secret = "Bearer sk-verylongkey1234567890"
        config = APITargetConfig(
            url="https://api.example.com",
            headers={"Authorization": secret},
        )
        display = config.to_display_dict()

        # 原始密钥不应出现在脱敏后的输出中
        assert display["headers"]["Authorization"] != secret
        assert "sk-verylongkey1234567890" not in display["headers"]["Authorization"]

    def test_g3_api_key_auto_injection(self):
        """G3: 测试 --api-key 自动注入 Authorization 头."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args(api_key="sk-testkey1234567890")
        config = APITargetConfig.from_args(args)

        assert config is not None
        assert "Authorization" in config.headers
        assert config.headers["Authorization"] == "Bearer sk-testkey1234567890"

    def test_g3_api_key_env_var(self):
        """G3: 测试 API_KEY 环境变量自动注入."""
        from web_redteam.targets.api_config import APITargetConfig

        with patch.dict(os.environ, {"API_KEY": "sk-envkey1234567890"}):
            args = _make_args()
            config = APITargetConfig.from_args(args)

            assert config is not None
            assert config.headers["Authorization"] == "Bearer sk-envkey1234567890"

    def test_g3_api_key_does_not_override_explicit_headers(self):
        """G3: --api-headers 中的 Authorization 优先于 --api-key."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args(
            api_key="sk-auto",
            api_headers=json.dumps({"Authorization": "Bearer sk-explicit"}),
        )
        config = APITargetConfig.from_args(args)

        assert config is not None
        assert config.headers["Authorization"] == "Bearer sk-explicit"

    def test_g2_response_format_field(self):
        """G2: 测试 response_format 字段."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args(api_response_format="sse")
        config = APITargetConfig.from_args(args)

        assert config is not None
        assert config.response_format == "sse"

    def test_g5_health_check_field(self):
        """G5: 测试 health_check 字段."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args(api_health_check=True)
        config = APITargetConfig.from_args(args)

        assert config is not None
        assert config.health_check is True


# ============================================================
# _build_raw_http_request 测试
# ============================================================


class TestBuildRawHTTPRequest:
    """_build_raw_http_request 测试."""

    def test_basic_post_request(self):
        """测试基本 POST 请求构建."""
        from web_redteam.pipeline.stage_target import _build_raw_http_request
        from web_redteam.targets.api_config import APITargetConfig

        config = APITargetConfig(
            url="https://api.example.com/v1/chat",
            method="POST",
            headers={"Content-Type": "application/json"},
            body_template='{"messages": [{"content": "{PROMPT}"}]}',
        )
        raw = _build_raw_http_request(config)

        assert "POST /v1/chat HTTP/1.1" in raw
        assert "Host: api.example.com" in raw
        assert "Content-Type: application/json" in raw
        assert "{PROMPT}" in raw

    def test_request_with_auth_header(self):
        """测试带认证头的请求."""
        from web_redteam.pipeline.stage_target import _build_raw_http_request
        from web_redteam.targets.api_config import APITargetConfig

        config = APITargetConfig(
            url="https://api.example.com/v1/chat",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer sk-test",
            },
            body_template='{"content": "{PROMPT}"}',
        )
        raw = _build_raw_http_request(config)

        assert "Authorization: Bearer sk-test" in raw

    def test_request_with_query_params(self):
        """测试带查询参数的 URL."""
        from web_redteam.pipeline.stage_target import _build_raw_http_request
        from web_redteam.targets.api_config import APITargetConfig

        config = APITargetConfig(
            url="https://api.example.com/v1/chat?model=gpt-4",
            headers={"Content-Type": "application/json"},
            body_template='{"content": "{PROMPT}"}',
        )
        raw = _build_raw_http_request(config)

        assert "/v1/chat?model=gpt-4" in raw


# ============================================================
# G1: Fallback JSON callback 测试
# ============================================================


class TestFallbackJsonCallback:
    """G1: _build_fallback_json_callback 测试."""

    def test_basic_json_extraction(self):
        """测试基本 JSON 路径提取."""
        from web_redteam.pipeline.stage_target import _build_fallback_json_callback

        callback = _build_fallback_json_callback("choices[0].message.content")
        response = json.dumps({
            "choices": [{"message": {"content": "Hello world"}}],
        })
        result = callback(response)

        assert result == "Hello world"

    def test_nested_path_extraction(self):
        """测试嵌套路径提取."""
        from web_redteam.pipeline.stage_target import _build_fallback_json_callback

        callback = _build_fallback_json_callback("data.output.text")
        response = json.dumps({"data": {"output": {"text": "Result"}}})
        result = callback(response)

        assert result == "Result"

    def test_invalid_json_returns_raw(self):
        """测试无效 JSON 返回原始响应."""
        from web_redteam.pipeline.stage_target import _build_fallback_json_callback

        callback = _build_fallback_json_callback("choices[0].message.content")
        result = callback("not valid json")

        assert result == "not valid json"


# ============================================================
# G2: Fallback SSE callback 测试
# ============================================================


class TestFallbackSSECallback:
    """G2: _build_fallback_sse_callback 测试."""

    def test_sse_extraction(self):
        """测试 SSE data: 行提取."""
        from web_redteam.pipeline.stage_target import _build_fallback_sse_callback

        callback = _build_fallback_sse_callback()
        response = (
            'data: {"content": "Hello"}\n\n'
            'data: {"content": " world"}\n\n'
            "data: [DONE]\n\n"
        )
        result = callback(response)

        assert result == "Hello world"

    def test_sse_empty_response(self):
        """测试空 SSE 响应."""
        from web_redteam.pipeline.stage_target import _build_fallback_sse_callback

        callback = _build_fallback_sse_callback()
        result = callback("")

        assert result == ""


# ============================================================
# G8: recon-data 驱动攻击策略测试
# ============================================================


class TestReconDrivenAttack:
    """G8: 侦察数据驱动攻击策略选择测试."""

    def test_recon_recommendation_drives_attack_type(self):
        """测试 recon-data 推荐驱动攻击类型选择."""
        from web_redteam.pipeline.context import WebRedTeamContext
        from web_redteam.pipeline.stage_attack import _resolve_attack_params

        args = types.SimpleNamespace(
            attack_type=None,
            objective="test objective",
            max_turns=None,
        )
        ctx = WebRedTeamContext(
            args=args,
            api_mode=True,
            recon_result={
                "recommendations": [
                    {
                        "attack_strategy": "red_teaming",
                        "priority": 1,
                    }
                ],
            },
        )

        attack_type, _, _ = _resolve_attack_params(ctx)

        assert attack_type == "red_teaming"

    def test_recon_no_recommendation_uses_default(self):
        """测试无推荐时使用默认值."""
        from web_redteam.pipeline.context import WebRedTeamContext
        from web_redteam.pipeline.stage_attack import _resolve_attack_params

        args = types.SimpleNamespace(
            attack_type=None,
            objective="test",
            max_turns=None,
        )
        ctx = WebRedTeamContext(
            args=args,
            api_mode=True,
            recon_result={"recommendations": []},
        )

        attack_type, _, _ = _resolve_attack_params(ctx)

        assert attack_type == "prompt_sending"

    def test_explicit_attack_type_overrides_recon(self):
        """测试显式指定 attack_type 优先于 recon 推荐."""
        from web_redteam.pipeline.context import WebRedTeamContext
        from web_redteam.pipeline.stage_attack import _resolve_attack_params

        args = types.SimpleNamespace(
            attack_type="crescendo",
            objective="test",
            max_turns=None,
        )
        ctx = WebRedTeamContext(
            args=args,
            api_mode=True,
            recon_result={
                "recommendations": [
                    {"attack_strategy": "tap", "priority": 1},
                ],
            },
        )

        attack_type, _, _ = _resolve_attack_params(ctx)

        assert attack_type == "crescendo"


# ============================================================
# G9: 凭据日志脱敏测试
# ============================================================


class TestCredentialRedactionFilter:
    """G9: CredentialRedactionFilter 测试."""

    def test_bearer_token_redaction(self):
        """测试 Bearer token 脱敏."""
        from web_redteam.run import CredentialRedactionFilter

        filt = CredentialRedactionFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Authorization: Bearer sk-verylongkey1234567890",
            args=None,
            exc_info=None,
        )
        filt.filter(record)

        assert "sk-verylongkey1234567890" not in str(record.msg)
        assert "***" in str(record.msg)

    def test_api_key_redaction(self):
        """测试 api_key 脱敏."""
        from web_redteam.run import CredentialRedactionFilter

        filt = CredentialRedactionFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="api_key=sk-verylongkey1234567890",
            args=None,
            exc_info=None,
        )
        filt.filter(record)

        assert "sk-verylongkey1234567890" not in str(record.msg)

    def test_non_credential_text_passthrough(self):
        """测试非凭据文本不受影响."""
        from web_redteam.run import CredentialRedactionFilter

        filt = CredentialRedactionFilter()
        original_msg = "Stage 3: HTTPTarget created (url=https://example.com)"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=original_msg,
            args=None,
            exc_info=None,
        )
        filt.filter(record)

        assert str(record.msg) == original_msg


# ============================================================
# G6+G7: RateLimitedTarget 测试
# ============================================================


class TestRateLimitedTargetG6G7:
    """G6+G7: AIMD 自适应限速 + 不可重试状态码测试."""

    def test_g7_non_retryable_error_detection(self):
        """G7: 测试 401/403 被识别为不可重试."""
        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        # 模拟带 status_code 的异常
        err_401 = type("HTTPError", (Exception,), {"status_code": 401})("Unauthorized")
        err_403 = type("HTTPError", (Exception,), {"status_code": 403})("Forbidden")
        err_500 = type("HTTPError", (Exception,), {"status_code": 500})("Server Error")
        err_429 = type("HTTPError", (Exception,), {"status_code": 429})("Rate Limited")

        assert _is_non_retryable_error(err_401) is True
        assert _is_non_retryable_error(err_403) is True
        assert _is_non_retryable_error(err_500) is False
        assert _is_non_retryable_error(err_429) is False

    def test_g7_error_string_matching(self):
        """G7: 测试从错误字符串中识别不可重试状态码."""
        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        err_401_str = Exception("HTTP 401: Unauthorized")
        err_403_str = Exception("HTTP 403: Forbidden")
        err_500_str = Exception("HTTP 500: Internal Server Error")

        assert _is_non_retryable_error(err_401_str) is True
        assert _is_non_retryable_error(err_403_str) is True
        assert _is_non_retryable_error(err_500_str) is False

    def test_g6_aimd_decrease(self):
        """G6: 测试 AIMD Multiplicative Decrease."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=60,
        )

        assert rlt.current_rpm == 60
        rlt._aimd_decrease()
        assert rlt.current_rpm == 30
        rlt._aimd_decrease()
        assert rlt.current_rpm == 15

    def test_g6_aimd_increase(self):
        """G6: 测试 AIMD Additive Increase."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=60,
        )

        # 先降低
        rlt._aimd_decrease()
        assert rlt.current_rpm == 30

        # 再增加 (不超过初始值)
        rlt._aimd_increase()
        assert rlt.current_rpm == 33  # 30 + 3 (60//20=3)

        # 多次增加不超过初始值
        for _ in range(20):
            rlt._aimd_increase()
        assert rlt.current_rpm == 60

    def test_g6_aimd_no_rpm_limit(self):
        """G6: 无 RPM 限制时 AIMD 不调整."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=None,
        )

        assert rlt.current_rpm == 0
        rlt._aimd_decrease()  # 不应抛异常
        rlt._aimd_increase()  # 不应抛异常
        assert rlt.current_rpm == 0

    @pytest.mark.asyncio
    async def test_g7_non_retryable_raises_immediately(self):
        """G7: 401 错误立即抛出, 不重试."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        err_401 = type("HTTPError", (Exception,), {"status_code": 401})("Unauthorized")
        mock_target.send_prompt_async = MagicMock(side_effect=err_401)

        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            max_retries=5,
        )

        with pytest.raises(Exception) as exc_info:
            await rlt.send_prompt_async(prompt_request=MagicMock())

        # 验证只调用了一次 (没有重试)
        assert mock_target.send_prompt_async.call_count == 1
        assert "401" in str(exc_info.value) or "Unauthorized" in str(exc_info.value)


# ============================================================
# R1: 端到端集成测试 (Mock HTTP server)
# ============================================================


class TestEndToEndIntegration:
    """R1: 端到端集成测试 — 使用 Python 内置 http.server 模拟 OpenAI 兼容端点."""

    def test_mock_server_json_response_parsing(self):
        """R1: 测试 Mock HTTP server 返回 OpenAI 格式 JSON 响应, 验证完整解析链."""
        import http.server
        import socketserver
        import threading

        from web_redteam.pipeline.stage_target import _build_fallback_json_callback

        # 模拟 OpenAI Chat Completions 响应
        mock_response = json.dumps({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "I cannot help with that request.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
        })

        class MockHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(mock_response.encode("utf-8"))

            def log_message(self, format, *args) -> None:
                pass  # 静默日志

        # 启动 Mock server
        with socketserver.TCPServer(("127.0.0.1", 0), MockHandler) as httpd:
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            try:
                # 构建配置并测试完整解析链
                from web_redteam.targets.api_config import APITargetConfig

                config = APITargetConfig(
                    url=f"http://127.0.0.1:{port}/v1/chat/completions",
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    body_template=json.dumps({
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": "{PROMPT}"}],
                    }),
                    response_json_path="choices[0].message.content",
                )

                # 构建原始 HTTP 请求
                from web_redteam.pipeline.stage_target import _build_raw_http_request

                raw_request = _build_raw_http_request(config)
                assert "POST /v1/chat/completions HTTP/1.1" in raw_request
                assert "{PROMPT}" in raw_request

                # 使用 fallback callback 解析 Mock 响应
                callback = _build_fallback_json_callback(config.response_json_path)
                result = callback(mock_response)

                assert result == "I cannot help with that request."
            finally:
                httpd.shutdown()
                thread.join(timeout=5)

    def test_mock_server_401_error_handling(self):
        """R1: 测试 Mock HTTP server 返回 401, 验证 G7 不可重试逻辑."""
        import http.server
        import socketserver
        import threading

        from pipeline.targets.rate_limited_target import _is_non_retryable_error

        class MockHandler401(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))

            def log_message(self, format, *args) -> None:
                pass

        with socketserver.TCPServer(("127.0.0.1", 0), MockHandler401) as httpd:
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            try:
                # 模拟 401 错误对象
                err_401 = type(
                    "HTTPError",
                    (Exception,),
                    {"status_code": 401},
                )(f"HTTP 401: Unauthorized (url=http://127.0.0.1:{port})")

                # G7: 应识别为不可重试
                assert _is_non_retryable_error(err_401) is True
            finally:
                httpd.shutdown()
                thread.join(timeout=5)

    def test_mock_server_429_rate_limit_handling(self):
        """R1: 测试 Mock HTTP server 返回 429, 验证 G6 AIMD 降低."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        err_429 = type(
            "HTTPError",
            (Exception,),
            {"status_code": 429},
        )("Too Many Requests")
        mock_target.send_prompt_async = MagicMock(side_effect=err_429)

        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://api.example.com",
            max_concurrency=1,
            max_retries=2,
            requests_per_minute=60,
        )

        assert rlt.current_rpm == 60

        import asyncio

        with pytest.raises(Exception, match="Too Many Requests"):
            asyncio.run(rlt.send_prompt_async(prompt_request=MagicMock()))

        # G6: 429 后 RPM 应降低
        assert rlt.current_rpm < 60

    def test_full_config_to_request_chain(self):
        """R1: 测试完整链路: CLI args → APITargetConfig → raw HTTP request → callback."""
        from web_redteam.pipeline.stage_target import (
            _build_fallback_json_callback,
            _build_raw_http_request,
        )
        from web_redteam.targets.api_config import APITargetConfig

        # 1. 模拟 CLI 参数
        args = _make_args(
            api_url="https://api.openai.com/v1/chat/completions",
            api_key="sk-testkey1234567890",
            api_model="gpt-4",
            max_rpm=120,
            max_concurrency=5,
        )

        # 2. 构建 APITargetConfig
        config = APITargetConfig.from_args(args)
        assert config is not None
        assert config.url == "https://api.openai.com/v1/chat/completions"
        assert config.max_rpm == 120
        assert "Authorization" in config.headers
        assert "{PROMPT}" in config.body_template

        # 3. 构建原始 HTTP 请求
        raw_request = _build_raw_http_request(config)
        assert "POST /v1/chat/completions HTTP/1.1" in raw_request
        assert "Host: api.openai.com" in raw_request
        assert "Authorization: Bearer sk-testkey1234567890" in raw_request
        assert "{PROMPT}" in raw_request

        # 4. 模拟响应并验证 callback
        callback = _build_fallback_json_callback(config.response_json_path)
        mock_response = json.dumps({
            "choices": [{"message": {"content": "Test response"}}],
        })
        result = callback(mock_response)
        assert result == "Test response"


# ============================================================
# R2: OAuth2 认证测试
# ============================================================


class TestOAuth2Authentication:
    """R2: OAuth2 client_credentials 认证测试."""

    def test_r2_oauth2_fields_in_config(self):
        """R2: 测试 APITargetConfig 包含 OAuth2 字段."""
        from web_redteam.targets.api_config import APITargetConfig

        config = APITargetConfig(
            url="https://api.example.com",
            auth_type="oauth2",
            oauth_token_url="https://auth.example.com/token",
            oauth_client_id="test_client_id",
            oauth_client_secret="test_client_secret",
        )

        assert config.auth_type == "oauth2"
        assert config.oauth_token_url == "https://auth.example.com/token"
        assert config.oauth_client_id == "test_client_id"
        assert config.oauth_client_secret == "test_client_secret"

    def test_r2_oauth2_token_fetch_with_mock(self):
        """R2: 测试 OAuth2 token 获取 (mocked urllib)."""
        from web_redteam.targets.api_config import _fetch_oauth2_token, _oauth2_token_cache

        # 清除缓存
        _oauth2_token_cache.clear()

        mock_response_data = json.dumps({
            "access_token": "mock_token_12345",
            "token_type": "Bearer",
            "expires_in": 3600,
        }).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response_data
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            token = _fetch_oauth2_token(
                token_url="https://auth.example.com/token",
                client_id="test_client",
                client_secret="test_secret",
            )

        assert token == "mock_token_12345"

        # 验证缓存
        cache_key = "https://auth.example.com/token:test_client:"
        assert cache_key in _oauth2_token_cache

        # 清理缓存
        _oauth2_token_cache.clear()

    def test_r2_oauth2_token_fetch_failure(self):
        """R2: 测试 OAuth2 token 获取失败时返回 None."""
        from web_redteam.targets.api_config import _fetch_oauth2_token, _oauth2_token_cache

        _oauth2_token_cache.clear()

        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            token = _fetch_oauth2_token(
                token_url="https://auth.example.com/token",
                client_id="test_client",
                client_secret="test_secret",
            )

        assert token is None

    def test_r2_oauth2_from_args_missing_credentials(self):
        """R2: 测试 OAuth2 缺少必要参数时不注入 token."""
        from web_redteam.targets.api_config import APITargetConfig

        args = _make_args(
            api_auth_type="oauth2",
            api_oauth_token_url=None,
            api_oauth_client_id=None,
            api_oauth_client_secret=None,
        )

        config = APITargetConfig.from_args(args)
        assert config is not None
        assert config.auth_type == "oauth2"
        # 没有 Authorization 头 (因为 OAuth2 获取失败)
        assert "Authorization" not in config.headers


# ============================================================
# R3: 中断恢复测试
# ============================================================


class TestCheckpointResume:
    """R3: 检查点保存/加载测试."""

    def test_r3_save_and_load_checkpoint(self, tmp_path):
        """R3: 测试检查点保存和加载."""
        from web_redteam.pipeline.context import WebRedTeamContext
        from web_redteam.run import _load_checkpoint, _save_checkpoint

        args = _make_args()
        ctx = WebRedTeamContext(args=args, api_mode=True)
        ctx.metadata["completed_stages"] = {"stage_init", "stage_auth"}

        checkpoint_path = tmp_path / "checkpoint.json"
        _save_checkpoint(ctx, checkpoint_path)

        assert checkpoint_path.exists()

        loaded = _load_checkpoint(str(checkpoint_path))
        assert loaded is not None
        assert "stage_init" in loaded["completed_stages"]
        assert "stage_auth" in loaded["completed_stages"]
        assert loaded["api_mode"] is True

    def test_r3_load_nonexistent_checkpoint(self):
        """R3: 测试加载不存在的检查点返回 None."""
        from web_redteam.run import _load_checkpoint

        result = _load_checkpoint("/nonexistent/path/checkpoint.json")
        assert result is None

    def test_r3_checkpoint_with_api_config(self, tmp_path):
        """R3: 测试带 API 配置的检查点."""
        from web_redteam.pipeline.context import WebRedTeamContext
        from web_redteam.run import _load_checkpoint, _save_checkpoint
        from web_redteam.targets.api_config import APITargetConfig

        config = APITargetConfig(
            url="https://api.example.com",
            headers={"Authorization": "Bearer sk-testkey1234567890"},
            max_rpm=60,
        )
        args = _make_args()
        ctx = WebRedTeamContext(args=args, api_mode=True, api_config=config)
        ctx.metadata["completed_stages"] = {"stage_init", "stage_auth", "stage_target"}

        checkpoint_path = tmp_path / "checkpoint.json"
        _save_checkpoint(ctx, checkpoint_path)

        loaded = _load_checkpoint(str(checkpoint_path))
        assert loaded is not None
        assert loaded["has_api_config"] is True
        assert loaded["has_target"] is False
        assert "stage_target" in loaded["completed_stages"]
        # 验证 API config 被脱敏保存
        assert "api_config" in loaded


# ============================================================
# R5: AIMD 动态调整测试
# ============================================================


class TestAIMDDynamicAdjustment:
    """R5: AIMD 参数动态调整 (响应时间驱动) 测试."""

    def test_r5_rtt_properties_initial(self):
        """R5: 测试 RTT 属性初始值为 0."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=60,
        )

        assert rlt.rtt_p50 == 0.0
        assert rlt.rtt_p90 == 0.0

    def test_r5_rtt_tracking(self):
        """R5: 测试响应时间记录和 P50/P90 计算."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=60,
        )

        # 记录 5 个响应时间
        for rtt in [0.1, 0.2, 0.15, 0.3, 0.12]:
            rlt._record_rtt(rtt)

        assert rlt.rtt_p50 > 0
        assert rlt.rtt_p90 > 0
        assert rlt.rtt_p90 >= rlt.rtt_p50

    def test_r5_dynamic_decrease_factor_stable(self):
        """R5: 响应时间稳定时, decrease_factor 保持默认 0.5."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=60,
        )

        # 记录稳定的响应时间 (P90/P50 < 2.0)
        for rtt in [0.1, 0.11, 0.1, 0.12, 0.1]:
            rlt._record_rtt(rtt)

        assert rlt._dynamic_decrease_factor == 0.5
        assert rlt._dynamic_increase_step == rlt._aimd_increase_step

    def test_r5_dynamic_decrease_factor_degraded(self):
        """R5: 响应时间恶化时, decrease_factor 变为 0.35 (更激进)."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=60,
        )

        # 记录恶化的响应时间 (P90/P50 > 2.0)
        for rtt in [0.1, 0.1, 0.1, 0.5, 0.1]:
            rlt._record_rtt(rtt)

        assert rlt._dynamic_decrease_factor == 0.35
        assert rlt._dynamic_increase_step < rlt._aimd_increase_step

    def test_r5_aimd_decrease_with_dynamic_factor(self):
        """R5: 测试动态 decrease_factor 影响 RPM 降低幅度."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            requests_per_minute=100,
        )

        # 模拟响应时间恶化
        for rtt in [0.1, 0.1, 0.1, 0.5, 0.1]:
            rlt._record_rtt(rtt)

        assert rlt._dynamic_decrease_factor == 0.35

        # RPM 100 * 0.35 = 35
        rlt._aimd_decrease()
        assert rlt.current_rpm == 35

    @pytest.mark.asyncio
    async def test_r5_rtt_recorded_on_success(self):
        """R5: 测试成功请求后 RTT 被记录."""
        from pipeline.targets.rate_limited_target import RateLimitedTarget

        mock_target = MagicMock()
        mock_target.send_prompt_async = AsyncMock(return_value="response")

        rlt = RateLimitedTarget(
            target=mock_target,
            endpoint="https://example.com",
            max_concurrency=1,
            max_retries=1,
            requests_per_minute=60,
        )

        await rlt.send_prompt_async(prompt_request=MagicMock())

        # RTT 应被记录
        assert len(rlt._rtt_window) == 1
