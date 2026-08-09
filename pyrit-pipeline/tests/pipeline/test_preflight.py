# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_preflight — P0 预检功能单元测试.

覆盖:
  - _classify_preflight_error: 错误分类 + 修复建议
  - _probe_chat_target: 模型探针 (成功/超时/认证失败/空响应)
  - _probe_target_url: URL 可达性 (成功/HTTP错误/DNS失败/超时)
  - _preflight_check: 集成测试 (全部通过/部分失败/无目标/跳过)

> **日期**: 2026-8-4
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pipeline.context import PipelineContext

# ============================================================
# _classify_preflight_error 单元测试
# ============================================================


class TestClassifyPreflightError:
    """_classify_preflight_error 错误分类测试."""

    def test_auth_error_401(self) -> None:
        """401 错误分类为认证失败."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(Exception("HTTP 401 Unauthorized"))
        assert "认证失败" in result
        assert "API_KEY" in result

    def test_auth_error_403(self) -> None:
        """403 错误分类为认证失败."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(Exception("403 Forbidden"))
        assert "认证失败" in result

    def test_model_not_found_404(self) -> None:
        """404 错误分类为模型不存在."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(Exception("404 model_not_found"))
        assert "模型不存在" in result
        assert "MODEL" in result

    def test_rate_limit_429(self) -> None:
        """429 错误分类为限速."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(Exception("429 rate limit exceeded"))
        assert "限速" in result

    def test_timeout_error(self) -> None:
        """超时错误分类正确."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(Exception("Connection timed out"))
        assert "超时" in result
        assert "ENDPOINT" in result

    def test_connection_refused(self) -> None:
        """连接拒绝错误分类正确."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(Exception("Connection refused"))
        assert "网络不可达" in result

    def test_ssl_error(self) -> None:
        """SSL 错误分类正确."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(Exception("SSL certificate verification failed"))
        assert "SSL" in result

    def test_unknown_error(self) -> None:
        """未知错误保留原始信息."""
        from pipeline.stages.stage_init import _classify_preflight_error

        result = _classify_preflight_error(RuntimeError("something weird"))
        assert "未知错误" in result
        assert "something weird" in result


# ============================================================
# _probe_chat_target 单元测试
# ============================================================


class TestProbeChatTarget:
    """_probe_chat_target 模型探针测试."""

    @pytest.mark.asyncio
    async def test_successful_probe(self) -> None:
        """成功响应返回 success=True."""
        from pipeline.stages.stage_init import _probe_chat_target

        mock_target = MagicMock()
        mock_response = MagicMock()
        mock_target.send_prompt_async = AsyncMock(return_value=mock_response)

        name, success, detail = await _probe_chat_target(mock_target, "openai_chat")

        assert name == "openai_chat"
        assert success is True
        assert detail == "OK"

    @pytest.mark.asyncio
    async def test_empty_response(self) -> None:
        """空响应返回 success=False."""
        from pipeline.stages.stage_init import _probe_chat_target

        mock_target = MagicMock()
        mock_target.send_prompt_async = AsyncMock(return_value=None)

        name, success, detail = await _probe_chat_target(mock_target, "openai_chat")

        assert name == "openai_chat"
        assert success is False
        assert "空响应" in detail

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        """超时返回 success=False."""
        from pipeline.stages.stage_init import _PREFLIGHT_TIMEOUT, _probe_chat_target

        mock_target = MagicMock()

        async def slow_response(*args, **kwargs):
            await asyncio.sleep(100)

        mock_target.send_prompt_async = slow_response

        name, success, detail = await _probe_chat_target(mock_target, "slow_target")

        assert name == "slow_target"
        assert success is False
        assert "超时" in detail
        assert str(int(_PREFLIGHT_TIMEOUT)) in detail

    @pytest.mark.asyncio
    async def test_auth_error(self) -> None:
        """401 认证错误返回 success=False + 修复建议."""
        from pipeline.stages.stage_init import _probe_chat_target

        mock_target = MagicMock()
        mock_target.send_prompt_async = AsyncMock(
            side_effect=Exception("HTTP 401 Unauthorized")
        )

        name, success, detail = await _probe_chat_target(mock_target, "bad_key_target")

        assert name == "bad_key_target"
        assert success is False
        assert "认证失败" in detail
        assert "API_KEY" in detail

    @pytest.mark.asyncio
    async def test_generic_exception(self) -> None:
        """通用异常被捕获并分类."""
        from pipeline.stages.stage_init import _probe_chat_target

        mock_target = MagicMock()
        mock_target.send_prompt_async = AsyncMock(
            side_effect=RuntimeError("unexpected error XYZ")
        )

        name, success, detail = await _probe_chat_target(mock_target, "weird_target")

        assert name == "weird_target"
        assert success is False
        assert "unexpected error XYZ" in detail


# ============================================================
# _probe_target_url 单元测试
# ============================================================


class TestProbeTargetUrl:
    """_probe_target_url URL 可达性测试."""

    @pytest.mark.asyncio
    async def test_successful_url(self) -> None:
        """可达 URL 返回 success=True."""
        from pipeline.stages.stage_init import _probe_target_url

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MagicMock(status=200)

            url, success, detail = await _probe_target_url("https://example.com/chat")

            assert url == "https://example.com/chat"
            assert success is True
            assert detail == "OK"

    @pytest.mark.asyncio
    async def test_http_405_reachable(self) -> None:
        """HTTP 405 (Method Not Allowed) 仍表示端点可达."""
        import urllib.error

        from pipeline.stages.stage_init import _probe_target_url

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="https://example.com",
                code=405,
                msg="Method Not Allowed",
                hdrs=None,
                fp=None,
            )

            url, success, detail = await _probe_target_url("https://example.com/chat")

            assert success is True
            assert "端点可达" in detail

    @pytest.mark.asyncio
    async def test_http_500_error(self) -> None:
        """HTTP 500 表示服务器错误, 不可达."""
        import urllib.error

        from pipeline.stages.stage_init import _probe_target_url

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="https://example.com",
                code=500,
                msg="Internal Server Error",
                hdrs=None,
                fp=None,
            )

            url, success, detail = await _probe_target_url("https://broken.example.com")

            assert success is False
            assert "500" in detail

    @pytest.mark.asyncio
    async def test_dns_failure(self) -> None:
        """DNS 解析失败返回 success=False."""
        import urllib.error

        from pipeline.stages.stage_init import _probe_target_url

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(
                reason=Exception("Name or service not known")
            )

            url, success, detail = await _probe_target_url("https://nonexistent.invalid")

            assert success is False
            assert "DNS" in detail

    @pytest.mark.asyncio
    async def test_connection_refused(self) -> None:
        """连接被拒绝返回 success=False."""
        import urllib.error

        from pipeline.stages.stage_init import _probe_target_url

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(
                reason=ConnectionRefusedError("Connection refused")
            )

            url, success, detail = await _probe_target_url("https://localhost:9999")

            assert success is False
            assert "连接被拒绝" in detail


# ============================================================
# _preflight_check 集成测试
# ============================================================


class TestPreflightCheck:
    """_preflight_check 集成测试."""

    def _make_mock_target(
        self, name: str = "openai_chat", success: bool = True
    ) -> tuple[MagicMock, MagicMock]:
        """创建 mock target + entry, 可复用."""
        mock_target = MagicMock()
        if success:
            mock_target.send_prompt_async = AsyncMock(return_value=MagicMock())
        else:
            mock_target.send_prompt_async = AsyncMock(
                side_effect=Exception("HTTP 401 Unauthorized")
            )
        mock_entry = MagicMock()
        mock_entry.instance = mock_target
        mock_entry.name = name
        return mock_target, mock_entry

    def _make_tag_side_effect(
        self, target_entry: MagicMock | None = None, adversarial_entry: MagicMock | None = None
    ) -> MagicMock:
        """创建 get_by_tag 的 side_effect, 按 tag 返回不同结果."""

        def _get_by_tag(tag: str = "", **kwargs):
            if tag in ("default_objective_target", "default"):
                return [target_entry] if target_entry else []
            if tag == "adversarial_chat":
                return [adversarial_entry] if adversarial_entry else []
            return []

        return MagicMock(side_effect=_get_by_tag)

    @pytest.mark.asyncio
    async def test_all_targets_pass(self, mock_args: pytest.fixture) -> None:
        """所有模型通过预检 → 不抛异常."""
        from pipeline.stages.stage_init import _preflight_check

        ctx = PipelineContext(args=mock_args)
        ctx.args.target_url = None
        ctx.args.skip_preflight = False
        ctx.args.run_preflight = True

        _, mock_entry = self._make_mock_target("openai_chat", success=True)

        mock_registry = MagicMock()
        mock_registry.instances.get_by_tag = self._make_tag_side_effect(
            target_entry=mock_entry, adversarial_entry=mock_entry
        )

        mock_scorer_registry = MagicMock()
        mock_scorer_registry.instances.get_by_tag = MagicMock(return_value=[])

        with (
            patch("pipeline.stages.stage_init.TargetRegistry") as mock_tr,
            patch("pipeline.stages.stage_init.ScorerRegistry") as mock_sr,
        ):
            mock_tr.get_registry_singleton.return_value = mock_registry
            mock_sr.get_registry_singleton.return_value = mock_scorer_registry

            await _preflight_check(ctx)  # 不抛异常即通过

    @pytest.mark.asyncio
    async def test_target_failure_raises_system_exit(
        self, mock_args: pytest.fixture
    ) -> None:
        """模型探针失败 → SystemExit(1)."""
        from pipeline.stages.stage_init import _preflight_check

        ctx = PipelineContext(args=mock_args)
        ctx.args.target_url = None
        ctx.args.skip_preflight = False
        ctx.args.run_preflight = True

        _, mock_entry = self._make_mock_target("bad_key_target", success=False)

        mock_registry = MagicMock()
        mock_registry.instances.get_by_tag = self._make_tag_side_effect(
            target_entry=mock_entry
        )

        mock_scorer_registry = MagicMock()
        mock_scorer_registry.instances.get_by_tag = MagicMock(return_value=[])

        with (
            patch("pipeline.stages.stage_init.TargetRegistry") as mock_tr,
            patch("pipeline.stages.stage_init.ScorerRegistry") as mock_sr,
        ):
            mock_tr.get_registry_singleton.return_value = mock_registry
            mock_sr.get_registry_singleton.return_value = mock_scorer_registry

            with pytest.raises(SystemExit, match="1"):
                await _preflight_check(ctx)

    @pytest.mark.asyncio
    async def test_no_targets_skips(self, mock_args: pytest.fixture) -> None:
        """无注册目标时跳过预检 (不抛异常)."""
        from pipeline.stages.stage_init import _preflight_check

        ctx = PipelineContext(args=mock_args)
        ctx.args.target_url = None

        mock_registry = MagicMock()
        mock_registry.instances.get_by_tag = self._make_tag_side_effect()

        mock_scorer_registry = MagicMock()
        mock_scorer_registry.instances.get_by_tag = MagicMock(return_value=[])

        with (
            patch("pipeline.stages.stage_init.TargetRegistry") as mock_tr,
            patch("pipeline.stages.stage_init.ScorerRegistry") as mock_sr,
        ):
            mock_tr.get_registry_singleton.return_value = mock_registry
            mock_sr.get_registry_singleton.return_value = mock_scorer_registry

            await _preflight_check(ctx)  # 不抛异常即通过

    @pytest.mark.asyncio
    async def test_url_probe_alongside_targets(
        self, mock_args: pytest.fixture
    ) -> None:
        """同时测试模型和 URL."""
        from pipeline.stages.stage_init import _preflight_check

        ctx = PipelineContext(args=mock_args)
        ctx.args.target_url = "https://example.com/chat"
        ctx.args.skip_preflight = False
        ctx.args.run_preflight = True

        _, mock_entry = self._make_mock_target("openai_chat", success=True)

        mock_registry = MagicMock()
        mock_registry.instances.get_by_tag = self._make_tag_side_effect(
            target_entry=mock_entry
        )

        mock_scorer_registry = MagicMock()
        mock_scorer_registry.instances.get_by_tag = MagicMock(return_value=[])

        with (
            patch("pipeline.stages.stage_init.TargetRegistry") as mock_tr,
            patch("pipeline.stages.stage_init.ScorerRegistry") as mock_sr,
            patch("urllib.request.urlopen") as mock_urlopen,
        ):
            mock_tr.get_registry_singleton.return_value = mock_registry
            mock_sr.get_registry_singleton.return_value = mock_scorer_registry
            mock_urlopen.return_value = MagicMock(status=200)

            await _preflight_check(ctx)  # 不抛异常即通过

    @pytest.mark.asyncio
    async def test_url_failure_raises_system_exit(
        self, mock_args: pytest.fixture
    ) -> None:
        """URL 不可达 → SystemExit(1)."""
        import urllib.error

        from pipeline.stages.stage_init import _preflight_check

        ctx = PipelineContext(args=mock_args)
        ctx.args.target_url = "https://broken.invalid"
        ctx.args.skip_preflight = False
        ctx.args.run_preflight = True

        _, mock_entry = self._make_mock_target("openai_chat", success=True)

        mock_registry = MagicMock()
        mock_registry.instances.get_by_tag = self._make_tag_side_effect(
            target_entry=mock_entry
        )

        mock_scorer_registry = MagicMock()
        mock_scorer_registry.instances.get_by_tag = MagicMock(return_value=[])

        with (
            patch("pipeline.stages.stage_init.TargetRegistry") as mock_tr,
            patch("pipeline.stages.stage_init.ScorerRegistry") as mock_sr,
            patch("urllib.request.urlopen") as mock_urlopen,
        ):
            mock_tr.get_registry_singleton.return_value = mock_registry
            mock_sr.get_registry_singleton.return_value = mock_scorer_registry
            mock_urlopen.side_effect = urllib.error.URLError(
                reason=Exception("Name or service not known")
            )

            with pytest.raises(SystemExit, match="1"):
                await _preflight_check(ctx)
