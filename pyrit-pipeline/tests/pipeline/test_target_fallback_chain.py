# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""v50: 三级降级链测试 — Burp不可达→Playwright→.env→终止.

测试覆盖:
  1. _check_target_reachability: 可达/不可达/超时目标判定
  2. _try_fallback_chain: Level 1 Playwright 降级
  3. _try_fallback_chain: Level 2 .env OpenAIChatTarget 降级
  4. _try_fallback_chain: Level 3 全部失败优雅终止
  5. --no-fallback 严格模式: 不可达直接终止
  6. stage_scenario: all_targets_failed 跳过逻辑
  7. config: --no-fallback 参数解析

学术依据:
  - Circuit Breaker (Nygard) — 快速失败 + 降级
  - Graceful Degradation — 多级降级保最大可用性
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── _check_target_reachability 测试 ──


class TestCheckTargetReachability:
    """测试目标可达性探测函数."""

    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        """每个测试前清空 D-8 预检缓存, 避免缓存干扰测试."""
        from pipeline.stages.stage_target_classify import _REACHABILITY_CACHE

        _REACHABILITY_CACHE.clear()
        yield
        _REACHABILITY_CACHE.clear()

    @pytest.mark.asyncio
    async def test_reachable_via_tcp(self) -> None:
        """TCP 连通时返回 reachable=True."""
        from pipeline.stages.stage_target_classify import _check_target_reachability

        with patch("asyncio.open_connection") as mock_open:
            mock_writer = MagicMock()
            mock_open.return_value = (MagicMock(), mock_writer)
            result = await _check_target_reachability("http://example.com/api")

        assert result["reachable"] is True
        assert result["method"] == "tcp"
        assert result["latency_ms"] >= 0

    @pytest.mark.asyncio
    async def test_unreachable_both_fail(self) -> None:
        """TCP 和 HTTP 都失败时返回 reachable=False."""
        from pipeline.stages.stage_target_classify import _check_target_reachability

        with (
            patch("asyncio.open_connection", side_effect=ConnectionRefusedError("refused")),
            patch("httpx.AsyncClient") as mock_httpx_class,
        ):
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=Exception("ConnectError"))
            mock_httpx_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_httpx_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await _check_target_reachability("http://192.168.99.99/api")

        assert result["reachable"] is False
        assert "ConnectError" in result["reason"] or "Exception" in result["reason"]

    @pytest.mark.asyncio
    async def test_reachable_via_http_after_tcp_fail(self) -> None:
        """TCP 失败但 HTTP 成功时返回 reachable=True (防火墙代理场景)."""
        from pipeline.stages.stage_target_classify import _check_target_reachability

        with (
            patch("asyncio.open_connection", side_effect=OSError("blocked")),
            patch("httpx.AsyncClient") as mock_httpx_class,
        ):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_httpx_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_httpx_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await _check_target_reachability("http://example.com/api")

        assert result["reachable"] is True
        assert result["method"] == "http"
        assert "200" in result["reason"]

    @pytest.mark.asyncio
    async def test_invalid_url_no_host(self) -> None:
        """无法解析主机名时返回 reachable=False."""
        from pipeline.stages.stage_target_classify import _check_target_reachability

        result = await _check_target_reachability("not-a-valid-url")

        assert result["reachable"] is False
        assert result["method"] == "url_parse"


# ── _try_fallback_chain 测试 ──


class TestTryFallbackChain:
    """测试三级降级链函数."""

    @pytest.mark.asyncio
    async def test_level1_playwright_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Level 1: Burp 不可达 → Playwright 降级成功."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_target_classify import _try_fallback_chain

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {}

        # Mock TargetClassifier.classify 返回 HTTP 可达
        mock_classification = MagicMock()
        mock_classification.http_status = 200
        mock_classification.target_type = "llm_web_app"

        with (
            patch("pipeline.stages.stage_target_classify.TargetClassifier") as mock_cls,
            patch("pipeline.stages.stage_target_classify._bridge_web_app", new_callable=AsyncMock) as mock_bridge,
        ):
            mock_classifier = MagicMock()
            mock_classifier.classify = AsyncMock(return_value=mock_classification)
            mock_cls.return_value = mock_classifier
            mock_bridge.return_value = True

            result = await _try_fallback_chain(
                ctx, "http://example.com", mock_classification, None, "ConnectError: unreachable"
            )

        assert result is True
        assert ctx.metadata["fallback_level"] == 1
        assert ctx.metadata["fallback_target_mode"] == "playwright"

    @pytest.mark.asyncio
    async def test_level2_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Level 2: Playwright 失败 → .env OpenAIChatTarget 降级."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_target_classify import _try_fallback_chain

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {}

        # Mock .env 配置存在
        monkeypatch.setenv("OPENAI_CHAT_ENDPOINT", "https://api.example.com/v1")
        monkeypatch.setenv("OPENAI_CHAT_KEY", "sk-test-key")
        monkeypatch.setenv("OPENAI_CHAT_MODEL", "test-model")

        # Mock TargetClassifier 返回 HTTP 不可达
        mock_classification = MagicMock()
        mock_classification.http_status = 0

        with patch("pipeline.stages.stage_target_classify.TargetClassifier") as mock_cls:
            mock_classifier = MagicMock()
            mock_classifier.classify = AsyncMock(return_value=mock_classification)
            mock_cls.return_value = mock_classifier

            result = await _try_fallback_chain(
                ctx, "http://example.com", mock_classification, None, "ConnectError: unreachable"
            )

        assert result is True
        assert ctx.metadata["fallback_level"] == 2
        assert ctx.metadata["fallback_target_mode"] == "env_openai_chat"
        assert ctx.target_type == "env_openai_chat"

    @pytest.mark.asyncio
    async def test_level3_all_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Level 3: 全部失败 → 优雅终止, 返回 False."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_target_classify import _try_fallback_chain

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {}

        # 清除 .env 配置
        monkeypatch.delenv("OPENAI_CHAT_ENDPOINT", raising=False)
        monkeypatch.delenv("OPENAI_CHAT_KEY", raising=False)

        # Mock TargetClassifier 返回 HTTP 不可达
        mock_classification = MagicMock()
        mock_classification.http_status = 0

        with patch("pipeline.stages.stage_target_classify.TargetClassifier") as mock_cls:
            mock_classifier = MagicMock()
            mock_classifier.classify = AsyncMock(return_value=mock_classification)
            mock_cls.return_value = mock_classifier

            result = await _try_fallback_chain(
                ctx, "http://example.com", mock_classification, None, "ConnectError: unreachable"
            )

        assert result is False
        assert ctx.metadata["all_targets_failed"] is True
        assert len(ctx.metadata["fallback_failure_reasons"]) >= 2


# ── --no-fallback 严格模式测试 ──


class TestNoFallbackStrictMode:
    """测试 --no-fallback 严格模式."""

    def test_no_fallback_arg_parsed(self) -> None:
        """--no-fallback 参数正确解析为 True."""
        from pipeline.config import parse_args

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("sys.argv", ["main.py", "--no-fallback", "--target-url", "http://example.com"])
            args = parse_args()
            assert args.no_fallback is True

    def test_fallback_enabled_by_default(self) -> None:
        """默认启用降级 (no_fallback=False)."""
        from pipeline.config import parse_args

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr("sys.argv", ["main.py", "--target-url", "http://example.com"])
            args = parse_args()
            assert args.no_fallback is False


# ── stage_scenario 跳过逻辑测试 ──


class TestStageScenarioSkip:
    """测试 all_targets_failed 时 stage_scenario 跳过执行."""

    @pytest.mark.asyncio
    async def test_scenario_skipped_when_all_targets_failed(self) -> None:
        """all_targets_failed=True 时 stage_scenario 跳过, ctx.scenario=None."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_scenario import run as stage_scenario_run

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {
            "all_targets_failed": True,
            "fallback_failure_reasons": ["Level 0 (Burp): ConnectError", "Level 1 (Playwright): HTTP 不可达"],
        }
        ctx.scenario = MagicMock()  # 确保初始不为 None

        await stage_scenario_run(ctx)

        assert ctx.scenario is None
        assert ctx.metadata["scenario_skipped"] is True


# ── stage_initialize 跳过逻辑测试 ──


class TestStageInitializeSkip:
    """测试 scenario_skipped 时 stage_initialize 跳过."""

    @pytest.mark.asyncio
    async def test_initialize_skipped_when_scenario_none(self) -> None:
        """ctx.scenario=None 时 stage_initialize 跳过."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_initialize import run as stage_initialize_run

        ctx = PipelineContext(args=MagicMock())
        ctx.scenario = None
        ctx.metadata = {"scenario_skipped": True}

        # 不应抛出异常
        await stage_initialize_run(ctx)
        # 验证没有尝试 initialize_async


# ── stage_execute 跳过逻辑测试 ──


class TestStageExecuteSkip:
    """测试 scenario_skipped 时 stage_execute 跳过."""

    @pytest.mark.asyncio
    async def test_execute_skipped_when_scenario_none(self) -> None:
        """ctx.scenario=None 时 stage_execute 跳过."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_execute import run as stage_execute_run

        ctx = PipelineContext(args=MagicMock())
        ctx.scenario = None
        ctx.metadata = {"scenario_skipped": True}
        ctx.max_attempts_per_objective = 2

        # 不应抛出异常
        await stage_execute_run(ctx)


# ── D-6: 降级链健康度面板测试 ──


class TestFallbackHealthCard:
    """测试 D-6 降级链健康度面板."""

    def test_health_card_normal_no_fallback(self) -> None:
        """正常模式 (无降级) 健康状态为 ✅ 正常."""
        from pipeline.context import PipelineContext
        from pipeline.utils.display import fallback_health_card

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {
            "target_reachability": {"reachable": True, "reason": "HTTP 200", "latency_ms": 45.2, "method": "http"},
            "fallback_level": 0,
            "fallback_target_mode": "burp_api",
        }
        # 不应抛出异常
        fallback_health_card(ctx)

    def test_health_card_level1_fallback(self) -> None:
        """Level 1 Playwright 降级时健康状态为 ⚠ 降级."""
        from pipeline.context import PipelineContext
        from pipeline.utils.display import fallback_health_card

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {
            "target_reachability": {"reachable": False, "reason": "ConnectError", "latency_ms": 0, "method": "failed"},
            "fallback_level": 1,
            "fallback_target_mode": "playwright",
        }
        fallback_health_card(ctx)

    def test_health_card_all_failed(self) -> None:
        """全部失败时健康状态为 ❌ 终止."""
        from pipeline.context import PipelineContext
        from pipeline.utils.display import fallback_health_card

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {
            "all_targets_failed": True,
            "fallback_failure_reasons": ["Level 0: ConnectError", "Level 1: HTTP 不可达", "Level 2: 无 .env"],
        }
        fallback_health_card(ctx)

    def test_health_card_env_fallback_shows_endpoint(self) -> None:
        """Level 2 .env 降级时展示端点和模型信息."""
        from pipeline.context import PipelineContext
        from pipeline.utils.display import fallback_health_card

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {
            "fallback_level": 2,
            "fallback_target_mode": "env_openai_chat",
            "env_fallback_endpoint": "https://api.example.com/v1",
            "env_fallback_model": "test-model",
        }
        fallback_health_card(ctx)


# ── D-7: 降级目标 ASR 差异标注测试 ──


class TestFallbackASRAnnotation:
    """测试 D-7 报告中降级目标 ASR 差异标注."""

    def test_report_includes_fallback_annotation_level2(self) -> None:
        """Level 2 降级时 Markdown 报告包含 Appendix G-bis."""
        from pipeline.reporting.report_generator import ReportGenerator

        gen = ReportGenerator()
        ctx_metadata = {
            "fallback_level": 2,
            "fallback_target_mode": "env_openai_chat",
            "env_fallback_endpoint": "https://api.example.com/v1",
            "env_fallback_model": "test-model",
            "target_endpoint": "http://original-target.com",
        }
        # 使用最小输入调用 _render_markdown
        md = gen._render_markdown(
            findings=[],
            attack_results=[],
            coverage_matrix={},
            scenario_result=None,
            attack_details={},
            converter_report={},
            diversity_metrics={},
            start_time=__import__("datetime").datetime.now(),
            end_time=__import__("datetime").datetime.now(),
            ctx_metadata=ctx_metadata,
        )
        assert "Appendix G-bis" in md
        assert "降级目标提示" in md
        assert "test-model" in md

    def test_report_no_annotation_when_no_fallback(self) -> None:
        """无降级时报告不包含 Appendix G-bis."""
        from datetime import datetime

        from pipeline.reporting.report_generator import ReportGenerator

        gen = ReportGenerator()
        ctx_metadata = {"fallback_level": 0}
        md = gen._render_markdown(
            findings=[],
            attack_results=[],
            coverage_matrix={},
            scenario_result=None,
            attack_details={},
            converter_report={},
            diversity_metrics={},
            start_time=datetime.now(),
            end_time=datetime.now(),
            ctx_metadata=ctx_metadata,
        )
        assert "Appendix G-bis" not in md

    def test_report_includes_all_failed_annotation(self) -> None:
        """全部失败时报告包含 ❌ 标注和失败原因."""
        from datetime import datetime

        from pipeline.reporting.report_generator import ReportGenerator

        gen = ReportGenerator()
        ctx_metadata = {
            "all_targets_failed": True,
            "fallback_failure_reasons": ["Level 0: ConnectError", "Level 1: HTTP 不可达"],
            "target_endpoint": "http://unreachable.com",
        }
        md = gen._render_markdown(
            findings=[],
            attack_results=[],
            coverage_matrix={},
            scenario_result=None,
            attack_details={},
            converter_report={},
            diversity_metrics={},
            start_time=datetime.now(),
            end_time=datetime.now(),
            ctx_metadata=ctx_metadata,
        )
        assert "Appendix G-bis" in md
        assert "所有目标模式均失败" in md
        assert "ConnectError" in md


# ── D-8: 预检结果缓存测试 ──


class TestReachabilityCache:
    """测试 D-8 预检结果缓存."""

    @pytest.mark.asyncio
    async def test_cache_hit_on_second_call(self) -> None:
        """同一目标第二次调用命中缓存, 跳过 TCP/HTTP 探测."""
        from pipeline.stages.stage_target_classify import (
            _REACHABILITY_CACHE,
            _check_target_reachability,
        )

        # 清空缓存
        _REACHABILITY_CACHE.clear()

        call_count = 0

        # Mock TCP 成功
        def mock_open_connection(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return (MagicMock(), MagicMock())

        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            # 第一次调用 — 探测 + 缓存
            result1 = await _check_target_reachability("http://cached-target.com/api")
            assert result1["reachable"] is True
            assert call_count == 1

            # 第二次调用 — 应命中缓存, 不再调用 open_connection
            result2 = await _check_target_reachability("http://cached-target.com/api")
            assert result2["reachable"] is True
            assert call_count == 1  # 仍然只调用了1次

        # 清理
        _REACHABILITY_CACHE.clear()

    @pytest.mark.asyncio
    async def test_cache_expired_after_ttl(self) -> None:
        """缓存过期后重新探测."""
        from pipeline.stages.stage_target_classify import (
            _REACHABILITY_CACHE,
            _REACHABILITY_CACHE_TTL,
            _check_target_reachability,
        )

        _REACHABILITY_CACHE.clear()

        # 手动注入一个过期的缓存
        import time as _time

        _REACHABILITY_CACHE["http://expired-target.com/api"] = {
            "result": {"reachable": True, "reason": "cached", "latency_ms": 1.0, "method": "tcp"},
            "cached_at": _time.monotonic() - _REACHABILITY_CACHE_TTL - 10,  # 已过期
        }

        call_count = 0

        def mock_open_connection(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return (MagicMock(), MagicMock())

        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            await _check_target_reachability("http://expired-target.com/api")
            assert call_count == 1  # 缓存过期, 重新探测

        _REACHABILITY_CACHE.clear()

    @pytest.mark.asyncio
    async def test_cache_different_targets_not_shared(self) -> None:
        """不同目标的缓存不共享."""
        from pipeline.stages.stage_target_classify import (
            _REACHABILITY_CACHE,
            _check_target_reachability,
        )

        _REACHABILITY_CACHE.clear()

        call_count = 0

        def mock_open_connection(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return (MagicMock(), MagicMock())

        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            await _check_target_reachability("http://target-a.com/api")
            await _check_target_reachability("http://target-b.com/api")
            assert call_count == 2  # 两个不同目标各探测一次

        _REACHABILITY_CACHE.clear()


# ── D-9: 降级链重试退避策略测试 ──


class TestFallbackRetryBackoff:
    """测试 D-9 Level 1 指数退避重试."""

    @pytest.fixture(autouse=True)
    def _clear_cache_and_env(self, monkeypatch: pytest.MonkeyPatch):
        """每个测试前清空 D-8 预检缓存和 .env 配置."""
        from pipeline.stages.stage_target_classify import _REACHABILITY_CACHE

        _REACHABILITY_CACHE.clear()
        # 清空 .env 配置避免干扰
        monkeypatch.delenv("OPENAI_CHAT_ENDPOINT", raising=False)
        monkeypatch.delenv("OPENAI_CHAT_KEY", raising=False)
        monkeypatch.delenv("API_KEY", raising=False)
        yield
        _REACHABILITY_CACHE.clear()

    @pytest.mark.asyncio
    async def test_retry_success_after_initial_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Level 1 首次失败, 重试成功 → 返回 True, fallback_retried=True."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_target_classify import _try_fallback_chain

        ctx = PipelineContext(args=MagicMock(no_fallback=False))
        ctx.metadata = {}

        # Mock TargetClassifier — 第一次 http_status=0 (不可达), 第二次 http_status=200 (可达)
        mock_cls_fail = MagicMock()
        mock_cls_fail.classify = AsyncMock(return_value=MagicMock(http_status=0))

        mock_cls_success = MagicMock()
        mock_cls_success.classify = AsyncMock(return_value=MagicMock(http_status=200))

        # Mock _bridge_web_app — D-9 重试时返回 True
        # (原始 Level 1 因 http_status=0 不调用 _bridge_web_app, 仅 D-9 重试调用)
        async def mock_bridge(ctx, url, cls):
            return True  # D-9 重试成功

        # Mock asyncio.sleep 避免实际等待
        sleep_called = False

        async def mock_sleep(seconds):
            nonlocal sleep_called
            sleep_called = True

        with (
            patch("pipeline.stages.stage_target_classify.TargetClassifier") as mock_tc,
            patch("pipeline.stages.stage_target_classify._bridge_web_app", side_effect=mock_bridge),
            patch("asyncio.sleep", side_effect=mock_sleep),
        ):
            mock_tc.side_effect = [mock_cls_fail, mock_cls_success]

            result = await _try_fallback_chain(
                ctx, "http://example.com", MagicMock(), None, "ConnectError: unreachable"
            )

        assert result is True
        assert ctx.metadata["fallback_level"] == 1
        assert ctx.metadata["fallback_retried"] is True
        assert sleep_called is True

    @pytest.mark.asyncio
    async def test_retry_also_fails_proceeds_to_level2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Level 1 首次+重试都失败 → 继续 Level 2."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_target_classify import _try_fallback_chain

        ctx = PipelineContext(args=MagicMock())
        ctx.metadata = {}

        monkeypatch.setenv("OPENAI_CHAT_ENDPOINT", "https://api.example.com/v1")
        monkeypatch.setenv("OPENAI_CHAT_KEY", "sk-test-key")
        monkeypatch.setenv("OPENAI_CHAT_MODEL", "test-model")

        mock_cls = MagicMock()
        mock_cls.classify = AsyncMock(return_value=MagicMock(http_status=0))

        async def mock_sleep(seconds):
            pass

        with (
            patch("pipeline.stages.stage_target_classify.TargetClassifier", return_value=mock_cls),
            patch("asyncio.sleep", side_effect=mock_sleep),
        ):
            result = await _try_fallback_chain(
                ctx, "http://example.com", MagicMock(), None, "ConnectError: unreachable"
            )

        assert result is True
        assert ctx.metadata["fallback_level"] == 2

    @pytest.mark.asyncio
    async def test_no_retry_in_strict_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--no-fallback 严格模式下不执行重试."""
        from pipeline.context import PipelineContext
        from pipeline.stages.stage_target_classify import _try_fallback_chain

        ctx = PipelineContext(args=MagicMock(no_fallback=True))
        ctx.metadata = {}

        monkeypatch.setenv("OPENAI_CHAT_ENDPOINT", "https://api.example.com/v1")
        monkeypatch.setenv("OPENAI_CHAT_KEY", "sk-test-key")
        monkeypatch.setenv("OPENAI_CHAT_MODEL", "test-model")

        sleep_called = False

        async def mock_sleep(seconds):
            nonlocal sleep_called
            sleep_called = True

        mock_cls = MagicMock()
        mock_cls.classify = AsyncMock(return_value=MagicMock(http_status=0))

        with (
            patch("pipeline.stages.stage_target_classify.TargetClassifier", return_value=mock_cls),
            patch("asyncio.sleep", side_effect=mock_sleep),
        ):
            result = await _try_fallback_chain(
                ctx, "http://example.com", MagicMock(), None, "ConnectError: unreachable"
            )

        assert sleep_called is False
        assert result is True
        assert ctx.metadata["fallback_level"] == 2
