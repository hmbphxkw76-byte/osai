"""REQ-161 接线回归测试（recon-deep 波次）。

覆盖三类问题：
1. `_ProbeCounter` 的**深度探测独立预算**（消费此前从未被消费的 `deep_probe_budget`）；
2. `_init_adaptive_probe` 的预算**静默覆盖**缺陷回归（日志行曾访问不存在的
   `behavioral_verify_budget` → KeyError → 已算出的预算被降级字典覆盖）；
3. GraphQL / 主动限流 / MCP 本地侦察三条探测链路的**真实接线**（结果入
   `target_fingerprint.extra`，不新建并行通道）。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from recon._target_router_helpers import (
    _MAX_PROBE_COUNT,
    _probe_mcp_locally,
    _ProbeCounter,
    _run_background_probes,
)
from recon.burp_parser import TargetFingerprint


class TestProbeCounterDeepBudget:
    def test_deep_budget_is_independent(self) -> None:
        counter = _ProbeCounter()
        counter._deep_max = 3
        counter.add(9)  # 总预算已近上限
        assert counter.can_deep_probe(2) is True  # 深度预算不受总预算影响
        counter.add_deep(2)
        assert counter.can_deep_probe(2) is False
        assert counter.can_deep_probe(1) is True

    def test_falls_back_to_max_when_unset(self) -> None:
        counter = _ProbeCounter()
        assert counter.can_deep_probe(_MAX_PROBE_COUNT) is True
        assert counter.can_deep_probe(_MAX_PROBE_COUNT + 1) is False

    def test_total_budget_unchanged_by_deep(self) -> None:
        counter = _ProbeCounter()
        counter._adaptive_max = 5
        counter.add_deep(100)
        assert counter.can_probe(5) is True


def _make_parsed(*, caps: str = "mcp", path: str = "/api/chat") -> SimpleNamespace:
    fp = TargetFingerprint()
    fp.extra["capabilities"] = caps
    return SimpleNamespace(
        use_tls=False,
        host="t.example.com",
        path=path,
        method="POST",
        body="",
        raw_headers=[("Content-Type", "application/json")],
        target_fingerprint=fp,
    )


def _make_ctx(target_url: str | None = "http://t.example.com/api/chat") -> SimpleNamespace:
    return SimpleNamespace(
        args=SimpleNamespace(target_url=target_url),
        service_profile={},
        orchestration_log=[],
        stealth_policy={"name": "balanced"},
    )


def _run_deep(parsed: SimpleNamespace, ctx: SimpleNamespace, **patches: object) -> _ProbeCounter:
    """Run `_run_background_probes(deep_probe=True)` with all network calls patched."""
    counter = _ProbeCounter()
    base_patches = {
        "recon._target_router_helpers.probe_active_capabilities": AsyncMock(return_value={}),
        "recon.model.system_prompt_extract.extract_system_prompt": AsyncMock(return_value={}),
        "recon.capability_probe.deep_probe_capabilities": AsyncMock(return_value={}),
        "recon.api.openapi_discoverer.discover_openapi_spec": AsyncMock(return_value=None),
    }
    base_patches.update(patches)
    entered = []
    try:
        for target, value in base_patches.items():
            patcher = patch(target, value)
            patcher.start()
            entered.append(patcher)
        asyncio.run(_run_background_probes(parsed, counter, ctx, deep_probe=True))
    finally:
        for patcher in entered:
            patcher.stop()
    return counter


class TestGraphQLWiring:
    def test_extra_written_when_detected(self) -> None:
        from recon.graphql_probe import GraphQLSchemaSummary

        summary = GraphQLSchemaSummary(
            detected=True,
            endpoint="http://t.example.com/graphql",
            introspection_enabled=True,
            types=["Query", "User"],
            queries=["user"],
        )
        parsed = _make_parsed()
        ctx = _make_ctx()
        _run_deep(parsed, ctx, **{"recon.graphql_probe.probe_graphql_endpoint": AsyncMock(return_value=summary)})
        graphql = parsed.target_fingerprint.extra.get("graphql")
        assert graphql is not None, "GraphQL 探测未接线（未写入 target_fingerprint.extra）"
        assert graphql["detected"] is True
        assert graphql["introspection_enabled"] is True
        assert "Query" in graphql["types"]

    def test_passive_signal_writes_extra_without_detection(self) -> None:
        from recon.graphql_probe import GraphQLSchemaSummary

        parsed = _make_parsed(path="/graphql")
        ctx = _make_ctx()
        _run_deep(
            parsed,
            ctx,
            **{"recon.graphql_probe.probe_graphql_endpoint": AsyncMock(return_value=GraphQLSchemaSummary())},
        )
        graphql = parsed.target_fingerprint.extra.get("graphql")
        assert graphql is not None
        assert graphql["passive_signal"] is True
        assert graphql["detected"] is False

    def test_absent_when_no_signal(self) -> None:
        from recon.graphql_probe import GraphQLSchemaSummary

        parsed = _make_parsed(path="/api/chat")
        ctx = _make_ctx()
        _run_deep(
            parsed,
            ctx,
            **{"recon.graphql_probe.probe_graphql_endpoint": AsyncMock(return_value=GraphQLSchemaSummary())},
        )
        assert "graphql" not in parsed.target_fingerprint.extra

    def test_failure_is_non_fatal(self) -> None:
        parsed = _make_parsed()
        ctx = _make_ctx()
        _run_deep(parsed, ctx, **{"recon.graphql_probe.probe_graphql_endpoint": AsyncMock(side_effect=RuntimeError("boom"))})
        assert any("graphql" in str(entry.get("decision", "")) for entry in ctx.orchestration_log)


class TestRateLimitWiring:
    def test_extra_written(self) -> None:
        from recon.waf_detector import RateLimitInfo

        info = RateLimitInfo(limited=True, limit=60, remaining=0, reset_seconds=12.0)
        parsed = _make_parsed()
        ctx = _make_ctx()
        _run_deep(parsed, ctx, **{"recon.waf_detector.probe_rate_limit": AsyncMock(return_value=info)})
        active = parsed.target_fingerprint.extra.get("rate_limit_active")
        assert active is not None, "主动限流探测未接线"
        assert active["limited"] is True
        assert active["limit"] == 60

    def test_failure_is_non_fatal(self) -> None:
        parsed = _make_parsed()
        ctx = _make_ctx()
        _run_deep(parsed, ctx, **{"recon.waf_detector.probe_rate_limit": AsyncMock(side_effect=RuntimeError("boom"))})
        assert "rate_limit_active" not in parsed.target_fingerprint.extra


class TestMcpLocalFallback:
    def test_fallback_runs_when_bridge_unavailable(self) -> None:
        from recon.mcp.capability_probe import MCPCapabilityInfo
        from recon.mcp.surface_scanner import SurfaceScanResult
        from recon.mcp.version_fingerprint import VersionFingerprintResult

        parsed = _make_parsed(caps="mcp")
        ctx = _make_ctx()
        bridge = SimpleNamespace(is_available=False)
        _run_deep(
            parsed,
            ctx,
            **{
                "strike.mcp.orchestrator.get_shared_bridge": lambda: bridge,
                "recon.mcp.capability_probe.probe_mcp_capabilities": AsyncMock(
                    return_value=MCPCapabilityInfo(server_name="mock-mcp", protocol_version="2024-11-05")
                ),
                "recon.mcp.surface_scanner.scan_mcp_security_surface": AsyncMock(
                    return_value=SurfaceScanResult(auth_required=True, tls_enabled=True, rate_limiting=True)
                ),
                "recon.mcp.version_fingerprint.fingerprint_mcp_version": AsyncMock(
                    return_value=VersionFingerprintResult()
                ),
            },
        )
        extra = parsed.target_fingerprint.extra
        assert "mcp_capabilities" in extra, "MCPSec 不可用时未回退到本地 recon.mcp.*（BL-029）"
        assert "mcp_surface" in extra
        assert extra["mcp_capabilities"]["server_name"] == "mock-mcp"
        assert ctx.service_profile.get("mcpsec_enumerated") is True
        assert set(ctx.service_profile.get("mcp_local_recon", [])) >= {"capabilities", "surface"}

    def test_no_mcp_capability_skips_local(self) -> None:
        parsed = _make_parsed(caps="rag")
        ctx = _make_ctx()
        _run_deep(parsed, ctx)
        assert "mcp_capabilities" not in parsed.target_fingerprint.extra

    def test_sub_probe_failure_isolated(self) -> None:
        from recon.mcp.capability_probe import MCPCapabilityInfo

        parsed = _make_parsed(caps="mcp")
        counter = _ProbeCounter()
        with (
            patch("recon.mcp.capability_probe.probe_mcp_capabilities", AsyncMock(return_value=MCPCapabilityInfo(server_name="ok"))),
            patch("recon.mcp.surface_scanner.scan_mcp_security_surface", AsyncMock(side_effect=RuntimeError("boom"))),
            patch("recon.mcp.version_fingerprint.fingerprint_mcp_version", AsyncMock(side_effect=RuntimeError("boom"))),
        ):
            result = asyncio.run(_probe_mcp_locally(parsed, counter, "http://t.example.com/mcp"))
        assert "capabilities" in result
        assert "surface" not in result
        # 本地 MCP 侦察属浅层探测序列，计入**总预算**（非 deep 预算）
        assert counter.value == 3 and counter.deep_value == 0


class TestAdaptiveBudgetNotClobbered:
    """回归：预算计算成功时不得被 except 分支的降级字典覆盖（原 KeyError 静默缺陷）。"""

    def _run_init(self, parsed: SimpleNamespace, ctx: SimpleNamespace) -> tuple[_ProbeCounter, dict]:
        from recon._target_router_helpers import _init_adaptive_probe

        guardrail = SimpleNamespace(
            guardrail_type="none",
            severity="none",
            stealth_level="balanced",
            to_dict=lambda: {"has_guardrail": False, "severity": "none", "stealth_level": "balanced"},
        )
        policy = SimpleNamespace(name="balanced", delay_range=(0.5, 1.5), allowed_converters=[], behavioral_verify=False)
        stealth_mgr = SimpleNamespace(get_policy=lambda _level: policy)
        counter = _ProbeCounter()
        with (
            patch("recon._target_router_helpers.detect_guardrail", AsyncMock(return_value=guardrail)),
            patch("recon._target_router_helpers.get_stealth_manager", lambda: stealth_mgr),
        ):
            probe_ctx = asyncio.run(_init_adaptive_probe(ctx, parsed, counter))
        return counter, probe_ctx

    def test_budget_preserved_and_deep_max_set(self) -> None:
        parsed = _make_parsed(caps="mcp")
        ctx = _make_ctx()
        counter, probe_ctx = self._run_init(parsed, ctx)
        budget = probe_ctx["probe_budget"]
        assert "deep_probe_budget" in budget, "预算被降级字典覆盖（KeyError 静默缺陷回归）"
        assert counter._adaptive_max == budget["budget"]
        assert counter._deep_max == budget["deep_probe_budget"]

    def test_reasoning_present(self) -> None:
        parsed = _make_parsed(caps="mcp")
        ctx = _make_ctx()
        _, probe_ctx = self._run_init(parsed, ctx)
        assert "reasoning" in probe_ctx["probe_budget"]


def test_no_behavioral_verify_budget_key_in_config() -> None:
    """记录事实：`compute_probe_budget` 不返回 `behavioral_verify_budget`。

    该键曾被日志行访问并触发 KeyError（静默覆盖预算）。若未来新增该键，
    本测试会失败并提醒同步更新消费方。
    """
    from recon.api.adaptive_config import compute_probe_budget

    budget = compute_probe_budget(capabilities={"a": True}, app_type="mcp")
    assert "behavioral_verify_budget" not in budget
    assert {"budget", "parallel", "deep_probe_budget", "complexity_level"} <= set(budget)


@pytest.mark.parametrize("app_type", ["chat", "mcp", "rag", "multi_agent"])
def test_deep_budget_positive_for_rich_targets(app_type: str) -> None:
    from recon.api.adaptive_config import compute_probe_budget

    budget = compute_probe_budget(capabilities={f"c{i}": True for i in range(6)}, app_type=app_type)
    assert budget["deep_probe_budget"] >= 0
    assert budget["deep_probe_budget"] <= budget["budget"]


class _FakeFingerprint:
    def __init__(self) -> None:
        self.extra: dict = {}
        self.content_type = ""
        self.model_family = ""
        self.system_prompt_leaked = False
        self.extracted_system_prompt = ""
        self.system_prompt_extraction_method = ""
        self.mcp_tools: list = []
        self.mcp_resources: list = []
        self.mcp_prompts: list = []
        self.session_type = ""
        self.openapi_spec_path = None
        self.openapi_endpoints: list = []


class _FakeParsed:
    def __init__(self) -> None:
        self.use_tls = False
        self.host = "x"
        self.path = "/"
        self.body = ""
        self.raw_headers: list = []
        self.target_fingerprint = _FakeFingerprint()


class TestDeepProbeQueue:
    """BL-036：深度探测显式优先级队列（优先级而非代码顺序决定饿死）。"""

    @staticmethod
    def _counter(deep_max: int) -> _ProbeCounter:
        c = _ProbeCounter()
        c._deep_max = deep_max
        return c

    @staticmethod
    def _patch(monkeypatch, ran: dict) -> None:
        import recon.api.openapi_discoverer as oa
        import recon.capability_probe as cap
        import recon.graphql_probe as gq
        import recon.waf_detector as wd

        async def _g(*_a, **_k):
            ran["graphql"] = True

        async def _r(*_a, **_k):
            ran["rate_limit"] = True

        async def _d(*_a, **_k):
            ran["deep_capabilities"] = True
            return {}

        async def _o(*_a, **_k):
            ran["openapi"] = True

        monkeypatch.setattr(gq, "probe_graphql_endpoint", _g)
        monkeypatch.setattr(gq, "is_graphql_signal", lambda **_k: False)
        monkeypatch.setattr(wd, "probe_rate_limit", _r)
        monkeypatch.setattr(cap, "deep_probe_capabilities", _d)
        monkeypatch.setattr(oa, "discover_openapi_spec", _o)

    def test_tight_budget_priority_governed(self, monkeypatch) -> None:
        from recon._target_router_helpers import _run_deep_probe_queue

        ran: dict = {}
        self._patch(monkeypatch, ran)
        asyncio.run(_run_deep_probe_queue(_FakeParsed(), self._counter(6), None))
        # priority 降序: deep_capabilities(90)→graphql(85) 先行；openapi(80)/rate_limit(75)
        # 预算耗尽被显式跳过（不再是代码书写顺序隐式决定"饥饿"）
        assert "deep_capabilities" in ran and "graphql" in ran
        assert "openapi" not in ran and "rate_limit" not in ran

    def test_ample_budget_all_run(self, monkeypatch) -> None:
        from recon._target_router_helpers import _run_deep_probe_queue

        ran: dict = {}
        self._patch(monkeypatch, ran)
        asyncio.run(_run_deep_probe_queue(_FakeParsed(), self._counter(20), None))
        assert {"deep_capabilities", "graphql", "openapi", "rate_limit"} <= set(ran)


class TestRelatedEndpointDiscovery:
    """BL-032：裸 URL 关联端点发现（有界、仅收录 <400、不爆破）。"""

    def test_filters_by_status_and_shape(self) -> None:
        from recon.api.url_endpoint_discoverer import discover_related_endpoints

        class _Resp:
            def __init__(self, code: int) -> None:
                self.status_code = code

        class _Client:
            async def get(self, url: str, **_k: object):
                from urllib.parse import urlparse

                path = urlparse(url).path
                return _Resp(200 if path in ("/api", "/openapi.json") else 404)

            async def aclose(self) -> None:
                pass

        res = asyncio.run(
            discover_related_endpoints(
                "http://t", client=_Client(), paths=("/api", "/openapi.json", "/nope")
            )
        )
        assert {r["path"] for r in res} == {"/api", "/openapi.json"}
        assert all(r["method"] == "GET" and r["source"] == "path_probe" for r in res)

    def test_empty_when_all_404(self) -> None:
        from recon.api.url_endpoint_discoverer import discover_related_endpoints

        class _Client:
            async def get(self, *_a: object, **_k: object):
                class _R:
                    status_code = 404

                return _R()

            async def aclose(self) -> None:
                pass

        res = asyncio.run(
            discover_related_endpoints("http://t", client=_Client(), paths=("/x", "/y"))
        )
        assert res == []
