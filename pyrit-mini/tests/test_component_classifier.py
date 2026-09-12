"""tests/test_component_classifier.py — 多信号融合组件识别（plan Wave 1）。

覆盖 DoD：
    - 组件键 ≥10（含 embedding / llm_gateway / audit_evasion / supply_chain）
    - 静默失败率 = 0%（降级必须 warning + reason 非空）
    - 未知组件返回 None 不崩溃（IA-6）
    - 组件键映射的代码持有者 = 1（IA-3）
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from core.component_classifier import (
    ClassificationResult,
    build_component_graph,
    classify,
)
from core.contracts.component_graph import ComponentGraph
from core.registry import ComponentRegistry, get_registry


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class _FakeFingerprint:
    def __init__(self, **kw: Any) -> None:
        self._d = dict(kw)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._d)


class _FakeParsed:
    """最小 ParsedBurpRequest 替身（只提供分类器消费的字段）。"""

    def __init__(self, *, url: str = "", path: str = "", body: str = "", **fp: Any) -> None:
        self.url = url
        self.path = path
        self.host = ""
        self.body = body
        self.api_category = "chat"
        self.target_fingerprint = _FakeFingerprint(**fp)


# =============================================================================
# 注册表：组件键覆盖（Wave 1 DoD）
# =============================================================================


class TestComponentKeyCoverage:
    def test_registry_has_at_least_ten_keys(self) -> None:
        keys = get_registry().keys()
        assert len(keys) >= 10, f"组件键应 >= 10，实际 {len(keys)}: {keys}"

    @pytest.mark.parametrize(
        "key",
        [
            "mcp_tool_poisoning",
            "a2a_agent_integrity",
            "rag_pipeline",
            "model_behavior_shift",
            "session_memory",
            "web_api",
            "embedding",
            "llm_gateway",
            "audit_evasion",
            "supply_chain",
        ],
    )
    def test_all_ten_component_keys_resolvable(self, key: str) -> None:
        spec = get_registry().spec(key)
        assert spec is not None, f"组件键 {key} 未注册"
        assert spec.component_key == key

    def test_unknown_key_returns_none(self) -> None:
        """IA-6：未知组件返回 None 不崩溃。"""
        assert get_registry().spec("no_such_component") is None

    def test_validate_wiring_has_no_blocking_errors(self) -> None:
        errs = get_registry().validate_wiring()
        blocking = [e for e in errs if e.severity == "blocking"]
        assert not blocking, f"存在 BLOCKING 接线错误: {[str(e) for e in blocking]}"


# =============================================================================
# 多信号融合识别
# =============================================================================


class TestClassify:
    def test_mcp_detected_by_path_and_body(self) -> None:
        parsed = _FakeParsed(
            url="https://t.example.com/mcp",
            path="/mcp",
            body='{"jsonrpc":"2.0","method":"tools/list"}',
        )
        result = classify(parsed)
        assert "mcp_tool_poisoning" in result.keys()
        node = next(n for n in result.nodes if n.component_key == "mcp_tool_poisoning")
        assert node.confidence >= 0.60

    def test_rag_detected_by_citation_markers(self) -> None:
        parsed = _FakeParsed(
            url="https://t.example.com/api/retrieve",
            path="/api/retrieve",
            body='{"citations":[],"retrieved":[]}',
        )
        result = classify(parsed)
        assert "rag_pipeline" in result.keys()

    def test_override_locks_components(self) -> None:
        """层 2 显式指定兜底：直接锁定，confidence=1.0。"""
        parsed = _FakeParsed(path="/anything")
        result = classify(parsed, override=["mcp_tool_poisoning", "rag_pipeline"])
        assert result.keys() == ["mcp_tool_poisoning", "rag_pipeline"]
        assert all(n.confidence == 1.0 for n in result.nodes)
        assert result.degraded is False

    def test_override_unknown_key_is_reported_not_silent(self, caplog: pytest.LogCaptureFixture) -> None:
        """反静默：未知组件键必须 warning，不得 debug 吞掉。"""
        with caplog.at_level(logging.WARNING):
            result = classify(_FakeParsed(path="/x"), override=["mcp_tool_poisoning", "bogus_key"])
        assert "bogus_key" in caplog.text
        assert [n.component_key for n in result.nodes] == ["mcp_tool_poisoning"]

    def test_empty_registry_degrades_with_reason(self, tmp_path: Path) -> None:
        """空注册表 → degraded=True 且 reason 非空（静默失败率 = 0%）。"""
        empty = ComponentRegistry(tmp_path / "none")
        import core.component_classifier as cc

        original = cc.get_registry
        cc.get_registry = lambda *a, **k: empty  # type: ignore[assignment]
        try:
            result = classify(_FakeParsed(path="/api/chat"))
        finally:
            cc.get_registry = original  # type: ignore[assignment]

        assert result.degraded is True
        assert result.reason, "降级原因禁止为空字符串"

    def test_degraded_result_has_non_empty_reason(self) -> None:
        """任何 degraded 结果都必须带人类可读 reason。"""
        result = classify(None, override=[])
        if result.degraded:
            assert result.reason

    def test_result_is_serializable(self) -> None:
        result = classify(_FakeParsed(path="/mcp", body='{"jsonrpc":"2.0"}'))
        payload = result.to_dict()
        assert payload["schema_version"] == "1.0"
        assert isinstance(payload["nodes"], list)


# =============================================================================
# ComponentGraph 构建
# =============================================================================


class TestBuildComponentGraph:
    def _graph(self) -> ComponentGraph:
        result = classify(_FakeParsed(path="/mcp", body='{"jsonrpc":"2.0","method":"tools/list"}'))
        return build_component_graph(result)

    def test_graph_has_nodes_and_entry_points(self) -> None:
        graph = self._graph()
        assert graph.nodes, "组件图不应为空"
        assert graph.entry_points, "必须声明入口节点"

    def test_edges_are_created_from_neighbors(self) -> None:
        graph = self._graph()
        assert graph.edges, "组合体应产生组件间关系边"

    def test_shortest_path_and_reachable(self) -> None:
        graph = self._graph()
        src = graph.entry_points[0]
        assert src in graph.reachable(src)
        for dst in graph.keys():
            path = graph.shortest_path(src, dst)
            if path is not None:
                assert path[0] == src and path[-1] == dst

    def test_unknown_key_shortest_path_returns_none(self) -> None:
        """IA-6：未知节点查询返回 None，不抛异常。"""
        graph = self._graph()
        assert graph.shortest_path("nope", "also_nope") is None

    def test_graph_is_serializable(self) -> None:
        payload = self._graph().to_dict()
        assert payload["schema_version"] == "1.0"


# =============================================================================
# 组合体推断
# =============================================================================


class TestComboInference:
    def test_inferred_neighbors_marked_as_inferred(self) -> None:
        result = classify(_FakeParsed(path="/mcp", body='{"jsonrpc":"2.0","method":"tools/list"}'))
        inferred = [n for n in result.nodes if n.attributes.get("inferred")]
        confirmed = [n for n in result.nodes if not n.attributes.get("inferred")]
        assert confirmed, "至少有一个稳固确认的组件"
        if inferred:
            assert all(n.confidence < 1.0 for n in inferred)

    def test_max_components_cap_applied(self, tmp_path: Path) -> None:
        """组件数超过 max_components 时按置信度裁剪（防组合体爆炸）。"""
        parsed = _FakeParsed(path="/mcp", body='{"jsonrpc":"2.0","method":"tools/list"}')

        class _Args:
            weight_path = 0.40
            weight_body = 0.30
            weight_capability = 0.20
            weight_profile = 0.10
            neighbor_infer_confidence = 0.30
            fallback_min_confidence = 0.20
            max_components = 2

        result = classify(parsed, args=_Args())
        assert len(result.nodes) <= 2


def test_classification_result_keys_and_top() -> None:
    result = ClassificationResult(nodes=[])
    assert result.keys() == []
    assert result.top() is None
