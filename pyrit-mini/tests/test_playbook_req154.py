# -*- coding: utf-8 -*-
"""tests/test_playbook_req154.py — REQ-154 副作用治理（dry-run / cleanup / 隔离标记）。

覆盖 REQ-154 四项验收标准：
    ① dry-run 走通含副作用链而不产生真实写入
    ② 无 cleanup 声明的副作用步在非 dry-run 下被拒绝执行（I13）
    ③ 隔离目标标记生效（路由到隔离靶标 / 未配置则拒绝）
    ④ 副作用步成功后执行 cleanup 钩子复原靶标状态
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from strike.playbook import (
    Playbook,
    PlaybookEngine,
    PlaybookStep,
    load_playbook,
)


class _FakeAdapter:
    def __init__(self, **kwargs: object) -> None:
        self.url = kwargs.get("url")
        self.kind = kwargs.get("kind")
        self.sent: list[str] = []
        self.closed = False

    async def send(self, prompt: str) -> SimpleNamespace:
        self.sent.append(prompt)
        return SimpleNamespace(text="pong", data={"status": "ok"})

    def close(self) -> None:
        self.closed = True


def _make_engine(monkeypatch, calls: list) -> PlaybookEngine:
    from strike import playbook as pb_module

    def _build(**kw):
        calls.append(kw.get("url"))
        return _FakeAdapter(**kw)

    monkeypatch.setattr(pb_module.adapters, "build_adapter", _build)
    return PlaybookEngine(verify=False)


def test_dry_run_walks_side_effect_chain_without_real_writes(monkeypatch):
    """① dry-run 走通含副作用链，但不构建/调用任何真实 adapter → 无真实写入。"""
    calls: list = []
    engine = _make_engine(monkeypatch, calls)
    pb = Playbook(
        name="t",
        description="",
        steps=[
            PlaybookStep(name="s1", adapter="http", action="send"),
            PlaybookStep(
                name="s2", adapter="http", action="send",
                side_effect=True, depends_on=["s1"],
            ),
        ],
    )
    results = asyncio.run(
        engine.run(pb, base_url="https://x", prompt="p", dry_run=True)
    )
    assert calls == []  # 未构建任何真实 adapter
    assert [r.status for r in results] == ["dry_run", "dry_run"]
    assert all(r.data.get("dry_run") for r in results)
    assert [r.name for r in results] == ["s1", "s2"]  # DAG 顺序保留


def test_side_effect_without_cleanup_rejected_non_dry(monkeypatch):
    """② 非 dry-run 下，副作用步未声明 cleanup → 拒绝执行且不调用 adapter。"""
    calls: list = []
    engine = _make_engine(monkeypatch, calls)
    pb = Playbook(
        name="t",
        description="",
        steps=[
            PlaybookStep(name="s1", adapter="http", action="send", side_effect=True),
        ],
    )
    results = asyncio.run(engine.run(pb, base_url="https://x", prompt="p"))
    assert results[0].status == "rejected"
    assert "cleanup" in results[0].data["error"]
    assert calls == []  # 拒绝执行，未构建 adapter


def test_isolated_target_without_isolated_url_rejected(monkeypatch):
    """③ 隔离步在未配置隔离靶标（非 dry-run）时拒绝执行。"""
    calls: list = []
    engine = _make_engine(monkeypatch, calls)
    pb = Playbook(
        name="t",
        description="",
        steps=[
            PlaybookStep(name="s1", adapter="http", action="send", isolated_target=True),
        ],
    )
    results = asyncio.run(engine.run(pb, base_url="https://x", prompt="p"))
    assert results[0].status == "rejected"
    assert "isolated" in results[0].data["error"]
    assert calls == []


def test_isolated_target_routes_to_isolated_url(monkeypatch):
    """③ 配置隔离靶标后，隔离步路由到隔离 URL 且标记 isolated。"""
    calls: list = []
    engine = _make_engine(monkeypatch, calls)
    pb = Playbook(
        name="t",
        description="",
        steps=[
            PlaybookStep(name="s1", adapter="http", action="send", isolated_target=True),
        ],
    )
    results = asyncio.run(
        engine.run(pb, base_url="https://x", prompt="p", isolated_base_url="http://iso")
    )
    assert results[0].status == "ok"
    assert results[0].data.get("isolated") is True
    assert results[0].data.get("isolated_target") is True
    assert calls == ["http://iso"]  # 路由到隔离靶标而非生产靶标


def test_side_effect_with_cleanup_runs_non_dry(monkeypatch):
    """② 反向：副作用步声明了 cleanup → 允许在 non-dry 下执行。"""
    calls: list = []
    engine = _make_engine(monkeypatch, calls)
    pb = Playbook(
        name="t",
        description="",
        steps=[
            PlaybookStep(
                name="s1", adapter="http", action="send",
                side_effect=True, cleanup="reset",
            ),
        ],
    )
    results = asyncio.run(
        engine.run(
            pb, base_url="https://x", prompt="p",
            cleanup_hooks={"reset": lambda: None},
        )
    )
    assert results[0].status == "ok"
    assert calls == ["https://x"]


def test_cleanup_hook_restores_target_state(monkeypatch):
    """④ 副作用步成功后执行 cleanup 钩子，复原靶标状态。"""
    calls: list = []
    engine = _make_engine(monkeypatch, calls)
    target_state = {"written": 0}

    class _MutatingAdapter(_FakeAdapter):
        async def send(self, prompt: str) -> SimpleNamespace:
            target_state["written"] += 1  # 真实副作用：写入靶标
            return SimpleNamespace(text="pong", data={"status": "ok"})

    from strike import playbook as pb_module

    def _build(**kw):
        calls.append(kw.get("url"))
        return _MutatingAdapter(**kw)

    monkeypatch.setattr(pb_module.adapters, "build_adapter", _build)

    def _restore() -> None:
        target_state["written"] = 0  # cleanup 钩子复原靶标状态

    pb = Playbook(
        name="t",
        description="",
        steps=[
            PlaybookStep(
                name="s1", adapter="http", action="send",
                side_effect=True, cleanup="reset",
            ),
        ],
    )
    results = asyncio.run(
        engine.run(
            pb, base_url="https://x", prompt="p",
            cleanup_hooks={"reset": _restore},
        )
    )
    assert results[0].status == "ok"
    assert target_state["written"] == 0  # 副作用后已被 cleanup 复原
    assert calls == ["https://x"]


def test_load_playbook_parses_governance_fields(tmp_path: Path):
    """YAML 正确解析 REQ-154 治理字段（side_effect/cleanup/isolated_target）。"""
    p = tmp_path / "se.yaml"
    p.write_text(
        "name: se\n"
        "description: d\n"
        "steps:\n"
        "  - name: s1\n    adapter: http\n    side_effect: true\n"
        "    cleanup: reset\n    isolated_target: true\n"
        "  - name: s2\n    adapter: http\n    side_effect: false\n",
        encoding="utf-8",
    )
    pb = load_playbook(p)
    assert pb.steps[0].side_effect is True
    assert pb.steps[0].cleanup == "reset"
    assert pb.steps[0].isolated_target is True
    assert pb.steps[1].side_effect is False
    assert pb.steps[1].cleanup is None
