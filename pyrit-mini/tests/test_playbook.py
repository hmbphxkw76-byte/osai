# -*- coding: utf-8 -*-
"""tests/test_playbook.py — strike/playbook.py 单元测试（Playbook 四链执行，REQ-151/IC-4）。"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from strike.playbook import (
    Playbook,
    PlaybookEngine,
    PlaybookStep,
    _order_steps,
    load_playbook,
    load_playbooks,
)


def test_load_playbook_parses_steps(tmp_path: Path):
    """YAML 文件 → Playbook，步骤含 adapter/action/depends_on。"""
    p = tmp_path / "mcp-recon.yaml"
    p.write_text(
        "name: mcp-recon\n"
        "description: d\n"
        "steps:\n"
        "  - name: s1\n    adapter: http\n    action: send\n"
        "  - name: s2\n    adapter: mcp\n    action: call_tool\n    depends_on: [s1]\n",
        encoding="utf-8",
    )
    pb = load_playbook(p)
    assert pb.name == "mcp-recon"
    assert len(pb.steps) == 2
    assert pb.steps[1].depends_on == ["s1"]


def test_order_steps_respects_dependencies():
    """拓扑排序：被依赖的步先执行。"""
    steps = [
        PlaybookStep(name="b", adapter="http", depends_on=["a"]),
        PlaybookStep(name="a", adapter="http"),
    ]
    ordered = [s.name for s in _order_steps(steps)]
    assert ordered.index("a") < ordered.index("b")


def test_order_steps_cycle_falls_back():
    """环依赖时回退到声明顺序（IA-6：不卡死）。"""
    steps = [
        PlaybookStep(name="x", adapter="http", depends_on=["y"]),
        PlaybookStep(name="y", adapter="http", depends_on=["x"]),
    ]
    ordered = _order_steps(steps)
    assert len(ordered) == 2  # 全部保留，未丢失


def test_load_playbooks_directory(tmp_path: Path):
    """目录下多 playbook 按名加载。"""
    (tmp_path / "p1.yaml").write_text("name: p1\nsteps: []\n", encoding="utf-8")
    (tmp_path / "p2.yaml").write_text("name: p2\nsteps: []\n", encoding="utf-8")
    pbs = load_playbooks(tmp_path)
    assert set(pbs) == {"p1", "p2"}


class _FakeAdapter:
    def __init__(self, text: str = "ok") -> None:
        self._text = text

    async def send(self, prompt: str) -> SimpleNamespace:
        return SimpleNamespace(text=self._text, data={"status": "ok"})

    def close(self) -> None:
        return None


def test_playbook_engine_dispatches_send(monkeypatch):
    """PlaybookEngine 通过 build_adapter 派发 send 动作（REQ-151）。"""
    from strike import playbook as pb_module

    monkeypatch.setattr(pb_module.adapters, "build_adapter", lambda **kw: _FakeAdapter())

    engine = PlaybookEngine(verify=False)
    pb = Playbook(
        name="t",
        description="",
        steps=[PlaybookStep(name="s1", adapter="http", action="send")],
    )
    results = asyncio.run(engine.run(pb, base_url="https://x", prompt="pwn"))
    assert len(results) == 1
    assert results[0].status == "ok"
    assert results[0].text == "ok"


def test_playbook_engine_step_failure_isolated(monkeypatch):
    """单步失败不阻断整条 playbook（优雅降级，status=error）。"""
    from strike import playbook as pb_module

    def _boom(**kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(pb_module.adapters, "build_adapter", _boom)
    engine = PlaybookEngine(verify=False)
    pb = Playbook(
        name="t",
        description="",
        steps=[PlaybookStep(name="s1", adapter="http", action="send")],
    )
    results = asyncio.run(engine.run(pb, base_url="https://x", prompt="pwn"))
    assert results[0].status == "error"
    assert "error" in results[0].data
