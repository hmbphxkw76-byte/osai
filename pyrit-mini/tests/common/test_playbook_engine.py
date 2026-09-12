"""REQ-151 PlaybookEngine 测试：步骤选 adapter、动作派发、依赖排序、动态数据流。

引擎逻辑（动作派发/排序/首工具解析）离线验证；adapter 本身对 MockRange 的端到端
已由 `tests/common/test_adapters.py` 覆盖，故本文件聚焦于编排层正确性。
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock  # noqa: F401

import pytest

import recon.adapters as adapters_mod
from strike.playbook import (
    Playbook,
    PlaybookEngine,
    PlaybookStep,
    load_playbook,
    load_playbooks,
)


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text
        self.data: dict[str, Any] = {}


class _FakeAdapter:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.calls: list[Any] = []
        self._tools = ["filesystem", "fetch"]

    async def send(self, prompt: str) -> _Resp:
        self.calls.append(("send", prompt))
        return _Resp("ok")

    async def handshake(self) -> dict[str, str]:
        self.calls.append(("handshake",))
        return {"status": "ready"}

    async def list_tools(self) -> list[str]:
        self.calls.append(("list_tools",))
        return self._tools

    async def call_tool(self, tool: str, args: dict[str, Any]) -> dict[str, str]:
        self.calls.append(("call_tool", tool, args))
        return {"status": "ran"}

    def close(self) -> None:
        self.calls.append(("close",))


@pytest.fixture
def fake_adapters(monkeypatch) -> list[_FakeAdapter]:
    made: list[_FakeAdapter] = []

    def _factory(*, url: str, kind: str, **_kw: Any) -> _FakeAdapter:
        a = _FakeAdapter(kind)
        made.append(a)
        return a

    monkeypatch.setattr(adapters_mod, "build_adapter", _factory)
    return made


def test_engine_dispatches_actions_in_order_and_resolves_first_tool(fake_adapters: list[_FakeAdapter]) -> None:
    pb = Playbook(
        name="mcp_enum_call",
        description="",
        steps=[
            PlaybookStep(name="handshake", adapter="mcp", action="handshake"),
            PlaybookStep(name="tools_list", adapter="mcp", action="list_tools", depends_on=["handshake"]),
            PlaybookStep(
                name="tool_call", adapter="mcp", action="call_tool",
                depends_on=["tools_list"], params={"arguments": {"query": "x"}},
            ),
        ],
    )
    results = asyncio.run(PlaybookEngine().run(pb, "http://t", "objective"))
    assert [r.name for r in results] == ["handshake", "tools_list", "tool_call"]
    assert all(r.adapter == "mcp" for r in results)
    assert results[2].status == "ok"
    assert results[2].data.get("status") == "ran"
    # 动态数据流：tool_call 应使用 list_tools 发现的第一个工具
    # （每个 step 独立建 adapter，call_tool 落在 tool_call 步的 adapter 上）
    tool_call_adapter = fake_adapters[2]
    call_tool_calls = [c for c in tool_call_adapter.calls if c[0] == "call_tool"]
    assert call_tool_calls
    assert call_tool_calls[-1][1] == "filesystem"


def test_step_failure_isolated_not_fatal(monkeypatch) -> None:
    made: list[_FakeAdapter] = []

    def _factory(*, url: str, kind: str, **_kw: Any) -> _FakeAdapter:
        a = _FakeAdapter(kind)
        made.append(a)
        if len(made) == 2:  # 第二个 step 的 list_tools 抛错
            a.list_tools = AsyncMock(side_effect=RuntimeError("explode"))
        return a

    monkeypatch.setattr(adapters_mod, "build_adapter", _factory)
    pb = Playbook(
        name="p",
        description="",
        steps=[
            PlaybookStep(name="ok", adapter="mcp", action="handshake"),
            PlaybookStep(name="boom", adapter="mcp", action="list_tools"),
        ],
    )
    results = asyncio.run(PlaybookEngine().run(pb, "http://t", "x"))
    # 单步失败不阻断整条 playbook，整体不抛
    assert {r.status for r in results} == {"ok", "error"}


def test_load_playbook_yaml(tmp_path) -> None:
    p = tmp_path / "mcp_enum_call.yaml"
    p.write_text(
        "name: mcp_enum_call\n"
        "description: d\n"
        "steps:\n"
        "  - name: handshake\n    adapter: mcp\n    action: handshake\n"
        "  - name: tool_call\n    adapter: mcp\n    action: call_tool\n"
        "    params:\n      arguments: {query: x}\n",
        encoding="utf-8",
    )
    pb = load_playbook(p)
    assert pb.name == "mcp_enum_call"
    assert pb.steps[1].action == "call_tool"
    assert pb.steps[1].params == {"arguments": {"query": "x"}}


def test_load_playbooks_directory(tmp_path) -> None:
    (tmp_path / "a.yaml").write_text("name: a\ndescription: ''\nsteps: []\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("name: b\ndescription: ''\nsteps: []\n", encoding="utf-8")
    pbs = load_playbooks(tmp_path)
    assert set(pbs) == {"a", "b"}
