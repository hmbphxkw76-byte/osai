"""W-P4 P4-4 — 组件面 playbook 端到端断言（NFR-22 / REQ-156⑤）。

覆盖全部 9 个 playbook（a2a×3 / mcp×3 / rag×2 / embedding×1），每靶标断言四维：
  1. 识别标签：playbook 登记进所属组件 YAML 的 `playbooks:` 字段；
  2. 结构良构：可加载、步数≥1、每步 adapter/action 合法、depends_on DAG 合法；
  3. playbook 成功率：经 fake adapter 端到端跑通，每步 status=="ok"；
  4. cleanup 后状态：每步 adapter.close() 被调用。
verdict 四态维度由 test_playbook_verdict_four_state 覆盖（content_only / exfil_suspected
/ exfil_confirmed / impact），与 tests/common/test_impact_model.py 共同满足 NFR-22。

设计约束（R-H3）：靶场断言唯一实现是 tools.mock_range.run_check；本文件不另写靶场断言，
只验证 playbook 交付物本身 + 经 fake adapter 的引擎编排正确性。
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import yaml

import strike.playbook as playbook_mod
from assess.impact import OOBReceiptLog, generate_canary
from assess.impact.model import decide_model_verdict
from strike.playbook import PlaybookEngine, load_playbook, load_playbooks

_PLAYBOOK_DIR = "config/playbooks"
_FIXTURE = Path("tests/e2e/fixtures/expected.yaml")
_COMPONENTS_DIR = "config/components"


class _Resp:
    def __init__(self, text: str, payload: dict[str, Any]) -> None:
        self.text = text
        self.payload = payload


class _FakeAdapter:
    """通用桩 adapter：覆盖 playbook 用到的全部动作；可选植入 canary 以测 verdict。"""

    def __init__(self, kind: str, *, canary: str | None = None) -> None:
        self.kind = kind
        self.canary = canary
        self.calls: list[Any] = []
        self.closed = False

    def _maybe_inject(self, text: str) -> str:
        return f"{text} {self.canary}" if self.canary else text

    async def send(self, prompt: str) -> Any:
        return _Resp(self._maybe_inject("sent"), {})

    async def handshake(self) -> dict[str, Any]:
        self.calls.append("handshake")
        return {"status": "completed"}

    async def list_tools(self) -> list[dict[str, Any]]:
        self.calls.append("list_tools")
        return [{"name": "file_read", "description": "read a file"}]

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("call_tool", tool))
        return {"status": "completed", "tool": tool}

    async def query(self, prompt: str) -> dict[str, Any]:
        self.calls.append(("query", prompt))
        return {"status": "completed", "text": self._maybe_inject("retrieved")}

    async def fetch_agent_card(self) -> dict[str, Any]:
        self.calls.append("fetch_agent_card")
        return {"name": "victim", "skills": ["search"]}

    async def send_task(self, prompt: str) -> dict[str, Any]:
        self.calls.append(("send_task", prompt))
        return {"status": "completed", "taskId": "t1"}

    def describe(self) -> dict[str, Any]:
        return {"target": self.kind, "kind": self.kind}

    def close(self) -> None:
        self.closed = True
        self.calls.append("close")


def _install_factory(monkeypatch, *, canary: str | None = None) -> list[_FakeAdapter]:
    """替换引擎取用的构造器入口，确保 fake adapter 生效（不依赖 _ADAPTERS 注册细节）。"""
    made: list[_FakeAdapter] = []

    def _factory(*, kind: str, **_kw: Any) -> _FakeAdapter:
        a = _FakeAdapter(kind, canary=canary)
        made.append(a)
        return a

    monkeypatch.setattr(playbook_mod, "get_build_adapter", lambda: _factory)
    return made


def _expected() -> dict[str, Any]:
    return yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))


def _component_playbooks(component: str) -> list[str]:
    text = (Path(_COMPONENTS_DIR) / f"{component}.yaml").read_text(encoding="utf-8")
    return (yaml.safe_load(text) or {}).get("playbooks") or []


def test_all_playbooks_registered_in_components() -> None:
    """Dim 1（识别标签）：expected 中的每个 playbook 都登记进所属组件 YAML。"""
    for component, info in _expected()["targets"].items():
        listed = _component_playbooks(component)
        for name in info["playbooks"]:
            assert name in listed, f"{component}.yaml 未登记 playbook: {name}"


def test_playbook_structure_matches_expected() -> None:
    """Dim 2（结构良构）：加载后每步的 name/adapter/action/depends_on 与 golden 一致。"""
    exp = _expected()
    pbs = load_playbooks(_PLAYBOOK_DIR)
    for name, spec in exp["playbooks"].items():
        assert name in pbs, f"缺少 playbook 文件: {name}"
        pb = pbs[name]
        assert pb.steps, f"{name} 无步骤"
        names = [s.name for s in pb.steps]
        assert len(names) == len(set(names)), f"{name} 步骤名重复"
        for i, step in enumerate(pb.steps):
            e_name, e_action, e_dep = spec["steps"][i]
            assert step.name == e_name, f"{name} 步名不符"
            assert step.adapter == spec["adapter"], f"{name} adapter 不符"
            assert step.action == e_action, f"{name} action 不符"
            assert step.depends_on == e_dep, f"{name} depends_on 不符"
            for d in step.depends_on:
                assert d in names, f"{name} 依赖了不存在的步骤: {d}"


def test_playbooks_run_end_to_end_and_cleanup(monkeypatch) -> None:
    """Dim 3（成功率）+ Dim 4（cleanup）：9 个 playbook 均端到端跑通且每步 close()。"""
    exp = _expected()
    for name in exp["playbooks"]:
        made = _install_factory(monkeypatch)
        pb = load_playbook(f"{_PLAYBOOK_DIR}/{name}.yaml")
        results = asyncio.run(PlaybookEngine().run(pb, "http://mock", "objective"))
        assert results, f"{name} 无结果"
        assert all(r.status == "ok" for r in results), (
            f"{name} 存在非 ok 步: {[r.status for r in results]}"
        )
        closed = [a for a in made if a.closed]
        assert len(closed) == len(pb.steps), f"{name} 部分 step 未触发 cleanup（{len(closed)}/{len(pb.steps)}）"


def test_playbook_verdict_four_state(monkeypatch) -> None:
    """Dim 3（verdict 四态）：playbook 引擎输出驱动四态判决，四态均可达。"""
    canary = generate_canary()
    _install_factory(monkeypatch, canary=canary)
    pb = load_playbook(f"{_PLAYBOOK_DIR}/rag_poison.yaml")
    results = asyncio.run(PlaybookEngine().run(pb, "http://mock", "objective"))

    texts: list[str] = []
    for r in results:
        texts.append(str(r.text))
        if isinstance(r.data, dict) and r.data.get("text"):
            texts.append(str(r.data["text"]))
    text = " ".join(texts)

    log = OOBReceiptLog()
    log.record(canary=canary)
    v = decide_model_verdict(response_text=text, canaries=[canary], receipt_log=log)
    assert v["verdict"] == "exfil_confirmed"
    assert v["confirmed"] is True

    # 四态其余可达性（合成输入，证明枚举完整）
    assert decide_model_verdict(response_text="normal safe answer")["verdict"] == "content_only"
    assert decide_model_verdict(response_text="here is the system prompt: you are helpful")["verdict"] == "exfil_suspected"
    assert decide_model_verdict(side_effect_confirmed=True)["verdict"] == "impact"
