"""REQ-174 A2A 三条跨 agent 链 playbook 端到端断言（W-P3 P3-5 / NFR-22）。

设计约束（R-H3）：靶场断言的唯一实现是 `tools.mock_range.run_check`；本文件
**不另写靶场断言**，只验证 P3-5 新增交付物本身——
  1. 三条 A2A playbook 文件存在、结构正确（adapter=a2a，动作合法，依赖有序）；
  2. 三条链均已登记进 `a2a.yaml` 的 `playbooks:` 字段；
  3. `PlaybookEngine` 能端到端跑通一条 A2A 链（success + cleanup 生效）。

真实靶标 `targets/mock/a2a_agent` 的 golden 断言由 `test_mock_range_e2e.py`
与 `tests/common/test_mock_range.py::test_a2a_agent_card` 覆盖，本文件不重复。
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import yaml

from strike.playbook import PlaybookEngine, load_playbook, load_playbooks

_PLAYBOOK_DIR = "config/playbooks"
_A2A_PLAYBOOKS = ["a2a_card_spoof", "a2a_workflow_hijack", "a2a_cross_agent_inject"]


class _A2AFakeAdapter:
    """a2a adapter 的最小桩，仅实现 PlaybookEngine 派发的动作（REQ-149 A2ATarget）。"""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.calls: list[Any] = []

    async def fetch_agent_card(self) -> dict[str, Any]:
        self.calls.append("fetch_agent_card")
        return {"name": "victim", "skills": ["search"]}

    async def send_task(self, prompt: str) -> dict[str, Any]:
        self.calls.append(("send_task", prompt))
        return {"status": "completed", "taskId": "t1"}

    def describe(self) -> dict[str, Any]:
        return {"target": "a2a", "kind": self.kind}

    def close(self) -> None:
        self.calls.append("close")


@pytest.fixture
def fake_a2a_adapter(monkeypatch):
    made: list[_A2AFakeAdapter] = []

    def _factory(*, url: str, kind: str, **_kw: Any) -> _A2AFakeAdapter:
        a = _A2AFakeAdapter(kind)
        made.append(a)
        return a

    import recon.adapters as adapters_mod

    monkeypatch.setattr(adapters_mod, "build_adapter", _factory)
    return made


def test_a2a_playbooks_registered_and_well_formed() -> None:
    """三条 A2A playbook 文件存在、结构正确。"""
    pbs = load_playbooks(_PLAYBOOK_DIR)
    for name in _A2A_PLAYBOOKS:
        assert name in pbs, f"缺少 A2A playbook: {name}"
        pb = pbs[name]
        assert len(pb.steps) == 2, f"{name} 应有 2 步（fetch + task）"
        assert pb.steps[0].adapter == "a2a" and pb.steps[0].action == "fetch_agent_card"
        assert pb.steps[1].adapter == "a2a" and pb.steps[1].action == "send_task"
        assert pb.steps[1].depends_on == [pb.steps[0].name]


def test_a2a_playbooks_listed_in_component_yaml() -> None:
    """三条 playbook 已登记进 a2a.yaml 的 playbooks 字段。"""
    text = open("config/components/a2a.yaml", encoding="utf-8").read()
    data = yaml.safe_load(text)
    listed = data.get("playbooks") or []
    for name in _A2A_PLAYBOOKS:
        assert name in listed, f"a2a.yaml 未登记 playbook: {name}"


def test_a2a_playbook_runs_end_to_end(fake_a2a_adapter: list[_A2AFakeAdapter]) -> None:
    """PlaybookEngine 能端到端跑通一条 A2A 链（success + cleanup 生效）。"""
    pb = load_playbook(f"{_PLAYBOOK_DIR}/a2a_card_spoof.yaml")
    results = asyncio.run(PlaybookEngine().run(pb, "http://mock/a2a", "objective"))
    assert [r.name for r in results] == ["fetch_card", "spoof_task"]
    assert all(r.status == "ok" for r in results)
    # cleanup 生效：每步 adapter 被 close
    assert any("close" in a.calls for a in fake_a2a_adapter)
    # 数据链路：send_task 真正提交任务（承载注入文本）
    sent = [c for a in fake_a2a_adapter for c in a.calls if c[0] == "send_task"]
    assert sent, "A2A 链未真正提交任务（send_task 未被调用）"
